package snyk

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/bitBucket"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
)

func Scan(content *database.TaskContent, secretData *database.TaskSecret, taskId *primitive.ObjectID) {
	SastResults := database.SastResults{}
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("snyk mongo-client-error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	cli, NewEnvClientErr := client.NewClientWithOpts()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("snyk new-env-client-error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var repoUrl string
	switch {
	case content.IntegrationType == "gitlab" || content.IntegrationType == "github":
		repoUrlSplit := strings.Split(content.Repourl, "//")
		repoUrl = "https://x-token-auth:" + secretData.Token + "@" + repoUrlSplit[1]
		break
	case content.IntegrationType == "bitbucket":
		repoUrlSplit := strings.Split(content.Repourl, "@")
		token := bitBucket.GetToken(secretData)
		repoUrl = "https://x-token-auth:{" + *token + "}@" + repoUrlSplit[1]
		break
	}
	imageName := docker.SnykCliImage
	sastScriptType := "sast"
	scaScriptType := "sca"
	var idArray []string
	sastResults, snykSastContainerID := execute(&sastScriptType, content, &imageName, secretData, &repoUrl, cli, tasksCollection, taskId, 50)
	idArray = append(idArray, *snykSastContainerID)
	scaResults, snykScaContainerID := execute(&scaScriptType, content, &imageName, secretData, &repoUrl, cli, tasksCollection, taskId, 90)
	idArray = append(idArray, *snykScaContainerID)
	SastResults.SnykOutput.CodeResults = *sastResults
	SastResults.SnykOutput.OpenSourceResults = *scaResults
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"sast_result", SastResults},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	docker.RemoveContainers(idArray)
	cli.Close()
	if update2Error != nil {
		err := fmt.Errorf("sast scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	return
}

func execute(scriptType *string, content *database.TaskContent, imageName *string, secretData *database.TaskSecret, repoUrl *string, cli *client.Client, tasksCollection *mongo.Collection, taskId *primitive.ObjectID, pct int) (*string, *string) {
	noR := "no results"
	noResults := base64.StdEncoding.EncodeToString([]byte(noR))
	script := fmt.Sprintf("scripts/run-%s", *scriptType)
	filePath := fmt.Sprintf("/app/%s-results.json", *scriptType)
	ctx := context.Background()
	snykConfig := &container.Config{
		Image: *imageName,
		Env: []string{
			"SNYK_API_KEY=" + secretData.SnykSecret.SnykApiKey,
			"SNYK_ORG_ID=" + secretData.SnykSecret.SnykOrgId,
			"BRANCH=" + content.BranchName,
			"REPOURL=" + *repoUrl,
			"TECH=" + content.Tech,
		},
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          []string{script},
	}
	snykResources := &container.Resources{
		Memory: 2.048e+9,
	}
	snykHostConfig := &container.HostConfig{
		Resources:   *snykResources,
		NetworkMode: "host",
	}
	now := time.Now()
	snykContainerName := "snyk-" + *scriptType + "-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	snykContainer, snykStartContainerErr := docker.StartContainer(imageName, &snykContainerName, snykConfig, snykHostConfig)
	if snykStartContainerErr != nil {
		err := fmt.Errorf("snyk start-container-error %v: %v", snykStartContainerErr, snykContainer)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return &noResults, nil
	}
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"container_id", snykContainer.ID}, {"status", "PROGRESS"}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("snyk task-update-error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return &noResults, &snykContainer.ID
	}
	snykStatusCh, snykErrCh := cli.ContainerWait(ctx, snykContainer.ID, container.WaitConditionNextExit)
	select {
	case err := <-snykErrCh:
		if err != nil {
			errMsg := fmt.Errorf("snyk container-wait-error %v", err)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(errMsg)
			}
			log.Println(errMsg)
			return &noResults, &snykContainer.ID
		}
	case <-snykStatusCh:
	}
	_, updateError2 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", pct}}}},
	)
	if updateError2 != nil {
		err := fmt.Errorf("snyk mongo-update error %v", updateError2)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return &noResults, &snykContainer.ID
	}

	fileReader, _, fileReaderErr := cli.CopyFromContainer(ctx, snykContainer.ID, filePath)
	if fileReaderErr != nil {
		if fileReader != nil {
			fileReader.Close()
		}
		return &noResults, &snykContainer.ID
	}
	tr := tar.NewReader(fileReader)
	var results []byte
	var jsonData []byte
	var jsonDataError error
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			fileReader.Close()
			return &noResults, &snykContainer.ID
		}
		results, err = io.ReadAll(tr)
		if err != nil {
			fileReader.Close()
			return &noResults, &snykContainer.ID
		}
	}
	fileReader.Close()
	if *scriptType == "sast" {
		jsonResults := &CodeResults{}
		_ = json.Unmarshal(results, &jsonResults)
		jsonData, jsonDataError = json.Marshal(jsonResults)
		if jsonDataError != nil {
			// do I really want to know about all of these?
			err := fmt.Errorf("nmap scan json-marshal error %v", jsonDataError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return &noResults, &snykContainer.ID
		}
	} else {
		jsonResults := OpenSourceResults{}
		_ = json.Unmarshal(results, &jsonResults)
		jsonData, jsonDataError = json.Marshal(jsonResults)
		if jsonDataError != nil {
			// do I really want to know about all of these?
			err := fmt.Errorf("nmap scan json-marshal error %v", jsonDataError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return &noResults, &snykContainer.ID
		}
	}
	SnykOutputResult := base64.StdEncoding.EncodeToString(jsonData)
	return &SnykOutputResult, &snykContainer.ID
}
