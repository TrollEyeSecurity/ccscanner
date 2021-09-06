package sonarqube

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func Scan(content *database.TaskContent, secretData *database.TaskSecret, taskId *primitive.ObjectID) {
	SastScanResults := database.SastResults{}
	var idArray []string
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("owasp zap scan error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("nmap scan error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var repourl string
	switch {
	case content.IntegrationType == "gitlab" || content.IntegrationType == "github":
		repourlSplit := strings.Split(content.Repourl, "//")
		repourl = repourlSplit[0] + "//" + secretData.Repouser + ":" + secretData.Data.Token + "@" + repourlSplit[1]
		break
	case content.IntegrationType == "bitbucket":
		repourlSplit := strings.Split(content.Repourl, "@")
		token := getBitbucketToken(&secretData.Data)
		repourl = "https://x-token-auth:{" + *token + "}@" + repourlSplit[1]
		break
	}
	imageName := docker.SastImage
	sonarconfig := &container.Config{
		Image: imageName,
		Env: []string{
			"PROJECTNAME=" + content.ProjectName,
			"BRANCH=" + content.BranchName,
			"REPOURL=" + repourl,
			"SONARLOGIN=" + secretData.SastSecret.Sonarlogin,
			"SONARHOSTURL=" + secretData.SastSecret.Sonarhosturl,
		},
		Cmd:          []string{"run-sonar.sh"},
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
	}
	depconfig := &container.Config{
		Image: imageName,
		Env: []string{
			"PROJECTNAME=" + content.ProjectName,
			"BRANCH=" + content.BranchName,
			"REPOURL=" + repourl,
		},
		Cmd:          []string{"run-dep-checker.sh"},
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
	}
	sastResources := &container.Resources{
		Memory: 2.048e+9,
	}
	depResources := &container.Resources{
		Memory: 5.12e+8,
	}
	sastHostConfig := &container.HostConfig{
		Resources:   *sastResources,
		NetworkMode: "host",
	}
	depHostConfig := &container.HostConfig{
		Resources:   *depResources,
		NetworkMode: "host",
	}
	now := time.Now()
	sastContainerName := "sast-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	depContainerName := "dep-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	SastContainer, SastStartContainerErr := docker.StartContainer(&imageName, &sastContainerName, sonarconfig, sastHostConfig)
	if SastStartContainerErr != nil {
		err := fmt.Errorf("sast scan error %v: %v", SastStartContainerErr, SastContainer)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	DepContainer, DepStartContainerErr := docker.StartContainer(&imageName, &depContainerName, depconfig, depHostConfig)
	if DepStartContainerErr != nil {
		err := fmt.Errorf("sast scan error %v: %v", DepStartContainerErr, SastContainer)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	idArray = append(idArray, SastContainer.ID)
	idArray = append(idArray, DepContainer.ID)
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"container_id", DepContainer.ID}, {"status", "PROGRESS"}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("nmap sast error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	_, sastErrCh := cli.ContainerWait(ctx, SastContainer.ID)
	if sastErrCh != nil {
		err := fmt.Errorf("sast scan error %v", sastErrCh)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}

	_, updateError2 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", 50}}}},
	)
	if updateError2 != nil {
		err := fmt.Errorf("sonarqube mongo-update error %v", updateError2)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		cli.Close()
		MongoClient.Disconnect(context.TODO())
		return
	}

	_, depErrCh := cli.ContainerWait(ctx, DepContainer.ID)
	if depErrCh != nil {
		err := fmt.Errorf("sast scan error %v", depErrCh)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}

	_, updateError3 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", 90}}}},
	)
	if updateError3 != nil {
		err := fmt.Errorf("sonarqube mongo-update error %v", updateError3)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		cli.Close()
		MongoClient.Disconnect(context.TODO())
		return
	}

	sastReader, SastContainerLogsErr := cli.ContainerLogs(ctx, SastContainer.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		Follow:     true,
	})
	if SastContainerLogsErr != nil {
		err := fmt.Errorf("sast scan error %v: %v", SastContainerLogsErr, sastReader)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		sastReader.Close()
		return
	}
	SastByteValue, sastIoutilReadAllError := ioutil.ReadAll(sastReader)
	sastReader.Close()
	if sastIoutilReadAllError != nil {
		err := fmt.Errorf("sast scan ioutil error %v", sastIoutilReadAllError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}
	SonarScannerError := "ERROR: Error during SonarScanner execution"
	if strings.Contains(SonarScannerError, string(SastByteValue)) {
		_, update2Error := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", taskId}},
			bson.D{{"$set", bson.D{
				{"sast_result", string(SastByteValue)},
				{"status", "SUCCESS"},
				{"percent", 100}}}},
		)
		docker.RemoveContainers(idArray)
		cli.Close()
		if update2Error != nil {
			err := fmt.Errorf("sonarqube update2Error %v", update2Error)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			MongoClient.Disconnect(context.TODO())
			return
		}
		MongoClient.Disconnect(context.TODO())
		return
	}
	taskIdRex := regexp.MustCompile(`(task\?id\=)(.*)`)
	taskIdMatch := taskIdRex.FindStringSubmatch(string(SastByteValue))
	if len(taskIdMatch) > 2 {
		sastOutput := taskIdMatch[2]
		SastScanResults.SonarScanId = sastOutput
	}

	depReader, depContainerLogsErr := cli.ContainerLogs(ctx, DepContainer.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		Follow:     true,
	})
	if depContainerLogsErr != nil {
		err := fmt.Errorf("sast scan error %v: %v", depContainerLogsErr, depReader)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		depReader.Close()
		return
	}
	depByteValue, depIoutilReadAllError := ioutil.ReadAll(depReader)
	depReader.Close()
	if depIoutilReadAllError != nil {
		err := fmt.Errorf("sast scan ioutil error %v", depIoutilReadAllError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}
	if len(depByteValue) > 0 {
		result := base64.StdEncoding.EncodeToString(depByteValue)
		SastScanResults.DependencyCheckerResults = result
	}
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"sast_result", SastScanResults},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	docker.RemoveContainers(idArray)
	cli.Close()
	if update2Error != nil {
		err := fmt.Errorf("owasp zap scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	MongoClient.Disconnect(context.TODO())
	return
}

func getBitbucketToken(secretData *database.SecretData) *string {
	b := []byte("grant_type=client_credentials")
	auth := base64.StdEncoding.EncodeToString([]byte(secretData.Key + ":" + secretData.Secret))
	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}
	req, NewRequestErr := http.NewRequest("POST", "https://bitbucket.org/site/oauth2/access_token", bytes.NewReader(b))
	if NewRequestErr != nil {
		log.Println(NewRequestErr)
		return nil
	}
	req.Header.Add("Authorization", "Basic "+auth)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Connection", "close")
	req.Close = true
	resp, httpClientErr := httpClient.Do(req)
	if httpClientErr != nil {
		log.Println(httpClientErr)
		return nil
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Print(err.Error())
	}
	var responseObject Response
	json.Unmarshal(bodyBytes, &responseObject)
	return &responseObject.AccessToken
}
