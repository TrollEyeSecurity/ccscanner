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
	SastResults := database.SastResults{}
	var idArray []string
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
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
	var repoUrl string
	var tech string
	switch {
	case content.IntegrationType == "gitlab" || content.IntegrationType == "github":
		repoUrlSplit := strings.Split(content.Repourl, "//")
		repoUrl = "https://x-token-auth:" + secretData.Data.Token + "@" + repoUrlSplit[1]
		break
	case content.IntegrationType == "bitbucket":
		repoUrlSplit := strings.Split(content.Repourl, "@")
		token := getBitbucketToken(&secretData.Data)
		repoUrl = "https://x-token-auth:{" + *token + "}@" + repoUrlSplit[1]
		break
	}

	// todo: what the tech?

	imageName := docker.SastImage
	sonarConfig := &container.Config{
		Image: imageName,
		Env: []string{
			"TECH=" + tech,
			"PROJECTNAME=" + content.ProjectName,
			"BRANCH=" + content.BranchName,
			"REPOURL=" + repoUrl,
			"SONARLOGIN=" + secretData.SastSecret.Sonarlogin,
			"SONARHOSTURL=" + secretData.SastSecret.Sonarhosturl,
		},
		Cmd:          []string{"run-sonar.sh"},
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
	}
	depConfig := &container.Config{
		Image: imageName,
		Env: []string{
			"PROJECTNAME=" + content.ProjectName,
			"BRANCH=" + content.BranchName,
			"REPOURL=" + repoUrl,
		},
		Cmd:          []string{"run-dep-checker.sh"},
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
	}
	sonarResources := &container.Resources{
		Memory: 2.048e+9,
	}
	depResources := &container.Resources{
		Memory: 5.12e+8,
	}
	sonarHostConfig := &container.HostConfig{
		Resources:   *sonarResources,
		NetworkMode: "host",
	}
	depHostConfig := &container.HostConfig{
		Resources:   *depResources,
		NetworkMode: "host",
	}
	now := time.Now()
	sonarContainerName := "sast-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	depContainerName := "dep-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	sonarContainer, sonarStartContainerErr := docker.StartContainer(&imageName, &sonarContainerName, sonarConfig, sonarHostConfig)
	if sonarStartContainerErr != nil {
		err := fmt.Errorf("sast scan error %v: %v", sonarStartContainerErr, sonarContainer)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	depContainer, depStartContainerErr := docker.StartContainer(&imageName, &depContainerName, depConfig, depHostConfig)
	if depStartContainerErr != nil {
		err := fmt.Errorf("sast scan error %v: %v", depStartContainerErr, sonarContainer)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	idArray = append(idArray, sonarContainer.ID)
	idArray = append(idArray, depContainer.ID)
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"container_id", depContainer.ID}, {"status", "PROGRESS"}}}},
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
	_, sonarErrCh := cli.ContainerWait(ctx, sonarContainer.ID)
	if sonarErrCh != nil {
		err := fmt.Errorf("sast scan error %v", sonarErrCh)
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

	_, depErrCh := cli.ContainerWait(ctx, depContainer.ID)
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

	sonarReader, sonarContainerLogsErr := cli.ContainerLogs(ctx, sonarContainer.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		Follow:     true,
	})
	if sonarContainerLogsErr != nil {
		err := fmt.Errorf("sast scan error %v: %v", sonarContainerLogsErr, sonarReader)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		sonarReader.Close()
		return
	}
	sonarByteValue, sonarIoutilReadAllError := ioutil.ReadAll(sonarReader)
	sonarReader.Close()
	SonarOutputResult := base64.StdEncoding.EncodeToString(sonarByteValue)
	SastResults.SonarOutput = SonarOutputResult
	if sonarIoutilReadAllError != nil {
		err := fmt.Errorf("sast scan ioutil error %v", sonarIoutilReadAllError)
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
	if strings.Contains(SonarScannerError, string(sonarByteValue)) {
		_, update2Error := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", taskId}},
			bson.D{{"$set", bson.D{
				{"sast_result", string(sonarByteValue)},
				{"status", "FAILURE"},
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
	taskIdMatch := taskIdRex.FindStringSubmatch(string(sonarByteValue))
	if len(taskIdMatch) > 2 {
		sonarScanId := taskIdMatch[2]
		SastResults.SonarScanId = sonarScanId
	}

	depReader, depContainerLogsErr := cli.ContainerLogs(ctx, depContainer.ID, types.ContainerLogsOptions{
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
		SastResults.DependencyCheckerResults = result
	}
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
