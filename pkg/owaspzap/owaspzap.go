package owaspzap

import (
	"context"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
)

func Scan(config *[]string, hosts *string, excludes *string, taskId *primitive.ObjectID) {
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
	/*
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
		var cmd string
		cmdS := strings.Split(cmd, " ")
		imageName := docker.OwaspZapImage
		config := &container.Config{
			Image:        imageName,
			Cmd:          cmdS,
			Tty:          true,
			AttachStdout: true,
			AttachStderr: true,
		}
		resources := &container.Resources{
			Memory: 5.12e+8,
		}
		hostConfig := &container.HostConfig{
			Resources:   *resources,
			NetworkMode: "host",
		}
		now := time.Now()
		containerName := "nmap-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
		NmapContainer, StartContainerErr := docker.StartContainer(&imageName, &containerName, config, hostConfig)
		if StartContainerErr != nil {
			err := fmt.Errorf("nmap scan error %v: %v", StartContainerErr, NmapContainer)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		idArray = append(idArray, NmapContainer.ID)

		_, updateError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"container_id", NmapContainer.ID}, {"status", "PROGRESS"}}}},
		)
		if updateError != nil {
			err := fmt.Errorf("nmap scan error %v", updateError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			docker.RemoveContainers(idArray)
			return
		}

	*/
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"owasp_zap_result", ""},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	//docker.RemoveContainers(idArray)
	//cli.Close()
	if update2Error != nil {
		err := fmt.Errorf("owasp zap scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	return
}
