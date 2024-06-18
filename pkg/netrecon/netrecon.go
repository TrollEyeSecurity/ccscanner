package netrecon

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"log"
	"strconv"
	"sync"
	"time"
)

func Recon(content *database.TaskContent, secretData *database.TaskSecret, taskId *primitive.ObjectID, wg *sync.WaitGroup) {
	defer wg.Done()
	defer time.Sleep(time.Millisecond * 4)
	var idArray []string
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewClientWithOpts()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("netrecon scan error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var netReconHost string
	if content.Hostname != "" {
		netReconHost = content.Hostname
	} else {
		netReconHost = content.Ip.String()
	}
	imageName := docker.NetReconImage
	config := &container.Config{
		Env: []string{
			"NETRECON_HOST=" + netReconHost,
			"NETRECON_USERNAME=" + secretData.Username,
			"NETRECON_PASSWORD=" + secretData.Password,
		},
		Image:        imageName,
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
		err := fmt.Errorf("net-recon start-container error %v: %v", StartContainerErr, NmapContainer)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.Close()
		return
	}
	idArray = append(idArray, NmapContainer.ID)
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("net-recon mongo-client error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		cli.Close()
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"container_id", NmapContainer.ID}, {"status", "PROGRESS"}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("net-recon update-task error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}
	statusCh, errCh := cli.ContainerWait(ctx, NmapContainer.ID, container.WaitConditionNextExit)
	select {
	case err := <-errCh:
		if err != nil {
			errMsg := fmt.Errorf("net-recon container-wait error %v", err)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(errMsg)
			}
			log.Println(errMsg)
			docker.RemoveContainers(idArray)
			MongoClient.Disconnect(context.TODO())
			cli.Close()
			return
		}
	case <-statusCh:
	}
	reader, ContainerLogsErr := cli.ContainerLogs(ctx, NmapContainer.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		Follow:     true,
	})
	if ContainerLogsErr != nil {
		err := fmt.Errorf("netrecon container-logs error %v: %v", ContainerLogsErr, reader)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		reader.Close()
		return
	}
	byteValue, ioutilReadAllError := io.ReadAll(reader)
	reader.Close()
	if ioutilReadAllError != nil {
		err := fmt.Errorf("netrecon ioutil error %v", ioutilReadAllError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}
	result := base64.StdEncoding.EncodeToString(byteValue)
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"net_recon_results", result},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	docker.RemoveContainers(idArray)
	cli.Close()
	if update2Error != nil {
		err := fmt.Errorf("nmap scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	return
}
