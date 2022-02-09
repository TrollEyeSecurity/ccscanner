package screenshots

import (
	"archive/tar"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"
)

func RunScreenShotTask(urls *database.Urls, taskId *primitive.ObjectID) {
	var ScreenShotDataList []string
	var uniqueRespBody map[string]string
	var idArray []string
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("screenshots new-client error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("screenshots mongo-client error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.Close()
		MongoClient.Disconnect(context.TODO())
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"status", "PROGRESS"}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("screenshots run-inspection error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.Close()
		MongoClient.Disconnect(context.TODO())
		return
	}
	timeout := 2 * time.Second
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	for _, u := range urls.UrlList {
		req, reqErr := http.NewRequest("GET", u, nil)
		if reqErr != nil {
			err := fmt.Errorf("screenshots req error %v", reqErr)
			log.Println(err)
			continue
		}
		req.Header.Set("Connection", "close")
		resp, respErr := httpClient.Do(req)
		if respErr != nil {
			if resp != nil {
				io.Copy(ioutil.Discard, resp.Body) // WE READ THE BODY
				resp.Body.Close()
			}
			err := fmt.Errorf("screenshots resp error %v", respErr)
			log.Println(err)
			continue
		}
		RespBody, RespBodyError := ioutil.ReadAll(resp.Body)
		if RespBodyError != nil {
			resp.Body.Close()
			err := fmt.Errorf("screenshots ioutil error %v", RespBodyError)
			log.Println(err)
			continue
		}
		respBody := string(RespBody)
		resp.Body.Close()
		b64Encoded := base64.StdEncoding.EncodeToString([]byte(respBody))
		uniqueRespBody = make(map[string]string)
		uniqueRespBody[b64Encoded] = u
	}
	idx := 0
	for _, v := range uniqueRespBody {
		ScreenShotData, ScreenShotDataIdArray, InspectUrlError := CaptureScreenShot(&v, taskId)
		if InspectUrlError != nil {
			if ScreenShotDataIdArray != nil {
				idArray = append(idArray, *ScreenShotDataIdArray...)
			}
			err := fmt.Errorf("screenshots capture-screen-shot error %v: %v", InspectUrlError, v)
			log.Println(err)
			continue
		}
		idArray = append(idArray, *ScreenShotDataIdArray...)
		ScreenShotDataList = append(ScreenShotDataList, *ScreenShotData)
		idx += 1
		value := PercentageChange(len(urls.UrlList), idx)
		_, updatePercentError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", taskId}},
			bson.D{{"$set", bson.D{
				{"percent", value}}}},
		)
		if updatePercentError != nil {
			err := fmt.Errorf("screenshots updatePercentError %v", updatePercentError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
	}
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"screen_shot_result", ScreenShotDataList},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	if update2Error != nil {
		err := fmt.Errorf("screenshots update error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.Close()
		MongoClient.Disconnect(context.TODO())
		docker.RemoveContainers(idArray)
		return
	}
	cli.Close()
	docker.RemoveContainers(idArray)
	return
}

func CaptureScreenShot(url *string, taskId *primitive.ObjectID) (*string, *[]string, error) {
	var idArray []string
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		return nil, nil, NewEnvClientErr
	}
	now := time.Now()
	imageName := docker.KaliLinuxImage
	filePath := "url_screen_shot"
	config := &container.Config{
		Image: imageName,
		Cmd: []string{
			"google-chrome",
			"--ignore-certificate-errors",
			"--enable-features=NetworkService",
			"--hide-scrollbars",
			"--headless",
			"--disable-gpu",
			"--screenshot=url_screen_shot",
			"--no-sandbox",
			"--window-size=1280,768",
			*url,
		},
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
	}
	resources := &container.Resources{
		Memory: 7.68e+8,
	}
	hostConfig := &container.HostConfig{
		Resources: *resources,
	}
	containerName := "screen_shot-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	screenShotContainer, StartContainerErr := docker.StartContainer(&imageName, &containerName, config, hostConfig)
	if StartContainerErr != nil {
		cli.Close()
		return nil, nil, StartContainerErr
	}
	idArray = append(idArray, screenShotContainer.ID)
	_, errCh := cli.ContainerWait(ctx, screenShotContainer.ID)
	if errCh != nil {
		cli.Close()
		return nil, &idArray, errCh
	}
	fileReader, _, fileReaderErr := cli.CopyFromContainer(ctx, screenShotContainer.ID, filePath)
	if fileReaderErr != nil {
		cli.Close()
		if fileReader != nil {
			fileReader.Close()
		}
		return nil, &idArray, fileReaderErr
	}
	tr := tar.NewReader(fileReader)
	var img []byte
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			fileReader.Close()
			cli.Close()
			return nil, &idArray, err
		}
		img, err = ioutil.ReadAll(tr)
		if err != nil {
			fileReader.Close()
			cli.Close()
			return nil, &idArray, err
		}
	}
	fileReader.Close()
	cli.Close()
	b64img := base64.StdEncoding.EncodeToString(img)
	return &b64img, &idArray, nil
}

func PercentageChange(old, new int) (delta int32) {
	diff := int32(new - old)
	delta = (diff / int32(old)) * 100
	return
}
