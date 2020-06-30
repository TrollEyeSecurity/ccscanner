package screenShots

import (
	"context"
	"encoding/base64"
	"github.com/CriticalSecurity/cc-scanner/pkg/docker"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io/ioutil"
	"strconv"
	"time"
)

func GetScreenShot(url *string, taskId *primitive.ObjectID) (*string, *[]string, error) {
	var idArray []string
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		return nil, nil, NewEnvClientErr
	}
	now := time.Now()
	imageName := docker.NmapDockerImage
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
		return nil, nil, StartContainerErr
	}
	idArray = append(idArray, screenShotContainer.ID)
	_, errCh := cli.ContainerWait(ctx, screenShotContainer.ID)
	if errCh != nil {
		return nil, &idArray, errCh
	}
	fileReader, _, fileReaderErr := cli.CopyFromContainer(ctx, screenShotContainer.ID, filePath)
	if fileReaderErr != nil {
		return nil, &idArray, fileReaderErr
	}
	img, imgError := ioutil.ReadAll(fileReader)
	fileReader.Close()
	cli.Close()
	if imgError != nil {
		return nil, &idArray, imgError
	}
	b64img := base64.StdEncoding.EncodeToString(img)
	return &b64img, &idArray, nil
}
