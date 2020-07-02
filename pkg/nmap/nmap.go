package nmap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/CriticalSecurity/ccscanner/internal/database"
	"github.com/CriticalSecurity/ccscanner/pkg/docker"
	"github.com/CriticalSecurity/ccscanner/pkg/names"
	"github.com/CriticalSecurity/ccscanner/pkg/screenShots"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"
)

func Scan(nmap_params *string, hosts *string, taskId *primitive.ObjectID, shodanKey *string) {
	var idArray []string
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
	cmd := "nmap --stats-every 30s " + *nmap_params + " " + *hosts + " -oX -"
	cmdS := strings.Split(cmd, " ")
	imageName := docker.NmapDockerImage
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
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("nmap scan error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
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
	_, errCh := cli.ContainerWait(ctx, NmapContainer.ID)
	if errCh != nil {
		err := fmt.Errorf("nmap scan error %v", errCh)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	reader, ContainerLogsErr := cli.ContainerLogs(ctx, NmapContainer.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		Follow:     true,
	})
	if ContainerLogsErr != nil {
		err := fmt.Errorf("nmap scan error %v: %v", ContainerLogsErr, reader)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	byteValue, _ := ioutil.ReadAll(reader)
	reader.Close()
	data := &Nmaprun{}
	XmlUnmarshalErr := xml.Unmarshal(byteValue, data)
	if XmlUnmarshalErr != nil {
		// do I really want to know about all of these?
		err := fmt.Errorf("nmap scan xml-unmarshal error %v: %v", XmlUnmarshalErr, string(byteValue))
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	jsonData, _ := json.Marshal(data)
	result := base64.StdEncoding.EncodeToString(jsonData)
	nameInfoMap := make(map[string]names.NameData)
	screenShotInfoMap := make(map[string][]map[string]string)
	for _, host := range data.Host {
		ip := ""
		for _, addr := range host.Address {
			if addr.Addrtype == "ipv4" || addr.Addrtype == "ipv6" {
				ip = addr.Addr
				break
			} else {
				continue
			}
		}
		if ip != "" {
			NameData := names.DoLookup(&ip, shodanKey)
			nameInfoMap[ip] = *NameData
		}
		for _, port := range host.Ports.Port {
			var list_maps []map[string]string
			url_map := make(map[string]string)
			var urls []string
			if port.Service.Name == "http" || port.Service.Name == "https" || port.Service.Name == "ipp" || port.Service.Name == "ssl" || port.Service.Name == "unicall" || port.Service.Name == "snet-sensor-mgmt" {
				protocol := "http://"
				if port.Service.Tunnel != "" {
					protocol = "https://"
				}
				url := protocol + ip + ":" + port.Portid + "/"
				urls = append(urls, url)
				for _, name := range nameInfoMap[ip].ValidNames {
					url = protocol + name + ":" + port.Portid + "/"
					urls = append(urls, url)
				}
			}
			for _, u := range urls {
				screenShot, ssIdArray, screenShotError := screenShots.GetScreenShot(&u, taskId)
				if screenShotError != nil {
					err := fmt.Errorf("nmap scan error %v: %v", screenShotError, screenShot)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					idArray = append(idArray, *ssIdArray...)
					continue
				}
				idArray = append(idArray, *ssIdArray...)
				url_map[u] = *screenShot
				list_maps = append(list_maps, url_map)
			}
			screenShotInfoMap[ip+":"+port.Portid] = list_maps
		}
	}
	jsonNameInfoData, _ := json.Marshal(nameInfoMap)
	jsonServiceScreenShotDataInfo, _ := json.Marshal(screenShotInfoMap)
	nameInfo := base64.StdEncoding.EncodeToString(jsonNameInfoData)
	serviceScreenShotDataInfo := base64.StdEncoding.EncodeToString(jsonServiceScreenShotDataInfo)
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"nmap_result", result},
			{"name_info", nameInfo},
			{"service_screen_shot_data", serviceScreenShotDataInfo},
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
		return
	}
	MongoClient.Disconnect(context.TODO())
	return
}
