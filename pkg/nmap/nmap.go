package nmap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
	"github.com/TrollEyeSecurity/ccscanner/pkg/names"
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

func Scan(nmap_params *string, hosts *string, excludes *string, taskId *primitive.ObjectID, shodanKey *string) {
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
	var cmd string
	if *excludes == "" {
		cmd = "nmap -oX - --stats-every 30s " + *nmap_params + " " + *hosts
	} else {
		cmd = "nmap -oX - --stats-every 30s " + *nmap_params + " " + *hosts + " --exclude " + *excludes
	}
	cmdS := strings.Split(cmd, " ")
	imageName := docker.KaliLinuxImage
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
		cli.Close()
		return
	}
	idArray = append(idArray, NmapContainer.ID)
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("nmap mongo-client error %v", MongoClientError)
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
		err := fmt.Errorf("nmap update-task error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}
	_, errCh := cli.ContainerWait(ctx, NmapContainer.ID, "next-exit")
	if err := <-errCh; err != nil {
		errMsg := fmt.Errorf("nmap container-wait error %v", err)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(errMsg)
		}
		log.Println(errMsg)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}
	reader, ContainerLogsErr := cli.ContainerLogs(ctx, NmapContainer.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		Follow:     true,
	})
	if ContainerLogsErr != nil {
		err := fmt.Errorf("nmap container-logs error %v: %v", ContainerLogsErr, reader)
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
	byteValue, ioutilReadAllError := ioutil.ReadAll(reader)
	reader.Close()
	if ioutilReadAllError != nil {
		err := fmt.Errorf("nmap scan ioutil error %v", ioutilReadAllError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}
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
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}
	jsonData, jsonDataError := json.Marshal(data)
	if jsonDataError != nil {
		// do I really want to know about all of these?
		err := fmt.Errorf("nmap scan json-marshal error %v", jsonDataError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		cli.Close()
		return
	}
	result := base64.StdEncoding.EncodeToString(jsonData)
	nameInfoMap := make(map[string]names.NameData)
	UrlInfoMap := make(map[string][]string)
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
			if NameData != nil {
				nameInfoMap[ip] = *NameData
			}
		}
		for _, port := range host.Ports.Port {
			var urls []string
			if port.Service.Name == "http" || port.Service.Name == "https" || port.Service.Name == "https-alt" || port.Service.Name == "ipp" || port.Service.Name == "ssl" || port.Service.Name == "unicall" || port.Service.Name == "snet-sensor-mgmt" {
				protocol := "http://"
				if port.Service.Tunnel != "" && port.Portid != "80" {
					protocol = "https://"
				}
				url := protocol + ip + ":" + port.Portid + "/"
				urls = append(urls, url)
				for _, name := range nameInfoMap[ip].ValidNames {
					name1 := strings.TrimRight(name, ".")
					url = protocol + name1 + ":" + port.Portid + "/"
					urls = append(urls, url)
				}
			}
			UrlInfoMap[ip+":"+port.Portid] = urls
		}
	}
	jsonNameInfoData, jsonNameInfoDataError := json.Marshal(nameInfoMap)
	if jsonNameInfoDataError != nil {
		err := fmt.Errorf("nmap scan json-marshal error %v", jsonNameInfoDataError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		return
	}
	jsonServiceUrlDataInfo, jsonServiceUrlDataInfoError := json.Marshal(UrlInfoMap)
	if jsonServiceUrlDataInfoError != nil {
		err := fmt.Errorf("nmap scan json-marshal error %v", jsonServiceUrlDataInfoError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		MongoClient.Disconnect(context.TODO())
		return
	}
	nameInfo := base64.StdEncoding.EncodeToString(jsonNameInfoData)
	serviceUrlDataInfo := base64.StdEncoding.EncodeToString(jsonServiceUrlDataInfo)
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"nmap_result", result},
			{"name_info", nameInfo},
			{"service_url_data", serviceUrlDataInfo},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	//docker.RemoveContainers(idArray)
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

type UrlData struct {
	UrlList  []string `bson:"url_list" json:"url_list"`
	BodyList []string `bson:"body_list" json:"body_list"`
}
