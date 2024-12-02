package nmap

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

func Scan(nmapParams *string, hosts *string, excludes *string, taskId *primitive.ObjectID, wg *sync.WaitGroup) {
	defer wg.Done()
	defer time.Sleep(time.Millisecond * 4)
	var idArray []string
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewClientWithOpts()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("nmap scan error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	defer cli.Close()
	var cmd string
	filePath := "nmap-scan-results.xml"
	if *excludes == "" {
		cmd = "nmap -vv -oX " + filePath + " --stats-every 30s " + *nmapParams + " " + *hosts
	} else {
		cmd = "nmap -vv -oX " + filePath + " --stats-every 30s " + *nmapParams + " " + *hosts + " --exclude " + *excludes
	}
	cmdS := strings.Split(cmd, " ")
	imageName := docker.NmapImage
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
	defer MongoClient.Disconnect(context.TODO())
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
	statusCh, errCh := cli.ContainerWait(ctx, NmapContainer.ID, container.WaitConditionNextExit)
	select {
	case err := <-errCh:
		if err != nil {
			errMsg := fmt.Errorf("nmap scan error %v", err)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(errMsg)
			}
			log.Println(errMsg)
			docker.RemoveContainers(idArray)
			return
		}
	case <-statusCh:
	}

	fileReader, _, fileReaderErr := cli.CopyFromContainer(ctx, NmapContainer.ID, filePath)
	if fileReaderErr != nil {
		if fileReader != nil {
			fileReader.Close()
			err1 := fmt.Errorf("nmap scan error %v", fileReader)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err1)
			}
			log.Println(err1)
			docker.RemoveContainers(idArray)
		}
	}
	tr := tar.NewReader(fileReader)
	var results []byte
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			fileReader.Close()
		}
		results, err = io.ReadAll(tr)
		if err != nil {
			fileReader.Close()
			err1 := fmt.Errorf("nmap scan error %v", err)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err1)
			}
			log.Println(err1)
			docker.RemoveContainers(idArray)
		}
	}
	fileReader.Close()

	data := &Nmaprun{}
	XmlUnmarshalErr := xml.Unmarshal(results, data)
	if XmlUnmarshalErr != nil {
		err := fmt.Errorf("nmap scan xml-unmarshal error %v: %v", XmlUnmarshalErr, string(results))
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	jsonData, jsonDataError := json.Marshal(data)
	if jsonDataError != nil {
		err := fmt.Errorf("nmap scan json-marshal error %v", jsonDataError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	result := base64.StdEncoding.EncodeToString(jsonData)
	nameInfoMap := make(map[string]NameData)
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
		for _, port := range host.Ports.Port {
			var urls []string
			var url string
			if port.Service.Name == "http" ||
				port.Service.Name == "https" ||
				port.Service.Name == "https-alt" ||
				port.Service.Name == "ipp" ||
				port.Service.Name == "ssl" ||
				port.Service.Name == "unicall" ||
				port.Service.Name == "snet-sensor-mgmt" {
				protocol := "http://"
				if port.Service.Tunnel != "" && port.Portid != "80" {
					protocol = "https://"
				}
				if port.Portid == "443" || port.Portid == "80" {
					url = protocol + ip + "/"

				} else {
					url = protocol + ip + ":" + port.Portid + "/"
				}
				urls = append(urls, url)
				for _, name := range nameInfoMap[ip].ValidNames {
					name1 := strings.TrimRight(name, ".")
					if port.Portid == "443" || port.Portid == "80" {
						url = protocol + name1 + "/"

					} else {
						url = protocol + name1 + ":" + port.Portid + "/"
					}
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
		return
	}
	nameInfo := base64.StdEncoding.EncodeToString(jsonNameInfoData)
	serviceUrlDataInfo := base64.StdEncoding.EncodeToString(jsonServiceUrlDataInfo)

	bsonData := bson.D{
		{"$set", bson.D{
			{"nmap_results", result},
			{"name_info", nameInfo},
			{"service_url_data", serviceUrlDataInfo},
			{"status", "SUCCESS"},
			{"percent", 100}}},
	}

	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bsonData,
	)
	if update2Error != nil {
		err := fmt.Errorf("nmap scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	docker.RemoveContainers(idArray)
	return
}

type UrlData struct {
	UrlList  []string `bson:"url_list" json:"url_list"`
	BodyList []string `bson:"body_list" json:"body_list"`
}

func checkIfDown(data *Nmaprun) *Nmaprun {
	for i := len(data.Host) - 1; i >= 0; i-- {
		host := data.Host[i]
		if host.Status.State == "down" {
			data.Host = append(data.Host[:i], data.Host[i+1:]...)
		}
	}
	return data
}
