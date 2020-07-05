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
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io/ioutil"
	"log"
	"net/http"
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
			nameInfoMap[ip] = *NameData
		}
		for _, port := range host.Ports.Port {
			var urls []string
			if port.Service.Name == "http" || port.Service.Name == "https" || port.Service.Name == "https-alt" || port.Service.Name == "ipp" || port.Service.Name == "ssl" || port.Service.Name == "unicall" || port.Service.Name == "snet-sensor-mgmt" {
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
			UrlInfoMap[ip+":"+port.Portid] = urls
		}
	}
	jsonNameInfoData, _ := json.Marshal(nameInfoMap)
	jsonServiceUrlDataInfo, _ := json.Marshal(UrlInfoMap)
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
	MongoClient.Disconnect(context.TODO())
	return
}

func InspectUrl(url *string) (*ServiceUrlData, error) {
	SuccessCodes := map[int]bool{
		200: true,
		201: true,
		202: true,
		203: true,
		204: true,
		205: true,
		206: true,
		207: true,
		208: true,
		226: true,
		// unoffical
		218: true,
	}
	RedirectCodes := map[int]bool{
		300: true,
		301: true,
		302: true,
		303: true,
		304: true,
		305: true,
		306: true,
		307: true,
		308: true,
	}
	ClientErrorCodes := map[int]bool{
		400: true,
		401: true,
		402: true,
		403: true,
		404: true,
		405: true,
		406: true,
		407: true,
		408: true,
		409: true,
		410: true,
		411: true,
		412: true,
		413: true,
		414: true,
		415: true,
		416: true,
		417: true,
		418: true,
		421: true,
		422: true,
		423: true,
		424: true,
		425: true,
		426: true,
		428: true,
		429: true,
		431: true,
		451: true,
		// unoffical
		419: true,
		420: true,
		430: true,
		450: true,
		498: true,
		499: true,
		440: true,
		449: true,
		444: true,
		494: true,
		495: true,
		496: true,
		497: true,
		460: true,
		463: true,
	}
	ServerErrorCodes := map[int]bool{
		500: true,
		501: true,
		502: true,
		503: true,
		504: true,
		505: true,
		506: true,
		507: true,
		508: true,
		509: true,
		510: true,
		511: true,
		// unoffical
		526: true,
		529: true,
		530: true,
		598: true,
		520: true,
		521: true,
		522: true,
		523: true,
		525: true,
		527: true,
	}
	resp, err := http.Get(*url)
	if err != nil {
		return nil, err
	}
	data := ServiceUrlData{}
	var urlList []string
	var finalLocation string
	var respBody string
	for {
		index := 0
		if RedirectCodes[resp.StatusCode] {
			index += 1
			newUrl := resp.Header.Get("Location")
			urlList = append(urlList, newUrl)
			resp, err = http.Get(newUrl)
			if err != nil {
				return nil, err
			}
		}
		if SuccessCodes[resp.StatusCode] {
			newUrl := resp.Header.Get("Location")
			if newUrl != "" {
				urlList = append(urlList, newUrl)
				index += 1
				resp, err = http.Get(newUrl)
				if err != nil {
					return nil, err
				}
				RespBody, _ := ioutil.ReadAll(resp.Body)
				respBody = string(RespBody)
				finalLocation = resp.Request.URL.String()
				resp.Body.Close()
				data.FinalLocation = finalLocation

				break
			} else {
				RespBody, _ := ioutil.ReadAll(resp.Body)
				respBody = string(RespBody)
				finalLocation = resp.Request.URL.String()
				resp.Body.Close()
				data.FinalLocation = finalLocation
				break
			}
		}
		if ClientErrorCodes[resp.StatusCode] {
			resp.Body.Close()
			break
		}
		if ServerErrorCodes[resp.StatusCode] {
			resp.Body.Close()
			break
		}
	}
	b64Encoded := base64.StdEncoding.EncodeToString([]byte(respBody))
	data.UrlList = urlList
	data.Body = b64Encoded
	return &data, nil
}

type ServiceUrlData struct {
	FinalLocation string   `bson:"final_location" json:"final_location"`
	UrlList       []string `bson:"url_list" json:"url_list"`
	Body          string   `bson:"body" json:"body"`
}

type UrlData struct {
	UrlList  []string `bson:"url_list" json:"url_list"`
	BodyList []string `bson:"body_list" json:"body_list"`
}

func uniqueNonEmptyElementsOf(s []string) []string {
	unique := make(map[string]bool, len(s))
	us := make([]string, len(unique))
	for _, elem := range s {
		if len(elem) != 0 {
			if !unique[elem] {
				us = append(us, elem)
				unique[elem] = true
			}
		}
	}
	return us
}
