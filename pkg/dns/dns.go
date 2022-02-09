package dns

import (
	"archive/tar"
	"bytes"
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
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func AnalyzeDomainNames(dnsnames *[]string, taskId *primitive.ObjectID) {
	var idArray []string
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("dns analyze-domain-names error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	imageName := docker.DnsReconImage
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("dns analyze-domain-names error %v: %v", MongoClientError, MongoClient)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	filePath := "/dnsrecon.json"
	var result []database.DnsResults
	for _, dnsname := range *dnsnames {
		results := database.DnsResults{}
		now := time.Now()
		cmd := "-d " + dnsname + " --disable_check_bindversion --j " + filePath + " -t std,srv,axfr,crt -D namelist.txt"
		cmdS := strings.Split(cmd, " ")
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
		containerName := "dnsrecon-" + strconv.FormatInt(now.Unix(), 10)
		DnsreconContainer, DnsreconContainerErr := docker.StartContainer(&imageName, &containerName, config, hostConfig)
		if DnsreconContainerErr != nil {
			err := fmt.Errorf("dns analyze-domain-names error %v: %v", DnsreconContainerErr, DnsreconContainer)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		idArray = append(idArray, DnsreconContainer.ID)
		_, taskUpdateError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"container_id", DnsreconContainer.ID}, {"status", "PROGRESS"}}}},
		)
		if taskUpdateError != nil {
			err := fmt.Errorf("dns analyze-domain-names error %v", taskUpdateError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		_, errCh := cli.ContainerWait(ctx, DnsreconContainer.ID)
		if errCh != nil {
			err := fmt.Errorf("dns analyze-domain-names error %v", errCh)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		fileReader, _, fileReaderErr := cli.CopyFromContainer(ctx, DnsreconContainer.ID, filePath)
		if fileReaderErr != nil {
			err := fmt.Errorf("dns analyze-domain-names error %v: %v", fileReaderErr, fileReader)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		tr := tar.NewReader(fileReader)
		_, tarErr := tr.Next()
		if tarErr != nil {
			err := fmt.Errorf("dns analyze-domain-names error %v", tarErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(tr)
		fileReader.Close()
		wholeContent := buf.String()
		b64Result := base64.StdEncoding.EncodeToString([]byte(wholeContent))
		dnsTXT, _ := net.LookupTXT(dnsname)
		dmarcTXT, _ := net.LookupTXT("_dmarc." + dnsname)
		spf := ExtractSPF(dnsTXT)
		dmarc := ExtractDMARC(dmarcTXT)
		digImageName := docker.KaliLinuxImage
		digConfig := &container.Config{
			Image: digImageName,
			Cmd: []string{
				"dig",
				"+dnssec",
				dnsname,
				"@8.8.8.8",
			},
			Tty:          true,
			AttachStdout: true,
			AttachStderr: true,
		}
		digResources := &container.Resources{
			//Memory:1e+9,
		}
		digHostConfig := &container.HostConfig{
			Resources:   *digResources,
			NetworkMode: "host",
		}
		digContainerName := "dig-" + strconv.FormatInt(now.Unix(), 10)
		DigContainer, DigContainerErr := docker.StartContainer(&imageName, &digContainerName, digConfig, digHostConfig)
		if DigContainerErr != nil {
			err := fmt.Errorf("dns analyze-domain-names error %v: %v", DigContainerErr, DigContainer)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		idArray = append(idArray, DigContainer.ID)
		_, dirErrCh := cli.ContainerWait(ctx, DigContainer.ID)
		if dirErrCh != nil {
			err := fmt.Errorf("dns analyze-domain-names error %v", dirErrCh)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		reader, ContainerLogsErr := cli.ContainerLogs(ctx, DigContainer.ID, types.ContainerLogsOptions{
			ShowStdout: true,
			Follow:     true,
		})
		if ContainerLogsErr != nil {
			err := fmt.Errorf("dns analyze-domain-names error %v: %v", ContainerLogsErr, reader)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		byteValue, _ := ioutil.ReadAll(reader)
		reader.Close()
		re := regexp.MustCompile(`^(;; flags:)(.*);`)
		for _, m := range strings.Split(string(byteValue), "\n") {
			if re.MatchString(m) {
				if strings.Contains(m, "ad") {
					results.DnsSec = true
					break
				}
			}
		}
		results.Spf = *spf
		results.Dmarc = *dmarc
		results.DomainName = dnsname
		results.DnsReconList = b64Result
		result = append(result, results)
	}
	cli.Close()
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"dns_result", result},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	docker.RemoveContainers(idArray)
	if update2Error != nil {
		err := fmt.Errorf("dns analyze-domain-names error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	return
}

func ExtractDMARC(records []string) *[]string {
	var dmarcRecords []string
	for _, value := range records {
		if strings.Contains(value, "v=DMARC1") {
			dmarcRecords = append(dmarcRecords, value)
		}
	}
	return &dmarcRecords
}

func ExtractSPF(records []string) *[]string {
	var spfRecords []string
	for _, value := range records {
		if strings.Contains(value, "v=spf1") {
			spfRecords = append(spfRecords, value)
		}
	}
	return &spfRecords
}
