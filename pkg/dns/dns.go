package dns

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"github.com/CriticalSecurity/cc-scanner/internal/database"
	"github.com/CriticalSecurity/cc-scanner/internal/errors"
	"github.com/CriticalSecurity/cc-scanner/pkg/docker"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io/ioutil"
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
		errors.HandleError(NewEnvClientErr, "AnalyzeDomainNames NewEnvClient Error")
		return
	}
	imageName := "docker.io/criticalsec/dnsrecon:latest"
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		errors.HandleError(MongoClientError, "AnalyzeDomainNames MongoClient Error")
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	filePath := "/dnsrecon.json"
	var result []database.DnsResults
	for _, dnsname := range *dnsnames{
		results := database.DnsResults{}
		now := time.Now()
		cmd := "-d " + dnsname + " --disable_check_bindversion --j " + filePath + " -t std,srv,axfr,crt " + "-D namelist.txt"
		cmdS := strings.Split(cmd, " ")
		config := &container.Config{
			Image: imageName,
			Cmd:   cmdS,
			Tty:   true,
			AttachStdout: true,
			AttachStderr: true,
		}
		resources := &container.Resources{
			Memory:5.12e+8,
		}
		hostConfig := &container.HostConfig{
			Resources: *resources,
			NetworkMode: "host",
		}
		containerName := "dnsrecon-" + strconv.FormatInt(now.Unix(), 10)
		DnsreconContainer, DnsreconContainerErr := docker.StartContainer(&imageName, &containerName, config, hostConfig)
		if DnsreconContainerErr != nil {
			errors.HandleError(DnsreconContainerErr, "AnalyzeDomainNames DnsreconContainer Error")
			continue
		}
		idArray = append(idArray, DnsreconContainer.ID)
		_, taskUpdateError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"container_id", DnsreconContainer.ID}, {"status", "PROGRESS"}}}},
		)
		if taskUpdateError != nil {
			errors.HandleError(taskUpdateError, "AnalyzeDomainNames taskUpdateError Error")
			continue
		}
		_, errCh := cli.ContainerWait(ctx, DnsreconContainer.ID)
		if errCh != nil {
			errors.HandleError(errCh, "AnalyzeDomainNames errCh Error")
			continue
		}
		fileReader, _, fileReaderErr := cli.CopyFromContainer(ctx, DnsreconContainer.ID, filePath)
		if fileReaderErr != nil {
			errors.HandleError(fileReaderErr, "AnalyzeDomainNames File Reader Error")
			continue
		}
		defer fileReader.Close()
		tr := tar.NewReader(fileReader)
		_, tarErr := tr.Next()
		if tarErr != nil {
			errors.HandleError(tarErr, "AnalyzeDomainNames Tar File Error")
			continue
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(tr)
		wholeContent := buf.String()
		b64Result := base64.StdEncoding.EncodeToString([]byte(wholeContent))
		dnsTXT, _ := net.LookupTXT(dnsname)
		dmarcTXT, _ := net.LookupTXT("_dmarc." + dnsname)
		spf := ExtractSPF(dnsTXT)
		dmarc := ExtractDMARC(dmarcTXT)
		digImageName := "docker.io/criticalsec/scanner:latest"
		digConfig := &container.Config{
			Image: digImageName,
			Cmd:   []string{
				"dig",
				"+dnssec",
				dnsname,
				"@8.8.8.8",
				},
			Tty:   true,
			AttachStdout: true,
			AttachStderr: true,
		}
		digResources := &container.Resources{
			//Memory:1e+9,
		}
		digHostConfig := &container.HostConfig{
			Resources: *digResources,
			NetworkMode: "host",
		}
		digContainerName := "dig-" + strconv.FormatInt(now.Unix(), 10)
		DigContainer, DigContainerErr := docker.StartContainer(&imageName, &digContainerName, digConfig, digHostConfig)
		if DigContainerErr != nil {
			errors.HandleError(DigContainerErr, "AnalyzeDomainNames DigContainer Error")
			continue
		}
		idArray = append(idArray, DigContainer.ID)
		_, dirErrCh := cli.ContainerWait(ctx, DigContainer.ID)
		if dirErrCh != nil {
			errors.HandleError(dirErrCh, "AnalyzeDomainNames DigContainer ContainerWait Error")
			continue
		}
		reader, ContainerLogsErr := cli.ContainerLogs(ctx, DigContainer.ID, types.ContainerLogsOptions{
			ShowStdout: true,
			Follow:     true,
		})
		if ContainerLogsErr != nil {
			errors.HandleError(ContainerLogsErr, "AnalyzeDomainNames ContainerLogs Error")
			continue
		}
		defer reader.Close()
		byteValue, _ := ioutil.ReadAll(reader)
		re := regexp.MustCompile(`^(;; flags:)(.*);`)
		for _, m := range strings.Split(string(byteValue),"\n") {
			if re.MatchString(m){
				if strings.Contains(m, "ad"){
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
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"dns_result",result},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	docker.RemoveContainers(idArray)
	if update2Error != nil {
		errors.HandleError(update2Error, "AnalyzeDomainNames update2 Error")
		return
	}
	MongoClient.Disconnect(context.TODO())
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