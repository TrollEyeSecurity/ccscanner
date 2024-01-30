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
	"io"
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
	cli, NewEnvClientErr := client.NewClientWithOpts()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("dns analyze-domain-names error new-env-client %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	dnsReconImage := docker.DnsReconImage
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("dns analyze-domain-names mongo error %v: %v", MongoClientError, MongoClient)
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

		dnsReconCmd := "-d " + dnsname + " --disable_check_bindversion --j " + filePath + " -t std,srv,axfr,crt -D namelist.txt"
		dnsReconCmdS := strings.Split(dnsReconCmd, " ")
		dnsReconConfig := &container.Config{
			Image:        dnsReconImage,
			Cmd:          dnsReconCmdS,
			Tty:          true,
			AttachStdout: true,
			AttachStderr: true,
		}
		DnsResonResources := &container.Resources{
			Memory: 5.12e+8,
		}
		dnsReconHostConfig := &container.HostConfig{
			Resources:   *DnsResonResources,
			NetworkMode: "host",
		}
		dnsReconConfigContainerName := "dnsrecon-" + strconv.FormatInt(now.Unix(), 10)
		DnsreconContainer, DnsreconContainerErr := docker.StartContainer(&dnsReconImage, &dnsReconConfigContainerName, dnsReconConfig, dnsReconHostConfig)

		if DnsreconContainerErr != nil {
			err := fmt.Errorf("dns analyze-domain-names dns-recon-container error %v: %v", DnsreconContainerErr, DnsreconContainer)
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
			err := fmt.Errorf("dns analyze-domain-names upadte-task error %v", taskUpdateError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		statusCh, errCh := cli.ContainerWait(ctx, DnsreconContainer.ID, container.WaitConditionNextExit)
		select {
		case err := <-errCh:
			if err != nil {
				errStr := <-errCh
				errMsg := fmt.Errorf("dns analyze-domain-names container-wait error %v", errStr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errMsg)
				}
				log.Println(errMsg)
				continue
			}
		case <-statusCh:
		}
		fileReader, _, fileReaderErr := cli.CopyFromContainer(ctx, DnsreconContainer.ID, filePath)
		if fileReaderErr != nil {
			err := fmt.Errorf("dns analyze-domain-names copy-from-container error %v: %v", fileReaderErr, fileReader)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		tr := tar.NewReader(fileReader)
		_, tarErr := tr.Next()
		if tarErr != nil {
			err := fmt.Errorf("dns analyze-domain-names tar error %v", tarErr)
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
		DigContainer, DigContainerErr := docker.StartContainer(&digImageName, &digContainerName, digConfig, digHostConfig)
		if DigContainerErr != nil {
			err := fmt.Errorf("dns analyze-domain-names dig-container error %v: %v", DigContainerErr, DigContainer)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		idArray = append(idArray, DigContainer.ID)
		statusCh, dirErrCh := cli.ContainerWait(ctx, DigContainer.ID, container.WaitConditionNextExit)
		select {
		case err := <-dirErrCh:
			if err != nil {
				errMsg := fmt.Errorf("dns analyze-domain-names container-wait error %v", err)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errMsg)
				}
				log.Println(errMsg)
				continue
			}
		case <-statusCh:
		}
		reader, ContainerLogsErr := cli.ContainerLogs(ctx, DigContainer.ID, types.ContainerLogsOptions{
			ShowStdout: true,
			Follow:     true,
		})
		if ContainerLogsErr != nil {
			err := fmt.Errorf("dns analyze-domain-names container-logs error %v: %v", ContainerLogsErr, reader)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		byteValue, _ := io.ReadAll(reader)
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

		/*
			dnstwistImage := docker.DnstwistImage
			dnstwistCmd := "-a -f json -r " + dnsname
			dnstwistCmdS := strings.Split(dnstwistCmd, " ")
			dnstwistConfig := &container.Config{
				Image:        dnstwistImage,
				Cmd:          dnstwistCmdS,
				Tty:          true,
				AttachStdout: true,
				AttachStderr: true,
			}
			_, update1Error := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", taskId}},
				bson.D{{"$set", bson.D{{"percent", 50}}}},
			)
			if update1Error != nil {
				err := fmt.Errorf("dns analyze-domain-names remove-containers error %v", update1Error)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				continue
			}
			dnstwstResources := &container.Resources{
				Memory: 5.12e+8,
			}
			dnstwistHostConfig := &container.HostConfig{
				Resources:   *dnstwstResources,
				NetworkMode: "host",
			}
			dnstwistConfigContainerName := "dnstwist-" + strconv.FormatInt(now.Unix(), 10)
			DnstwistContainer, DnstwistContainerErr := docker.StartContainer(&dnstwistImage, &dnstwistConfigContainerName, dnstwistConfig, dnstwistHostConfig)
			if DnstwistContainerErr != nil {
				err := fmt.Errorf("dns analyze-domain-names dnstwist-container error %v: %v", DnstwistContainerErr, DnstwistContainer)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				continue
			}
			idArray = append(idArray, DnstwistContainer.ID)
			dnstwistStatusCh, dnstwistErrCh := cli.ContainerWait(ctx, DnstwistContainer.ID, container.WaitConditionNextExit)
			select {
			case err := <-dnstwistErrCh:
				if err != nil {
					errMsg := fmt.Errorf("dnstwist analyze-domain-names container-wait error %v", err)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(errMsg)
					}
					log.Println(errMsg)
					continue
				}
			case <-dnstwistStatusCh:
			}
			dnsTwistReader, dnstwsistContainerLogsErr := cli.ContainerLogs(ctx, DnstwistContainer.ID, types.ContainerLogsOptions{
				ShowStdout: true,
				Follow:     true,
			})
			if dnstwsistContainerLogsErr != nil {
				err := fmt.Errorf("dnstwist analyze-domain-names container-logs error %v: %v", dnstwsistContainerLogsErr, dnsTwistReader)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				continue
			}
			dnstwistByteValue, _ := io.ReadAll(dnsTwistReader)
			dnsTwistReader.Close()
			dnstwistResults := base64.StdEncoding.EncodeToString(dnstwistByteValue)
		*/
		results.Spf = *spf
		results.Dmarc = *dmarc
		results.DomainName = dnsname
		results.DnsReconList = b64Result
		//results.Dnstwist = dnstwistResults
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
		err := fmt.Errorf("dns analyze-domain-names remove-containers error %v", update2Error)
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
