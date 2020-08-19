package openvas

import (
	"context"
	"encoding/xml"
	"fmt"
	"github.com/CriticalSecurity/ccscanner/internal/database"
	"github.com/CriticalSecurity/ccscanner/pkg/docker"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

func StopVulnerabilityScan(ScanTaskId int64) {
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("openvas error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	var VulnerabilityScanTask database.Task
	VulnerabilityScanTaskError := tasksCollection.FindOne(context.TODO(), bson.D{{"task_id", ScanTaskId}}).Decode(&VulnerabilityScanTask)
	if VulnerabilityScanTaskError != nil {
		log.Println(VulnerabilityScanTaskError)
	}
	if VulnerabilityScanTask.Status == "STOPPED" || VulnerabilityScanTask.Status == "SUCCESS" {
		return
	}
	baseCmd := "gvm-cli --gmp-username admin --gmp-password admin socket --socketpath=/tmp/gvmd.sock --xml "
	username := "openvas_user"
	host := "127.0.0.1"
	pass := "openvas_user"
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	sshDest := host + ":" + VulnerabilityScanTask.SshPort
	sshClient, sshClientErr := ssh.Dial("tcp", sshDest, sshConfig)
	if sshClientErr != nil {
		err := fmt.Errorf("openvas error %v: %v", sshClientErr, sshClient)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	stopTaskSshSession, stopTaskSshSessionErr := sshClient.NewSession()
	if stopTaskSshSessionErr != nil {
		err := fmt.Errorf("openvas error %v: %v", stopTaskSshSessionErr, stopTaskSshSession)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	stopTaskXml := "<stop_task task_id='" + VulnerabilityScanTask.OpenvasTaskId + "'/>"
	stopTaskOutPut, stopTaskOutErr := stopTaskSshSession.CombinedOutput(baseCmd + "\"" + stopTaskXml + "\"")
	if stopTaskOutErr != nil {
		err := fmt.Errorf("openvas error %v: %v", stopTaskOutErr, stopTaskOutPut)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", VulnerabilityScanTask.TaskId}},
		bson.D{{"$set", bson.D{
			{"status", "STOPPED"}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("openvas error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	MongoClient.Disconnect(context.TODO())
}

func StartOpenVas(taskId *primitive.ObjectID, sshPort *string) (*string, error) {
	imageName := docker.OpenVasImage
	config := &container.Config{
		Image:        imageName,
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
		ExposedPorts: nat.PortSet{
			"22/tcp": struct{}{},
		},
	}
	resources := &container.Resources{
		Memory: 4.096e+9,
	}
	hostConfig := &container.HostConfig{
		Resources: *resources,
		PortBindings: nat.PortMap{
			"22/tcp": []nat.PortBinding{
				{
					HostIP:   "127.0.0.1",
					HostPort: *sshPort,
				},
			},
		},
	}
	now := time.Now()
	containerName := "openvas-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	OpenVasContainer, OpenVasContainerErr := docker.StartContainer(&imageName, &containerName, config, hostConfig)
	if OpenVasContainerErr != nil {
		return nil, OpenVasContainerErr
	}
	return &OpenVasContainer.ID, nil
}

func VulnerabilityScan(hosts *string, excludedHosts *string, taskId *primitive.ObjectID, configuration *string, disabledNvts *map[string][]string) {
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("openvas error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("openvas error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var sshPort string
	attempts := 0
	for {
		rand.Seed(time.Now().UnixNano())
		min := 2222
		max := 2232
		sshPort = strconv.Itoa(rand.Intn(max-min+1) + min)
		listenPort, listenPortErr := net.Listen("tcp", ":"+sshPort)
		if listenPortErr != nil {
			attempts++
			if attempts > 9 {
				err := fmt.Errorf("openvas error %v: %v", listenPortErr, "VulnerabilityScan listenPortErr - Cannot find an open port for ssh")
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				cli.Close()
				return
			}
		}
		if listenPort != nil {
			listenPort.Close()
			break
		}
		time.Sleep(3 * time.Second)
	}
	username := "openvas_user"
	host := "127.0.0.1"
	pass := "openvas_user"
	OpenVasContainer, StartOpenVasErr := StartOpenVas(taskId, &sshPort)
	if StartOpenVasErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v: %v", StartOpenVasErr, OpenVasContainer)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		_, updateError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"container_id", nil}, {"status", "FAILURE"}}}},
		)
		if updateError != nil {
			cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas error %v", updateError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			cli.Close()
			return
		}
		cli.Close()
		return
	}
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{
			{"container_id", OpenVasContainer},
			{"status", "INITIALIZING"},
			{"ssh_port", &sshPort}}}},
	)
	if updateError != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.Close()
		return
	}
	// check if the OpenVas Container is ready to scan
	for {
		OpenVasContainerLogReader, OpenVasContainerLogStreamErr := cli.ContainerLogs(ctx, *OpenVasContainer, types.ContainerLogsOptions{
			ShowStderr: true,
			ShowStdout: true,
			Timestamps: false,
		})
		if OpenVasContainerLogStreamErr != nil {
			cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas error %v: %v", OpenVasContainerLogStreamErr, OpenVasContainerLogReader)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			cli.Close()
			return
		}
		byteValue, _ := ioutil.ReadAll(OpenVasContainerLogReader)
		OpenVasContainerLogReader.Close()
		if strings.Contains(string(byteValue), "sync_cert: Updating CERT info succeeded.") {
			_, updateError1 := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{{"$set", bson.D{{"status", "PROGRESS"}}}},
			)
			if updateError1 != nil {
				cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
				cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("openvas error %v", updateError1)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				cli.Close()
				return
			}
			break
		}
		if strings.Contains(string(byteValue), "pg_ctl: server did not start in time") {
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas error %v: %v", StartOpenVasErr, OpenVasContainer)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			_, updateError := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{{"$set", bson.D{{"container_id", nil}, {"status", "ASSIGNED"}}}},
			)
			if updateError != nil {
				err := fmt.Errorf("openvas error %v", updateError)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				cli.Close()
				return
			}
			cli.Close()
			return
		}
		time.Sleep(15 * time.Second)
	}
	// Start scanning
	baseCmd := "gvm-cli --gmp-username admin --gmp-password admin socket --socketpath=/tmp/gvmd.sock --xml "
	createTargetXml := "<create_target><name>newtarget</name><hosts>" + *hosts + "</hosts><alive_tests>Consider Alive</alive_tests><exclude_hosts>" + *excludedHosts + "</exclude_hosts></create_target>"
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	sshDest := host + ":" + sshPort
	sshClient, sshClientErr := ssh.Dial("tcp", sshDest, sshConfig)
	if sshClientErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v", sshClientErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	createTargetSshSession, createTargetSshSessionErr := sshClient.NewSession()
	if createTargetSshSessionErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v", createTargetSshSessionErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	createTargetOutPut, createTargetOutPutErr := createTargetSshSession.CombinedOutput(baseCmd + "\"" + createTargetXml + "\"")
	if createTargetOutPutErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v: %v", createTargetOutPutErr, createTargetOutPut)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	CreateTargetResponseData := &CreateTargetResponse{}
	CreateTargetResponseDataErr := xml.Unmarshal(createTargetOutPut, CreateTargetResponseData)
	if CreateTargetResponseDataErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v", CreateTargetResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	defer createTargetSshSession.Close()

	createTaskSshSession, createTaskSshSessionErr := sshClient.NewSession()
	if createTaskSshSessionErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v", createTaskSshSessionErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var config string
	if len(*disabledNvts) > 0 {
		createConfigSshSession, createConfigSshSessionErr := sshClient.NewSession()
		createConfigXml := "<create_config><copy>" + *configuration + "</copy><name>newconfig</name></create_config>"
		if createConfigSshSessionErr != nil {
			cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas vulnerability scan create-config-ssh-session error %v", createConfigSshSessionErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		createConfigOutPut, createConfigXmlOutPutErr := createConfigSshSession.CombinedOutput(baseCmd + "\"" + createConfigXml + "\"")
		if createConfigXmlOutPutErr != nil {
			cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas vulnerability scan create-config-xml-output error %v: %v", createConfigXmlOutPutErr, string(createConfigOutPut))
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		CreateConfigResponseData := &CreateConfigResponse{}
		CreateConfigResponseDataErr := xml.Unmarshal(createConfigOutPut, CreateConfigResponseData)
		if CreateConfigResponseDataErr != nil {
			cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas error %v: %v", CreateConfigResponseDataErr, createConfigOutPut)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		defer createConfigSshSession.Close()
		for k, v := range *disabledNvts {
			var nvts string
			for _, nvt := range v {
				nvts += "<nvt oid='" + nvt + "'/>"
			}
			ModifyConfigSshSession, ModifyConfigSshSessionErr := sshClient.NewSession()
			modifyConfigXml := "<modify_config config_id='" + CreateConfigResponseData.ID + "'><nvt_selection><family>" + k + "</family>" + nvts + "</nvt_selection></modify_config>"
			if ModifyConfigSshSessionErr != nil {
				cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
				cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("openvas error %v", ModifyConfigSshSessionErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				return
			}
			modifyConfigOutPut, modifyConfigXmlOutPutErr := ModifyConfigSshSession.CombinedOutput(baseCmd + "\"" + modifyConfigXml + "\"")
			if modifyConfigXmlOutPutErr != nil {
				cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
				cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("openvas error %v: %v", modifyConfigXmlOutPutErr, modifyConfigOutPut)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				return
			}
			ModifyConfigResponseData := &ModifyConfigResponse{}
			ModifyConfigResponseDataErr := xml.Unmarshal(modifyConfigOutPut, ModifyConfigResponseData)
			if ModifyConfigResponseDataErr != nil {
				cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
				cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("openvas error %v", ModifyConfigResponseDataErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				return
			}
			defer ModifyConfigSshSession.Close()
		}
		config = CreateConfigResponseData.ID
	} else {
		config = *configuration
	}
	createTaskXml := "<create_task><name>newtask</name><comment></comment><config id='" + config + "'/><target id='" + CreateTargetResponseData.ID + "'/></create_task>"
	createTaskOutPut, createTaskOutPutErr := createTaskSshSession.CombinedOutput(baseCmd + "\"" + createTaskXml + "\"")
	if createTaskOutPutErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v: %v", createTaskOutPutErr, createTaskOutPut)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	CreateTaskResponseData := &CreateTaskResponse{} // Create and initialise a data variablgo as a PostData struct
	CreateTaskResponseDataErr := xml.Unmarshal(createTaskOutPut, CreateTaskResponseData)
	if CreateTaskResponseDataErr != nil {
		return
	}
	defer createTaskSshSession.Close()
	tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{
			{"openvas_task_id", CreateTaskResponseData.ID}}}},
	)
	startTaskSshSession, startTaskSshSessionErr := sshClient.NewSession()
	if startTaskSshSessionErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v", startTaskSshSessionErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	startTaskXml := "<start_task task_id='" + CreateTaskResponseData.ID + "'/>"
	startTaskOutPut, startTaskOutErr := startTaskSshSession.CombinedOutput(baseCmd + "\"" + startTaskXml + "\"")
	if startTaskOutErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v: %v", startTaskOutErr, startTaskOutPut)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	StartTaskResponseData := &StartTaskResponse{} // Create and initialise a data variablgo as a PostData struct
	StartTaskResponseDataErr := xml.Unmarshal(startTaskOutPut, StartTaskResponseData)
	if StartTaskResponseDataErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v", StartTaskResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	defer startTaskSshSession.Close()
	for {
		getTaskSshSession, getTaskSshSessionErr := sshClient.NewSession()
		if getTaskSshSessionErr != nil {
			cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas error %v", getTaskSshSessionErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		getTaskXml := "<get_tasks task_id='" + CreateTaskResponseData.ID + "'/>"
		getTaskOutPut, getTaskOutPutErr := getTaskSshSession.CombinedOutput(baseCmd + "\"" + getTaskXml + "\"")
		if getTaskOutPutErr != nil {
			cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas error %v: %v", getTaskOutPutErr, getTaskOutPut)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		GetTasksResponseData := &GetTasksResponse{} // Create and initialise a data variablgo as a PostData struct
		GetTaskResponseDataErr := xml.Unmarshal(getTaskOutPut, GetTasksResponseData)
		defer getTaskSshSession.Close()
		if GetTaskResponseDataErr != nil {
			cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas error %v", GetTaskResponseDataErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		if GetTasksResponseData.Task.Status == "Done" || GetTasksResponseData.Task.Status == "Stopped" {
			break
		}
		percent, _ := strconv.Atoi(GetTasksResponseData.Task.Progress.Text)
		_, updateError2 := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"percent", percent}}}},
		)
		if updateError2 != nil {
			err := fmt.Errorf("openvas error %v", updateError2)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
			cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
			return
		}
		time.Sleep(15 * time.Second)
	}
	getReportsSshSession, getReportsSshSessionErr := sshClient.NewSession()
	if getReportsSshSessionErr != nil {
		err := fmt.Errorf("openvas error %v", getReportsSshSessionErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		return
	}
	getReportsXml := "<get_reports report_id='" + StartTaskResponseData.ReportID + "' details='1' ignore_pagination='1' filter='levels=hml' format_id='c1645568-627a-11e3-a660-406186ea4fc5'/>"
	getReportsOutPut, getReportsOutPutErr := getReportsSshSession.CombinedOutput(baseCmd + "\"" + getReportsXml + "\"")
	if getReportsOutPutErr != nil {
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("openvas error %v: %v", getReportsOutPutErr, getReportsOutPut)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
	}
	GetReportsResponseData := &GetReportsResponse{} // Create and initialise a data variablgo as a PostData struct
	GetReportsResponseDataErr := xml.Unmarshal(getReportsOutPut, GetReportsResponseData)
	if GetReportsResponseDataErr != nil {
		return
	}
	defer getReportsSshSession.Close()
	sshClient.Close()
	_, updateError2 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{
			{"openvas_result", GetReportsResponseData.Report.Text},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	if updateError2 != nil {
		err := fmt.Errorf("openvas error %v", updateError2)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
		cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
		return
	}
	cli.ContainerStop(context.Background(), *OpenVasContainer, nil)
	cli.ContainerRemove(context.Background(), *OpenVasContainer, types.ContainerRemoveOptions{})
	cli.Close()
	MongoClient.Disconnect(context.TODO())
	return
}
