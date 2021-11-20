package gvm

import (
	"context"
	"encoding/xml"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
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
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("gvm mongo-client error %v", MongoClientError)
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
	baseCmd := "gvm-cli --gmp-username admin --gmp-password admin socket --socketpath=/var/run/gvm/gvmd.sock --xml "
	username := "gvm_user"
	host := "127.0.0.1"
	pass := "gvm_user"
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	sshDest := host + ":" + VulnerabilityScanTask.SshPort
	sshClient, sshClientErr := ssh.Dial("tcp", sshDest, sshConfig)
	if sshClientErr != nil {
		err := fmt.Errorf("gvm ssh-client error %v: %v", sshClientErr, sshClient)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	stopTaskSshSession, stopTaskSshSessionErr := sshClient.NewSession()
	if stopTaskSshSessionErr != nil {
		err := fmt.Errorf("gvm stop-task-ssh-session error %v: %v", stopTaskSshSessionErr, stopTaskSshSession)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	stopTaskXml := "<stop_task task_id='" + VulnerabilityScanTask.OpenvasTaskId + "'/>"
	stopTaskOutPut, stopTaskOutErr := stopTaskSshSession.CombinedOutput(baseCmd + "\"" + stopTaskXml + "\"")
	if stopTaskOutErr != nil {
		err := fmt.Errorf("gvm stop-task-output error %v: %v", stopTaskOutErr, string(stopTaskOutPut))
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
		err := fmt.Errorf("gvm update-mongo error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
}

func StartGVM(taskId *primitive.ObjectID, sshPort *string) (*string, error) {
	imageName := docker.GVMImage
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
	containerName := "gvm-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	GVMContainer, GVMContainerErr := docker.StartContainer(&imageName, &containerName, config, hostConfig)
	if GVMContainerErr != nil {
		return nil, GVMContainerErr
	}
	return &GVMContainer.ID, nil
}

func VulnerabilityScan(hosts *string, excludedHosts *string, taskId *primitive.ObjectID, configuration *string, disabledNvts *map[string][]string) {
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("gvm mongo-client error %v", MongoClientError)
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
		err := fmt.Errorf("gvm new-client error %v: %v", NewEnvClientErr, cli)
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
				err := fmt.Errorf("gvm listen-port error %v: %v", listenPortErr, "VulnerabilityScan listenPortErr - Cannot find an open port for ssh")
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
	username := "gvm_user"
	host := "127.0.0.1"
	pass := "gvm_user"
	baseCmd := "gvm-cli --gmp-username admin --gmp-password admin socket --socketpath=/var/run/gvm/gvmd.sock --xml "
	GVMContainer, StartGVMErr := StartGVM(taskId, &sshPort)
	if StartGVMErr != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm start-gvm error %v: %v", StartGVMErr, GVMContainer)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		_, updateError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"container_id", nil}, {"status", "FAILURE"}}}},
		)
		if updateError != nil {
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm mongo-update error %v", updateError)
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
			{"container_id", GVMContainer},
			{"status", "INITIALIZING"},
			{"ssh_port", &sshPort}}}},
	)
	if updateError != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm mongo-upate error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.Close()
		return
	}
	// check if the GVM Container is ready to scan
	for {
		GVMContainerLogReader, GVMContainerLogStreamErr := cli.ContainerLogs(ctx, *GVMContainer, types.ContainerLogsOptions{
			ShowStderr: true,
			ShowStdout: true,
			Timestamps: false,
		})
		if GVMContainerLogStreamErr != nil {
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm gvm-log-reader error %v: %v", GVMContainerLogStreamErr, GVMContainerLogReader)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			cli.Close()
			return
		}
		byteValue, _ := ioutil.ReadAll(GVMContainerLogReader)
		GVMContainerLogReader.Close()
		if strings.Contains(string(byteValue), "sync_cert: Updating CERT info succeeded.") {
			_, updateError1 := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{{"$set", bson.D{{"status", "STAGE1-INITIALIZED"}}}},
			)
			if updateError1 != nil {
				cli.ContainerStop(context.Background(), *GVMContainer, nil)
				cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("gvm mongo-update error %v", updateError1)
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
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm pg_ctl error %v: %v", StartGVMErr, GVMContainer)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			_, updateError := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{{"$set", bson.D{{"container_id", nil}, {"status", "ASSIGNED"}}}},
			)
			if updateError != nil {
				err := fmt.Errorf("gvm mongo-update error %v", updateError)
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
	// monkey patch - temporary fix for https://github.com/greenbone/ospd-openvas/issues/335
	/**/
	hostsArray := strings.Split(*hosts, ",")
	excludeHostsArray := strings.Split(*excludedHosts, ",")
	for _, item := range excludeHostsArray {
		i, found := Find(hostsArray, item)
		if found {
			hostsArray = append(hostsArray[:i], hostsArray[i+1:]...)
		}
	}

	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	sshDest := host + ":" + sshPort
	sshClient, sshClientErr := ssh.Dial("tcp", sshDest, sshConfig)
	if sshClientErr != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm ssh-client error %v", sshClientErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	/*
		/**/
	// createGetConfig"
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	for {
		createGetConfigsSshSession, createGetConfigsSshSessionErr := sshClient.NewSession()
		if createGetConfigsSshSessionErr != nil {
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm create-target-ssh-session error %v", createGetConfigsSshSessionErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		createGetConfigsOutPut, createGetConfigsOutPutErr := createGetConfigsSshSession.CombinedOutput(baseCmd + "\"<get_configs/>\"")
		if createGetConfigsOutPutErr != nil {
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm create-target-output error %v: %v", createGetConfigsOutPutErr, string(createGetConfigsOutPut))
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		if strings.Contains(string(createGetConfigsOutPut), "<config_count>12") {
			_, updateError1 := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{{"$set", bson.D{{"status", "PROGRESS"}}}},
			)
			if updateError1 != nil {
				cli.ContainerStop(context.Background(), *GVMContainer, nil)
				cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("gvm mongo-update error %v", updateError1)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				cli.Close()
				return
			}
			break
		}
		defer createGetConfigsSshSession.Close()
		time.Sleep(15 * time.Second)
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/**/
	s := strings.Join(hostsArray, ",")
	newHosts := &s
	createTargetXml := "<create_target><name>newtarget</name><hosts>" + *newHosts + "</hosts><alive_tests>Consider Alive</alive_tests><port_list id='33d0cd82-57c6-11e1-8ed1-406186ea4fc5'></port_list></create_target>"
	// createTargetXml := "<create_target><name>newtarget</name><hosts>" + *hosts + "</hosts><alive_tests>Consider Alive</alive_tests><exclude_hosts>" + *excludedHosts + "</exclude_hosts><port_list id='33d0cd82-57c6-11e1-8ed1-406186ea4fc5'></port_list></create_target>"
	createTargetSshSession, createTargetSshSessionErr := sshClient.NewSession()
	if createTargetSshSessionErr != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm create-target-ssh-session error %v", createTargetSshSessionErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	createTargetOutPut, createTargetOutPutErr := createTargetSshSession.CombinedOutput(baseCmd + "\"" + createTargetXml + "\"")
	if createTargetOutPutErr != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm create-target-output error %v: %v", createTargetOutPutErr, string(createTargetOutPut))
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	CreateTargetResponseData := &CreateTargetResponse{}
	CreateTargetResponseDataErr := xml.Unmarshal(createTargetOutPut, CreateTargetResponseData)
	if CreateTargetResponseDataErr != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm create-target-response-data error %v", CreateTargetResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	defer createTargetSshSession.Close()

	createTaskSshSession, createTaskSshSessionErr := sshClient.NewSession()
	if createTaskSshSessionErr != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm create-task-ssh-session error %v", createTaskSshSessionErr)
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
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm vulnerability scan create-config-ssh-session error %v", createConfigSshSessionErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		createConfigOutPut, createConfigXmlOutPutErr := createConfigSshSession.CombinedOutput(baseCmd + "\"" + createConfigXml + "\"")
		if createConfigXmlOutPutErr != nil {
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm vulnerability scan create-config-xml-output error %v: %v", createConfigXmlOutPutErr, string(createConfigOutPut))
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		CreateConfigResponseData := &CreateConfigResponse{}
		CreateConfigResponseDataErr := xml.Unmarshal(createConfigOutPut, CreateConfigResponseData)
		if CreateConfigResponseDataErr != nil {
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm create-config-response-data error %v: %v", CreateConfigResponseDataErr, createConfigOutPut)
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
				cli.ContainerStop(context.Background(), *GVMContainer, nil)
				cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("gvm modify-config-ssh-session error %v", ModifyConfigSshSessionErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				return
			}
			modifyConfigOutPut, modifyConfigXmlOutPutErr := ModifyConfigSshSession.CombinedOutput(baseCmd + "\"" + modifyConfigXml + "\"")
			if modifyConfigXmlOutPutErr != nil {
				cli.ContainerStop(context.Background(), *GVMContainer, nil)
				cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("gvm modify-config-xml-output error %v: %v", modifyConfigXmlOutPutErr, string(modifyConfigOutPut))
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				return
			}
			ModifyConfigResponseData := &ModifyConfigResponse{}
			ModifyConfigResponseDataErr := xml.Unmarshal(modifyConfigOutPut, ModifyConfigResponseData)
			if ModifyConfigResponseDataErr != nil {
				cli.ContainerStop(context.Background(), *GVMContainer, nil)
				cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("gvm modify-config-response-data error %v", ModifyConfigResponseDataErr)
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
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm create-task-output error %v: %v", createTaskOutPutErr, string(createTaskOutPut))
		noConfig := "Response Error 404. Failed to find config"
		if strings.Contains(err.Error(), noConfig) {
			sshClient.Close()
			cli.Close()
			_, updateError2 := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{{"$set", bson.D{
					{"openvas_result", noConfig},
					{"status", "FAILURE"},
					{"percent", 100}}}},
			)
			if updateError2 != nil {
				err := fmt.Errorf("gvm mongo-update error %v", updateError2)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				return
			}
			MongoClient.Disconnect(context.TODO())
			return
		}
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
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm start-task-ssh-session error %v", startTaskSshSessionErr)

		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	startTaskXml := "<start_task task_id='" + CreateTaskResponseData.ID + "'/>"
	startTaskOutPut, startTaskOutErr := startTaskSshSession.CombinedOutput(baseCmd + "\"" + startTaskXml + "\"")
	if startTaskOutErr != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm start-task-out error %v: %v", startTaskOutErr, string(startTaskOutPut))
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	StartTaskResponseData := &StartTaskResponse{} // Create and initialise a data variablgo as a PostData struct
	StartTaskResponseDataErr := xml.Unmarshal(startTaskOutPut, StartTaskResponseData)
	if StartTaskResponseDataErr != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm start-task-response-data error %v", StartTaskResponseDataErr)
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
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm get-task-ssh-session error %v", getTaskSshSessionErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		getTaskXml := "<get_tasks task_id='" + CreateTaskResponseData.ID + "'/>"
		getTaskOutPut, getTaskOutPutErr := getTaskSshSession.CombinedOutput(baseCmd + "\"" + getTaskXml + "\"")
		if getTaskOutPutErr != nil {
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm get-task-output error %v: %v", getTaskOutPutErr, string(getTaskOutPut))
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
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("gvm get-task-response-data error %v", GetTaskResponseDataErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		if GetTasksResponseData.Task.Status == "Interrupted" || GetTasksResponseData.Task.Status == "Done" || GetTasksResponseData.Task.Status == "Stopped" {
			break
		}
		percent, _ := strconv.Atoi(GetTasksResponseData.Task.Progress.Text)
		_, updateError2 := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"percent", percent}}}},
		)
		if updateError2 != nil {
			err := fmt.Errorf("gvm mongo-update error %v", updateError2)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			cli.ContainerStop(context.Background(), *GVMContainer, nil)
			cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
			return
		}
		time.Sleep(15 * time.Second)
	}
	getReportsSshSession, getReportsSshSessionErr := sshClient.NewSession()
	if getReportsSshSessionErr != nil {
		err := fmt.Errorf("gvm get-reports-ssh-ession error %v", getReportsSshSessionErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		return
	}
	getReportsXml := "<get_reports report_id='" + StartTaskResponseData.ReportID + "' details='1' ignore_pagination='1' filter='levels=hml' format_id='c1645568-627a-11e3-a660-406186ea4fc5'/>"
	getReportsOutPut, getReportsOutPutErr := getReportsSshSession.CombinedOutput(baseCmd + "\"" + getReportsXml + "\"")
	if getReportsOutPutErr != nil {
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		err := fmt.Errorf("gvm get-reports-output error %v: %v", getReportsOutPutErr, string(getReportsOutPut))
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
		err := fmt.Errorf("gvm mongo-update error %v", updateError2)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		cli.ContainerStop(context.Background(), *GVMContainer, nil)
		cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
		return
	}
	cli.ContainerStop(context.Background(), *GVMContainer, nil)
	cli.ContainerRemove(context.Background(), *GVMContainer, types.ContainerRemoveOptions{})
	cli.Close()
	return
}

func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}
