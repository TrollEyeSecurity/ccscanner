package gvm

import (
	"context"
	"encoding/xml"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/ssh"
	"log"
	"math/rand"
	"os/exec"
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

func StartVulnerabilityScan(hosts *string, excludedHosts *string, taskId *primitive.ObjectID, configuration *string, disabledNvts *map[string][]string) {
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
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("gvm new-client error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	opts := options.Find().SetSort(bson.D{{"_id", -1}}).SetLimit(1)
	systemCollection := MongoClient.Database("core").Collection("system")
	cursor, ConfigurationError := systemCollection.Find(context.TODO(), bson.D{{"_id", "configuration"}}, opts)
	if ConfigurationError != nil {
		err := fmt.Errorf("gvm find configuration error vulnerability-scan %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	for cursor.Next(context.TODO()) {
		for {
			if isGvmReady() {
				break
			}
			_, updateError1 := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{{"$set", bson.D{{"status", "INITIALIZING"}}}},
			)
			if updateError1 != nil {
				err := fmt.Errorf("gvm status mongo-update error %v", updateError1)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				return
			}
			fmt.Println("GVM is not ready to scan")
			time.Sleep(15 * time.Second)
		}
		_, updateProgressError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"status", "PROGRESS"}}}},
		)
		if updateProgressError != nil {
			err := fmt.Errorf("gvm status mongo-update error %v", updateProgressError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		hostsArray := strings.Split(*hosts, ",")
		excludeHostsArray := strings.Split(*excludedHosts, ",")
		for _, item := range excludeHostsArray {
			i, found := Find(hostsArray, item)
			if found {
				hostsArray = append(hostsArray[:i], hostsArray[i+1:]...)
			}
		}

		s := strings.Join(hostsArray, ",")
		newHosts := &s
		createTargetXml := "<create_target><name>target-" + taskId.Hex() + "</name><hosts>" + *newHosts + "</hosts><alive_tests>Consider Alive</alive_tests><port_list id='33d0cd82-57c6-11e1-8ed1-406186ea4fc5'></port_list></create_target>"
		// createTargetXml := "<create_target><name>target-" + taskId.Hex() + "</name><hosts>" + *newHosts + "</hosts><alive_tests>Consider Alive</alive_tests><port_list id='4a4717fe-57d2-11e1-9a26-406186ea4fc5'></port_list></create_target>"
		createConfigXml := "<create_config><copy>" + *configuration + "</copy><name>config-" + taskId.Hex() + "</name></create_config>"
		targetResp := createTarget(&createTargetXml)
		configResp := createConfig(&createConfigXml)
		/*
			if len(*disabledNvts) > 0 {
				for k, v := range *disabledNvts {
					var nvts string
					for _, nvt := range v {
						nvts += "<nvt oid='" + nvt + "'/>"
					}
					modifyConfigXml := "<modify_config config_id='" + *configId + "'><nvt_selection><family>" + k + "</family>" + nvts + "</nvt_selection></modify_config>"
					modifyConfig(&modifyConfigXml)
				}
			}
		*/
		createTaskXml := "<create_task><name>task-" + taskId.Hex() + "</name><comment></comment><config id='" + configResp.ID + "'/><target id='" + targetResp.ID + "'/></create_task>"
		createTaskOutput := createTask(&createTaskXml)
		if createTaskOutput == nil {
			_, updateTaskIdError := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{
					{"openvas_result", "COULD NOT CREATE TASK"},
					{"status", "FAILURE"},
					{"percent", 100}},
			)
			if updateTaskIdError != nil {
				err := fmt.Errorf("gvm status mongo-update error %v", updateTaskIdError)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				return
			}
			return
		}
		_, updateTaskIdError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"openvas_task_id", createTaskOutput.ID}}}},
		)
		if updateTaskIdError != nil {
			err := fmt.Errorf("gvm status mongo-update error %v", updateTaskIdError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		startTaskXml := "<start_task task_id='" + createTaskOutput.ID + "'/>"
		startTask(&startTaskXml)
	}
	/*

			createTaskOutPut, createTaskOutPutErr := createTaskSshSession.CombinedOutput(baseCmd + "\"" + createTaskXml + "\"")
			if createTaskOutPutErr != nil {
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
				return
			}
			getReportsXml := "<get_reports report_id='" + StartTaskResponseData.ReportID + "' details='1' ignore_pagination='1' filter='levels=hml' format_id='c1645568-627a-11e3-a660-406186ea4fc5'/>"
			getReportsOutPut, getReportsOutPutErr := getReportsSshSession.CombinedOutput(baseCmd + "\"" + getReportsXml + "\"")
			if getReportsOutPutErr != nil {
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
				{"openvas_result", ""},
				{"status", "SUCCESS"},
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
	*/
	cli.Close()
	return
}

func CheckVulnerabilityScan(taskId *primitive.ObjectID) {
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
	task := database.Task{}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	tasksCollection.FindOne(context.TODO(), bson.D{{"_id", taskId}}).Decode(&task)
	getTasksCmd := exec.Command("gvm-cli", "socket", "--socketpath=/run/gvmd/gvmd.sock", "--xml", "<get_tasks task_id='"+task.OpenvasTaskId+"'/>")
	getTasksCmdByts, _ := getTasksCmd.CombinedOutput()
	getTasksResponseData := &GetTasksResponse{} // Create and initialise a data variablgo as a PostData struct
	getTasksResponseDataErr := xml.Unmarshal(getTasksCmdByts, getTasksResponseData)
	if getTasksResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal get-tasks error %v", getTasksResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	if getTasksResponseData.Task.Status == "Interrupted" || getTasksResponseData.Task.Status == "Done" || getTasksResponseData.Task.Status == "Stopped" {
		reportData := getReports(&getTasksResponseData.Task.CurrentReport.Report.ID)
		_, updateTaskIdError := MongoClient.Database("core").Collection("tasks").UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"openvas_result", reportData.Report.Text}, {"status", "SUCCESS"}, {"percent", 100}}}},
		)
		if updateTaskIdError != nil {
			err := fmt.Errorf("gvm status mongo-update error %v", updateTaskIdError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
	}
	percent, _ := strconv.Atoi(getTasksResponseData.Task.Progress.Text)
	_, updateError2 := MongoClient.Database("core").Collection("tasks").UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", percent}}}},
	)
	if updateError2 != nil {
		err := fmt.Errorf("gvm mongo-update error %v", updateError2)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	return
}

func getReports(reportId *string) *GetReportsResponse {
	getReportsXml := "<get_reports report_id='" + *reportId + "' details='1' ignore_pagination='1' filter='levels=hml' format_id='c1645568-627a-11e3-a660-406186ea4fc5'/>"
	getReportsCmd := exec.Command("gvm-cli", "socket", "--socketpath=/run/gvmd/gvmd.sock", "--xml", getReportsXml)
	getReportsCmdByts, _ := getReportsCmd.CombinedOutput()
	getReportsResponseData := &GetReportsResponse{} // Create and initialise a data variablgo as a PostData struct
	getReportsResponseDataErr := xml.Unmarshal(getReportsCmdByts, getReportsResponseData)
	if getReportsResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal get-reports error %v", getReportsResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return nil
	}
	return getReportsResponseData
}

func createTarget(xmlString *string) *CreateTargetResponse {
	createTargetCmd := exec.Command("gvm-cli", "socket", "--socketpath=/run/gvmd/gvmd.sock", "--xml", *xmlString)
	createTargetCmdByts, _ := createTargetCmd.CombinedOutput()
	createTargetResponseData := &CreateTargetResponse{} // Create and initialise a data variablgo as a PostData struct
	createTargetResponseDataErr := xml.Unmarshal(createTargetCmdByts, createTargetResponseData)
	if createTargetResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal create-target error %v", createTargetResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return nil
	}
	return createTargetResponseData
}

func createConfig(xmlString *string) *CreateConfigResponse {
	createConfigCmd := exec.Command("gvm-cli", "socket", "--socketpath=/run/gvmd/gvmd.sock", "--xml", *xmlString)
	createConfigCmdByts, _ := createConfigCmd.CombinedOutput()
	CreateConfigResponseData := &CreateConfigResponse{}
	CreateConfigResponseDataErr := xml.Unmarshal(createConfigCmdByts, CreateConfigResponseData)
	if CreateConfigResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal create-config error %v", CreateConfigResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return nil
	}
	return CreateConfigResponseData
}

func modifyConfig(xmlString *string) *string {
	var s string
	modifyConfigCmd := exec.Command("gvm-cli", "socket", "--socketpath=/run/gvmd/gvmd.sock", "--xml", *xmlString)
	modifyConfigCmdByts, _ := modifyConfigCmd.CombinedOutput()
	ModifyConfigResponseData := &CreateTaskResponse{} // Create and initialise a data variablgo as a PostData struct
	ModifyConfigResponseDataErr := xml.Unmarshal(modifyConfigCmdByts, ModifyConfigResponseData)
	if ModifyConfigResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal modify-config error %v", ModifyConfigResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return &s
	}
	return &ModifyConfigResponseData.ID
}

func createTask(xmlString *string) *CreateTaskResponse {
	createTaskCmd := exec.Command("gvm-cli", "socket", "--socketpath=/run/gvmd/gvmd.sock", "--xml", *xmlString)
	createTaskCmdByts, _ := createTaskCmd.CombinedOutput()
	CreateTaskResponseData := &CreateTaskResponse{} // Create and initialise a data variablgo as a PostData struct
	CreateTaskResponseDataErr := xml.Unmarshal(createTaskCmdByts, CreateTaskResponseData)
	if CreateTaskResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal create-config error %v", CreateTaskResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return nil
	}
	return CreateTaskResponseData
}

func startTask(xmlString *string) *StartTaskResponse {
	createTaskCmd := exec.Command("gvm-cli", "socket", "--socketpath=/run/gvmd/gvmd.sock", "--xml", *xmlString)
	createTaskCmdByts, _ := createTaskCmd.CombinedOutput()
	StartTaskResponseData := &StartTaskResponse{} // Create and initialise a data variablgo as a PostData struct
	StartTaskResponseDataErr := xml.Unmarshal(createTaskCmdByts, StartTaskResponseData)
	if StartTaskResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal start-task error %v", StartTaskResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return nil
	}
	return StartTaskResponseData
}

func isGvmReady() bool {
	getFeedsCmd := exec.Command("gvm-cli", "socket", "--socketpath=/run/gvmd/gvmd.sock", "--xml", "<get_feeds/>")
	getFeedsCmdByts, _ := getFeedsCmd.CombinedOutput()
	getFeedsResponseData := &GetFeedsResponse{} // Create and initialise a data variablgo as a PostData struct
	StartTaskResponseDataErr := xml.Unmarshal(getFeedsCmdByts, getFeedsResponseData)
	if StartTaskResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal error %v", StartTaskResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return false
	}
	for _, feed := range getFeedsResponseData.Feed {
		if feed.CurrentlySyncing.Text == "" {
			break
		} else {
			return false
		}
	}
	return true
}

func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

func Initialize() {
	if *CheckStatus() {
		MongoClient, MongoClientError := database.GetMongoClient()
		defer MongoClient.Disconnect(context.TODO())
		if MongoClientError != nil {
			err := fmt.Errorf("database initialize gvm error %v", MongoClient)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Fatalf("MongoClient Error: %s", MongoClientError)
		}
		systemCollection := MongoClient.Database("core").Collection("system")
		opts := options.Find().SetSort(bson.D{{"_id", -1}}).SetLimit(1)
		cursor, _ := systemCollection.Find(context.TODO(), bson.D{{"_id", "configuration"}}, opts)
		var results []bson.M
		cursor.All(context.TODO(), &results)
		if results[0]["gvm_initialized"] == false {
			fmt.Println("need to init")
			password := randomString(18)
			gvmdCreateUserCmd := exec.Command("/usr/local/sbin/gvmd", "--create-user=ccscanner", "--password="+*password)
			_, gvmdCreateUserCmdErr := gvmdCreateUserCmd.CombinedOutput()
			gvmdCreateUserCmdStatus := 99
			gvmdUpdateUserCmdStatus := 99
			if gvmdCreateUserExitErr, ok := gvmdCreateUserCmdErr.(*exec.ExitError); ok {
				gvmdCreateUserCmdStatus = gvmdCreateUserExitErr.ExitCode()
			}
			if gvmdCreateUserCmdStatus == 1 {
				gvmdUpdateUserCmd := exec.Command("/usr/local/sbin/gvmd", "--user=ccscanner", "--new-password="+*password)
				_, gvmdUpdateUserCmdErr := gvmdUpdateUserCmd.CombinedOutput()
				if exitErr, ok := gvmdUpdateUserCmdErr.(*exec.ExitError); ok {
					gvmdUpdateUserCmdStatus = exitErr.ExitCode()
				}
				gvmdUpdateUserCmdStatus = 0
			}
			exec.Command("python3", "-m", "pip", "install", "--user", "gvm-tools")
			if gvmdCreateUserCmdStatus == 0 || gvmdUpdateUserCmdStatus == 0 {
				_, ConfigurationError := systemCollection.UpdateOne(context.TODO(),
					bson.D{{"_id", "configuration"}}, bson.D{{"$set", bson.D{{"_id", "configuration"}, {"gvm_initialized", true}, {"gvm_creds", bson.D{{"username", "ccscanner"}, {"password", *password}}}}}},
				)
				if ConfigurationError != nil {
					err := fmt.Errorf("update gvm configuration error %v", ConfigurationError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Fatalf("GVM Configuration Error: %s", ConfigurationError)
				}
			}
		}
	}
}

func randomString(length int) *string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	rand.Read(b)
	resp := fmt.Sprintf("%x", b)[:length]
	return &resp
}

func CheckStatus() *bool {
	isGvmAvailable := false
	gvmdCmd := exec.Command("systemctl", "status", "gvmd.service")
	_, gvmdCmdErr := gvmdCmd.CombinedOutput()
	gvmdCmdStatus := 0
	if gvmdCmdErr != nil {
		if exitErr, ok := gvmdCmdErr.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				gvmdCmdStatus = 1
			}
			if exitErr.ExitCode() == 2 {
				gvmdCmdStatus = 2
			}
			if exitErr.ExitCode() == 3 {
				gvmdCmdStatus = 3
			}
			if exitErr.ExitCode() == 4 {
				gvmdCmdStatus = 4
			}
		} else {
			gvmdCmdStatus = 99
			fmt.Printf("failed to run systemctl: %v", gvmdCmdErr)
		}
	}
	ospdCmd := exec.Command("systemctl", "status", "ospd-openvas.service")
	_, ospdCmdErr := ospdCmd.CombinedOutput()
	ospdCmdStatus := 0
	if ospdCmdErr != nil {
		if exitErr, ok := ospdCmdErr.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				ospdCmdStatus = 1
			}
			if exitErr.ExitCode() == 2 {
				ospdCmdStatus = 2
			}
			if exitErr.ExitCode() == 3 {
				ospdCmdStatus = 3
			}
			if exitErr.ExitCode() == 4 {
				ospdCmdStatus = 4
			}
		} else {
			ospdCmdStatus = 99
			fmt.Printf("failed to run systemctl: %v", ospdCmdErr)
		}
	}
	if gvmdCmdStatus == 0 && ospdCmdStatus == 0 {
		isGvmAvailable = true
	}
	return &isGvmAvailable
}
