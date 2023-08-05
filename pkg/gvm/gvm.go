package gvm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
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
		return
	}
	if VulnerabilityScanTask.Status == "STOPPED" || VulnerabilityScanTask.Status == "SUCCESS" {
		return
	}
	stopTaskXml := "<stop_task task_id='" + VulnerabilityScanTask.OpenvasTaskId + "'/>"
	stopTask(&stopTaskXml)
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
	cli, NewEnvClientErr := client.NewClientWithOpts()
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
			if IsGvmReady() {
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
		// TCP 33d0cd82-57c6-11e1-8ed1-406186ea4fc5
		// UDP 4a4717fe-57d2-11e1-9a26-406186ea4fc5
		createConfigXml := "<create_config><copy>" + *configuration + "</copy><name>config-" + taskId.Hex() + "</name></create_config>"
		targetResp := createTarget(&createTargetXml)
		if targetResp == nil {
			err := fmt.Errorf("gvm could not create target for %s", *newHosts)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			_, updateProgressError1 := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{{"$set", bson.D{{"status", "FAILURE"}}}},
			)
			if updateProgressError1 != nil {
				err1 := fmt.Errorf("gvm status mongo-update error %v", updateProgressError)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err1)
				}
				log.Println(err1)
				return
			}
			return
		}
		configResp := createConfig(&createConfigXml)
		if len(*disabledNvts) > 0 {
			for k, v := range *disabledNvts {
				var nvts string
				for _, nvt := range v {
					nvts += "<nvt oid='" + nvt + "'/>"
				}
				modifyConfigXml := "<modify_config config_id='" + configResp.ID + "'><nvt_selection><family>" + k + "</family>" + nvts + "</nvt_selection></modify_config>"
				modifyConfig(&modifyConfigXml)
			}
		}
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
	getTasksCmd := exec.Command(gvmCli, "socket", "--socketpath="+socketPath, "--xml", "<get_tasks task_id='"+task.OpenvasTaskId+"'/>")
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
		var reportId string
		if getTasksResponseData.Task.LastReport.Report.ID != "" {
			reportId = getTasksResponseData.Task.LastReport.Report.ID
		}
		if getTasksResponseData.Task.CurrentReport.Report.ID != "" {
			reportId = getTasksResponseData.Task.CurrentReport.Report.ID
		}
		reportData := getReports(&reportId)
		jsonData, _ := json.Marshal(reportData)
		result := base64.StdEncoding.EncodeToString(jsonData)
		_, updateTaskIdError := MongoClient.Database("core").Collection("tasks").UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"openvas_result", result}, {"status", "SUCCESS"}, {"percent", 100}}}},
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
	getReportsXml := "<get_reports report_id='" + *reportId + "' details='1' ignore_pagination='1' filter='levels=hml' format_id='a994b278-1f62-11e1-96ac-406186ea4fc5'/>"
	getReportsCmd := exec.Command(gvmCli, "socket", "--socketpath="+socketPath, "--xml", getReportsXml)
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
	createTargetCmd := exec.Command(gvmCli, "socket", "--socketpath="+socketPath, "--xml", *xmlString)
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
	createConfigCmd := exec.Command(gvmCli, "socket", "--socketpath="+socketPath, "--xml", *xmlString)
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
	modifyConfigCmd := exec.Command(gvmCli, "socket", "--socketpath="+socketPath, "--xml", *xmlString, "--pretty")
	modifyConfigCmdByts, _ := modifyConfigCmd.CombinedOutput()
	ModifyConfigResponseData := &ModifyConfigResponse{} // Create and initialise a data variablgo as a PostData struct
	ModifyConfigResponseDataErr := xml.Unmarshal(modifyConfigCmdByts, ModifyConfigResponseData)
	if ModifyConfigResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal modify-config error %v", ModifyConfigResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return &s
	}
	return &ModifyConfigResponseData.Status
}

func createTask(xmlString *string) *CreateTaskResponse {
	createTaskCmd := exec.Command(gvmCli, "socket", "--socketpath="+socketPath, "--xml", *xmlString)
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
	createTaskCmd := exec.Command(gvmCli, "socket", "--socketpath="+socketPath, "--xml", *xmlString)
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

func stopTask(xmlString *string) *StopTaskResponse {
	stopTaskCmd := exec.Command(gvmCli, "socket", "--socketpath="+socketPath, "--xml", *xmlString)
	stopTaskCmdByts, _ := stopTaskCmd.CombinedOutput()
	StopTaskResponseData := &StopTaskResponse{} // Create and initialise a data variablgo as a PostData struct
	StopTaskResponseDataErr := xml.Unmarshal(stopTaskCmdByts, StopTaskResponseData)
	if StopTaskResponseDataErr != nil {
		err := fmt.Errorf("gvm unmarshal stop-task error %v", StopTaskResponseDataErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return nil
	}
	return StopTaskResponseData
}

func IsGvmReady() bool {
	getFeedsCmd := exec.Command(gvmCli, "socket", "--socketpath="+socketPath, "--xml", "<get_feeds/>")
	getFeedsCmdByts, _ := getFeedsCmd.CombinedOutput()
	getFeedsResponseData := &GetFeedsResponse{} // Create and initialise a data variable as a PostData struct
	StartTaskResponseDataErr := xml.Unmarshal(getFeedsCmdByts, getFeedsResponseData)
	if StartTaskResponseDataErr != nil {
		if getFeedsCmdByts == nil {
			return false
		}
		err := fmt.Errorf("gvm unmarshal error: %v", string(getFeedsCmdByts))
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return false
	}
	for _, feed := range getFeedsResponseData.Feed {
		if feed.CurrentlySyncing.Timestamp == "" {
			continue
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
