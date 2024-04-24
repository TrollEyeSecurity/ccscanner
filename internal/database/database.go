package database

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io"
	"log"
	"os"
	"strconv"
	"time"
)

func GetMongoClient() (*mongo.Client, error) {
	serverAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().
		ApplyURI("mongodb://127.0.0.1:27017").
		SetServerAPIOptions(serverAPIOptions)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	MongoClient, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}
	return MongoClient, nil
}

func GetCurrentTasks() *[]Task {
	var tasks []Task
	MongoClient, MongoClientError := GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("database get-current-tasks error %v", MongoClient)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	RunningTasks, _ := tasksCollection.Find(context.TODO(), bson.M{"status": bson.M{"$ne": "DONE"}})
	cli, NewEnvClientErr := client.NewClientWithOpts()
	defer cli.Close()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("database get-current-tasks error %v", NewEnvClientErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return &tasks
	}
	for RunningTasks.Next(context.TODO()) {
		var task Task
		RunningTasksDecodeErr := RunningTasks.Decode(&task)
		if RunningTasksDecodeErr != nil {
			err := fmt.Errorf("database get-current-tasks error %v", RunningTasksDecodeErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		if task.Status == "PROGRESS" && dontReassign(task.Content.Function) {
			ContainerFilter := filters.NewArgs()
			ContainerFilter.Add("id", task.ContainerId)
			TaskContainer, TaskContainerErr := cli.ContainerList(context.Background(), types.ContainerListOptions{
				All:     true,
				Filters: ContainerFilter,
			})
			if TaskContainerErr != nil {
				err := fmt.Errorf("database get-current-tasks error %v", TaskContainerErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				continue
			}
			if len(TaskContainer) == 0 {
				ReassignTask(tasksCollection, &task)
			} else if TaskContainer[0].State == "exited" {
				info, ContainerInspectErr := cli.ContainerInspect(context.Background(), TaskContainer[0].ID)
				if ContainerInspectErr != nil {
					err := fmt.Errorf("database get-current-tasks error %v", ContainerInspectErr)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
				}
				t, tpError := time.Parse(time.RFC3339Nano, info.State.FinishedAt)
				if tpError != nil {
					err := fmt.Errorf("database get-current-tasks error %v", tpError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
				}
				elapsed := time.Since(t)
				if elapsed.Minutes() > 15 {
					ReassignTask(tasksCollection, &task)
					ContainerRemoveError := cli.ContainerRemove(context.Background(), task.ContainerId, types.ContainerRemoveOptions{})
					if ContainerRemoveError != nil {
						err := fmt.Errorf("database get-current-tasks error %v", ContainerRemoveError)
						if sentry.CurrentHub().Client() != nil {
							sentry.CaptureException(err)
						}
						log.Println(err)
					}
				}
			} else if TaskContainer[0].State == "running" {
				reader, ContainerLogsErr := cli.ContainerLogs(context.Background(), task.ContainerId, types.ContainerLogsOptions{
					ShowStdout: true,
				})
				if ContainerLogsErr != nil {
					err := fmt.Errorf("database get-current-tasks error %v", ContainerLogsErr)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					continue
				}
				byteValue, _ := io.ReadAll(reader)
				reader.Close()
				data := &NmapLogs{}
				xml.Unmarshal(byteValue, data)
				if data.Taskprogress.Percent != "" {
					f, _ := strconv.ParseFloat(data.Taskprogress.Percent, 64)
					var percent = int(f)
					_, updatePError := tasksCollection.UpdateOne(context.TODO(),
						bson.D{{"_id", task.ID}},
						bson.D{{"$set", bson.D{{"percent", percent}}}},
					)
					if updatePError != nil {
						err := fmt.Errorf("database get-current-tasks error %v", updatePError)
						if sentry.CurrentHub().Client() != nil {
							sentry.CaptureException(err)
						}
						log.Println(err)
						continue
					}
					task.Percent = percent
				}
			}
		}
		if task.Status == "SUCCESS" && task.Content.Function == "sast" {
			if task.SastResult.SnykOutput.OpenSourceResultsFile != "bm8gcmVzdWx0cw==" {
				openSourceResults, readOpenSourceResultsFileErr := os.ReadFile(task.SastResult.SnykOutput.OpenSourceResultsFile)
				if readOpenSourceResultsFileErr != nil {
					fmt.Println(readOpenSourceResultsFileErr.Error())
					continue
				}
				jsonOpenSourceResults := OpenSourceResults{}
				_ = json.Unmarshal(openSourceResults, &jsonOpenSourceResults)
				jsonOpenSourceResultsData, jsonOpenSourceResultsDataError := json.Marshal(jsonOpenSourceResults)
				if jsonOpenSourceResultsDataError != nil {
					fmt.Println(jsonOpenSourceResultsDataError.Error())
					continue
				}
				SnykOpenSourceResults := base64.StdEncoding.EncodeToString(jsonOpenSourceResultsData)
				task.SastResult.SnykOutput.OpenSourceResults = SnykOpenSourceResults

			} else {
				task.SastResult.SnykOutput.OpenSourceResults = "bm8gcmVzdWx0cw=="
			}
			if task.SastResult.SnykOutput.CodeResultsFile != "bm8gcmVzdWx0cw==" {
				codeResults, readCodeResultsFileErr := os.ReadFile(task.SastResult.SnykOutput.CodeResultsFile)
				if readCodeResultsFileErr != nil {
					fmt.Println(readCodeResultsFileErr.Error())
					continue
				}
				jsonCodeResultsResults := CodeResults{}
				_ = json.Unmarshal(codeResults, &jsonCodeResultsResults)
				jsonCodeResultsResultsData, jsonCodeResultsResultsDataError := json.Marshal(jsonCodeResultsResults)
				if jsonCodeResultsResultsDataError != nil {
					fmt.Println(jsonCodeResultsResultsDataError.Error())
					continue
				}
				SnykCodeResults := base64.StdEncoding.EncodeToString(jsonCodeResultsResultsData)
				task.SastResult.SnykOutput.CodeResults = SnykCodeResults
			} else {
				task.SastResult.SnykOutput.CodeResults = "bm8gcmVzdWx0cw=="
			}
		}
		tasks = append(tasks, task)
	}
	return &tasks
}

type NmapLogs struct {
	Taskprogress struct {
		Percent string `xml:"percent,attr"`
	} `xml:"taskprogress"`
}

func ReassignTask(tasksCollection *mongo.Collection, task *Task) {
	fmt.Printf("re-assigning task %d\n", &task.TaskId)
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", &task.ID}},
		bson.D{{"$set", bson.D{{"status", "ASSIGNED"}, {"percent", 0}, {"container_id", nil}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("database reassign-tasks error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(updateError)
	}
}

func DeleteTaskById(taskId int64) {
	MongoClient, MongoClientError := GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("database delete-tasks error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(MongoClientError)
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	var task Task
	findErr := tasksCollection.FindOne(context.TODO(), bson.D{{"task_id", &taskId}}).Decode(&task)
	if findErr != nil {
		err := fmt.Errorf("database find task error %v", findErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
	}

	if task.Content.Function == "sast" {
		if task.SastResult.SnykOutput.OpenSourceResultsFile != "bm8gcmVzdWx0cw==" {
			rerr1 := os.Remove(task.SastResult.SnykOutput.OpenSourceResultsFile)
			if rerr1 != nil {
				err1 := fmt.Errorf("database delete-file error %v", rerr1)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err1)
				}
				log.Println(err1)
			}
		}
		if task.SastResult.SnykOutput.CodeResultsFile != "bm8gcmVzdWx0cw==" {
			rerr2 := os.Remove(task.SastResult.SnykOutput.CodeResultsFile)
			if rerr2 != nil {
				err2 := fmt.Errorf("database delete-file error %v", rerr2)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err2)
				}
				log.Println(err2)
			}
		}
	}
	_, updateError := tasksCollection.DeleteOne(context.TODO(),
		bson.D{{"task_id", taskId}},
	)
	if updateError != nil {
		err := fmt.Errorf("database delete-tasks error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(updateError)
	}
}

func UpdateTaskById(taskId int64, status string) {
	MongoClient, MongoClientError := GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("database update-tasks error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(MongoClientError)
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"task_id", taskId}},
		bson.D{{"$set", bson.D{{"status", status}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("database update-tasks error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(updateError)
	}
}

func GetOwaspZapResultById(taskId int64) *[]ZapResults {
	MongoClient, MongoClientError := GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("database update-tasks error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(MongoClientError)
	}
	var task Task
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	tasksCollection.FindOne(context.TODO(), bson.D{{"task_id", taskId}}).Decode(&task)
	return &task.OwaspZapResults
}

func GetTaskStatusByTaskId(taskId int64) (*string, *int) {
	MongoClient, MongoClientError := GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("database update-tasks error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(MongoClientError)
	}
	var task Task
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	tasksCollection.FindOne(context.TODO(), bson.D{{"task_id", taskId}}).Decode(&task)
	return &task.Status, &task.Percent
}

func dontReassign(category string) bool {
	switch category {
	case
		"openvas_vulnerability_scan",
		"dast",
		"get_screen_shot",
		"url_inspection",
		"dns_check":
		return false
	}
	return true
}

func GetCurrentMode() *string {
	errorString := "\n\nHave you linked the scanner to Command Center?"
	MongoClient, MongoClientError := GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("database update-tasks error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(MongoClientError)
	}
	opts := options.Find().SetSort(bson.D{{"_id", -1}}).SetLimit(1)
	systemCollection := MongoClient.Database("core").Collection("system")
	cursor, ConfigurationError := systemCollection.Find(context.TODO(), bson.D{{"_id", "configuration"}}, opts)
	if ConfigurationError != nil {
		fmt.Println(ConfigurationError.Error(), errorString)
		time.Sleep(30 * time.Second)
		fmt.Println(errorString)
		os.Exit(0)
		return &errorString
	}
	var results []bson.M
	cursor.All(context.TODO(), &results)
	if len(results) < 1 {
		fmt.Println(errorString)
		time.Sleep(30 * time.Second)
		log.Println(errorString)
	}
	notmode := results[0]["mode"]
	if notmode != nil {
		mode := results[0]["mode"].(string)
		return &mode
	}
	return &errorString
}
