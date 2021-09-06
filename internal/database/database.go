package database

import (
	"context"
	"encoding/xml"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"
)

func StartDatabase() {
	imageName := docker.MongoDbDockerImage
	containerName := "mongoDB"
	config := &container.Config{
		ExposedPorts: nat.PortSet{"27017/tcp": struct{}{}},
		Image:        imageName,
	}
	resources := &container.Resources{
		Memory: 2.048e+9,
	}
	hostConfig := &container.HostConfig{
		PortBindings: nat.PortMap{
			"27017/tcp": []nat.PortBinding{
				{
					HostIP:   "127.0.0.1",
					HostPort: "27017",
				},
			},
		},
		Resources: *resources,
	}
	ctx := context.Background()
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("database new-client error %v", NewEnvClientErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("Start Database Error: %s", err)
	}
	imagePullOptions := &types.ImagePullOptions{}
	out, ImagePullErr := cli.ImagePull(ctx, imageName, *imagePullOptions)
	if ImagePullErr != nil {
		err := fmt.Errorf("database image-pull error %v", ImagePullErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("Start Database Error: %s", err)
	}
	io.Copy(ioutil.Discard, out)
	out.Close()
	_, StartContainerErr := docker.StartContainer(&imageName, &containerName, config, hostConfig)
	if StartContainerErr != nil {
		err := fmt.Errorf("database start-container error %v", StartContainerErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("Start Database Error: %s", err)
	}
	return
}

func GetMongoClient() (*mongo.Client, error) {
	MongoClient, err := mongo.NewClient(options.Client().ApplyURI("mongodb://@127.0.0.1:27017"))
	if err != nil {
		return nil, err
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = MongoClient.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return MongoClient, nil
}

func GetCurrentTasks() *[]Task {
	var tasks []Task
	MongoClient, MongoClientError := GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("database get-current-tasks error %v", MongoClient)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	RunningTasks, _ := tasksCollection.Find(context.TODO(), bson.M{"status": bson.M{"$ne": "DONE"}})
	for RunningTasks.Next(context.TODO()) {
		var task Task
		RunningTasksDecodeErr := RunningTasks.Decode(&task)
		if RunningTasksDecodeErr != nil {
			err := fmt.Errorf("database get-current-tasks error %v", RunningTasksDecodeErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			continue
		}
		cli, NewEnvClientErr := client.NewEnvClient()
		if NewEnvClientErr != nil {
			err := fmt.Errorf("database get-current-tasks error %v", NewEnvClientErr)
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
				cli, NewEnvClientErr := client.NewEnvClient()
				if NewEnvClientErr != nil {
					err := fmt.Errorf("database get-current-tasks error %v", NewEnvClientErr)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					continue
				}
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
				cli.Close()
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
				byteValue, _ := ioutil.ReadAll(reader)
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
		cli.Close()
		tasks = append(tasks, task)
	}
	MongoClient.Disconnect(context.TODO())
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
		log.Fatalf("Update Error: %s", updateError)
	}
}

func DeleteTaskById(taskId int64) {
	MongoClient, MongoClientError := GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("database delete-tasks error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	_, updateError := tasksCollection.DeleteOne(context.TODO(),
		bson.D{{"task_id", taskId}},
	)
	if updateError != nil {
		err := fmt.Errorf("database delete-tasks error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("Update Error: %s", updateError)
	}
	MongoClient.Disconnect(context.TODO())
}

func UpdateTaskById(taskId int64, status string) {
	MongoClient, MongoClientError := GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("database update-tasks error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
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
		log.Fatalf("Update Error: %s", updateError)
	}
	MongoClient.Disconnect(context.TODO())
}

func dontReassign(category string) bool {
	switch category {
	case
		"get_screen_shot",
		"url_inspection":
		return false
	}
	return true
}

func GetCurrentMode() *string {
	errorString := "\n\nHave you linked the scanner to Command Center?"
	MongoClient, MongoClientError := GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("database update-tasks error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
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
		log.Fatalf("Configuraton Error: %s", errorString)
	}
	notmode := results[0]["mode"]
	if notmode != nil {
		mode := results[0]["mode"].(string)
		return &mode
	}
	log.Fatalf("Configuraton Error: %s", errorString)
	return &errorString
}
