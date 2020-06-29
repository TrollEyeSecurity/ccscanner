package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/CriticalSecurity/cc-scanner/internal/config"
	"github.com/CriticalSecurity/cc-scanner/internal/database"
	"github.com/CriticalSecurity/cc-scanner/internal/errors"
	"github.com/CriticalSecurity/cc-scanner/internal/phonehome"
	"github.com/CriticalSecurity/cc-scanner/pkg/openvas"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
	"time"
)

func main() {
	configFile := flag.String("config", "", "Enter the path to the config file.")
	flag.Parse()
	os.Setenv("CONFIGFILE", *configFile)
	appConfiguration := config.LoadConfiguration(*configFile)
	if appConfiguration.SentryIoDsn != "" {
		err := sentry.Init(sentry.ClientOptions{
			Dsn: appConfiguration.SentryIoDsn,
		})
		if err != nil {
			log.Fatalf("sentry.Init: %s", err)
		}
		defer sentry.Flush(2 * time.Second)
	}
	database.StartDatabase()
	ScannerMain()
}

func ScannerMain()  {
	errorString := "\n\nHave you linked the scanner to Command Center yet?"
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		errors.HandleError(MongoClientError, "ScannerMain MongoClient Error")
		return
	}
	for {
		opts := options.Find().SetSort(bson.D{{"_id", -1}}).SetLimit(1)
		systemCollection := MongoClient.Database("core").Collection("system")
		cursor, ConfigurationError := systemCollection.Find(context.TODO(), bson.D{{"_id", "configuration"}}, opts)
		if ConfigurationError != nil {
			fmt.Println(ConfigurationError.Error(), errorString)
			time.Sleep(30 * time.Second)
			continue
		}
		var results []bson.M
		cursor.All(context.TODO(), &results)
		if len(results) < 1 {
			fmt.Println(errorString)
			time.Sleep(30 * time.Second)
			continue
		}
		response, CommunicateError := phonehome.Communicate(results[0]["baseurl"].(string), results[0]["token"].(string))
		if CommunicateError != nil {
			err := fmt.Errorf("scanner-main communicate error %v: %v", CommunicateError, response)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			time.Sleep(30 * time.Second)
			continue
		}
		taskResults := &response.Results
		newTasks := &response.NewTasks
		tasksCollection := MongoClient.Database("core").Collection("tasks")
		for _, taskResult := range *taskResults {
			if taskResult.Result == "DONE" {
				go database.DeleteTaskById(taskResult.TaskId)
			} else if taskResult.Result == "STOP_SCAN" {
				go openvas.StopVulnerabilityScan(taskResult.TaskId)
			} else {
				go database.UpdateTaskById(taskResult.TaskId, taskResult.Result)
			}
		}
		for _, task := range *newTasks {
			_, TasksError := tasksCollection.InsertOne(context.TODO(), bson.D{
				{"name", task.Name},
				{"task_id", task.TaskId},
				{"status", "ASSIGNED"},
				{"content", task.Content},
				{"secret_data", task.SecretData},
				{"percent", 0},
				{"nmap_result", nil},
				{"openvas_result", nil},
				{"openvas_result", nil},
				{"dns_result", nil},
				{"osint_result", nil},
				{"container_id", nil},
				{"service_screen_shot_data", nil},
				{"name_info", nil},
				{"ssh_port", nil},
			})
			if TasksError != nil {
				errors.HandleError(TasksError, "Tasks Error")
				time.Sleep(30 * time.Second)
				continue
			}
		}
		time.Sleep(30 * time.Second)
	}
}