package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/config"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/gvm"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
	"sync"
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
	TaskManagerMain()
}

func TaskManagerMain() {
	var wg sync.WaitGroup
	sleepTime := 10 * time.Second
	errorString := "\n\nHave you linked the scanner to Command Center yet?"
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("taskmanager error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	systemCollection := MongoClient.Database("core").Collection("system")
	cursor, ConfigurationError := systemCollection.Find(context.TODO(), bson.D{{"_id", "configuration"}}, options.Find().SetSort(bson.D{{"_id", -1}}).SetLimit(1))
	if ConfigurationError != nil {
		fmt.Println(ConfigurationError.Error(), errorString)
		return
	}
	var results []bson.M
	cursorError := cursor.All(context.TODO(), &results)
	if cursorError != nil {
		err := fmt.Errorf("taskmanager cursor error %v", cursorError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	if len(results) < 1 {
		fmt.Println(errorString)
		return
	}

	assignedQuery := bson.D{
		{"status", "ASSIGNED"},
		{"content.function", bson.D{
			{"$in",
				bson.A{
					"openvas_vulnerability_scan",
				},
			},
		}},
	}

	progressingQuery := bson.D{
		{"status", "PROGRESS"},
		{"content.function", bson.D{
			{"$in",
				bson.A{
					"openvas_vulnerability_scan",
				},
			},
		}},
	}

	for {
		NewlyAssignedTasks, NewlyAssignedTasksFindError := tasksCollection.Find(context.TODO(), assignedQuery)
		ProgressingTasks, ProgressingTasksFindError := tasksCollection.Find(context.TODO(), progressingQuery)
		if NewlyAssignedTasksFindError != nil {
			err := fmt.Errorf("taskmanager find error %v", NewlyAssignedTasksFindError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		if ProgressingTasksFindError != nil {
			err := fmt.Errorf("taskmanager find error %v", ProgressingTasksFindError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		for NewlyAssignedTasks.Next(context.TODO()) {
			var task database.Task
			NewlyAssignedTasksErr := NewlyAssignedTasks.Decode(&task)
			if NewlyAssignedTasksErr != nil {
				err := fmt.Errorf("taskmanager error %v", NewlyAssignedTasksErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				continue
			}
			switch {
			case task.Content.Function == "openvas_vulnerability_scan":
				wg.Add(1)
				go gvm.StartVulnerabilityScan(&task.Content.Args.Hosts, &task.Content.Args.Excludes, &task.ID, &task.Content.Args.Configuration, &task.Content.Args.DisabledNvts, &wg)
				break
			}
		}
		for ProgressingTasks.Next(context.TODO()) {
			var task database.Task
			ProgressingTasksErr := ProgressingTasks.Decode(&task)
			if ProgressingTasksErr != nil {
				err := fmt.Errorf("taskmanager error %v", ProgressingTasksErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				continue
			}
			switch {
			case task.Content.Function == "openvas_vulnerability_scan":
				wg.Add(1)
				go gvm.CheckVulnerabilityScan(&task.ID, &wg)
				break
			}
		}
		wg.Wait()
		time.Sleep(sleepTime)
	}
}
