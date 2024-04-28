package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/config"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/fortinet"
	"github.com/TrollEyeSecurity/ccscanner/pkg/gvm"
	"github.com/TrollEyeSecurity/ccscanner/pkg/netrecon"
	"github.com/TrollEyeSecurity/ccscanner/pkg/nmap"
	"github.com/TrollEyeSecurity/ccscanner/pkg/owaspzap"
	"github.com/TrollEyeSecurity/ccscanner/pkg/screenshots"
	"github.com/TrollEyeSecurity/ccscanner/pkg/snyk"
	"github.com/TrollEyeSecurity/ccscanner/pkg/urlinspection"
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
	for {
		NewlyAssignedTasks, NewlyAssignedTasksFindError := tasksCollection.Find(context.TODO(), bson.D{{"status", "ASSIGNED"}})
		ProgressingTasks, ProgressingTasksFindError := tasksCollection.Find(context.TODO(), bson.D{{"status", "PROGRESS"}})
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
			case task.Content.Function == "infrastructure_discovery" && task.Content.Ssh == true:
				wg.Add(1)
				go netrecon.Recon(&task.Content, &task.SecretData, &task.ID, &wg)
				break

			case task.Content.Function == "infrastructure_discovery" && task.Content.Api == true && task.Content.IntegrationType == "fortios":
				wg.Add(1)
				go fortinet.Discovery(&task.Content, &task.SecretData, &task.ID, &wg)
				break
			case task.Content.Function == "sast":
				wg.Add(1)
				go snyk.Scan(&task.Content, &task.SecretData, &task.ID, &wg)
				break
			case task.Content.Function == "dast":
				wg.Add(1)
				go owaspzap.Scan(task.Content.DastConfigList, &task.ID, &wg)
				break
			case task.Content.Function == "get_screen_shot":
				wg.Add(1)
				go screenshots.RunScreenShotTask(&task.Content.Args.Urls, &task.ID, &wg)
				break
			case task.Content.Function == "url_inspection":
				wg.Add(1)
				go urlinspection.RunInspection(&task.Content.Args.Urls, &task.ID, &wg)
				break
			case task.Content.Function == "nmap_host_discovery":
				wg.Add(1)
				go nmap.Scan(&task.Content.Args.NmapParams, &task.Content.Args.Hosts, &task.Content.Args.Excludes, &task.ID, &wg)
				break
			case task.Content.Function == "openvas_vulnerability_scan":
				wg.Add(1)
				go gvm.StartVulnerabilityScan(&task.Content.Args.Hosts, &task.Content.Args.Excludes, &task.ID, &task.Content.Args.Configuration, &task.Content.Args.DisabledNvts, &wg)
				break
			case task.Content.Function == "nmap_port_scan":
				wg.Add(1)
				go nmap.Scan(&task.Content.Args.NmapParams, &task.Content.Args.Hosts, &task.Content.Args.Excludes, &task.ID, &wg)
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
		time.Sleep(15 * time.Second)
		wg.Wait()
	}
}
