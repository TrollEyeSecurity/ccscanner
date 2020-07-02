package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/CriticalSecurity/ccscanner/internal/config"
	"github.com/CriticalSecurity/ccscanner/internal/database"
	"github.com/CriticalSecurity/ccscanner/pkg/dns"
	"github.com/CriticalSecurity/ccscanner/pkg/nmap"
	"github.com/CriticalSecurity/ccscanner/pkg/openvas"
	"github.com/CriticalSecurity/ccscanner/pkg/osint"
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
	TaskManagerMain()
}

func TaskManagerMain() {
	errorString := "\n\nHave you linked the scanner to Command Center yet?"
	MongoClient, MongoClientError := database.GetMongoClient()
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
	cursor.All(context.TODO(), &results)
	if len(results) < 1 {
		fmt.Println(errorString)
		return
	}
	for {
		NewlyAssignedTasks, _ := tasksCollection.Find(context.TODO(), bson.D{{"status", "ASSIGNED"}})
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
			case task.Content.Function == "dns_check":
				go dns.AnalyzeDomainNames(&task.Content.Args.Dns, &task.ID)
				break
			case task.Content.Function == "osint_discovery":
				osint.Discovery(&task.Content.Args.Hosts, &task.ID, &task.SecretData.Osint.Shodan, &task.SecretData.Osint.Otx)
				break
			case task.Content.Function == "nmap_host_discovery":
				go nmap.Scan(&task.Content.Args.NmapParams, &task.Content.Args.Hosts, &task.ID, &task.SecretData.Osint.Shodan)
				break
			case task.Content.Function == "openvas_vulnerability_scan":
				go openvas.VulnerabilityScan(&task.Content.Args.Hosts, &task.Content.Args.Excludes, &task.ID, &task.Content.Args.Configuration, &task.Content.Args.DisabledNvts)
				break
			case task.Content.Function == "nmap_port_scan":
				go nmap.Scan(&task.Content.Args.NmapParams, &task.Content.Args.Hosts, &task.ID, &task.SecretData.Osint.Shodan)
				break
			}
		}
		time.Sleep(15 * time.Second)
	}
}
