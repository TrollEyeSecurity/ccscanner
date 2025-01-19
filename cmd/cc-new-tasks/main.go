package main

import (
	"context"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/auth"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/internal/ovpn"
	"github.com/TrollEyeSecurity/ccscanner/internal/phonehome"
	"github.com/TrollEyeSecurity/ccscanner/internal/users"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"log"
	"sync"
	"time"
)

func main() {
	ScannerMain()
}

func ScannerMain() {
	var wg sync.WaitGroup
	errorString := "\n\nHave you linked the scanner to Command Center?"
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("ccscanner mongo-client connect error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var accessToken *string
	tokenExpiresAt := time.Time{}
	var accessTokenErr *error

	for {
		systemCollection := MongoClient.Database("core").Collection("system")
		var configuration database.ConfigFields
		ConfigurationError := systemCollection.FindOne(context.TODO(), bson.D{{"_id", "configuration"}}).Decode(&configuration)
		if ConfigurationError != nil {
			fmt.Println(ConfigurationError.Error(), errorString)
			time.Sleep(30 * time.Second)
			continue
		}
		authUrl := configuration.Auth.AuthUrl
		secret := configuration.Auth.Secret
		clientId := configuration.Auth.ClientId
		baseurl := configuration.BaseURL
		orgId := configuration.OrgId
		scannerGroupId := configuration.ScannerGroupId
		now := time.Now()
		if accessToken == nil || now.After(tokenExpiresAt) {
			accessToken, tokenExpiresAt, accessTokenErr = auth.GetToken(&authUrl, &secret, &clientId)
		}

		if accessTokenErr != nil {
			err := fmt.Errorf("access-token error %v", *accessTokenErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		response, CommunicateError := phonehome.NewTasks(&baseurl, accessToken, scannerGroupId, orgId)
		if CommunicateError != nil {
			err := fmt.Errorf("scanner-main communicate error %v: %v", CommunicateError, response)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			time.Sleep(30 * time.Second)
			continue
		}
		if response == nil {
			time.Sleep(10 * time.Second)
			continue
		}
		newTasks := &response.NewTasks
		allowedUsers := &response.AllowedUsers
		Ovpn := &response.Ovpn
		// todo: add new config items to db like new auth tokens, or new scanner groups
		wg.Add(1)
		go users.ProcessUsers(*allowedUsers, &wg)

		wg.Add(1)
		go ovpn.ProcessOvpnConfig(*Ovpn, &wg)
		tasksCollection := MongoClient.Database("core").Collection("tasks")
		for _, task := range *newTasks {
			_, TasksError := tasksCollection.InsertOne(context.TODO(), bson.D{
				{"name", task.Name},
				{"task_id", task.TaskId},
				{"zone", task.Zone},
				{"status", "ASSIGNED"},
				{"content", task.Content},
				{"secret_data", task.SecretData},
				{"percent", 0},
				{"nmap_results", nil},
				{"openvas_results", nil},
				{"owasp_zap_json_results", nil},
				{"owasp_zap_html_results", nil},
				{"sast_results", nil},
				{"net_recon_results", nil},
				{"container_id", nil},
				{"service_url_data", nil},
				{"name_info", nil},
				{"ssh_port", nil},
				{"web_discovery_results", nil},
				{"screen_shot_results", nil},
			})
			if TasksError != nil {
				err := fmt.Errorf("ccscanner error %v", TasksError)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				time.Sleep(30 * time.Second)
				continue
			}
		}
		time.Sleep(30 * time.Second)
		wg.Wait()
	}
}
