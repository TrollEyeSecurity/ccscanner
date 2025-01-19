package main

import (
	"context"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/auth"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/internal/phonehome"
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
		response, doneTasks, communicateError := phonehome.CompletedTasks(&baseurl, accessToken, scannerGroupId, orgId)
		if communicateError != nil {
			err := fmt.Errorf("scanner-main communicate error %v: %v", communicateError, response)
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
		if response.Results == "DONE" {
			for _, task := range *doneTasks {
				wg.Add(1)
				go database.DeleteTaskById(task, &wg)
			}
		}
		time.Sleep(45 * time.Second)
		wg.Wait()
	}
}
