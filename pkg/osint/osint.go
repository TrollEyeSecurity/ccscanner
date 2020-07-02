package osint

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/CriticalSecurity/ccscanner/internal/database"
	"github.com/CriticalSecurity/ccscanner/pkg/otx"
	"github.com/CriticalSecurity/ccscanner/pkg/shodan"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io/ioutil"
	"log"
	"strings"
)

func Discovery(hosts *string, taskId *primitive.ObjectID, shodanKey *string, otxKey *string) {
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("osint error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	_, update1Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"status", "PROGRESS"}}}},
	)
	if update1Error != nil {
		err := fmt.Errorf("osint error %v", update1Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var output []database.OsintResults
	for _, host := range strings.Split(*hosts, " ") {
		var results database.OsintResults
		shodanResp, _ := shodan.LoopkupIp(&host, shodanKey)
		shodanRespBody, _ := ioutil.ReadAll(shodanResp.Body)
		shodanData := base64.StdEncoding.EncodeToString(shodanRespBody)
		otxResp, _ := otx.GetIpReputation(&host, otxKey)
		otxRespBody, _ := ioutil.ReadAll(otxResp.Body)
		otxData := base64.StdEncoding.EncodeToString(otxRespBody)
		results.ShodanData = shodanData
		results.Reputation = otxData
		results.Host = host
		output = append(output, results)
		shodanResp.Body.Close()
		otxResp.Body.Close()
	}
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"osint_result", output},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	if update2Error != nil {
		err := fmt.Errorf("osint error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	MongoClient.Disconnect(context.TODO())
}
