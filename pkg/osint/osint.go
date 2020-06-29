package osint

import (
	"context"
	"encoding/base64"
	"github.com/CriticalSecurity/cc-scanner/internal/database"
	"github.com/CriticalSecurity/cc-scanner/internal/errors"
	"github.com/CriticalSecurity/cc-scanner/pkg/otx"
	"github.com/CriticalSecurity/cc-scanner/pkg/shodan"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io/ioutil"
	"log"
	"strings"
)

func Discovery(hosts *string,taskId *primitive.ObjectID, shodanKey *string, otxKey *string){
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		errors.HandleError(MongoClientError, "Osint Discovery MongoClient Error")
		log.Fatalf("MongoClient Error: %s", MongoClientError)
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	_, update1Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"status", "PROGRESS"}}}},
	)
	if update1Error != nil {
		errors.HandleError(update1Error, "Osint Discovery update1 Error")
		return
	}
	var output []database.OsintResults
	for _, host := range strings.Split(*hosts," ") {
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
			{"osint_result",output},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	if update2Error != nil {
		errors.HandleError(update2Error, "Osint Discovery update2 Error")
		return
	}
	MongoClient.Disconnect(context.TODO())
}