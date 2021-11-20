package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/internal/phonehome"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
)

func main() {
	baseUrl := flag.String("url", "", "Enter the base url for your instance of Command Center.")
	linkingToken := flag.String("token", "", "The linking token can be found in the Scanner Group you are trying to join.")
	flag.Parse()
	database.StartDatabase()
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("link error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
	}
	opts := options.Find().SetSort(bson.D{{"_id", -1}}).SetLimit(1)
	systemCollection := MongoClient.Database("core").Collection("system")
	cursor, _ := systemCollection.Find(context.TODO(), bson.D{{"_id", "configuration"}}, opts)
	var results []bson.M
	cursor.All(context.TODO(), &results)
	if len(results) > 0 {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("It appears that you have already linked to Command Center.\n")
		for {
			fmt.Println("Would you like to re-link, (Y/N)?")
			char, err := reader.ReadByte()
			if err != nil {
				fmt.Println(err)
			}
			if string(char) == "Y" {
				fmt.Println("Continuing on to re-link to Command Center.\n")
				break
			} else if string(char) == "N" {
				fmt.Println("Good by.")
				return
			}
		}
	}
	lr, lrError := phonehome.Link(*baseUrl, *linkingToken)
	if lrError != nil {
		err := fmt.Errorf("link error %v", lrError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("Link Error: %s", lrError)
	}
	if len(results) > 0 {
		_, ConfigurationError := systemCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", "configuration"}},
			bson.D{{"$set", bson.D{{"_id", "configuration"}, {"baseurl", *baseUrl}, {"token", &lr.Token}, {"shodan", &lr.Shodan}, {"mode", "running"}}}},
		)
		if ConfigurationError != nil {
			err := fmt.Errorf("link error %v", ConfigurationError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Fatalf("Configuration Error: %s", ConfigurationError)
		}

	} else {
		_, ConfigurationError := systemCollection.InsertOne(context.TODO(), bson.D{
			{"_id", "configuration"},
			{"baseurl", *baseUrl},
			{"token", &lr.Token},
			{"mode", "running"}},
		)
		if ConfigurationError != nil {
			err := fmt.Errorf("link error %v", ConfigurationError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Fatalf("Configuration Error: %s", ConfigurationError)
		}
	}
	fmt.Println("\nLink to Command Center was successful.\n")
}
