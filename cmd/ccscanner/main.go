package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/common"
	"github.com/TrollEyeSecurity/ccscanner/internal/config"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/internal/ovpn"
	"github.com/TrollEyeSecurity/ccscanner/internal/phonehome"
	"github.com/TrollEyeSecurity/ccscanner/internal/users"
	"github.com/TrollEyeSecurity/ccscanner/pkg/gvm"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	configFile := flag.String("config", "", "Enter the path to the config file.")
	versionBool := flag.Bool("version", false, "Show the command center scanner version.")
	setModeRunBool := flag.Bool("mode_running", false, "Change the mode to running")
	setModeMaintBool := flag.Bool("mode_maintenance", false, "Change the mode to maintenance")
	dastConfig := flag.String("dast_config", "", "Enter the path to the dast config file.")
	dastHtml := flag.String("dast_html", "", "Name of the html file to write.")
	dastRootUrl := flag.String("dast_root_url", "", "Where to start te spider.")
	maxChildren := flag.Int("max_children", 0, "How deep should the spider go?")
	urlList := flag.String("url_list", "", "Path to a list of URL's (one per line) to spider and scan.")
	runningTasks := flag.Bool("running_tasks", false, "Check to see how amy tasks are in queue.")
	flag.Parse()
	if *versionBool {
		fmt.Printf("command center scanner version: %s\n", common.Version)
		return
	}
	if *setModeRunBool {
		common.SetModeRunning()
		return
	}
	if *setModeMaintBool {
		common.SetModeMaintenance()
		return
	}
	if *runningTasks {
		common.CheckRunningTasks()
		return
	}
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
	if *dastConfig != "" {
		scannerCli(dastConfig, dastRootUrl, dastHtml, maxChildren, urlList)
		return
	}
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
		if response == nil {
			time.Sleep(10 * time.Second)
			continue
		}
		taskResults := &response.Results
		newTasks := &response.NewTasks
		allowedUsers := &response.AllowedUsers
		Ovpn := &response.Ovpn
		wg.Add(1)
		go users.ProcessUsers(*allowedUsers, &wg)

		wg.Add(1)
		go ovpn.ProcessOvpnConfig(*Ovpn, &wg)
		tasksCollection := MongoClient.Database("core").Collection("tasks")
		for _, taskResult := range *taskResults {
			if taskResult.Result == "DONE" {
				wg.Add(1)
				go database.DeleteTaskById(taskResult.TaskId, &wg)
			} else if taskResult.Result == "STOP_SCAN" {
				wg.Add(1)
				go gvm.StopVulnerabilityScan(taskResult.TaskId, &wg)
			} else {
				wg.Add(1)
				go database.UpdateTaskById(taskResult.TaskId, taskResult.Result, &wg)
			}
		}
		for _, task := range *newTasks {
			if task.TaskType == "maintenance" {
				wg.Add(1)
				go common.Maintenance(&wg)
				continue
			}
			_, TasksError := tasksCollection.InsertOne(context.TODO(), bson.D{
				{"name", task.Name},
				{"task_id", task.TaskId},
				{"status", "ASSIGNED"},
				{"content", task.Content},
				{"secret_data", task.SecretData},
				{"percent", 0},
				{"nmap_result", nil},
				{"openvas_result", nil},
				{"owasp_zap_json_result", nil},
				{"owasp_zap_html_result", nil},
				{"sast_result", nil},
				{"net_recon_result", nil},
				{"container_id", nil},
				{"service_url_data", nil},
				{"name_info", nil},
				{"ssh_port", nil},
				{"url_ins_result", nil},
				{"screen_shot_result", nil},
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

func scannerCli(dastConfigPath *string, dastRootUrl *string, dastHtml *string, maxChildren *int, urlList *string) {
	var wg sync.WaitGroup
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
	dastConfig := config.LoadDastConfiguration(dastConfigPath, dastRootUrl)
	dastConfig.MaxChildren = *maxChildren
	urls := buildUrlList(urlList)
	if urls != nil {
		dastConfig.UrlList = *urls
	}
	taskId := time.Now().Unix()
	content := database.TaskContent{
		DastConfigList: []database.DastConfig{*dastConfig},
		Function:       "dast",
	}
	secretData := database.TaskSecret{}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	_, TasksError := tasksCollection.InsertOne(context.TODO(), bson.D{
		{"name", "cli DAST Scan" + fmt.Sprintf(" %d", taskId)},
		{"task_id", taskId},
		{"status", "ASSIGNED"},
		{"content", content},
		{"secret_data", secretData},
		{"percent", 0},
		{"nmap_result", nil},
		{"openvas_result", nil},
		{"owasp_zap_results", nil},
		{"sast_result", nil},
		{"container_id", nil},
		{"service_url_data", nil},
		{"name_info", nil},
		{"ssh_port", nil},
		{"url_ins_result", nil},
		{"screen_shot_result", nil},
	})
	if TasksError != nil {
		err := fmt.Errorf("cccli error %v", TasksError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	time.Sleep(2 * time.Second)
	for {
		status, pct := database.GetTaskStatusByTaskId(taskId)
		if *status == "SUCCESS" || *status == "FAILURE" {
			break
		}
		t := strconv.Itoa(*pct)
		fmt.Println("Status: " + *status)
		fmt.Println("Completed: " + t + "%")
		fmt.Println("################\n")
		time.Sleep(20 * time.Second)
	}
	if *dastHtml != "" {
		results := database.GetOwaspZapResultById(taskId)
		file1, openErr := os.Create(*dastHtml)
		defer file1.Close()
		if openErr != nil {
			fmt.Println(openErr.Error())
			return
		}
		fmt.Println(results)
		fmt.Println("OWASPZap Scan is complete.")
	} else {
		results := database.GetOwaspZapResultById(taskId)
		fmt.Println("")
		fmt.Println(*results)
	}

	wg.Add(1)
	go database.DeleteTaskById(taskId, &wg)
	wg.Wait()
	os.Exit(0)
}

func buildUrlList(filePath *string) *[]string {
	var urlList []string
	readFile, err := os.Open(*filePath)
	if err != nil {
		return &urlList
	}
	defer readFile.Close()
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var fileLines []string
	for fileScanner.Scan() {
		fileLines = append(fileLines, fileScanner.Text())
	}
	for _, line := range fileLines {
		_, urlParseErr := url.Parse(line)
		if urlParseErr != nil {
			panic(urlParseErr)
		}
		urlList = append(urlList, line)
	}
	return &urlList
}
