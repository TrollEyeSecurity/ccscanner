package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/common"
	"github.com/TrollEyeSecurity/ccscanner/internal/config"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
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
		scannerCli(dastConfig, dastRootUrl, maxChildren, urlList)
		return
	}
}

func scannerCli(dastConfigPath *string, dastRootUrl *string, maxChildren *int, urlList *string) {
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
	taskId := string(time.Now().Unix())
	content := database.TaskContent{
		DastConfig: *dastConfig,
		Function:   "dast",
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

	results := database.GetOwaspZapResultById(taskId)
	fmt.Println("")
	fmt.Println(*results)

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
