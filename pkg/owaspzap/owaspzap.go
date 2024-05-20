package owaspzap

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/docker"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func Scan(dastConfigList []database.DastConfig, taskId *primitive.ObjectID, wg *sync.WaitGroup) {
	defer wg.Done()
	defer time.Sleep(time.Millisecond * 4)
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("zap mongo-client error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var idArray []string
	cli, NewEnvClientErr := client.NewClientWithOpts()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("zap scan error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	var reports []map[string]interface{}
	var proxyPort string
	attempts := 0
	for {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		minPort := 8080
		maxPort := 8090
		proxyPort = strconv.Itoa(r.Intn(maxPort-minPort+1) + minPort)
		listenPort, listenPortErr := net.Listen("tcp", ":"+proxyPort)
		if listenPortErr != nil {
			attempts++
			if attempts > 9 {
				err := fmt.Errorf("owaspzap listen-port error %v: %v", listenPortErr, "ZapScan listenPortErr - Cannot find an open port for the proxy")
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				cli.Close()
				return
			}
		}
		if listenPort != nil {
			listenPort.Close()
			break
		}
		time.Sleep(3 * time.Second)
	}
	dt := time.Now().Unix()
	containerName := fmt.Sprintf("%d", dt)
	ZapContainerId, StartZapErr := StartZap(taskId, &containerName, &proxyPort)
	if StartZapErr != nil {
		err := fmt.Errorf("zap start-zap error %v: %v", StartZapErr, ZapContainerId)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		_, updateError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"container_id", nil}, {"status", "FAILURE"}}}},
		)
		if updateError != nil {
			err1 := fmt.Errorf("zap mongo-update error %v", updateError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err1)
			}
			log.Println(err1)
			cli.Close()
			return
		}
		cli.Close()
		return
	}
	idArray = append(idArray, *ZapContainerId)
	totalNumberOfApps := len(dastConfigList)
	numberOfAppsComplete := 0
	for _, dastConfig := range dastConfigList {
		var contextConfiguration ContextConfiguration
		t := time.Now().Unix()
		contextName := fmt.Sprintf("%d", t)
		if dastConfig.WebappZapContext != "" {
			xml.Unmarshal([]byte(dastConfig.WebappZapContext), &contextConfiguration)
		} else {
			var urlRegexList []string
			var techIncludes []string
			for _, x := range strings.Split(dastConfig.WebappUrlregex, ",") {
				urlRegexList = append(urlRegexList, x)
			}
			contextConfiguration.Context.Name = dastConfig.WebappName
			contextConfiguration.Context.Incregexes = urlRegexList
			if dastConfig.WebappApache {
				techIncludes = append(techIncludes, "")
			}
			if dastConfig.WebappCouchdb {
				techIncludes = append(techIncludes, "Db.CouchDB")
			}
			if dastConfig.WebappFirebird {
				techIncludes = append(techIncludes, "Db.Firebird")
			}
			if dastConfig.WebappHypersonicsql {
				techIncludes = append(techIncludes, "Db.HypersonicSQL")
			}
			if dastConfig.WebappDb2 {
				techIncludes = append(techIncludes, "Db.IBM DB2")
			}
			if dastConfig.WebappAccess {
				techIncludes = append(techIncludes, "Db.Microsoft Access")
			}
			if dastConfig.WebappMssql {
				techIncludes = append(techIncludes, "Db.Microsoft SQL Server")
			}
			if dastConfig.WebappMongodb {
				techIncludes = append(techIncludes, "Db.MongoDB")
			}
			if dastConfig.WebappMysql {
				techIncludes = append(techIncludes, "Db.MySQL")
			}
			if dastConfig.WebappOracle {
				techIncludes = append(techIncludes, "Db.Oracle")
			}
			if dastConfig.WebappPostgresql {
				techIncludes = append(techIncludes, "Db.PostgreSQL")
			}
			if dastConfig.WebappMaxdb {
				techIncludes = append(techIncludes, "Db.SAP MaxDB")
			}
			if dastConfig.WebappSqlite {
				techIncludes = append(techIncludes, "Db.SQLite")
			}
			if dastConfig.WebappSybase {
				techIncludes = append(techIncludes, "Db.Sybase")
			}
			if dastConfig.WebappAsp {
				techIncludes = append(techIncludes, "Language.ASP")
			}
			if dastConfig.WebappC {
				techIncludes = append(techIncludes, "Language.C")
			}
			if dastConfig.WebappJsp {
				techIncludes = append(techIncludes, "Language.JSP/Servlet")
			}
			if dastConfig.WebappJava {
				techIncludes = append(techIncludes, "Language.Java")
			}
			if dastConfig.WebappJavaSpring {
				techIncludes = append(techIncludes, "Language.Java.Spring")
			}
			if dastConfig.WebappJavascript {
				techIncludes = append(techIncludes, "Language.JavaScript")
			}
			if dastConfig.WebappPhp {
				techIncludes = append(techIncludes, "Language.PHP")
			}
			if dastConfig.WebappPython {
				techIncludes = append(techIncludes, "Language.Python")
			}
			if dastConfig.WebappRuby {
				techIncludes = append(techIncludes, "Language.Ruby")
			}
			if dastConfig.WebappXML {
				techIncludes = append(techIncludes, "Language.XML")
			}
			if dastConfig.WebappLinux {
				techIncludes = append(techIncludes, "OS.Linux")
			}
			if dastConfig.WebappMacos {
				techIncludes = append(techIncludes, "OS.MacOS")
			}
			if dastConfig.WebappWindows {
				techIncludes = append(techIncludes, "OS.Windows")
			}
			if dastConfig.WebappGit {
				techIncludes = append(techIncludes, "SCM.Git")
			}
			if dastConfig.WebappSvn {
				techIncludes = append(techIncludes, "SCM.SVN")
			}
			if dastConfig.WebappPython {
				techIncludes = append(techIncludes, "WS.Apache")
			}
			if dastConfig.WebappPython {
				techIncludes = append(techIncludes, "WS.IIS")
			}
			if dastConfig.WebappPython {
				techIncludes = append(techIncludes, "WS.Tomcat")
			}
			if dastConfig.WebappNginx {
				techIncludes = append(techIncludes, "WS.Nginx")
			}
			contextConfiguration.Context.Inscope = "true"
			contextConfiguration.Context.Tech.Include = techIncludes
		}

		_, updateError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"container_id", ZapContainerId}, {"status", "PROGRESS"}}}})
		if updateError != nil {
			err := fmt.Errorf("zap scan error %v", updateError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		time.Sleep(15 * time.Second)
		for {
			waitForHealthy, containerInspectErr := cli.ContainerInspect(context.TODO(), *ZapContainerId)
			if containerInspectErr != nil {
				log.Println(containerInspectErr)
				continue
			}
			if waitForHealthy.State.Health.Status == "healthy" {
				break
			}
			time.Sleep(15 * time.Second)
		}
		contextId, newContextErr := newContext(&proxyPort, &contextName)
		if newContextErr != nil {
			err := fmt.Errorf("zap new-context error %v", newContextErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		if contextId == nil {
			err := fmt.Errorf("zap context-id error %v", contextName)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		var baseUrlList []string
		if dastConfig.UrlList != nil {
			for _, dastUrl := range dastConfig.UrlList {
				u, urlParsErr := url.Parse(dastUrl)
				if urlParsErr != nil {
					continue
				}
				s := u.Scheme + "://" + u.Host
				urlRegex := fmt.Sprintf("%s.*", s)
				baseUrlList = append(baseUrlList, urlRegex)
			}
		}
		uniqueBaseUrlList := uniqueSlice(baseUrlList)
		if uniqueBaseUrlList != nil {
			for _, dastUrl := range uniqueBaseUrlList {
				u, urlParsErr := url.Parse(dastUrl)
				if urlParsErr != nil {
					continue
				}
				s := u.Scheme + "://" + u.Host
				urlRegex := fmt.Sprintf("%s.*", s)
				_, err := includeInContext(&proxyPort, &contextName, &urlRegex)
				if err != nil {
					errLogg := fmt.Errorf("zap urlRegex error %v", urlRegex)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(errLogg)
					}
					log.Println(errLogg)
					continue
				}
			}
		} else {
			for _, urlRegex := range contextConfiguration.Context.Incregexes {
				_, err := includeInContext(&proxyPort, &contextName, &urlRegex)
				if err != nil {
					errLogg := fmt.Errorf("zap urlRegex error %v", urlRegex)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(errLogg)
					}
					log.Println(errLogg)
					continue
				}
			}
		}
		_, setInScopeErr := setInScope(&proxyPort, &contextName, &contextConfiguration.Context.Inscope)
		if setInScopeErr != nil {
			errLogg := fmt.Errorf("zap setInScope error %v", setInScopeErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(errLogg)
			}
			log.Println(errLogg)
			continue
		}

		if len(contextConfiguration.Context.Users) < 0 {
			formBasedAuthentication := "formBasedAuthentication"
			_, setAuthenticationMethodErr := setAuthenticationMethod(&proxyPort, contextId, &formBasedAuthentication, &contextConfiguration.Context.Authentication.Form.Loginurl, &contextConfiguration.Context.Authentication.Form.Loginbody)
			if setAuthenticationMethodErr != nil {
				errLogg := fmt.Errorf("zap setAuthenticationMethodErr error %v", setAuthenticationMethodErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errLogg)
				}
				log.Println(errLogg)
				continue
			}
			_, setLoggedInIndicatorErr := setLoggedInIndicator(&proxyPort, contextId, &contextConfiguration.Context.Authentication.Loggedin)
			if setLoggedInIndicatorErr != nil {
				errLogg := fmt.Errorf("zap setLoggedInIndicatorErr error %v", setLoggedInIndicatorErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errLogg)
				}
				log.Println(errLogg)
				continue
			}
			for _, user := range contextConfiguration.Context.Users {
				s := strings.Split(user.User, ";")
				up := strings.Split(s[4], "~")
				userName := up[0]
				userPass := up[1]
				userNameDecodedText, _ := base64.StdEncoding.DecodeString(userName)
				userPassDecodedText, _ := base64.StdEncoding.DecodeString(userPass)
				uns := string(userNameDecodedText)
				newUserId, newUserErr := newUser(&proxyPort, contextId, &uns)
				if newUserErr != nil {
					errLogg := fmt.Errorf("zap newUserErr error %v", newUserErr)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(errLogg)
					}
					log.Println(errLogg)
					continue
				}
				authCredentialsConfigParams := "username=" + string(userNameDecodedText) + "&password=" + string(userPassDecodedText)
				_, setAuthenticationCredentialsErr := setAuthenticationCredentials(&proxyPort, contextId, newUserId, &authCredentialsConfigParams)
				if setAuthenticationCredentialsErr != nil {
					errLogg := fmt.Errorf("zap setAuthenticationCredentials error %v", setAuthenticationCredentialsErr)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(errLogg)
					}
					log.Println(errLogg)
					continue
				}
				enabled := "true"
				_, setUserEnabledErr := setUserEnabled(&proxyPort, contextId, newUserId, &enabled)
				if setUserEnabledErr != nil {
					errLogg := fmt.Errorf("zap setUserEnabled error %v", setUserEnabledErr)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(errLogg)
					}
					log.Println(errLogg)
					continue
				}
			}
		}

		var spiderSIds []string
		activeScanPct := 0
		spiderScanPct := 0
		if dastConfig.MaxChildren == 0 {
			dastConfig.MaxChildren = 10
		}
		if dastConfig.UrlList != nil {
			uniqueUrlList := uniqueSlice(dastConfig.UrlList)
			for _, v := range uniqueUrlList {
				spiderSId, spiderScanErr := spiderScan(&proxyPort, &contextName, &v, &dastConfig.MaxChildren)
				if spiderScanErr != nil {
					errLogg := fmt.Errorf("zap spiderScanErr error %v", spiderScanErr)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(errLogg)
					}
					log.Println(errLogg)
					continue
				}
				spiderSIds = append(spiderSIds, *spiderSId)
			}
		} else {
			rootUrl := dastConfig.WebappRooturl
			spiderSId, spiderScanErr := spiderScan(&proxyPort, &contextName, &rootUrl, &dastConfig.MaxChildren)
			if spiderScanErr != nil {
				errLogg := fmt.Errorf("zap spiderScanErr error %v", spiderScanErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errLogg)
				}
				log.Println(errLogg)
				continue
			}
			spiderSIds = append(spiderSIds, *spiderSId)
		}
		time.Sleep(1 * time.Second)
		checkSpiderScans(&spiderSIds, &proxyPort)
		spiderScanPct = 100
		time.Sleep(3 * time.Second)
		activeScanId, activeScanErr := activeScan(&proxyPort, contextId)
		if activeScanErr != nil {
			errLogg := fmt.Errorf("zap activeScanErr error %v", activeScanErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(errLogg)
			}
			log.Println(errLogg)
			continue
		}
		time.Sleep(1 * time.Second)
		for {
			activeScanStatusResp, activeScanStatusErr := activeScanStatus(&proxyPort, activeScanId)
			if activeScanStatusErr != nil {
				errLogg := fmt.Errorf("zap sctiveScanStatusErr error %v", activeScanStatusErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errLogg)
				}
				log.Println(errLogg)
				continue
			}
			if activeScanStatusResp == nil {
				break
			}
			intStrconvActiveScanStatusResp, strconvActiveScanStatusRespErr := strconv.Atoi(*activeScanStatusResp)
			if strconvActiveScanStatusRespErr != nil {
				errLogg := fmt.Errorf("zap strconvActiveScanStatusRespErr error %v", strconvActiveScanStatusRespErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errLogg)
				}
				log.Println(errLogg)
				continue
			}
			activeScanPct = intStrconvActiveScanStatusResp
			pct := float64(numberOfAppsComplete) / float64(totalNumberOfApps)
			percent := float64(spiderScanPct+activeScanPct) / float64(200) * 100 * pct
			_, activeScanPctUpdateError := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", taskId}},
				bson.D{{"$set", bson.D{
					{"status", "PROGRESS"},
					{"percent", int(percent)}}}},
			)
			if activeScanPctUpdateError != nil {
				err := fmt.Errorf("owasp zap activeScanPctUpdate error %v", activeScanPctUpdateError)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				continue
			}
			if *activeScanStatusResp == "100" {
				break
			}
			time.Sleep(10 * time.Second)
		}
		jsonReportResp, jsonReportErr := jsonReport(&proxyPort, &contextName)
		if jsonReportErr != nil {
			err := fmt.Errorf("owasp zap jsonReport error %v", jsonReportErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}
		fileReader, _, fileReaderErr := cli.CopyFromContainer(context.TODO(), *ZapContainerId, *jsonReportResp)
		if fileReaderErr != nil {
			cli.Close()
			if fileReader != nil {
				fileReader.Close()
			}
			err := fmt.Errorf("owasp zap fileReader error %v", jsonReportErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			continue
		}

		tr := tar.NewReader(fileReader)
		var data []byte
		for {
			_, err := tr.Next()
			if err == io.EOF {
				break // End of archive
			}
			if err != nil {
				fileReader.Close()
				cli.Close()
				errLogg := fmt.Errorf("file read error %v", err)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errLogg)
				}
				log.Println(errLogg)
				continue
			}
			data, err = io.ReadAll(tr)
			if err != nil {
				fileReader.Close()
				cli.Close()
				errLogg := fmt.Errorf("file read error %v", err)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errLogg)
				}
				log.Println(errLogg)
				continue
			}
		}
		fileReader.Close()
		b64data := base64.StdEncoding.EncodeToString(data)
		report := map[string]interface{}{
			"app_id": dastConfig.ID,
			"data":   b64data,
		}
		reports = append(reports, report)
		numberOfAppsComplete += 1
	}
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"owasp_zap_results", reports},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	if update2Error != nil {
		err := fmt.Errorf("owasp zap scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	docker.RemoveContainers(idArray)
	cli.Close()
	return
}

func StartZap(taskId *primitive.ObjectID, contextName *string, proxyPort *string) (*string, error) {
	imageName := docker.OwaspZapImage
	bash := strings.Split("/bin/bash -c", " ")
	port := nat.Port(fmt.Sprintf("%s/tcp", *proxyPort))
	config := &container.Config{
		Image:        imageName,
		Env:          []string{"ZAP_PORT=" + *proxyPort},
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
		User:         "zap",
		Entrypoint:   bash,
		Cmd:          []string{"mkdir ~/.ZAP/contexts && echo " + *contextName + " | tee ~/.ZAP/contexts/context.xml && zap.sh -addonupdate -daemon -host 0.0.0.0 -port " + *proxyPort + " -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true"},
		ExposedPorts: nat.PortSet{
			port: struct{}{},
		},
	}
	resources := &container.Resources{
		Memory: 4.096e+9,
	}
	hostConfig := &container.HostConfig{
		Resources: *resources,
		PortBindings: nat.PortMap{
			port: []nat.PortBinding{
				{
					HostIP:   "127.0.0.1",
					HostPort: *proxyPort,
				},
			},
		},
	}
	now := time.Now()
	containerName := "zap-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	ZapContainer, ZapContainerErr := docker.StartContainer(&imageName, &containerName, config, hostConfig)
	if ZapContainerErr != nil {
		return nil, ZapContainerErr
	}
	return &ZapContainer.ID, nil
}

func newUser(proxyPort *string, contextId *string, userName *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/users/action/newUser/"
	body := []byte("contextId=" + *contextId + "&name=" + *userName)
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.UserID != "" {
		return &result.UserID, nil
	}
	return nil, nil
}

func newContext(proxyPort *string, contextName *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/context/action/newContext/"
	body := []byte("contextName=" + *contextName)
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.ContextID != "" {
		return &result.ContextID, nil
	}
	return nil, nil
}

func includeInContext(proxyPort *string, contextName *string, regex *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/context/action/includeInContext/"
	body := []byte("contextName=" + *contextName + "&regex=" + *regex)
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Result == "OK" {
		return &result.Result, nil
	}
	return nil, nil
}

func setInScope(proxyPort *string, contextName *string, inScope *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/context/action/setContextInScope/"
	body := []byte("contextName=" + *contextName + "&booleanInScope=" + *inScope)
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Result == "OK" {
		return &result.Result, nil
	}
	return nil, nil
}

func setAuthenticationMethod(proxyPort *string, contextId *string, authMethodName *string, loginUrl *string, loginRequestData *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/authentication/action/setAuthenticationMethod/"
	body := []byte("contextId=" + *contextId + "&authMethodName=" + *authMethodName + "&authMethodConfigParams=loginUrl=" + url.QueryEscape(*loginUrl) + "&loginRequestData=" + url.QueryEscape(*loginRequestData))
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Result == "OK" {
		return &result.Result, nil
	}
	return nil, nil
}

func setAuthenticationCredentials(proxyPort *string, contextId *string, newUserId *string, authCredentialsConfigParams *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/users/action/setAuthenticationCredentials/"
	body := []byte("contextId=" + *contextId + "&userId=" + url.QueryEscape(*newUserId) + "&authCredentialsConfigParams=" + url.QueryEscape(*authCredentialsConfigParams))
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Result == "OK" {
		return &result.Result, nil
	}
	return nil, nil
}

func setUserEnabled(proxyPort *string, contextId *string, newUserId *string, enabled *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/users/action/setUserEnabled/"
	body := []byte("contextId=" + *contextId + "&userId=" + *newUserId + "&enabled=" + *enabled)
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Result == "OK" {
		return &result.Result, nil
	}
	return nil, nil
}

func setLoggedInIndicator(proxyPort *string, contextId *string, loggedInIndicatorRegex *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/authentication/action/setLoggedInIndicator/"
	body := []byte("contextId=" + *contextId + "&loggedInIndicatorRegex=" + *loggedInIndicatorRegex)
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Result == "OK" {
		return &result.Result, nil
	}
	return nil, nil
}

func spiderScan(proxyPort *string, contextName *string, url *string, maxChildren *int) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/spider/action/scan/"
	maxChildrenString := fmt.Sprintf("&maxChildren=%d", *maxChildren)
	body := []byte("url=" + *url + maxChildrenString + "&recurse=true&contextName=" + *contextName + "&subtreeOnly=true")
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Scan != "" {
		return &result.Scan, nil
	}
	return nil, nil
}

func spiderScanStatus(proxyPort *string, scanId *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/spider/view/status/?scanId=" + *scanId
	method := "GET"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, nil, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Status != "" {
		return &result.Status, nil
	}
	return nil, nil
}

func activeScan(proxyPort *string, contextId *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/ascan/action/scan/"
	body := []byte("recurse=true&inScopeOnly=true&scanPolicyName=&method=&postData=&contextId=" + *contextId)
	method := "POST"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, &body, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Scan != "" {
		return &result.Scan, nil
	}
	return nil, nil
}

func activeScanStatus(proxyPort *string, scanId *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/ascan/view/status/?scanId=" + *scanId
	method := "GET"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, nil, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Status != "" {
		return &result.Status, nil
	}
	return nil, nil
}

func jsonReport(proxyPort *string, contextName *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/reports/action/generate/?title=" + *contextName + "title&template=traditional-json&theme=&description=&contexts=" + *contextName + "&sites=&sections=&includedConfidences=&includedRisks=&reportFileName=&reportFileNamePattern=&reportDir=&display="
	method := "GET"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, nil, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result jsonResponse
	json.Unmarshal(respBody, &result)
	if result.Generate != "" {
		return &result.Generate, nil
	}
	return nil, nil
}

func htmlReport(proxyPort *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/OTHER/core/other/htmlreport/"
	method := "GET"
	resp, respErr := HttpClientRequest(&baseUrl, &urlPath, nil, &method)
	if respErr != nil {
		log.Println(respErr.Error())
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	result := base64.StdEncoding.EncodeToString(respBody)
	return &result, nil
}

func HttpClientRequest(baseURL *string, path *string, data *[]byte, method *string) (*http.Response, error) {
	//proxyStr := "http://127.0.0.1:8081"
	//proxyURL, ProxyURLErr := url.Parse(proxyStr)
	//if ProxyURLErr != nil {
	//	return &http.Response{}, ProxyURLErr
	//}
	urlStr := *baseURL + *path
	scannersUrl, ScannersUrlErr := url.Parse(urlStr)
	if ScannersUrlErr != nil {
		return nil, ScannersUrlErr
	}
	transport := &http.Transport{
		//	Proxy: http.ProxyURL(proxyURL),
		//	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	myClient := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 60,
	}
	//generating the HTTP GET request
	if data == nil {
		data = &[]byte{}
	}
	request, RequestErr := http.NewRequest(
		*method,
		scannersUrl.String(),
		bytes.NewBuffer(*data),
	)
	if RequestErr != nil {
		return nil, RequestErr
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Connection", "close")
	request.Close = true
	response, ClientErr := myClient.Do(request)
	if ClientErr != nil {
		return nil, ClientErr
	}
	return response, nil
}

func checkSpiderScans(scanIds *[]string, proxyPort *string) {
	var wg sync.WaitGroup
	wg.Add(len(*scanIds))
	for _, spiderSId := range *scanIds {
		spiderFunc(&wg, &spiderSId, proxyPort)

		/*
			intSpiderScanStatusResp, strconvSpiderScanStatusRespErr := strconv.Atoi(*spiderScanStatusResp)
			if strconvSpiderScanStatusRespErr != nil {
				errLogg := fmt.Errorf("zap strconvSpiderScanStatusRespErr error %v", strconvSpiderScanStatusRespErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(errLogg)
				}
				log.Println(errLogg)
				return
			}

			spiderScanPct = intSpiderScanStatusResp
			percent := float64(spiderScanPct+activeScanPct) / float64(200) * 100
			_, spiderScanPctUpdateError := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", taskId}},
				bson.D{{"$set", bson.D{
					{"status", "PROGRESS"},
					{"percent", int(percent)}}}},
			)
			if spiderScanPctUpdateError != nil {
				err := fmt.Errorf("owasp zap spiderScanPctUpdate error %v", spiderScanPctUpdateError)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				MongoClient.Disconnect(context.TODO())
				return
			}
		*/
	}

	wg.Wait()
}

func spiderFunc(wg *sync.WaitGroup, spiderSId *string, proxyPort *string) {
	defer wg.Done()
	for {
		spiderScanStatusResp, spiderScanStatusErr := spiderScanStatus(proxyPort, spiderSId)
		if spiderScanStatusErr != nil {
			errLogg := fmt.Errorf("zap spiderScanStatusErr error %v", spiderScanStatusErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(errLogg)
			}
			log.Println(errLogg)
			return
		}
		if *spiderScanStatusResp == "100" {
			break
		}
		time.Sleep(10 * time.Second)
	}
}

func uniqueSlice(intSlice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
