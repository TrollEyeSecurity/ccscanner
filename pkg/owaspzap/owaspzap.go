package owaspzap

import (
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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func Scan(dastConfig database.DastConfig, taskId *primitive.ObjectID) {
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("gvm mongo-client error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var idArray []string
	cli, NewEnvClientErr := client.NewClientWithOpts()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("nmap scan error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	proxyPort := "8080"
	/*var proxyPort string
	attempts := 0
	for {
		rand.Seed(time.Now().UnixNano())
		min := 8080
		max := 8090
		proxyPort = strconv.Itoa(rand.Intn(max-min+1) + min)
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
	*/
	var contextConfiguration ContextConfiguration
	t := time.Now().Unix()
	contextName := fmt.Sprintf("%d", t)
	if dastConfig.WebappZapContext != "" {
		xml.Unmarshal([]byte(dastConfig.WebappZapContext), &contextConfiguration)
	} else {

	}
	ZapContainerId, StartZapErr := StartZap(taskId, &contextName, &proxyPort)
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
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"container_id", ZapContainerId}, {"status", "PROGRESS"}}}})
	if updateError != nil {
		err := fmt.Errorf("zap scan error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	idArray = append(idArray, *ZapContainerId)
	time.Sleep(15 * time.Second)
	for {
		waitForHealthy, containerInspectErr := cli.ContainerInspect(context.TODO(), *ZapContainerId)
		if containerInspectErr != nil {
			log.Println(containerInspectErr)
			docker.RemoveContainers(idArray)
			return
		}
		if waitForHealthy.State.Health.Status == "healthy" {
			log.Println("OWASP ZAP container health status: " + waitForHealthy.State.Health.Status)
			break
		}
		log.Println("OWASP ZAP container health status: " + waitForHealthy.State.Health.Status)
		time.Sleep(15 * time.Second)
	}
	contextId, newContextErr := newContext(&proxyPort, &contextName)
	if newContextErr != nil {
		err := fmt.Errorf("zap new-context error %v", newContextErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	if contextId == nil {
		err := fmt.Errorf("zap context-id error %v", contextName)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
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
	}
	formBasedAuthentication := "formBasedAuthentication"
	_, setAuthenticationMethodErr := setAuthenticationMethod(&proxyPort, contextId, &formBasedAuthentication, &contextConfiguration.Context.Authentication.Form.Loginurl, &contextConfiguration.Context.Authentication.Form.Loginbody)
	if setAuthenticationMethodErr != nil {
		errLogg := fmt.Errorf("zap setAuthenticationMethodErr error %v", setAuthenticationMethodErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(errLogg)
		}
		log.Println(errLogg)
		return
	}
	_, setLoggedInIndicatorErr := setLoggedInIndicator(&proxyPort, contextId, &contextConfiguration.Context.Authentication.Loggedin)
	if setLoggedInIndicatorErr != nil {
		errLogg := fmt.Errorf("zap setLoggedInIndicatorErr error %v", setLoggedInIndicatorErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(errLogg)
		}
		log.Println(errLogg)
		return
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
			return
		}
		authCredentialsConfigParams := "username=" + string(userNameDecodedText) + "&password=" + string(userPassDecodedText)
		_, setAuthenticationCredentialsErr := setAuthenticationCredentials(&proxyPort, contextId, newUserId, &authCredentialsConfigParams)
		if setAuthenticationCredentialsErr != nil {
			errLogg := fmt.Errorf("zap setAuthenticationCredentials error %v", setAuthenticationCredentialsErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(errLogg)
			}
			log.Println(errLogg)
			return
		}
		enabled := "true"
		_, setUserEnabledErr := setUserEnabled(&proxyPort, contextId, newUserId, &enabled)
		if setUserEnabledErr != nil {
			errLogg := fmt.Errorf("zap setUserEnabled error %v", setUserEnabledErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(errLogg)
			}
			log.Println(errLogg)
			return
		}
	}
	var spiderSIds []string
	activeScanPct := 0
	spiderScanPct := 0
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
				return
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
			return
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
		return
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
			return
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
			return
		}
		activeScanPct = intStrconvActiveScanStatusResp
		percent := float64(spiderScanPct+activeScanPct) / float64(200) * 100
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
			MongoClient.Disconnect(context.TODO())
			return
		}
		if *activeScanStatusResp == "100" {
			break
		}
		time.Sleep(10 * time.Second)
	}
	jsonReportResp, jsonReportErr := jsonReport(&proxyPort)
	if jsonReportErr != nil {
		err := fmt.Errorf("owasp zap jsonReport error %v", jsonReportErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	htmlReportResp, htmlReportErr := htmlReport(&proxyPort)
	if htmlReportErr != nil {
		err := fmt.Errorf("owasp zap htmlReport error %v", htmlReportErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"owasp_zap_json_result", *jsonReportResp},
			{"owasp_zap_html_result", *htmlReportResp},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	docker.RemoveContainers(idArray)
	cli.Close()
	if update2Error != nil {
		err := fmt.Errorf("owasp zap scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	return
}

func StartZap(taskId *primitive.ObjectID, contextName *string, proxyPort *string) (*string, error) {
	imageName := docker.OwaspZapImage
	bash := strings.Split("/bin/bash -c", " ")
	config := &container.Config{
		Image:        imageName,
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
		User:         "zap",
		Entrypoint:   bash,
		Cmd:          []string{"mkdir ~/.ZAP/contexts && echo " + *contextName + " | tee ~/.ZAP/contexts/context.xml && zap.sh -addonupdate -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true"},
		ExposedPorts: nat.PortSet{
			"8080/tcp": struct{}{},
		},
	}
	resources := &container.Resources{
		Memory: 4.096e+9,
	}
	hostConfig := &container.HostConfig{
		Resources: *resources,
		PortBindings: nat.PortMap{
			"8080/tcp": []nat.PortBinding{
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

func jsonReport(proxyPort *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/OTHER/core/other/jsonreport/"
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
