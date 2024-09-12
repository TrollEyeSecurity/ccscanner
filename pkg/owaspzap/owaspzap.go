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
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func StartDASTVulnerabilityScan(dastConfig database.DastConfig, taskId *primitive.ObjectID, wg *sync.WaitGroup) {
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
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	proxyPort := "8888"
	var contextConfiguration ContextConfiguration
	t := time.Now().Unix()
	contextName := fmt.Sprintf("%d%d", t, rand.Int())
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
		uid := 1
		for _, secret := range dastConfig.SecretList {
			var appSecret database.AppSecret
			sErr := json.Unmarshal([]byte(secret), &appSecret)
			if sErr != nil {
				err := fmt.Errorf("zap unmarshal-secret error %v", sErr)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				continue
			}
			username := base64.StdEncoding.EncodeToString([]byte(appSecret.Username))
			password := base64.StdEncoding.EncodeToString([]byte(appSecret.Password))
			name := fmt.Sprintf("User%d", uid)
			b64User := fmt.Sprintf("%s~%s~", username, password)
			user := fmt.Sprintf("%d;true;%s;%d;%s", uid, name, uid, b64User)
			u := User{User: user}
			contextConfiguration.Context.Users = append(contextConfiguration.Context.Users, u)
			uid += 1
		}

		contextConfiguration.Context.Authentication.Form.Loginurl = dastConfig.WebappLoginurl
		contextConfiguration.Context.Authentication.Form.Loginbody = dastConfig.WebappLoginrequestdata
		contextConfiguration.Context.Authentication.Loggedin = dastConfig.WebappLoggedinindicatorregex
		contextConfiguration.Context.Authentication.Loggedout = dastConfig.WebappLoggedoutindicatorregex

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
		bson.D{{"$set", bson.D{{"status", "PROGRESS"}}}})

	if updateError != nil {
		err := fmt.Errorf("zap scan error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}

	contextId, newContextErr := newContext(&proxyPort, &contextName)
	if newContextErr != nil {
		err := fmt.Errorf("zap new-context error %v", newContextErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	if contextId == nil {
		err := fmt.Errorf("zap context-id error %v", contextName)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
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
		return
	}

	if len(contextConfiguration.Context.Users) > 0 {
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

		_, setLoggedOutIndicatorErr := setLoggedOutIndicator(&proxyPort, contextId, &contextConfiguration.Context.Authentication.Loggedout)
		if setLoggedOutIndicatorErr != nil {
			errLogg := fmt.Errorf("zap setLoggedOutIndicatorErr error %v", setLoggedOutIndicatorErr)
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
			return
		}
		spiderSIds = append(spiderSIds, *spiderSId)
	}
	time.Sleep(1 * time.Second)
	checkSpiderScans(&spiderSIds, &proxyPort)
	time.Sleep(3 * time.Second)

	// start active scan
	activeScanId, activeScanErr := activeScan(&proxyPort, contextId)
	if activeScanErr != nil {
		errLogg := fmt.Errorf("zap activeScanErr error %v", activeScanErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(errLogg)
		}
		log.Println(errLogg)
		return
	}
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"owasp_zap_context_id", contextId},
			{"owasp_zap_context_name", contextName},
			{"owasp_zap_ascan_id", *activeScanId}}}},
	)
	if update2Error != nil {
		err := fmt.Errorf("owasp zap scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	return
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
	body := []byte("contextId=" + *contextId + "&authMethodName=" + *authMethodName + "&authMethodConfigParams=loginUrl%3D" + url.QueryEscape(*loginUrl) + "%26loginRequestData%3D" + url.QueryEscape(*loginRequestData))
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

func setLoggedOutIndicator(proxyPort *string, contextId *string, loggedOutIndicatorRegex *string) (*string, error) {
	baseUrl := "http://127.0.0.1:" + *proxyPort
	urlPath := "/JSON/authentication/action/setLoggedOutIndicator/"
	body := []byte("contextId=" + *contextId + "&loggedOutIndicatorRegex=" + *loggedOutIndicatorRegex)
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

func getActiveScanStatus(proxyPort *string, scanId *string) (*string, error) {
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
	urlPath := "/JSON/reports/action/generate/?title=" + *contextName + "title&template=traditional-json&theme=&description=&contexts=" + *contextName + "&sites=&sections=&includedConfidences=&includedRisks=&reportFileName=" + *contextName + "&reportFileNamePattern=&reportDir=&display="
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
	//proxyStr := "http://127.0.0.1:8080"
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
		//Proxy:           http.ProxyURL(proxyURL),
		//TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
	for _, spiderSId := range *scanIds {
		wg.Add(1)
		spiderFunc(&wg, &spiderSId, proxyPort)
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

func CheckVulnerabilityScan(taskId *primitive.ObjectID, wg *sync.WaitGroup) {
	defer wg.Done()
	defer time.Sleep(time.Millisecond * 4)
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("owaspzap mongo-client error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	cli, NewEnvClientErr := client.NewClientWithOpts()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("zap scan error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	task := database.Task{}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	tasksCollection.FindOne(context.TODO(), bson.D{{"_id", taskId}}).Decode(&task)
	proxyPort := "8888"
	activeScanStatus, activeScanStatusErr := getActiveScanStatus(&proxyPort, &task.OwaspZapAscanId)
	if activeScanStatusErr != nil {
		err := fmt.Errorf("activeScanStatusErr: %v", activeScanStatusErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}

	if *activeScanStatus == "100" {

		jsonReportResp, jsonReportErr := jsonReport(&proxyPort, &task.OwaspZapContextName)
		if jsonReportErr != nil {
			err := fmt.Errorf("owasp zap jsonReport error %v", jsonReportErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}

		var ZapContainerId string
		containers, containerListErr := cli.ContainerList(context.TODO(), types.ContainerListOptions{})
		if containerListErr != nil {
			err := fmt.Errorf("owasp zap ContainerList error %v", containerListErr)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}

		for _, container := range containers {
			for _, name := range container.Names {
				if name == "/ccscanner_owaspZap_1" {
					ZapContainerId = container.ID
				}
			}
		}

		fileReader, _, fileReaderErr := cli.CopyFromContainer(context.TODO(), ZapContainerId, *jsonReportResp)
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
			return
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
			"app_id": task.Content.DastConfig.ID,
			"data":   b64data,
		}
		_, update2Error := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", taskId}},
			bson.D{{"$set", bson.D{
				{"owasp_zap_results", report},
				{"status", "SUCCESS"},
				{"percent", 100}}}},
		)
		if update2Error != nil {
			if update2Error.Error() == "an inserted document is too large" {
				filePath := fmt.Sprintf("/tmp/large_docs/%s.json", taskId.String())
				f, err := os.Create(filePath)
				if err != nil {
					fmt.Println(err)
					return
				}
				defer f.Close()
				_, writeErr := f.Write(data)
				if writeErr != nil {
					fmt.Println(writeErr)
				}
				d := database.LargDoc{Path: filePath}
				_, update3Error := tasksCollection.UpdateOne(context.TODO(),
					bson.D{{"_id", taskId}},
					bson.D{{"$set", bson.D{
						{"owasp_zap_results", d},
						{"document_too_large", true},
						{"status", "SUCCESS"},
						{"percent", 100}}}},
				)
				if update3Error != nil {
					err1 := fmt.Errorf("owasp zap scan update3Error %v", update3Error)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err1)
					}
					log.Println(err1)
					return
				}
				return
			}

			err := fmt.Errorf("owasp zap scan error %v", update2Error)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			return
		}
		return
	}

	percent, _ := strconv.Atoi(*activeScanStatus)
	_, updateError2 := MongoClient.Database("core").Collection("tasks").UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", percent}}}},
	)
	if updateError2 != nil {
		err := fmt.Errorf("owaspzap mongo-update error %v", updateError2)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	return
}
