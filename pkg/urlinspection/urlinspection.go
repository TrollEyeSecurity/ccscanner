package urlinspection

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func RunInspection(urls *database.Urls, taskId *primitive.ObjectID) {
	SuccessCodes := map[int]bool{
		200: true,
		201: true,
		202: true,
		203: true,
		204: true,
		205: true,
		206: true,
		207: true,
		208: true,
		226: true,
		304: true,
		// unoffical
		218: true,
	}
	RedirectCodes := map[int]bool{
		300: true,
		301: true,
		302: true,
		303: true,
		305: true,
		306: true,
		307: true,
		308: true,
	}
	ClientErrorCodes := map[int]bool{
		400: true,
		401: true,
		402: true,
		403: true,
		404: true,
		405: true,
		406: true,
		407: true,
		408: true,
		409: true,
		410: true,
		411: true,
		412: true,
		413: true,
		414: true,
		415: true,
		416: true,
		417: true,
		418: true,
		421: true,
		422: true,
		423: true,
		424: true,
		425: true,
		426: true,
		428: true,
		429: true,
		431: true,
		451: true,
		// unoffical
		419: true,
		420: true,
		430: true,
		450: true,
		498: true,
		499: true,
		440: true,
		449: true,
		444: true,
		494: true,
		495: true,
		496: true,
		497: true,
		460: true,
		463: true,
	}
	ServerErrorCodes := map[int]bool{
		500: true,
		501: true,
		502: true,
		503: true,
		504: true,
		505: true,
		506: true,
		507: true,
		508: true,
		509: true,
		510: true,
		511: true,
		// unoffical
		526: true,
		529: true,
		530: true,
		598: true,
		520: true,
		521: true,
		522: true,
		523: true,
		525: true,
		527: true,
	}
	var results []database.UrlData
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("urlinspection mongo-client error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"status", "PROGRESS"}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("urlinspection task-update error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	for _, u := range urls.UrlList {
		InspectionResults, InspectUrlError := InspectUrl(&u, SuccessCodes, RedirectCodes, ClientErrorCodes, ServerErrorCodes)
		if InspectUrlError != nil {
			err := fmt.Errorf("urlinspection run-inspection error %v: %v", InspectUrlError, u)
			log.Println(err)
			continue
		}
		if SuccessCodes[InspectionResults.StatusCode] {
			results = append(results, *InspectionResults)
		}
	}
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"url_ins_result", results},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	if update2Error != nil {
		err := fmt.Errorf("urlinspection task-update error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	return
}

func InspectUrl(myUrl *string, SuccessCodes map[int]bool, RedirectCodes map[int]bool, ClientErrorCodes map[int]bool, ServerErrorCodes map[int]bool) (*database.UrlData, error) {
	timeout := 2 * time.Second
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	urlData := database.UrlData{}
	var urlList []string
	var urlCodesList []int
	var finalLocation string
	jsAttempt := 0
	for {
		var newUrl string
		request, err := http.NewRequest("GET", *myUrl, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Connection", "close")
		response, originalRespErr := client.Do(request)
		if originalRespErr != nil {
			if response != nil {
				response.Body.Close()
			}
			return nil, originalRespErr
		}
		urlList = append(urlList, *myUrl)
		urlCodesList = append(urlCodesList, response.StatusCode)
		RespBody, RespBodyError := ioutil.ReadAll(response.Body)
		if RespBodyError != nil {
			return nil, RespBodyError
		}
		respBody := string(RespBody)
		var nl string
		if jsAttempt == 0 {
			nl = extractJavascriptLocation(respBody)
			jsAttempt += 1
		}
		spaces := strings.Contains(nl, " ")
		if spaces {
			nl = ""
		}
		if nl != "" {
			newUrl = *myUrl + strings.TrimLeft(nl, "/")
		}
		hm := extractMeta(respBody)
		if hm.ApplicationRedirect != "" {
			appRedirect := hm.ApplicationRedirect
			res1 := strings.ToLower(appRedirect)
			res2 := strings.Replace(res1, " ", "", -1)
			res3 := strings.Split(res2, "url=")
			res4 := strings.Replace(res3[1], "\"", "", -1)
			res5 := strings.Replace(res4, "'", "", -1)
			fullUrl := strings.Contains(res5, "://")
			if fullUrl {
				newUrl = res5
			} else {
				newUrl = *myUrl + res5
			}
			response.Body.Close()
		}
		switch {
		case newUrl != "":
			*myUrl = newUrl
		case RedirectCodes[response.StatusCode]:
			newLocation := response.Header.Get("Location")
			fullUrl := strings.Contains(newLocation, "://")
			if fullUrl {
				*myUrl = newLocation
			} else {
				*myUrl = *myUrl + strings.TrimLeft(newLocation, "/")
			}
			response.Body.Close()
			_, DiscardErr := io.Copy(ioutil.Discard, response.Body)
			if DiscardErr != nil {
				return nil, DiscardErr
			}
		case SuccessCodes[response.StatusCode] && newUrl == "":
			finalLocation = response.Request.URL.String()
			urlData.Data.Server = response.Header.Get("Server")
			urlData.Data.XPoweredBy = response.Header.Get("X-Powered-By")
			urlData.Data.ContentType = response.Header.Get("Content-Type")
			urlData.StatusCode = response.StatusCode
			plainXml := strings.Contains(urlData.Data.ContentType, "text/xml")
			appXml := strings.Contains(urlData.Data.ContentType, "application/xml")
			switch {
			case strings.Contains(urlData.Data.ContentType, "json"):
				jsonTitle, jsonUniqueText, jsonError := parseJson(&respBody)
				if jsonError != nil {
					if response != nil {
						response.Body.Close()
					}
					return nil, jsonError
				}
				b64 := base64.StdEncoding.EncodeToString([]byte(*jsonUniqueText))
				uniqueId := md5.Sum([]byte(b64))
				urlData.Data.Title = *jsonTitle
				urlData.Data.UniqueId = hex.EncodeToString(uniqueId[:])
			case plainXml || appXml:
				xmlTitle, xmlUniqueText, xmlError := parseXML(&respBody)
				if xmlError != nil {
					if response != nil {
						response.Body.Close()
					}
					return nil, xmlError
				}
				b64 := base64.StdEncoding.EncodeToString([]byte(*xmlUniqueText))
				uniqueId := md5.Sum([]byte(b64))
				urlData.Data.Title = *xmlTitle
				urlData.Data.UniqueId = hex.EncodeToString(uniqueId[:])
			default:
				uniqueTxt := ""
				head, getHeadError := getHead(respBody)
				if getHeadError != nil {
					log.Println(getHeadError)
				}
				var metaData string
				hm := extractMeta(respBody)
				if hm.ApplicationName != "" {
					metaData += hm.ApplicationName
				}
				if hm.ApplicationVersion != "" {
					metaData += " " + hm.ApplicationVersion
				}
				if hm.ApplicationTitle != "" && hm.ApplicationTitle != hm.ApplicationName {
					metaData += " | " + hm.ApplicationTitle
				}
				if hm.Description != "" && metaData == "" {
					metaData += hm.Description
				}
				if urlData.Data.Server == "DNVRS-Webs" && metaData == "" {
					metaData += "Hikvision DVR"
				}
				uniqueTxt = metaData
				if metaData == "" && hm.Title != "" {
					uniqueTxt = hm.Title
				} else if uniqueTxt == "" {
					uniqueTxt = *head
				}
				b64 := base64.StdEncoding.EncodeToString([]byte(uniqueTxt))
				uniqueId := md5.Sum([]byte(b64))
				if metaData != "" {
					urlData.Data.Title = metaData
				} else {
					urlData.Data.Title = hm.Title
				}
				urlData.Data.UniqueId = hex.EncodeToString(uniqueId[:])
			}
			response.Body.Close()
			urlData.FinalLocation = finalLocation
			return &urlData, nil
		case ClientErrorCodes[response.StatusCode]:
			switch {
			case len(urlCodesList) > 0:
				index, success := findSuccess(urlCodesList, SuccessCodes)
				if success {
					*myUrl = urlList[index]
					newUrl = ""
					jsAttempt = 2
					response.Body.Close()
				} else {
					urlData.StatusCode = response.StatusCode
					response.Body.Close()
					return &urlData, nil
				}
			default:
				urlData.StatusCode = response.StatusCode
				response.Body.Close()
				return &urlData, nil
			}
		case ServerErrorCodes[response.StatusCode]:
			switch {
			case len(urlCodesList) > 0:
				index, success := findSuccess(urlCodesList, SuccessCodes)
				if success {
					*myUrl = urlList[index]
					newUrl = ""
					jsAttempt = 2
					response.Body.Close()

				} else {
					urlData.StatusCode = response.StatusCode
					response.Body.Close()
					return &urlData, nil
				}
			default:
				urlData.StatusCode = response.StatusCode
				response.Body.Close()
				return &urlData, nil
			}
		}
	}
}

func findSuccess(responseCodesArray []int, SuccessCodes map[int]bool) (int, bool) {
	for index, n := range responseCodesArray {
		if SuccessCodes[n] {
			return index, true
		}
	}
	return 0, false
}

func Head(doc *html.Node) (*html.Node, error) {
	var head *html.Node
	var crawler func(*html.Node)
	crawler = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "head" {
			head = node
			return
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			crawler(child)
		}
	}
	crawler(doc)
	if head != nil {
		return head, nil
	}
	return nil, errors.New("Missing <head> in the node tree")
}

func renderNode(n *html.Node) (string, error) {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	renderError := html.Render(w, n)
	if renderError != nil {
		return "", renderError
	}
	return buf.String(), nil
}

func getHead(htm string) (*string, error) {
	doc, _ := html.Parse(strings.NewReader(htm))
	bn, err := Head(doc)
	if err != nil {
		return nil, err
	}
	head, renderNodeErr := renderNode(bn)
	if renderNodeErr != nil {
		return nil, renderNodeErr
	}
	return &head, nil
}

func parseJson(jsonBody *string) (title *string, uniqueText *string, err error) {
	var es ES
	jsonError := json.Unmarshal([]byte(*jsonBody), &es)
	if jsonError != nil {
		return nil, nil, jsonError
	}
	if es.Tagline == "You Know, for Search" {
		esTitle := "Elasticsearch " + es.Version.Number
		unique := es.Version.BuildHash
		uniqueText = &unique
		title = &esTitle
	} else {
		defaultTitle := "A RESTFul API"
		title = &defaultTitle
		unique := *jsonBody
		uniqueText = &unique
	}
	return title, uniqueText, nil
}

func parseXML(xmlBody *string) (title *string, uniqueText *string, err error) {
	var wsdlMeta WSDLMeta
	xmlError := xml.Unmarshal([]byte(*xmlBody), &wsdlMeta)
	if xmlError != nil {
		return nil, nil, xmlError
	}
	switch {
	case wsdlMeta.TargetNamespace != "":
		title = &wsdlMeta.TargetNamespace
		unique := wsdlMeta.TargetNamespace + "-" + wsdlMeta.Name + "-" + wsdlMeta.Service.Doc
		uniqueText = &unique
	default:
		var s string
		s = "A SOAP API"
		title = &s
		unique := *xmlBody
		uniqueText = &unique
	}

	return title, uniqueText, nil
}

func extractMeta(HTMLString string) *HTMLMeta {
	r := strings.NewReader(HTMLString)
	z := html.NewTokenizer(r)
	titleFound := false
	hm := new(HTMLMeta)
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return hm
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if t.Data == `body` {
				return hm
			}
			if t.Data == "title" {
				titleFound = true
			}
			if t.Data == "meta" {
				desc, ok := extractMetaName(t, "description")
				if ok {
					hm.Description = desc
				}
				a10, ok := extractMetaName(t, "ATEN International Co Ltd.")
				if ok {
					hm.Description = a10
				}
				ogTitle, ok := extractMetaProperty(t, "og:title")
				if ok {
					hm.Title = ogTitle
				}
				ogDesc, ok := extractMetaProperty(t, "og:description")
				if ok {
					hm.Description = ogDesc
				}
				ogSiteName, ok := extractMetaProperty(t, "og:site_name")
				if ok {
					hm.SiteName = ogSiteName
				}
				appName, ok := extractMetaName(t, "application-name")
				if ok {
					hm.ApplicationName = appName
				}
				ajsVersion, ok := extractMetaName(t, "ajs-version-number")
				if ok {
					hm.ApplicationVersion = ajsVersion
				}
				ajsTitle, ok := extractMetaName(t, "ajs-app-title")
				if ok {
					hm.ApplicationTitle = ajsTitle
				}
				redirect, ok := extractMetaRedirect(t, "Refresh")
				if ok {
					hm.ApplicationRedirect = redirect
				}
			}
		case html.TextToken:
			if titleFound {
				t := z.Token()
				fortiClient := strings.Contains(HTMLString, "Launch FortiClient")
				fortiGate := strings.Contains(HTMLString, "FortiGate")
				sonicWall := strings.Contains(HTMLString, "SonicWall - Virtual Office - Powered by SonicWall, Inc.")
				netapp := strings.Contains(HTMLString, "https://mysupport.netapp.com/")
				netappOntapSysManager := strings.Contains(HTMLString, "/sysmgr/v4/")
				raritanLogoLegrand := strings.Contains(HTMLString, "raritan-logo-legrand")
				webuiLogin := strings.Contains(HTMLString, "/webui/login/")
				ciscoSystems := strings.Contains(HTMLString, "Cisco Systems, Inc.")
				wdMyCloud := strings.Contains(HTMLString, "WDMyCloud")
				switch {
				case t.Data == "Please Login" && fortiClient:
					hm.Title = "FortiClient VPN"
				case fortiGate:
					hm.Title = "FortiGate Administration"
				case sonicWall:
					hm.Title = "SonicWall - Virtual Office"
				case netapp:
					hm.Title = "NetApp Administration"
				case t.Data == "Loading..." && netappOntapSysManager:
					hm.Title = "NetApp ONTAP System Manager"
				case raritanLogoLegrand:
					hm.Title = "Raritan Administration"
				case webuiLogin && ciscoSystems && t.Data == "":
					hm.Title = "Cisco Systems Switch Administration"
				case wdMyCloud && t.Data == "":
					hm.Title = "WD My Cloud Home Administration"
				default:
					hm.Title = t.Data
				}
				titleFound = false
			}
		}
	}
}

func extractMetaProperty(t html.Token, prop string) (content string, ok bool) {
	for _, attr := range t.Attr {
		if attr.Key == "property" && attr.Val == prop {
			ok = true
		}
		if attr.Key == "content" {
			content = attr.Val
		}
	}
	return
}

func extractMetaName(t html.Token, prop string) (content string, ok bool) {
	for _, attr := range t.Attr {
		if attr.Key == "name" && attr.Val == prop {
			ok = true
		}
		if attr.Key == "content" {
			content = attr.Val
		}
	}
	return
}

func extractMetaRedirect(t html.Token, prop string) (content string, ok bool) {
	for _, attr := range t.Attr {
		if attr.Key == "http-equiv" && attr.Val == prop {
			ok = true
		}
		if attr.Key == "content" {
			content = attr.Val
		}
	}
	return
}

func extractJavascriptLocation(HTMLString string) string {
	s := ""
	reader := strings.NewReader(HTMLString)
	z := html.NewTokenizer(reader)
	jsFound := false
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return s
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if t.Data == `body` {
				return s
			}
			if t.Data == "script" {
				jsFound = true
			}
		case html.TextToken:
			if jsFound {
				t := z.Token()
				wl := strings.Contains(t.Data, "window.location")
				tl := strings.Contains(t.Data, "top.location")
				if wl || tl {
					r := regexp.MustCompile("[\"'](.*?)[\"']")
					s1 := r.FindString(t.Data)
					t2 := strings.Replace(s1, "\"", "", -1)
					t3 := strings.Replace(t2, "'", "", -1)
					s = t3
					return s
				}
				jsFound = false
			}
		}
	}
}
