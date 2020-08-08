package urlinspection

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/CriticalSecurity/ccscanner/internal/database"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
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
		// unoffical
		218: true,
	}
	var results []database.UrlData
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("urlinspection run-inspection error %v", MongoClientError)
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
		err := fmt.Errorf("urlinspection run-inspection error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	for _, u := range urls.UrlList {
		InspectionResults, InspectUrlError := InspectUrl(&u)
		if InspectUrlError != nil {
			err := fmt.Errorf("urlinspection run-inspection error %v: %v", InspectUrlError, u)
			//if sentry.CurrentHub().Client() != nil {
			//	sentry.CaptureException(err)
			//}
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
		err := fmt.Errorf("nmap scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	MongoClient.Disconnect(context.TODO())
	return
}

func InspectUrl(url *string) (*database.UrlData, error) {
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
		// unoffical
		218: true,
	}
	RedirectCodes := map[int]bool{
		300: true,
		301: true,
		302: true,
		303: true,
		304: true,
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
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := http.Get(*url)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, err
	}
	urlData := database.UrlData{}
	var urlList []string
	var finalLocation string
	var respBody string
	for {
		index := 0
		if RedirectCodes[resp.StatusCode] {
			index += 1
			newUrl := resp.Header.Get("Location")
			urlList = append(urlList, newUrl)
			resp, err = http.Get(newUrl)
			if err != nil {
				if resp != nil {
					resp.Body.Close()
				}
				return nil, err
			}
		}
		if SuccessCodes[resp.StatusCode] {
			newUrl := resp.Header.Get("Location")
			if newUrl != "" {
				urlList = append(urlList, newUrl)
				index += 1
				resp, err = http.Get(newUrl)
				if err != nil {
					if resp != nil {
						resp.Body.Close()
					}
					return nil, err
				}
				RespBody, _ := ioutil.ReadAll(resp.Body)
				respBody = string(RespBody)
				finalLocation = resp.Request.URL.String()
				urlData.Data.Server = resp.Header.Get("Server")
				urlData.Data.XPoweredBy = resp.Header.Get("X-Powered-By")
				urlData.Data.ContentType = resp.Header.Get("Content-Type")
				urlData.StatusCode = resp.StatusCode
				if strings.Contains(urlData.Data.ContentType, "json") {
					jsonTitle, jsonUniqueText, jsonError := parseJson(&respBody)
					if jsonError != nil {
						if resp != nil {
							resp.Body.Close()
						}
						return nil, jsonError
					}
					b64 := base64.StdEncoding.EncodeToString([]byte(*jsonUniqueText))
					uniqueId := md5.Sum([]byte(b64))
					urlData.Data.Title = *jsonTitle
					urlData.Data.UniqueId = hex.EncodeToString(uniqueId[:])
				} else if strings.Contains(urlData.Data.ContentType, "xml") {
					xmlTitle, xmlUniqueText, xmlError := parseXML(&respBody)
					if xmlError != nil {
						if resp != nil {
							resp.Body.Close()
						}
						return nil, xmlError
					}
					b64 := base64.StdEncoding.EncodeToString([]byte(*xmlUniqueText))
					uniqueId := md5.Sum([]byte(b64))
					urlData.Data.Title = *xmlTitle
					urlData.Data.UniqueId = hex.EncodeToString(uniqueId[:])
				} else {
					title := getTitle(respBody)
					head, _ := getHead(respBody)
					b64 := base64.StdEncoding.EncodeToString([]byte(*head))
					uniqueId := md5.Sum([]byte(b64))
					urlData.Data.Title = title
					urlData.Data.UniqueId = hex.EncodeToString(uniqueId[:])
				}
				resp.Body.Close()
				urlData.FinalLocation = finalLocation
				break
			} else {
				RespBody, _ := ioutil.ReadAll(resp.Body)
				respBody = string(RespBody)
				finalLocation = resp.Request.URL.String()
				urlData.Data.Server = resp.Header.Get("Server")
				urlData.Data.XPoweredBy = resp.Header.Get("X-Powered-By")
				urlData.Data.ContentType = resp.Header.Get("Content-Type")
				urlData.StatusCode = resp.StatusCode
				if strings.Contains(urlData.Data.ContentType, "json") {
					jsonTitle, jsonUniqueText, jsonError := parseJson(&respBody)
					if jsonError != nil {
						if resp != nil {
							resp.Body.Close()
						}
						return nil, jsonError
					}
					b64 := base64.StdEncoding.EncodeToString([]byte(*jsonUniqueText))
					uniqueId := md5.Sum([]byte(b64))
					urlData.Data.Title = *jsonTitle
					urlData.Data.UniqueId = hex.EncodeToString(uniqueId[:])
				} else if strings.Contains(urlData.Data.ContentType, "xml") {
					xmlTitle, xmlUniqueText, xmlError := parseXML(&respBody)
					if xmlError != nil {
						if resp != nil {
							resp.Body.Close()
						}
						return nil, xmlError
					}
					b64 := base64.StdEncoding.EncodeToString([]byte(*xmlUniqueText))
					uniqueId := md5.Sum([]byte(b64))
					urlData.Data.Title = *xmlTitle
					urlData.Data.UniqueId = hex.EncodeToString(uniqueId[:])
				} else {
					title := getTitle(respBody)
					head, _ := getHead(respBody)
					b64 := base64.StdEncoding.EncodeToString([]byte(*head))
					uniqueId := md5.Sum([]byte(b64))
					urlData.Data.Title = title
					urlData.Data.UniqueId = hex.EncodeToString(uniqueId[:])
				}
				resp.Body.Close()
				urlData.FinalLocation = finalLocation
				break
			}
		}
		if ClientErrorCodes[resp.StatusCode] {
			urlData.StatusCode = resp.StatusCode
			resp.Body.Close()
			break
		}
		if ServerErrorCodes[resp.StatusCode] {
			urlData.StatusCode = resp.StatusCode
			resp.Body.Close()
			break
		}
	}
	//urlData.Body = respBody
	return &urlData, nil
}

func getTitle(HTMLString string) (title string) {
	r := strings.NewReader(HTMLString)
	z := html.NewTokenizer(r)
	var i int
	for {
		tt := z.Next()
		i++
		if i > 100 { // Title should be one of the first tags
			return
		}
		switch {
		case tt == html.ErrorToken:
			// End of the document, we're done
			return
		case tt == html.StartTagToken:
			t := z.Token()
			// Check if the token is an <title> tag
			if t.Data != "title" {
				continue
			}
			// fmt.Printf("%+v\n%v\n%v\n%v\n", t, t, t.Type.String(), t.Attr)
			tt := z.Next()
			if tt == html.TextToken {
				t := z.Token()
				title = t.Data
				return
				// fmt.Printf("%+v\n%v\n", t, t.Data)
			}
		}
	}
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

func renderNode(n *html.Node) string {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	html.Render(w, n)
	return buf.String()
}

func getHead(htm string) (*string, error) {
	doc, _ := html.Parse(strings.NewReader(htm))
	bn, err := Head(doc)
	if err != nil {
		return nil, err
	}
	head := renderNode(bn)
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
	/*var es ES
	jsonError := xml.Unmarshal([]byte(*xmlBody), &es)
	if jsonError != nil {
		return nil, nil, jsonError
	}
	if es.Tagline == "You know, for Search" {
		esTitle := "Elasticsearch " + es.Version.Number
		unique := es.Version.BuildHash
		uniqueText = &unique
		title = &esTitle
	} else {
		defaultTitle := "A SOAP API"
		title = &defaultTitle
		unique := *xmlBody
		uniqueText = &unique
	}
	*/
	defaultTitle := "A SOAP API"
	title = &defaultTitle
	unique := *xmlBody
	uniqueText = &unique
	return title, uniqueText, nil
}