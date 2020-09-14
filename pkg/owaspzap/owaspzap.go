package owaspzap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/CriticalSecurity/ccscanner/internal/database"
	"github.com/CriticalSecurity/ccscanner/pkg/docker"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func StartOwaspZap(taskId *primitive.ObjectID, apiPort *string) (*string, error) {
	imageName := docker.OwaspZapImage
	exposedString := nat.Port(*apiPort + "/tcp")
	config := &container.Config{
		Image: imageName,
		Env: []string{
			"ZAP_PORT=" + *apiPort,
		},
		Cmd: []string{
			"zap.sh",
			"-daemon",
			"-host",
			"0.0.0.0",
			"-port",
			*apiPort,
			"-config",
			"api.addrs.addr.name=.*",
			"-config",
			"api.addrs.addr.regex=true",
			"-config",
			"api.disablekey=true",
		},
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
		User:         "zap",
		ExposedPorts: nat.PortSet{
			exposedString: struct{}{},
		},
	}
	resources := &container.Resources{
		Memory: 4.096e+9,
	}
	hostConfig := &container.HostConfig{
		Resources: *resources,
		PortBindings: nat.PortMap{
			exposedString: []nat.PortBinding{
				{
					HostIP:   "127.0.0.1",
					HostPort: *apiPort,
				},
			},
		},
	}
	now := time.Now()
	containerName := "owaspzap-" + strconv.FormatInt(now.Unix(), 10) + "-" + taskId.Hex()
	OwaspZapContainer, OwaspZapContainerErr := docker.StartContainer(&imageName, &containerName, config, hostConfig)
	if OwaspZapContainerErr != nil {
		return nil, OwaspZapContainerErr
	}
	return &OwaspZapContainer.ID, nil
}

func VulnerabilityScan(OwaspZapConfigs *[]database.OwaspZapConfig, taskId *primitive.ObjectID) {
	var idArray []string
	var results []string
	ctx := context.Background()
	MongoClient, MongoClientError := database.GetMongoClient()
	if MongoClientError != nil {
		err := fmt.Errorf("owasp zap scan error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	cli, NewEnvClientErr := client.NewEnvClient()
	if NewEnvClientErr != nil {
		err := fmt.Errorf("nmap scan error %v: %v", NewEnvClientErr, cli)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		return
	}
	var apiPort string
	attempts := 0
	for {
		rand.Seed(time.Now().UnixNano())
		min := 8888
		max := 8897
		apiPort = strconv.Itoa(rand.Intn(max-min+1) + min)
		listenPort, listenPortErr := net.Listen("tcp", ":"+apiPort)
		if listenPortErr != nil {
			attempts++
			if attempts > 9 {
				err := fmt.Errorf("owaspzap error %v: %v", listenPortErr, "VulnerabilityScan listenPortErr - Cannot find an open port for api")
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
	OwaspZapContainer, StartOwaspZapErr := StartOwaspZap(taskId, &apiPort)
	if StartOwaspZapErr != nil {
		if OwaspZapContainer != nil {
			cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
			cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
		}
		err := fmt.Errorf("owaspzap error %v: %v", StartOwaspZapErr, OwaspZapContainer)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		_, updateError := tasksCollection.UpdateOne(context.TODO(),
			bson.D{{"_id", *taskId}},
			bson.D{{"$set", bson.D{{"container_id", nil}, {"status", "FAILURE"}}}},
		)
		if updateError != nil {
			cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
			cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("openvas error %v", updateError)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			cli.Close()
			return
		}
		cli.Close()
		return
	}
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{
			{"container_id", OwaspZapContainer},
			{"status", "INITIALIZING"},
			{"ssh_port", &apiPort}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("owaspzap scan error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		docker.RemoveContainers(idArray)
		return
	}
	for {
		OwaspZapContainerLogReader, OwaspZapContainerLogStreamErr := cli.ContainerLogs(ctx, *OwaspZapContainer, types.ContainerLogsOptions{
			ShowStderr: true,
			ShowStdout: true,
			Timestamps: false,
		})
		if OwaspZapContainerLogStreamErr != nil {
			cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
			cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
			err := fmt.Errorf("owaspzap error %v: %v", OwaspZapContainerLogStreamErr, OwaspZapContainerLogReader)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Println(err)
			cli.Close()
			return
		}
		byteValue, _ := ioutil.ReadAll(OwaspZapContainerLogReader)
		OwaspZapContainerLogReader.Close()
		if strings.Contains(string(byteValue), "ZAP is now listening") {
			_, updateError1 := tasksCollection.UpdateOne(context.TODO(),
				bson.D{{"_id", *taskId}},
				bson.D{{"$set", bson.D{{"status", "PROGRESS"}}}},
			)
			if updateError1 != nil {
				cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
				cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
				err := fmt.Errorf("owaspzap error %v", updateError1)
				if sentry.CurrentHub().Client() != nil {
					sentry.CaptureException(err)
				}
				log.Println(err)
				cli.Close()
				return
			}
			break
		}
	}
	owaspZapHost := "127.0.0.1"
	for _, OwaspZapConfig := range *OwaspZapConfigs {
		webappTech := getTechArray(&OwaspZapConfig)
		if OwaspZapConfig.WebappAuthmethod == "formBasedAuthentication" {
			for _, webAppSecret := range OwaspZapConfig.SecretList {
				authCredentialsConfigParams := url.QueryEscape("username=" + webAppSecret.Username + "&password=" + webAppSecret.Password)
				// bodies
				contextName := "context_" + webAppSecret.Username + "_" + OwaspZapConfig.WebappName
				contextNameBody := "contextName=" + contextName
				technologyNamesContextNameBody := contextNameBody + "&technologyNames=" + strings.Join(*webappTech, ",")
				regexContextNameBody := contextNameBody + "&regex=" + url.QueryEscape(OwaspZapConfig.WebappUrlregex)
				// paths
				newContextPath := "/JSON/context/action/newContext/"
				excludeAllTechPath := "/JSON/context/action/excludeAllContextTechnologies/"
				includeContextTechnologiesPath := "/JSON/context/action/includeContextTechnologies/"
				includeUrlsInContextPath := "/JSON/context/action/includeInContext/"
				setAuthenticationMethodPath := "/JSON/authentication/action/setAuthenticationMethod/"
				newUserPath := "/JSON/users/action/newUser/"
				setAuthenticationCredentialsPath := "/JSON/users/action/setAuthenticationCredentials/"
				setUserEnabledPath := "/JSON/users/action/setUserEnabled/"
				setLoggedInIndicatorPath := "/JSON/authentication/action/setLoggedInIndicator/"
				setLoggedOutIndicatorPath := "/JSON/authentication/action/setLoggedOutIndicator/"
				spiderScanAsUserPath := "/JSON/spider/action/scanAsUser/"
				spiderScanStatusPath := "/JSON/spider/view/status/?scanId="
				activeScanAsUserPath := "/JSON/ascan/action/scanAsUser/"
				activeScanStatusPath := "/JSON/ascan/view/status/?scanId="
				jsonReportPath := "/OTHER/core/other/jsonreport/"
				//
				postMethod := "POST"
				getMethod := "GET"
				newContextResponse, newContextResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &contextNameBody, &newContextPath)
				if newContextResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", newContextResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				contextResp := NewContextResponse{}
				newContextResponseBody, newContextResponseBodyError := ioutil.ReadAll(newContextResponse.Body)
				if newContextResponseBodyError != nil {
					//return nil, RespBodyError
				}
				newContextResponse.Body.Close()
				newContextRespBody := string(newContextResponseBody)
				jsonError := json.Unmarshal([]byte(newContextRespBody), &contextResp)
				if jsonError != nil {
					//return nil, nil, jsonError
				}
				//contextIdString := strconv.Itoa(contextResp.ContextId)
				contextId := "contextId=" + contextResp.ContextId
				// wipe the tech slate clean
				excludeAllTechResponse, excludeAllTechResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &contextNameBody, &excludeAllTechPath)
				if excludeAllTechResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", excludeAllTechResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				_, DiscardExcludeAllTechErr := io.Copy(ioutil.Discard, excludeAllTechResponse.Body) // WE READ THE BODY
				if DiscardExcludeAllTechErr != nil {
					//return nil, DiscardErr
				}
				excludeAllTechResponse.Body.Close()
				includeTechResponse, includeTechResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &technologyNamesContextNameBody, &includeContextTechnologiesPath)
				if includeTechResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", includeTechResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				_, DiscardincludeTechResponseErr := io.Copy(ioutil.Discard, includeTechResponse.Body) // WE READ THE BODY
				if DiscardincludeTechResponseErr != nil {
					//return nil, DiscardErr
				}
				includeTechResponse.Body.Close()
				includeUrlsRegexResponse, includeUrlRegexResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &regexContextNameBody, &includeUrlsInContextPath)
				if includeUrlRegexResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", includeUrlRegexResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				_, DiscardincludeUrlsRegexResponseErr := io.Copy(ioutil.Discard, includeUrlsRegexResponse.Body) // WE READ THE BODY
				if DiscardincludeUrlsRegexResponseErr != nil {
					//return nil, DiscardErr
				}
				loginRequestData := url.QueryEscape(OwaspZapConfig.WebappLoginrequestdata)
				setAuthMethodBody := contextId + "&authMethodName=" + OwaspZapConfig.WebappAuthmethod + "&authMethodConfigParams=" + url.QueryEscape("loginUrl="+OwaspZapConfig.WebappLoginurl+"&loginRequestData="+loginRequestData)
				includeUrlsRegexResponse.Body.Close()
				setAuthenticationMethodResponse, setAuthenticationMethodResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &setAuthMethodBody, &setAuthenticationMethodPath)
				if setAuthenticationMethodResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", setAuthenticationMethodResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				_, DiscardsetAuthenticationMethodResponseErr := io.Copy(ioutil.Discard, setAuthenticationMethodResponse.Body) // WE READ THE BODY
				if DiscardsetAuthenticationMethodResponseErr != nil {
					//return nil, DiscardErr
				}
				setAuthenticationMethodResponse.Body.Close()
				newUserBody := contextId + "&name=" + webAppSecret.Username
				newUserResponse, newUserResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &newUserBody, &newUserPath)
				if newUserResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", newUserResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				newUserResp := NewUserResponse{}
				newUserResponseBody, newUserResponseBodyError := ioutil.ReadAll(newUserResponse.Body)
				if newUserResponseBodyError != nil {
					//return nil, RespBodyError
				}
				newUserResponse.Body.Close()
				newUserRespBody := string(newUserResponseBody)
				newUserJsonError := json.Unmarshal([]byte(newUserRespBody), &newUserResp)
				if newUserJsonError != nil {
					//return nil, nil, jsonError
				}
				setAuthenticationCredentialsBody := contextId + "&userId=" + newUserResp.UserId + "&authCredentialsConfigParams=" + authCredentialsConfigParams
				setAuthenticationCredentialsResponse, setAuthenticationCredentialsResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &setAuthenticationCredentialsBody, &setAuthenticationCredentialsPath)
				if setAuthenticationCredentialsResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", setAuthenticationCredentialsResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				_, DiscardsetAuthenticationCredentialsResponseErr := io.Copy(ioutil.Discard, setAuthenticationCredentialsResponse.Body) // WE READ THE BODY
				if DiscardsetAuthenticationCredentialsResponseErr != nil {
					//return nil, DiscardErr
				}
				setAuthenticationCredentialsResponse.Body.Close()
				setUserEnabledBody := contextId + "&userId=" + newUserResp.UserId + "&enabled=true"
				setUserEnabledBodyResponse, setUserEnabledBodyResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &setUserEnabledBody, &setUserEnabledPath)
				if setUserEnabledBodyResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", setUserEnabledBodyResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				_, DiscardsetUserEnabledBodyResponseErr := io.Copy(ioutil.Discard, setUserEnabledBodyResponse.Body) // WE READ THE BODY
				if DiscardsetUserEnabledBodyResponseErr != nil {
					//return nil, DiscardErr
				}
				setUserEnabledBodyResponse.Body.Close()
				setLoggedInIndicatorBody := contextId + "&loggedInIndicatorRegex=" + url.QueryEscape(OwaspZapConfig.WebappLoggedinindicatorregex)
				setLoggedInIndicatorResponse, setLoggedInIndicatorResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &setLoggedInIndicatorBody, &setLoggedInIndicatorPath)
				if setLoggedInIndicatorResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", setLoggedInIndicatorResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				_, DiscardsetLoggedInIndicatorResponseErr := io.Copy(ioutil.Discard, setLoggedInIndicatorResponse.Body) // WE READ THE BODY
				if DiscardsetLoggedInIndicatorResponseErr != nil {
					//return nil, DiscardErr
				}
				setLoggedInIndicatorResponse.Body.Close()
				setLoggedOutIndicatorBody := contextId + "&loggedOutIndicatorRegex=" + url.QueryEscape(OwaspZapConfig.WebappLoggedOutindicatorregex)
				setLoggedOutIndicatorResponse, setLoggedOutIndicatorResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &setLoggedOutIndicatorBody, &setLoggedOutIndicatorPath)
				if setLoggedOutIndicatorResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", setLoggedOutIndicatorResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				_, DiscardsetLoggedOutIndicatorResponseErr := io.Copy(ioutil.Discard, setLoggedOutIndicatorResponse.Body) // WE READ THE BODY
				if DiscardsetLoggedOutIndicatorResponseErr != nil {
					//return nil, DiscardErr
				}
				setLoggedOutIndicatorResponse.Body.Close()
				spiderScanBody := "url=" + OwaspZapConfig.WebappRooturl + "&recurse=true&" + contextId + "&userId=" + newUserResp.UserId
				spiderScanResponse, spiderScanResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &spiderScanBody, &spiderScanAsUserPath)
				if spiderScanResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", spiderScanResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				spiderScanResp := SpiderScanResponse{}
				spiderScanResponseBody, spiderScanResponseBodyError := ioutil.ReadAll(spiderScanResponse.Body)
				if spiderScanResponseBodyError != nil {
					//return nil, RespBodyError
				}
				spiderScanResponse.Body.Close()
				spiderScanRespBody := string(spiderScanResponseBody)
				spiderScanJsonError := json.Unmarshal([]byte(spiderScanRespBody), &spiderScanResp)
				if spiderScanJsonError != nil {
					//return nil, nil, jsonError
				}
				fullSpiderScanStatusPath := spiderScanStatusPath + spiderScanResp.ScanAsUser
				for {
					spiderScanStatusResp := SpiderScanStatusResponse{}
					checkScanStatusResponse, checkScanStatusResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, nil, &fullSpiderScanStatusPath)
					if checkScanStatusResponseError != nil {
						cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
						cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
						err := fmt.Errorf("owaspzap error %v", checkScanStatusResponseError)
						if sentry.CurrentHub().Client() != nil {
							sentry.CaptureException(err)
						}
						log.Println(err)
						cli.Close()
						return
					}
					spiderScanStatusResponseBody, spiderScanStatusResponseBodyError := ioutil.ReadAll(checkScanStatusResponse.Body)
					if spiderScanStatusResponseBodyError != nil {
						//return nil, RespBodyError
					}
					checkScanStatusResponse.Body.Close()
					spiderScanStatusRespBody := string(spiderScanStatusResponseBody)
					spiderScanJsonError := json.Unmarshal([]byte(spiderScanStatusRespBody), &spiderScanStatusResp)
					if spiderScanJsonError != nil {
						//return nil, nil, jsonError
					}
					if spiderScanStatusResp.Status == "100" {
						break
					}
					if spiderScanStatusResp.Code != "" {
						break
					}
					time.Sleep(30 * time.Second)

				}
				activeScanBody := "url=" + OwaspZapConfig.WebappRooturl + "&recurse=true&scanPolicyName=&method=&postData=&" + contextId + "&userId=" + newUserResp.UserId
				activeScanResponse, activeScanResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, &activeScanBody, &activeScanAsUserPath)
				if activeScanResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", activeScanResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				activeScanResp := SpiderScanResponse{}
				activeScanResponseBody, activeScanResponseBodyError := ioutil.ReadAll(activeScanResponse.Body)
				if activeScanResponseBodyError != nil {
					//return nil, RespBodyError
				}
				activeScanResponse.Body.Close()
				activeScanRespBody := string(activeScanResponseBody)
				activeScanJsonError := json.Unmarshal([]byte(activeScanRespBody), &activeScanResp)
				if activeScanJsonError != nil {
					//return nil, nil, jsonError
				}
				fullActiveScanStatusPath := activeScanStatusPath + activeScanResp.ScanAsUser
				for {
					activeScanStatusResp := SpiderScanStatusResponse{}
					checkActiveScanStatusResponse, checkActiveScanStatusResponseError := Communicate(&postMethod, &owaspZapHost, &apiPort, nil, &fullActiveScanStatusPath)
					if checkActiveScanStatusResponseError != nil {
						cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
						cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
						err := fmt.Errorf("owaspzap error %v", checkActiveScanStatusResponseError)
						if sentry.CurrentHub().Client() != nil {
							sentry.CaptureException(err)
						}
						log.Println(err)
						cli.Close()
						return
					}
					activeScanStatusResponseBody, activeScanStatusResponseBodyError := ioutil.ReadAll(checkActiveScanStatusResponse.Body)
					if activeScanStatusResponseBodyError != nil {
						//return nil, RespBodyError
					}
					checkActiveScanStatusResponse.Body.Close()
					activeScanStatusRespBody := string(activeScanStatusResponseBody)
					activeScanJsonError := json.Unmarshal([]byte(activeScanStatusRespBody), &activeScanStatusResp)
					if activeScanJsonError != nil {
						//return nil, nil, jsonError
					}
					if activeScanStatusResp.Status == "100" {
						break
					}
					if activeScanStatusResp.Code != "" {
						break
					}
					i, strconvErr := strconv.Atoi(activeScanStatusResp.Status)
					if strconvErr != nil {
						err := fmt.Errorf("owaspzap error %v", strconvErr)
						if sentry.CurrentHub().Client() != nil {
							sentry.CaptureException(err)
						}
						log.Println(err)
						cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
						cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
						return
					}
					_, updateError2 := tasksCollection.UpdateOne(context.TODO(),
						bson.D{{"_id", *taskId}},
						bson.D{{"$set", bson.D{{"percent", i}}}},
					)
					if updateError2 != nil {
						err := fmt.Errorf("owaspzap error %v", updateError2)
						if sentry.CurrentHub().Client() != nil {
							sentry.CaptureException(err)
						}
						log.Println(err)
						cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
						cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
						return
					}
					time.Sleep(30 * time.Second)
				}
				getJsonReportResponse, getJsonReportResponseError := Communicate(&getMethod, &owaspZapHost, &apiPort, nil, &jsonReportPath)
				if getJsonReportResponseError != nil {
					cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
					cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
					err := fmt.Errorf("owaspzap error %v", getJsonReportResponseError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					cli.Close()
					return
				}
				jsonReportByteValue, jsonReportByteValueError := ioutil.ReadAll(getJsonReportResponse.Body)
				getJsonReportResponse.Body.Close()
				if jsonReportByteValueError != nil {
					err := fmt.Errorf("owaspzap scan ioutil error %v", jsonReportByteValueError)
					if sentry.CurrentHub().Client() != nil {
						sentry.CaptureException(err)
					}
					log.Println(err)
					docker.RemoveContainers(idArray)
					MongoClient.Disconnect(context.TODO())
					cli.Close()
					return
				}
				if len(jsonReportByteValue) > 0 {
					result := base64.StdEncoding.EncodeToString(jsonReportByteValue)
					results = append(results, result)
				}
			}
		}
	}
	_, update2Error := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", taskId}},
		bson.D{{"$set", bson.D{
			{"owasp_zap_result", results},
			{"status", "SUCCESS"},
			{"percent", 100}}}},
	)
	if update2Error != nil {
		err := fmt.Errorf("owasp zap scan error %v", update2Error)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	cli.ContainerStop(context.Background(), *OwaspZapContainer, nil)
	cli.ContainerRemove(context.Background(), *OwaspZapContainer, types.ContainerRemoveOptions{})
	cli.Close()
	MongoClient.Disconnect(context.TODO())
	return
}

func getTechArray(owaspZapConfig *database.OwaspZapConfig) (TechList *[]string) {
	var techList []string
	if owaspZapConfig.WebappMysql == true {
		techList = append(techList, "DB.MySQL")
	}
	if owaspZapConfig.WebappPostgresql == true {
		techList = append(techList, "Db.PostgreSQL")
	}
	if owaspZapConfig.WebappMssql == true {
		techList = append(techList, "Db.Microsoft SQL Server")
	}
	if owaspZapConfig.WebappOracle == true {
		techList = append(techList, "Db.Oracle")
	}
	if owaspZapConfig.WebappSqlite == true {
		techList = append(techList, "DB.SQLite")
	}
	if owaspZapConfig.WebappFirebird == true {
		techList = append(techList, "DB.Firebird")
	}
	if owaspZapConfig.WebappMaxdb == true {
		techList = append(techList, "DB.SAP MaxDB")
	}
	if owaspZapConfig.WebappDb2 == true {
		techList = append(techList, "DB.IBM DB2")
	}
	if owaspZapConfig.WebappHypersonicsql == true {
		techList = append(techList, "DB.HypersonicSQL")
	}
	if owaspZapConfig.WebappCouchdb == true {
		techList = append(techList, "DB.CouchDB")
	}
	if owaspZapConfig.WebappAsp == true {
		techList = append(techList, "Language.ASP")
	}
	if owaspZapConfig.WebappC == true {
		techList = append(techList, "Language.C")
	}
	if owaspZapConfig.WebappJava == true {
		techList = append(techList, "Language.Java")
	}
	if owaspZapConfig.WebappJavaScript == true {
		techList = append(techList, "Language.JavaScript")
	}
	if owaspZapConfig.WebappJsp == true {
		techList = append(techList, "Language.JSP/Servlet")
	}
	if owaspZapConfig.WebappPhp == true {
		techList = append(techList, "Language.PHP")
	}
	if owaspZapConfig.WebappPython == true {
		techList = append(techList, "Language.Python")
	}
	if owaspZapConfig.WebappRuby == true {
		techList = append(techList, "Language.Ruby")
	}
	if owaspZapConfig.WebappXml == true {
		techList = append(techList, "Language.XML")
	}
	if owaspZapConfig.WebappLinux == true {
		techList = append(techList, "OS.Linux")
	}
	if owaspZapConfig.WebappMacos == true {
		techList = append(techList, "OS.MacOS")
	}
	if owaspZapConfig.WebappWindows == true {
		techList = append(techList, "OS.Windows")
	}
	if owaspZapConfig.WebappGit == true {
		techList = append(techList, "SCM.Git")
	}
	if owaspZapConfig.WebappSvn == true {
		techList = append(techList, "SCM.SVN")
	}
	if owaspZapConfig.WebappApache == true {
		techList = append(techList, "WS.Apache")
	}
	if owaspZapConfig.WebappIis == true {
		techList = append(techList, "WS.IIS")
	}
	if owaspZapConfig.WebappTomcat == true {
		techList = append(techList, "WS.Tomcat")
	}
	return &techList
}

func Communicate(method *string, ipAddress *string, apiPort *string, body *string, path *string) (*http.Response, error) {
	//proxyStr := "http://127.0.0.1:8080"
	//proxyURL, ProxyURLErr := url.Parse(proxyStr)
	//if ProxyURLErr != nil {
	//	return &http.Response{}, ProxyURLErr
	//}
	//creating the URL to be loaded through the proxy
	urlStr := "http://" + *ipAddress + ":" + *apiPort + *path
	scannersUrl, ScannersUrlErr := url.Parse(urlStr)
	if ScannersUrlErr != nil {
		return nil, ScannersUrlErr
	}
	//adding the proxy settings to the Transport object
	transport := &http.Transport{
		//Proxy: http.ProxyURL(proxyURL),
		//TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	//adding the Transport object to the http Client
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 10,
	}
	//generating the HTTP GET request
	var b string
	if body != nil {
		b = *body
	}
	request, RequestErr := http.NewRequest(
		*method,
		scannersUrl.String(),
		bytes.NewBuffer([]byte(b)),
	)
	if RequestErr != nil {
		return nil, RequestErr
	}
	request.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	request.Header.Add("Content-type", "application/x-www-form-urlencoded")
	request.Header.Set("Connection", "close")
	request.Close = true
	response, ClientErr := httpClient.Do(request)
	if ClientErr != nil {
		return nil, ClientErr
	}
	return response, nil
}
