package phonehome

import (
	"encoding/json"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/common"
	"github.com/TrollEyeSecurity/ccscanner/internal/httpclient"
	"log"
	"os"
)

func Link(baseURL string, scannerGroupId string, orgId string) (*LinkResp, error) {
	ScannerData, ScannerDataErr := common.GetScannerDataWithoutTasks(true)
	if ScannerDataErr != nil {
		return nil, ScannerDataErr
	}
	ScannerData.ScannerGroupId = scannerGroupId
	ScannerData.OrgId = orgId
	lr := LinkResp{}
	bytesRepresentation, BytesRepresentationErr := json.Marshal(&ScannerData)
	if BytesRepresentationErr != nil {
		return &lr, BytesRepresentationErr
	}
	path := fmt.Sprintf("api/scanners/link")
	nilStr := ""
	method := "POST"
	contentType := "application/json"
	response, linkError := httpclient.Request(&baseURL, &path, &bytesRepresentation, &method, &contentType, &nilStr)
	if linkError != nil {
		fmt.Println(linkError)
		os.Exit(1)
	}
	if response == nil {
		fmt.Println("No response from server.")
		os.Exit(1)
	}
	if response.Status == "403 Forbidden" {
		fmt.Println("403 Forbidden, likely a bad key.")
		os.Exit(1)
	} else if response.Status == "401 Unauthorized" {
		response.Body.Close()
		fmt.Println("401 Unauthorized.")
		os.Exit(1)
	} else if response.Status == "500 Internal Server Error" {
		response.Body.Close()
		fmt.Println("500 Internal Server Error.")
		os.Exit(1)
	} else if response.Status == "404 Not Found" {
		response.Body.Close()
		fmt.Println("404 Not Found.")
		os.Exit(1)
	}
	NewDecoderError := json.NewDecoder(response.Body).Decode(&lr)
	if NewDecoderError != nil {
		response.Body.Close()
		return nil, NewDecoderError
	}
	response.Body.Close()
	return &lr, nil
}

func NewTasks(baseUrl *string, token *string, scannerGroupId string, orgId string) (*CommunicateResp, error) {
	cr := CommunicateResp{}
	ScannerData, ScannerDataErr := common.GetScannerDataWithoutTasks(false)
	if ScannerDataErr != nil {
		return nil, ScannerDataErr
	}
	ScannerData.OrgId = orgId
	ScannerData.ScannerGroupId = scannerGroupId
	bytesRepresentation, BytesRepresentationErr := json.Marshal(*ScannerData)
	if BytesRepresentationErr != nil {
		return nil, BytesRepresentationErr
	}
	path := "api/scanners/new_tasks"
	method := "POST"
	contentType := "application/json"
	response, linkError := httpclient.Request(baseUrl, &path, &bytesRepresentation, &method, &contentType, token)
	if linkError != nil {
		fmt.Println(linkError)
		return nil, nil
	}
	if response == nil {
		fmt.Println("No response from server.")
		return nil, nil
	}
	if response.Status == "403 Forbidden" {
		response.Body.Close()
		fmt.Println("403 Forbidden, likely a bad key.")
		return nil, nil
	} else if response.Status == "500 Internal Server Error" {
		response.Body.Close()
		fmt.Println("500 Internal Server Error.")
		return nil, nil
	} else if response.Status == "404 Not Found" {
		response.Body.Close()
		fmt.Println("404 Not Found.")
		return nil, nil
	} else if response.Status == "401 Unauthorized" {
		response.Body.Close()
		fmt.Println("401 Unauthorized - You may want to re-link to Command Center")
		return nil, nil
	}
	NewDecoderError := json.NewDecoder(response.Body).Decode(&cr)
	if NewDecoderError != nil {
		response.Body.Close()
		err := fmt.Errorf("can't decode response. %v - %v", NewDecoderError, response.StatusCode)
		log.Println(err)
		return nil, err
	}
	response.Body.Close()
	return &cr, nil
}

func CompletedTasks(baseUrl *string, token *string, scannerGroupId string, orgId string) (*CompletedTasksResp, *[]string, error) {
	cr := CompletedTasksResp{}
	ScannerData, ScannerDataErr := common.GetScannerDataWithTasks(false)
	if ScannerDataErr != nil {
		return nil, nil, ScannerDataErr
	}
	ScannerData.OrgId = orgId
	ScannerData.ScannerGroupId = scannerGroupId
	bytesRepresentation, BytesRepresentationErr := json.Marshal(*ScannerData)
	if BytesRepresentationErr != nil {
		return nil, nil, BytesRepresentationErr
	}
	path := "api/scanners/completed_tasks"
	method := "POST"
	contentType := "application/json"
	response, responseErr := httpclient.Request(baseUrl, &path, &bytesRepresentation, &method, &contentType, token)
	if responseErr != nil {
		fmt.Println(responseErr)
		return nil, nil, responseErr
	}
	if response == nil {
		fmt.Println("No response from server.")
		return nil, nil, nil
	}
	defer response.Body.Close()
	if response.Status == "403 Forbidden" {
		fmt.Println("403 Forbidden, likely a bad key.")
		return nil, nil, nil
	} else if response.Status == "500 Internal Server Error" {
		fmt.Println("500 Internal Server Error.")
		return nil, nil, nil
	} else if response.Status == "404 Not Found" {
		fmt.Println("404 Not Found.")
		return nil, nil, nil
	} else if response.Status == "401 Unauthorized" {
		fmt.Println("401 Unauthorized - You may want to re-link to Command Center")
		return nil, nil, nil
	}
	NewDecoderError := json.NewDecoder(response.Body).Decode(&cr)
	if NewDecoderError != nil {
		err := fmt.Errorf("can't decode response. %v - %v", NewDecoderError, response.StatusCode)
		log.Println(err)
		return nil, nil, err
	}
	var doneTasks []string
	for _, task := range ScannerData.Tasks {
		if task.Status == "SUCCESS" {
			doneTasks = append(doneTasks, task.TaskId)
		}
	}
	return &cr, &doneTasks, nil
}
