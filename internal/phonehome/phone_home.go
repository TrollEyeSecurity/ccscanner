package phonehome

import (
	"encoding/json"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/common"
	"github.com/TrollEyeSecurity/ccscanner/internal/httpclient"
	"log"
	"os"
)

func Link(baseURL string, linkToken string) (*LinkResp, error) {
	ScannerData, ScannerDataErr := common.GetScannerData(true)
	if ScannerDataErr != nil {
		return nil, ScannerDataErr
	}
	lr := LinkResp{}
	bytesRepresentation, BytesRepresentationErr := json.Marshal(&ScannerData)
	if BytesRepresentationErr != nil {
		return &lr, BytesRepresentationErr
	}
	path := "api/ccscanner/link"
	method := "POST"
	contentType := "application/json"
	response, linkError := httpclient.Request(&baseURL, &path, &bytesRepresentation, &method, &contentType, &linkToken)
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

func Communicate(baseUrl *string, token *string) (*CommunicateResp, error) {
	cr := CommunicateResp{}
	ScannerData, ScannerDataErr := common.GetScannerData(false)
	if ScannerDataErr != nil {
		return nil, ScannerDataErr
	}
	bytesRepresentation, BytesRepresentationErr := json.Marshal(*ScannerData)
	if BytesRepresentationErr != nil {
		return nil, BytesRepresentationErr
	}
	path := "api/ccscanner/communicate"
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
