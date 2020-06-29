package phonehome

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/CriticalSecurity/cc-scanner/internal/common"
	"net/http"
	"net/url"
	"os"
	"time"
)

func Link(baseURL string, linkToken string) (*LinkResp, error) {
	ld := common.LinkData{
		Token:    linkToken,
		Uuid:     *common.GetUuid(),
		Hostname: *common.GetFqdn(),
	}
	lr := LinkResp{}
	bytesRepresentation, BytesRepresentationErr := json.Marshal(&ld)
	if BytesRepresentationErr != nil {
		return &lr, BytesRepresentationErr
	}
	path := "/scanners/link"
	method := "POST"
	response, _ := HttpClientRequest(&baseURL, &path, bytesRepresentation, &method, &linkToken)
	if response == nil {
		fmt.Println("No response from server.")
		os.Exit(1)
	}
	if response.Status == "403 Forbidden" {
		fmt.Println("403 Forbidden, likely a bad key.")
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

func Communicate(baseUrl string, token string) (*CommunicateResp, error) {
	cr := CommunicateResp{}
	ScannerData, ScannerDataErr := common.GetScannerData()
	if ScannerDataErr != nil {
		return nil, ScannerDataErr
	}
	bytesRepresentation, BytesRepresentationErr := json.Marshal(*ScannerData)
	if BytesRepresentationErr != nil {
		return nil, BytesRepresentationErr
	}
	path := "/scanners/communicate"
	method := "POST"
	response, _ := HttpClientRequest(&baseUrl, &path, bytesRepresentation, &method, &token)
	if response == nil {
		fmt.Println("No response from server.")
		return &cr, nil
	}
	if response.Status == "403 Forbidden" {
		response.Body.Close()
		fmt.Println("403 Forbidden, likely a bad key.")
		return &cr, nil
	} else if response.Status == "500 Internal Server Error" {
		response.Body.Close()
		fmt.Println("500 Internal Server Error.")
		return &cr, nil
	} else if response.Status == "404 Not Found" {
		response.Body.Close()
		fmt.Println("404 Not Found.")
		return &cr, nil
	}
	NewDecoderError := json.NewDecoder(response.Body).Decode(&cr)
	if NewDecoderError != nil {
		response.Body.Close()
		fmt.Println("Can\"t decode response. (If using a proxy the host could be down)")
		return nil, NewDecoderError
	}
	response.Body.Close()
	return &cr, nil
}

func HttpClientRequest(baseURL *string, path *string, data []byte, method *string, token *string) (*http.Response, error) {
	/*proxyStr := "http://localhost:8080"
	proxyURL, ProxyURLErr := url.Parse(proxyStr)
	if ProxyURLErr != nil {
		return &http.Response{}, ProxyURLErr
	}*/
	//creating the URL to be loaded through the proxy
	urlStr := *baseURL + *path
	scannersUrl, ScannersUrlErr := url.Parse(urlStr)
	if ScannersUrlErr != nil {
		return nil, ScannersUrlErr
	}
	//adding the proxy settings to the Transport object
	transport := &http.Transport{
		// Proxy: http.ProxyURL(proxyURL),
	}
	//adding the Transport object to the http Client
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 20,
	}
	//generating the HTTP GET request
	request, RequestErr := http.NewRequest(
		*method,
		scannersUrl.String(),
		bytes.NewBuffer(data),
	)
	if RequestErr != nil {
		return nil, RequestErr
	}
	if *token != "" {
		var authToken = "Token " + *token
		request.Header.Add("Authorization", authToken)
		request.Header.Set("Connection", "close")
		request.Close = true
	}
	response, ClientErr := client.Do(request)
	if ClientErr != nil {
		return nil, ClientErr
	}
	return response, nil
}
