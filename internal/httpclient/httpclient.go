package httpclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func Request(baseURL *string, path *string, data *[]byte, method *string, contentType *string, token *string) (*http.Response, error) {
	proxyStr := "http://127.0.0.1:8081"
	proxyURL, ProxyURLErr := url.Parse(proxyStr)
	if ProxyURLErr != nil {
		return &http.Response{}, ProxyURLErr
	}
	//creating the URL to be loaded through the proxy
	urlStr := *baseURL + *path
	scannersUrl, ScannersUrlErr := url.Parse(urlStr)
	if ScannersUrlErr != nil {
		return nil, ScannersUrlErr
	}
	//adding the proxy settings to the Transport object
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
		bytes.NewBuffer(*data),
	)
	if RequestErr != nil {
		return nil, RequestErr
	}
	request.Header.Add("Content-Type", *contentType)
	request.Header.Set("Connection", "close")
	request.Close = true
	if *token != "" {
		var authToken = fmt.Sprintf("Bearer %s", *token)
		request.Header.Add("Authorization", authToken)
	}
	response, ClientErr := client.Do(request)
	if ClientErr != nil {
		return nil, ClientErr
	}
	return response, nil
}
