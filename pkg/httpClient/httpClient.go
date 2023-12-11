package httpClient

import (
	"bytes"
	"net/http"
	"net/url"
	"time"
)

func Request(baseURL *string, path *string, data *[]byte, method *string, contentType *string, headerKv *map[string]string) (*http.Response, error) {

	/*
		proxyStr := "http://127.0.0.1:8080"
		proxyURL, ProxyURLErr := url.Parse(proxyStr)
		if ProxyURLErr != nil {
			return &http.Response{}, ProxyURLErr
		}
	*/
	urlStr := *baseURL + *path
	cleanUrl, cleanUrlErr := url.Parse(urlStr)
	if cleanUrlErr != nil {
		return nil, cleanUrlErr
	}
	transport := &http.Transport{
		//Proxy:           http.ProxyURL(proxyURL),
		//TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	myClient := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 45,
	}
	//generating the HTTP GET request
	if data == nil {
		data = &[]byte{}
	}
	request, RequestErr := http.NewRequest(
		*method,
		cleanUrl.String(),
		bytes.NewBuffer(*data),
	)
	if RequestErr != nil {
		return nil, RequestErr
	}
	request.Header.Add("Content-Type", *contentType)
	request.Header.Set("Connection", "close")
	if len(*headerKv) > 0 {
		for k, v := range *headerKv {
			request.Header.Set(k, v)
		}
	}
	request.Close = true
	response, ClientErr := myClient.Do(request)
	if ClientErr != nil {
		return nil, ClientErr
	}
	return response, nil
}
