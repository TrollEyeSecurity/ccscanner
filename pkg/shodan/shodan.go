package shodan

import (
	"bytes"
	"net/http"
	"net/url"
	"time"
)

func LoopkupIp(ip *string, shodanKey *string) (*http.Response, error) {
	/*proxyStr := "http://localhost:8080"
	proxyURL, ProxyURLErr := url.Parse(proxyStr)
	if ProxyURLErr != nil {
		return &http.Response{}, ProxyURLErr
	}*/
	//creating the URL to be loaded through the proxy
	urlStr := "https://api.shodan.io/shodan/host/" + *ip + "?key=" + *shodanKey
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
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 10,
	}
	//generating the HTTP GET request
	var data []byte
	request, RequestErr := http.NewRequest(
		"GET",
		scannersUrl.String(),
		bytes.NewBuffer(data),
	)
	if RequestErr != nil {
		return nil, RequestErr
	}
	request.Header.Set("Connection", "close")
	request.Close = true
	response, ClientErr := client.Do(request)
	if ClientErr != nil {
		return nil, ClientErr
	}
	return response, nil
}
