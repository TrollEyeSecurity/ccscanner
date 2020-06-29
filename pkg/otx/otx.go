package otx

import (
	"bytes"
	"net"
	"net/http"
	"net/url"
	"time"
)

func GetIpReputation(ip *string, otxKey *string) (*http.Response, error){
	/*proxyStr := "http://localhost:8080"
	proxyURL, ProxyURLErr := url.Parse(proxyStr)
	if ProxyURLErr != nil {
		return &http.Response{}, ProxyURLErr
	}*/
	//creating the URL to be loaded through the proxy
	IPAddress := net.ParseIP(*ip)
	var version string
	if IPAddress.To4() != nil{
		version = "4"
	} else {
		version = "6"
	}
	urlStr := "https://otx.alienvault.com/api/v1/indicators/IPv" + version + "/" + *ip + "/" +"reputation"
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
		Timeout: time.Second * 10,
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
	request.Header.Add("X-OTX-API-KEY", *otxKey)
	response, ClientErr := client.Do(request)
	if ClientErr != nil {
		return nil, ClientErr
	}
	return response, nil
}