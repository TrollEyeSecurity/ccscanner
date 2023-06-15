package bitBucket

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func GetToken(secretData *database.TaskSecret) *string {
	b := []byte("grant_type=client_credentials")
	auth := base64.StdEncoding.EncodeToString([]byte(secretData.Key + ":" + secretData.Secret))
	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}
	req, NewRequestErr := http.NewRequest("POST", "https://bitbucket.org/site/oauth2/access_token", bytes.NewReader(b))
	if NewRequestErr != nil {
		log.Println(NewRequestErr)
		return nil
	}
	req.Header.Add("Authorization", "Basic "+auth)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Connection", "close")
	req.Close = true
	resp, httpClientErr := httpClient.Do(req)
	if httpClientErr != nil {
		log.Println(httpClientErr)
		return nil
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Print(err.Error())
	}
	var responseObject Response
	json.Unmarshal(bodyBytes, &responseObject)
	return &responseObject.AccessToken
}
