package auth

import (
	"encoding/json"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/httpclient"
)

func GetToken(authUrl *string, authSecret *string, clientId *string) (*string, *error) {
	auth := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s",
		*clientId,
		*authSecret,
	)
	authBytes := []byte(auth)
	method := "POST"
	contentType := "application/x-www-form-urlencoded"
	nilStr := ""
	results, httpErr := httpclient.Request(authUrl, &nilStr, &authBytes, &method, &contentType, &nilStr)
	if httpErr != nil {
		return nil, &httpErr
	}
	defer results.Body.Close()
	var authResponse AuthResponse
	json.NewDecoder(results.Body).Decode(&authResponse)
	return &authResponse.AccessToken, nil
}
