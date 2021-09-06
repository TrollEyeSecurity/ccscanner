package phonehome

import "github.com/TrollEyeSecurity/ccscanner/internal/database"

type CommunicateResp struct {
	NewTasks     []database.Task   `json:"new_tasks"`
	Results      []database.Result `json:"results"`
	AllowedUsers [][]string        `json:"allowed_users"`
	Ovpn         OvpnConfig        `json:"ovpn"`
}

type LinkResp struct {
	Token  string `json:"token"`
	Shodan string `json:"shodan"`
	Otx    string `json:"otx"`
}

type OvpnConfig struct {
	OvpnConnect bool   `json:"ovpn_connect"`
	OvpnConfig  string `json:"ovpn_config"`
}
