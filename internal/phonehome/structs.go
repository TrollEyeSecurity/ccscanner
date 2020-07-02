package phonehome

import "github.com/CriticalSecurity/ccscanner/internal/database"

type CommunicateResp struct {
	NewTasks []database.Task   `json:"new_tasks"`
	Results  []database.Result `json:"results"`
}

type LinkResp struct {
	Token  string `json:"token"`
	Shodan string `json:"shodan"`
	Otx    string `json:"otx"`
}
