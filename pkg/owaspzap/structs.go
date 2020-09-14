package owaspzap

type NewContextResponse struct {
	ContextId string `json:"contextId"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

type NewUserResponse struct {
	UserId  string `json:"userId"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type SpiderScanResponse struct {
	ScanAsUser string `json:"scanAsUser"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

type SpiderScanStatusResponse struct {
	Status  string `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
