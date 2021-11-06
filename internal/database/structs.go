package database

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ConfigFields struct {
	ID      primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	BaseURL string             `json:"baseurl"`
	Token   string             `json:"token"`
	Mode    string             `json:"mode"`
}

/*
{
	"name": "Nmap Host Discovery SERVER_SG:1588877954",
	"task_id": 984369,
	"task_type": "task",
	"scan_id": 984383,
	"content": {"function": "nmap_host_discovery", "args": [{"nmap_params": "-sn -T4", "hosts": "string"}]}}
*/

type Task struct {
	ID               primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Name             string             `json:"name"`
	TaskId           int64              `bson:"task_id" json:"task_id"`
	Status           string             `json:"status"`
	ContainerId      string             `bson:"container_id" json:"container_id"`
	Content          TaskContent        `json:"content"`
	SecretData       TaskSecret         `bson:"secret_data" json:"secret_data"`
	NmapResult       string             `bson:"nmap_result" json:"nmap_result"`
	OpenvasResult    string             `bson:"openvas_result" json:"openvas_result"`
	OwaspZapResult   string             `bson:"owasp_zap_result" json:"owasp_zap_result"`
	SastResult       SastResults        `bson:"sast_result" json:"sast_result"`
	OpenvasTaskId    string             `bson:"openvas_task_id" json:"openvas_task_id"`
	DnsResult        []DnsResults       `bson:"dns_result" json:"dns_result"`
	OsintResult      []OsintResults     `bson:"osint_result" json:"osint_result"`
	UrlInsResult     []UrlData          `bson:"url_ins_result" json:"url_ins_result"`
	ScreenShotResult []string           `bson:"screen_shot_result" json:"screen_shot_result"`
	NameInfo         string             `bson:"name_info" json:"name_info"`
	ServiceUrlData   string             `bson:"service_url_data" json:"service_url_data"`
	Percent          int                `json:"percent"`
	SshPort          string             `bson:"ssh_port" json:"ssh_port"`
}

/*
{
	"function": "nmap_host_discovery",
	"args": [{"nmap_params": "-sn -T4", "hosts": "string"}]}}
*/

type TaskContent struct {
	IntegrationType string  `json:"integration_type"`
	ProjectName     string  `json:"project_name"`
	Repourl         string  `json:"repourl"`
	BranchName      string  `json:"branch_name"`
	Function        string  `json:"function"`
	Args            TaskArg `json:"args"`
}

type TaskSecret struct {
	Osint      OsintSecrets `bson:"osint" json:"osint"`
	Repouser   string       `bson:"repouser" json:"repouser"`
	SastSecret SastSecret   `bson:"sast_secret" json:"sast_secret"`
	Data       SecretData   `bson:"data" json:"data"`
}

type SecretData struct {
	Token  string `bson:"token" json:"token"`
	Key    string `bson:"key" json:"key"`
	Secret string `bson:"secret" json:"secret"`
}

type SastSecret struct {
	Sonarhosturl string `bson:"sonarhosturl" json:"sonarhosturl"`
	Sonarlogin   string `bson:"sonarlogin" json:"sonarlogin"`
}

type OsintSecrets struct {
	Otx    string `json:"otx"`
	Shodan string `bson:"shodan" json:"shodan"`
}

type TaskArg struct {
	NmapParams     string              `json:"nmap_params"`
	Hosts          string              `json:"hosts"`
	Excludes       string              `json:"excludes"`
	Dns            []string            `json:"dns"`
	Urls           Urls                `bson:"urls" json:"urls"`
	Configuration  string              `json:"configuration"`
	DastConfigList []string            `json:"dast_config_list"`
	DisabledNvts   map[string][]string `bson:"disabled_nvts" json:"disabled_nvts"`
}

type Urls struct {
	PortId   int64    `bson:"port_id" json:"port_id"`
	WebappId int64    `bson:"webapp_id" json:"webapp_id"`
	UrlList  []string `bson:"url_list" json:"url_list"`
}

type Result struct {
	TaskId int64  `bson:"task_id" json:"task_id"`
	Result string `json:"result"`
}

type DnsResults struct {
	DomainName   string   `bson:"domain_name" json:"domain_name"`
	DnsReconList string   `bson:"dns_recon_list" json:"dns_recon_list"`
	Dmarc        []string `bson:"dmarc" json:"dmarc"`
	Spf          []string `bson:"spf" json:"spf"`
	DnsSec       bool     `json:"dns_sec"`
}

type OsintResults struct {
	Host       string `bson:"host" json:"host"`
	ShodanData string `bson:"shodan_data" json:"shodan_data"`
	Reputation string `bson:"reputation" json:"reputation"`
}

type UrlData struct {
	FinalLocation string   `bson:"final_location" json:"final_location"`
	UrlList       []string `bson:"url_list" json:"url_list"`
	StatusCode    int      `bson:"status_code" json:"status_code"`
	Data          Data     `bson:"data" json:"data"`
}

type Data struct {
	Server      string `bson:"server" json:"server"`
	XPoweredBy  string `bson:"x_powered_by" json:"x_powered_by"`
	ContentType string `bson:"content_type" json:"content_type"`
	Title       string `bson:"title" json:"title"`
	UniqueId    string `bson:"unique_id" json:"unique_id"`
}

type FinalLocationUrlData struct {
	Title    string `json:"title"`
	Url      string `json:"url"`
	UniqueId string `json:"unique_id"`
}

type SastResults struct {
	SonarScanId              string `bson:"sonar_scan_id" json:"sonar_scan_id"`
	DependencyCheckerResults string `bson:"dependency_checker_results" json:"dependency_checker_results"`
	SonarOutput              string `bson:"sonar_output" json:"sonar_output"`
}
