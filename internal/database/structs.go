package database

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ConfigFields struct {
	ID      primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	BaseURL string             `json:"baseurl"`
	Token   string             `json:"token"`
}

/*
{
	"name": "Nmap Host Discovery FSLSO_SERVER_SG:1588877954",
	"task_id": 984369,
	"task_type": "task",
	"scan_id": 984383,
	"content": {"function": "nmap_host_discovery", "args": [{"nmap_params": "-sn -T4", "hosts": "string"}]}}
*/

type Task struct {
	ID                primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Name              string             `json:"name"`
	TaskId            int64              `bson:"task_id" json:"task_id"`
	Status            string             `json:"status"`
	ContainerId       string             `bson:"container_id" json:"container_id"`
	Content           TaskContent        `json:"content"`
	SecretData        TaskSecret         `bson:"secret_data" json:"secret_data"`
	NmapResult        string             `bson:"nmap_result" json:"nmap_result"`
	OpenvasResult     string             `bson:"openvas_result" json:"openvas_result"`
	OpenvasTaskId     string             `bson:"openvas_task_id" json:"openvas_task_id"`
	DnsResult         []DnsResults       `bson:"dns_result" json:"dns_result"`
	OsintResult       []OsintResults     `bson:"osint_result" json:"osint_result"`
	NameInfo          string             `bson:"name_info" json:"name_info"`
	ServiceWebAppData string             `bson:"service_web_app_data" json:"service_web_app_data"`
	Percent           int                `json:"percent"`
	SshPort           string             `bson:"ssh_port" json:"ssh_port"`
}

/*
{
	"function": "nmap_host_discovery",
	"args": [{"nmap_params": "-sn -T4", "hosts": "string"}]}}
*/

type TaskContent struct {
	Function string  `json:"function"`
	Args     TaskArg `json:"args"`
}

type TaskSecret struct {
	Osint Secrets `bson:"osint" json:"osint"`
}

type Secrets struct {
	Otx    string `json:"otx"`
	Shodan string `bson:"shodan" json:"shodan"`
}

type TaskArg struct {
	NmapParams    string              `json:"nmap_params"`
	Hosts         string              `json:"hosts"`
	Excludes      string              `json:"excludes"`
	Dns           []string            `json:"dns"`
	Configuration string              `json:"configuration"`
	DisabledNvts  map[string][]string `bson:"disabled_nvts" json:"disabled_nvts"`
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
