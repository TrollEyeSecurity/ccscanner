package database

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net"
)

type ConfigFields struct {
	ID      string `bson:"_id" json:"id,omitempty"`
	BaseURL string `json:"baseurl"`
	Auth    Auth   `json:"auth"`
	Mode    string `json:"mode"`
}

type Auth struct {
	Secret   string `bson:"secret" json:"secret"`
	AuthUrl  string `bson:"authUrl" json:"authUrl"`
	ClientId string `bson:"clientId" json:"clientId"`
}

type Task struct {
	ID                primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Name              string             `json:"name"`
	TaskId            int64              `bson:"task_id" json:"task_id"`
	TaskType          string             `bson:"task_type" json:"task_type"`
	Status            string             `json:"status"`
	ContainerId       string             `bson:"container_id" json:"container_id"`
	Content           TaskContent        `json:"content"`
	SecretData        TaskSecret         `bson:"secret_data" json:"secret_data"`
	NmapResults       string             `bson:"nmap_results" json:"nmap_results"`
	OpenvasResults    string             `bson:"openvas_results" json:"openvas_results"`
	OwaspZapResults   []ZapResults       `bson:"owasp_zap_results" json:"owasp_zap_results"`
	SastResults       SastResults        `bson:"sast_results" json:"sast_results"`
	NetReconResults   string             `bson:"net_recon_results" json:"net_recon_results"`
	OpenvasTaskId     string             `bson:"openvas_task_id" json:"openvas_task_id"`
	UrlInsResults     []UrlData          `bson:"url_ins_results" json:"url_ins_results"`
	ScreenShotResults []string           `bson:"screen_shot_results" json:"screen_shot_results"`
	NameInfo          string             `bson:"name_info" json:"name_info"`
	ServiceUrlData    string             `bson:"service_url_data" json:"service_url_data"`
	Percent           int                `json:"percent"`
	SshPort           string             `bson:"ssh_port" json:"ssh_port"`
}

type ZapResults struct {
	AppId int    `bson:"app_id" json:"app_id"`
	Data  string `bson:"data" json:"data"`
}

type TaskContent struct {
	IntegrationType string       `bson:"integration_type" json:"integration_type"`
	ProjectName     string       `bson:"project_name" json:"project_name"`
	Repourl         string       `bson:"repourl" json:"repourl"`
	BranchName      string       `bson:"branch_name" json:"branch_name"`
	Function        string       `bson:"function" json:"function"`
	Tech            string       `bson:"tech" json:"tech"`
	Args            TaskArg      `bson:"args" json:"args"`
	DastConfigList  []DastConfig `bson:"dast_config_list" json:"dast_config_list"`
	Ip              net.IP       `bson:"ip" json:"ip"`
	Port            int          `bson:"port" json:"port"`
	Hostname        string       `bson:"hostname" json:"hostname"`
	Api             bool         `bson:"api" json:"api"`
	Tls             bool         `bson:"tls" json:"tls"`
	Ssh             bool         `bson:"ssh" json:"ssh"`
}

type TaskSecret struct {
	Repouser      string     `bson:"repouser" json:"repouser"`
	SnykSecret    SnykSecret `bson:"snyk_secret" json:"snyk_secret"`
	Username      string     `bson:"username" json:"username"`
	Password      string     `bson:"password" json:"password"`
	Token         string     `bson:"token" json:"token"`
	Key           string     `bson:"key" json:"key"`
	Secret        string     `bson:"secret" json:"secret"`
	FortiosApiKey string     `bson:"fortios_api_key" json:"fortios_api_key"`
}

type SnykSecret struct {
	SnykApiKey string `bson:"snyk_api_key" json:"snyk_api_key"`
	SnykOrgId  string `bson:"snyk_org_id" json:"snyk_org_id"`
}

type TaskArg struct {
	NmapParams    string              `json:"nmap_params"`
	Hosts         string              `json:"hosts"`
	Excludes      string              `json:"excludes"`
	Dns           []string            `json:"dns"`
	Urls          Urls                `bson:"urls" json:"urls"`
	Configuration string              `json:"configuration"`
	DisabledNvts  map[string][]string `bson:"disabled_nvts" json:"disabled_nvts"`
}

type Urls struct {
	WebappId string   `bson:"webapp_id" json:"webapp_id"`
	UrlList  []string `bson:"url_list" json:"url_list"`
}

type Result struct {
	TaskId int64  `bson:"task_id" json:"task_id"`
	Result string `json:"result"`
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
	Error      string     `bson:"error,omitempty" json:"error,omitempty"`
	SnykOutput SnykOutput `bson:"snyk_output" json:"snyk_output"`
}

type SnykOutput struct {
	CodeResults           string `bson:"code_results" json:"code_results"`
	OpenSourceResults     string `bson:"open_source_results" json:"open_source_results"`
	CodeResultsFile       string `bson:"code_results_file" json:"code_results_file"`
	OpenSourceResultsFile string `bson:"open_source_results_file" json:"open_source_results_file"`
}

type DastConfig struct {
	WebappName                    string   `bson:"webapp_name" json:"webapp_name"`
	WebappAka                     string   `bson:"webapp_aka" json:"webapp_aka"`
	WebappRooturl                 string   `bson:"webapp_rooturl" json:"webapp_rooturl"`
	WebappZapContext              string   `bson:"webapp_zap_context" json:"webapp_zap_context"`
	WebappMysql                   bool     `bson:"webapp_mysql" json:"webapp_mysql"`
	WebappPostgresql              bool     `bson:"webapp_postgresql" json:"webapp_postgresql"`
	WebappMssql                   bool     `bson:"webapp_mssql" json:"webapp_mssql"`
	WebappOracle                  bool     `bson:"webapp_oracle" json:"webapp_oracle"`
	WebappSqlite                  bool     `bson:"webapp_sqlite" json:"webapp_sqlite"`
	WebappAccess                  bool     `bson:"webapp_access" json:"webapp_access"`
	WebappFirebird                bool     `bson:"webapp_firebird" json:"webapp_firebird"`
	WebappMaxdb                   bool     `bson:"webapp_maxdb" json:"webapp_maxdb"`
	WebappSybase                  bool     `bson:"webapp_sybase" json:"webapp_sybase"`
	WebappDb2                     bool     `bson:"webapp_db2" json:"webapp_db2"`
	WebappHypersonicsql           bool     `bson:"webapp_hypersonicsql" json:"webapp_hypersonicsql"`
	WebappMongodb                 bool     `bson:"webapp_mongodb" json:"webapp_mongodb"`
	WebappCouchdb                 bool     `bson:"webapp_couchdb" json:"webapp_couchdb"`
	WebappAsp                     bool     `bson:"webapp_asp" json:"webapp_asp"`
	WebappC                       bool     `bson:"webapp_c" json:"webapp_c"`
	WebappJava                    bool     `bson:"webapp_java" json:"webapp_java"`
	WebappJavaSpring              bool     `bson:"webapp_java_spring" json:"webapp_java_spring"`
	WebappJavascript              bool     `bson:"webapp_javascript" json:"webapp_javascript"`
	WebappJsp                     bool     `bson:"webapp_jsp" json:"webapp_jsp"`
	WebappPhp                     bool     `bson:"webapp_php" json:"webapp_php"`
	WebappPython                  bool     `bson:"webapp_python" json:"webapp_python"`
	WebappRuby                    bool     `bson:"webapp_ruby" json:"webapp_ruby"`
	WebappXML                     bool     `bson:"webapp_xml" json:"webapp_xml"`
	WebappLinux                   bool     `bson:"webapp_linux" json:"webapp_linux"`
	WebappMacos                   bool     `bson:"webapp_macos" json:"webapp_macos"`
	WebappWindows                 bool     `bson:"webapp_windows" json:"webapp_windows"`
	WebappGit                     bool     `bson:"webapp_git" json:"webapp_git"`
	WebappSvn                     bool     `bson:"webapp_svn" json:"webapp_svn"`
	WebappApache                  bool     `bson:"webapp_apache" json:"webapp_apache"`
	WebappIis                     bool     `bson:"webapp_iis" json:"webapp_iis"`
	WebappTomcat                  bool     `bson:"webapp_tomcat" json:"webapp_tomcat"`
	WebappNginx                   bool     `bson:"webapp_nginx" json:"webapp_nginx"`
	WebappUrlregex                string   `bson:"webapp_urlregex" json:"webapp_urlregex"`
	WebappAuthmethod              string   `bson:"webapp_authmethod" json:"webapp_authmethod"`
	WebappLoginurl                string   `bson:"webapp_loginurl" json:"webapp_loginurl"`
	WebappLoginrequestdata        string   `bson:"webapp_loginrequestdata" json:"webapp_loginrequestdata"`
	WebappLoggedinindicatorregex  string   `bson:"webapp_loggedinindicatorregex" json:"webapp_loggedinindicatorregex"`
	WebappLoggedoutindicatorregex string   `bson:"webapp_loggedoutindicatorregex" json:"webapp_loggedoutindicatorregex"`
	WebappUsers                   []string `bson:"webapp_users" json:"webapp_users"`
	SecretList                    []string `bson:"secret_list" json:"secret_list"`
	ID                            int      `bson:"id" json:"id"`
	MaxChildren                   int      `bson:"max_children" json:"max_children"`
	UrlList                       []string `bson:"url_list" json:"url_list"`
}
