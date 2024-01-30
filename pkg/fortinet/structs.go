package fortinet

import "time"

type NetworkArpResponse struct {
	HttpMethod string      `json:"http_method"`
	Results    []ArpResult `json:"results"`
	Vdom       string      `json:"vdom"`
	Path       string      `json:"path"`
	Name       string      `json:"name"`
	Action     string      `json:"action"`
	Status     string      `json:"status"`
	Serial     string      `json:"serial"`
	Version    string      `json:"version"`
	Build      int         `json:"build"`
}

type ArpResult struct {
	Ip        string `json:"ip"`
	Age       int    `json:"age"`
	Mac       string `json:"mac"`
	Interface string `json:"interface"`
}

type NetworkRouterResponse struct {
	HttpMethod string          `json:"http_method"`
	Results    []NetworkResult `json:"results"`
	Vdom       string          `json:"vdom"`
	Path       string          `json:"path"`
	Name       string          `json:"name"`
	Action     string          `json:"action"`
	Status     string          `json:"status"`
	Serial     string          `json:"serial"`
	Version    string          `json:"version"`
	Build      int             `json:"build"`
}

type NetworkResult struct {
	IpVersion int    `json:"ip_version"`
	Type      string `json:"type"`
	IpMask    string `json:"ip_mask"`
	Distance  int    `json:"distance"`
	Metric    int    `json:"metric"`
	Priority  int    `json:"priority"`
	Vrf       int    `json:"vrf"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
}

type SystemInterfaces struct {
	HttpMethod string                     `json:"http_method"`
	Results    map[string]SystemInterface `json:"results"`
	Vdom       string                     `json:"vdom"`
	Path       string                     `json:"path"`
	Name       string                     `json:"name"`
	Action     string                     `json:"action"`
	Status     string                     `json:"status"`
	Serial     string                     `json:"serial"`
	Version    string                     `json:"version"`
	Build      int                        `json:"build"`
}

type SystemInterface struct {
	Id        string  `json:"id"`
	Name      string  `json:"name"`
	Alias     string  `json:"'alias'"`
	Mac       string  `json:"mac"`
	Ip        string  `json:"ip"`
	Mask      int     `json:"mask"`
	Link      bool    `json:"link"`
	Speed     float32 `json:"speed"`
	Duplex    int     `json:"duplex"`
	TxPackets int     `json:"tx_packets"`
	RxPackets int     `json:"rx_packets"`
	TxBytes   int     `json:"tx_bytes"`
	RxBytes   int     `json:"rx_bytes"`
	TxErrors  int     `json:"tx_errors"`
	RxErrors  int     `json:"rx_errors"`
}

type ApiKeySecret struct {
	FortiosApiKey string `json:"fortios_api_key"`
}

type SystemStatusResponse struct {
	HttpMethod string       `json:"http_method"`
	Results    SystemStatus `json:"results"`
	Vdom       string       `json:"vdom"`
	Path       string       `json:"path"`
	Name       string       `json:"name"`
	Action     string       `json:"action"`
	Status     string       `json:"status"`
	Serial     string       `json:"serial"`
	Version    string       `json:"version"`
	Build      int          `json:"build"`
}

type SystemStatus struct {
	ModelName     string `json:"model_name"`
	ModelNumber   string `json:"model_number"`
	Model         string `json:"model"`
	Hostname      string `json:"hostname"`
	LogDiskStatus string `json:"log_disk_status"`
}

type Subnet struct {
	SourceInterface string `bson:"source_interface" json:"source_interface"`
	Subnet          string `bson:"subnet" json:"subnet"`
	Public          bool   `bson:"public" json:"public"`
}

type PolicyResponse struct {
	HTTPMethod   string   `json:"http_method"`
	Size         int      `json:"size"`
	MatchedCount int      `json:"matched_count"`
	NextIdx      int      `json:"next_idx"`
	Revision     string   `json:"revision"`
	Results      []Policy `bson:"results" json:"results"`
	Vdom         string   `json:"vdom"`
	Path         string   `json:"path"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	HTTPStatus   int      `json:"http_status"`
	Serial       string   `json:"serial"`
	Version      string   `json:"version"`
	Build        int      `json:"build"`
}

type AddressResponse struct {
	HTTPMethod   string    `json:"http_method"`
	Size         int       `json:"size"`
	MatchedCount int       `json:"matched_count"`
	NextIdx      int       `json:"next_idx"`
	Revision     string    `json:"revision"`
	Results      []Address `json:"results"`
	Vdom         string    `json:"vdom"`
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	HTTPStatus   int       `json:"http_status"`
	Serial       string    `json:"serial"`
	Version      string    `json:"version"`
	Build        int       `json:"build"`
}

type Host struct {
	AdjacencyInterface string `json:"adjacency_interface"`
	HostAddress        string `json:"host_address"`
	MacAddress         string `json:"mac_address"`
	MacVendor          string `json:"mac_vendor"`
	Port               string `json:"port"`
	Type               string `json:"type"`
	Vlan               int    `json:"vlan"`
	Routes             string `json:"routes"`
	LatestShowRun      string `json:"latest_show_run"`
}

type System struct {
	SystemModel     string `json:"system_model"`
	SystemSerial    string `json:"system_serial"`
	SystemSwVersion string `json:"system_sw_version"`
	License         string `json:"license"`
	SystemType      string `json:"system_type"`
}

type SystemIp struct {
	Name            string    `bson:"name" json:"name"`
	ObjType         string    `bson:"obj_type,omitempty" json:"obj_type,omitempty"`
	LocationId      int64     `bson:"location_id" json:"location_id"`
	LineStatus      string    `bson:"line_status" json:"line_status"`
	Status          string    `bson:"status" json:"status"`
	StatusColor     string    `bson:"status_color" json:"status_color"`
	StatusFa        string    `bson:"status_fa" json:"status_fa"`
	SystemIpAddress string    `bson:"system_ip_address" json:"system_ip_address"`
	NetMask         string    `bson:"net_mask" json:"net_mask"`
	Zone            string    `bson:"zone" json:"zone"`
	Vlan            int       `bson:"vlan" json:"vlan"`
	Interface       string    `bson:"interface" json:"interface"`
	SecurityLevel   int       `bson:"security_level" json:"security_level"`
	LastSeen        time.Time `bson:"last_seen" json:"last_seen"`
}

type Policy struct {
	Policyid                       int                  `bson:"policyid" json:"policyid"`
	Status                         string               `bson:"status" json:"status"`
	Name                           string               `bson:"name" json:"name"`
	UUID                           string               `bson:"uuid" json:"uuid"`
	Srcintf                        []Interfaces         `bson:"srcintf" json:"srcintf"`
	Dstintf                        []Interfaces         `bson:"dstintf" json:"dstintf"`
	Action                         string               `bson:"action" json:"action"`
	Nat64                          string               `bson:"nat64" json:"nat64"`
	Nat46                          string               `bson:"nat46" json:"nat46"`
	ZtnaStatus                     string               `bson:"ztna-status" json:"ztna-status"`
	ZtnaDeviceOwnership            string               `bson:"ztna-device-ownership" json:"ztna-device-ownership"`
	Srcaddr                        []Addresses          `bson:"srcaddr" json:"srcaddr"`
	Dstaddr                        []Addresses          `bson:"dstaddr" json:"dstaddr"`
	Srcaddr6                       []Addresses          `bson:"srcaddr6" json:"srcaddr6"`
	Dstaddr6                       []Addresses          `bson:"dstaddr6" json:"dstaddr6"`
	ZtnaEmsTag                     []Tags               `bson:"ztna-ems-tag" json:"ztna-ems-tag"`
	ZtnaTagsMatchLogic             string               `bson:"ztna-tags-match-logic" json:"ztna-tags-match-logic"`
	ZtnaGeoTag                     []Tags               `bson:"ztna-geo-tag" json:"ztna-geo-tag"`
	InternetService                string               `bson:"internet-service" json:"internet-service"`
	InternetServiceName            []Addresses          `bson:"internet-service-name" json:"internet-service-name"`
	InternetServiceGroup           []Addresses          `bson:"internet-service-group" json:"internet-service-group"`
	InternetServiceCustom          []Addresses          `bson:"internet-service-custom" json:"internet-service-custom"`
	NetworkServiceDynamic          []Addresses          `bson:"network-service-dynamic" json:"network-service-dynamic"`
	InternetServiceCustomGroup     []Addresses          `bson:"internet-service-custom-group" json:"internet-service-custom-group"`
	InternetServiceSrc             string               `bson:"internet-service-src" json:"internet-service-src"`
	InternetServiceSrcName         []Addresses          `bson:"internet-service-src-name" json:"internet-service-src-name"`
	InternetServiceSrcGroup        []Addresses          `bson:"internet-service-src-group" json:"internet-service-src-group"`
	InternetServiceSrcCustom       []Addresses          `bson:"internet-service-src-custom" json:"internet-service-src-custom"`
	NetworkServiceSrcDynamic       []Addresses          `bson:"network-service-src-dynamic" json:"network-service-src-dynamic"`
	InternetServiceSrcCustomGroup  []Addresses          `bson:"internet-service-src-custom-group" json:"internet-service-src-custom-group"`
	ReputationMinimum              int                  `bson:"reputation-minimum" json:"reputation-minimum"`
	ReputationDirection            string               `bson:"reputation-direction" json:"reputation-direction"`
	SrcVendorMac                   []VendorMacAddresses `bson:"src-vendor-mac" json:"src-vendor-mac"`
	InternetService6               string               `bson:"internet-service-6" json:"internet-service6"`
	InternetService6Name           []Addresses          `bson:"internet-service-6-name" json:"internet-service6-name"`
	InternetService6Group          []Addresses          `bson:"internet-service-6-group" json:"internet-service6-group"`
	InternetService6Custom         []Addresses          `bson:"internet-service-6-custom" json:"internet-service6-custom"`
	InternetService6CustomGroup    []Addresses          `bson:"internet-service-6-custom-group" json:"internet-service6-custom-group"`
	InternetService6Src            string               `bson:"internet-service-6-src" json:"internet-service6-src"`
	InternetService6SrcName        []Addresses          `bson:"internet-service-6-src-name" json:"internet-service6-src-name"`
	InternetService6SrcGroup       []Addresses          `bson:"internet-service-6-src-group" json:"internet-service6-src-group"`
	InternetService6SrcCustom      []Addresses          `bson:"internet-service-6-src-custom" json:"internet-service6-src-custom"`
	InternetService6SrcCustomGroup []Addresses          `bson:"internet-service-6-src-custom-group" json:"internet-service6-src-custom-group"`
	ReputationMinimum6             int                  `bson:"reputation-minimum-6" json:"reputation-minimum6"`
	ReputationDirection6           string               `bson:"reputation-direction-6" json:"reputation-direction6"`
	RtpNat                         string               `bson:"rtp-nat" json:"rtp-nat"`
	RtpAddr                        []Addresses          `bson:"rtp-addr" json:"rtp-addr"`
	SendDenyPacket                 string               `bson:"send-deny-packet" json:"send-deny-packet"`
	FirewallSessionDirty           string               `bson:"firewall-session-dirty" json:"firewall-session-dirty"`
	Schedule                       string               `bson:"schedule" json:"schedule"`
	ScheduleTimeout                string               `bson:"schedule-timeout" json:"schedule-timeout"`
	PolicyExpiry                   string               `bson:"policy-expiry" json:"policy-expiry"`
	PolicyBehaviourType            string               `bson:"policy-behaviour-type" json:"policy-behaviour-type"`
	IPVersionType                  string               `bson:"ip-version-type" json:"ip-version-type"`
	PolicyExpiryDateUtc            string               `bson:"policy-expiry-date-utc" json:"policy-expiry-date-utc"`
	Service                        []Addresses          `bson:"service" json:"service"`
	Tos                            string               `bson:"tos" json:"tos"`
	TosMask                        string               `bson:"tos-mask" json:"tos-mask"`
	TosNegate                      string               `bson:"tos-negate" json:"tos-negate"`
	AntiReplay                     string               `bson:"anti-replay" json:"anti-replay"`
	TCPSessionWithoutSyn           string               `bson:"tcp-session-without-syn" json:"tcp-session-without-syn"`
	GeoipAnycast                   string               `bson:"geoip-anycast" json:"geoip-anycast"`
	GeoipMatch                     string               `bson:"geoip-match" json:"geoip-match"`
	DynamicShaping                 string               `bson:"dynamic-shaping" json:"dynamic-shaping"`
	PassiveWanHealthMeasurement    string               `bson:"passive-wan-health-measurement" json:"passive-wan-health-measurement"`
	UtmStatus                      string               `bson:"utm-status" json:"utm-status"`
	InspectionMode                 string               `bson:"inspection-mode" json:"inspection-mode"`
	HTTPPolicyRedirect             string               `bson:"http-policy-redirect" json:"http-policy-redirect"`
	SSHPolicyRedirect              string               `bson:"ssh-policy-redirect" json:"ssh-policy-redirect"`
	ZtnaPolicyRedirect             string               `bson:"ztna-policy-redirect" json:"ztna-policy-redirect"`
	WebproxyProfile                string               `bson:"webproxy-profile" json:"webproxy-profile"`
	ProfileType                    string               `bson:"profile-type" json:"profile-type"`
	ProfileGroup                   string               `bson:"profile-group" json:"profile-group"`
	ProfileProtocolOptions         string               `bson:"profile-protocol-options" json:"profile-protocol-options"`
	SslSSHProfile                  string               `bson:"ssl-ssh-profile" json:"ssl-ssh-profile"`
	AvProfile                      string               `bson:"av-profile" json:"av-profile"`
	WebfilterProfile               string               `bson:"webfilter-profile" json:"webfilter-profile"`
	DnsfilterProfile               string               `bson:"dnsfilter-profile" json:"dnsfilter-profile"`
	EmailfilterProfile             string               `bson:"emailfilter-profile" json:"emailfilter-profile"`
	DlpProfile                     string               `bson:"dlp-profile" json:"dlp-profile"`
	FileFilterProfile              string               `bson:"file-filter-profile" json:"file-filter-profile"`
	IpsSensor                      string               `bson:"ips-sensor" json:"ips-sensor"`
	ApplicationList                string               `bson:"application-list" json:"application-list"`
	VoipProfile                    string               `bson:"voip-profile" json:"voip-profile"`
	IpsVoipFilter                  string               `bson:"ips-voip-filter" json:"ips-voip-filter"`
	SctpFilterProfile              string               `bson:"sctp-filter-profile" json:"sctp-filter-profile"`
	IcapProfile                    string               `bson:"icap-profile" json:"icap-profile"`
	CifsProfile                    string               `bson:"cifs-profile" json:"cifs-profile"`
	VideofilterProfile             string               `bson:"videofilter-profile" json:"videofilter-profile"`
	WafProfile                     string               `bson:"waf-profile" json:"waf-profile"`
	SSHFilterProfile               string               `bson:"ssh-filter-profile" json:"ssh-filter-profile"`
	Logtraffic                     string               `bson:"logtraffic" json:"logtraffic"`
	LogtrafficStart                string               `bson:"logtraffic-start" json:"logtraffic-start"`
	CapturePacket                  string               `bson:"capture-packet" json:"capture-packet"`
	AutoAsicOffload                string               `bson:"auto-asic-offload" json:"auto-asic-offload"`
	NpAcceleration                 string               `bson:"np-acceleration" json:"np-acceleration"`
	WebproxyForwardServer          string               `bson:"webproxy-forward-server" json:"webproxy-forward-server"`
	TrafficShaper                  string               `bson:"traffic-shaper" json:"traffic-shaper"`
	TrafficShaperReverse           string               `bson:"traffic-shaper-reverse" json:"traffic-shaper-reverse"`
	PerIPShaper                    string               `bson:"per-ip-shaper" json:"per-ip-shaper"`
	Nat                            string               `bson:"nat" json:"nat"`
	PermitAnyHost                  string               `bson:"permit-any-host" json:"permit-any-host"`
	PermitStunHost                 string               `bson:"permit-stun-host" json:"permit-stun-host"`
	Fixedport                      string               `bson:"fixedport" json:"fixedport"`
	Ippool                         string               `bson:"ippool" json:"ippool"`
	Poolname                       []Addresses          `bson:"poolname" json:"poolname"`
	Poolname6                      []Addresses          `bson:"poolname-6" json:"poolname6"`
	SessionTTL                     string               `bson:"session-ttl" json:"session-ttl"`
	VlanCosFwd                     int                  `bson:"vlan-cos-fwd" json:"vlan-cos-fwd"`
	VlanCosRev                     int                  `bson:"vlan-cos-rev" json:"vlan-cos-rev"`
	Inbound                        string               `bson:"inbound" json:"inbound"`
	Outbound                       string               `bson:"outbound" json:"outbound"`
	Natinbound                     string               `bson:"natinbound" json:"natinbound"`
	Natoutbound                    string               `bson:"natoutbound" json:"natoutbound"`
	Fec                            string               `bson:"fec" json:"fec"`
	Wccp                           string               `bson:"wccp" json:"wccp"`
	Ntlm                           string               `bson:"ntlm" json:"ntlm"`
	NtlmGuest                      string               `bson:"ntlm-guest" json:"ntlm-guest"`
	NtlmEnabledBrowsers            []Browsers           `bson:"ntlm-enabled-browsers" json:"ntlm-enabled-browsers"`
	FssoAgentForNtlm               string               `bson:"fsso-agent-for-ntlm" json:"fsso-agent-for-ntlm"`
	Groups                         []Addresses          `bson:"groups" json:"groups"`
	Users                          []Addresses          `bson:"users" json:"users"`
	FssoGroups                     []Addresses          `bson:"fsso-groups" json:"fsso-groups"`
	AuthPath                       string               `bson:"auth-path" json:"auth-path"`
	Disclaimer                     string               `bson:"disclaimer" json:"disclaimer"`
	EmailCollect                   string               `bson:"email-collect" json:"email-collect"`
	Vpntunnel                      string               `bson:"vpntunnel" json:"vpntunnel"`
	Natip                          string               `bson:"natip" json:"natip"`
	MatchVip                       string               `bson:"match-vip" json:"match-vip"`
	MatchVipOnly                   string               `bson:"match-vip-only" json:"match-vip-only"`
	DiffservCopy                   string               `bson:"diffserv-copy" json:"diffserv-copy"`
	DiffservForward                string               `bson:"diffserv-forward" json:"diffserv-forward"`
	DiffservReverse                string               `bson:"diffserv-reverse" json:"diffserv-reverse"`
	DiffservcodeForward            string               `bson:"diffservcode-forward" json:"diffservcode-forward"`
	DiffservcodeRev                string               `bson:"diffservcode-rev" json:"diffservcode-rev"`
	TCPMssSender                   int                  `bson:"tcp-mss-sender" json:"tcp-mss-sender"`
	TCPMssReceiver                 int                  `bson:"tcp-mss-receiver" json:"tcp-mss-receiver"`
	Comments                       string               `bson:"comments" json:"comments"`
	Label                          string               `bson:"label" json:"label"`
	GlobalLabel                    string               `bson:"global-label" json:"global-label"`
	AuthCert                       string               `bson:"auth-cert" json:"auth-cert"`
	AuthRedirectAddr               string               `bson:"auth-redirect-addr" json:"auth-redirect-addr"`
	RedirectURL                    string               `bson:"redirect-url" json:"redirect-url"`
	IdentityBasedRoute             string               `bson:"identity-based-route" json:"identity-based-route"`
	BlockNotification              string               `bson:"block-notification" json:"block-notification"`
	CustomLogFields                []LogFields          `bson:"custom-log-fields" json:"custom-log-fields"`
	ReplacemsgOverrideGroup        string               `bson:"replacemsg-override-group" json:"replacemsg-override-group"`
	SrcaddrNegate                  string               `bson:"srcaddr-negate" json:"srcaddr-negate"`
	Srcaddr6Negate                 string               `bson:"srcaddr-6-negate" json:"srcaddr6-negate"`
	DstaddrNegate                  string               `bson:"dstaddr-negate" json:"dstaddr-negate"`
	Dstaddr6Negate                 string               `bson:"dstaddr-6-negate" json:"dstaddr6-negate"`
	ServiceNegate                  string               `bson:"service-negate" json:"service-negate"`
	InternetServiceNegate          string               `bson:"internet-service-negate" json:"internet-service-negate"`
	InternetServiceSrcNegate       string               `bson:"internet-service-src-negate" json:"internet-service-src-negate"`
	InternetService6Negate         string               `bson:"internet-service-6-negate" json:"internet-service6-negate"`
	InternetService6SrcNegate      string               `bson:"internet-service-6-src-negate" json:"internet-service6-src-negate"`
	TimeoutSendRst                 string               `bson:"timeout-send-rst" json:"timeout-send-rst"`
	CaptivePortalExempt            string               `bson:"captive-portal-exempt" json:"captive-portal-exempt"`
	DecryptedTrafficMirror         string               `bson:"decrypted-traffic-mirror" json:"decrypted-traffic-mirror"`
	Dsri                           string               `bson:"dsri" json:"dsri"`
	RadiusMacAuthBypass            string               `bson:"radius-mac-auth-bypass" json:"radius-mac-auth-bypass"`
	DelayTCPNpuSession             string               `bson:"delay-tcp-npu-session" json:"delay-tcp-npu-session"`
	VlanFilter                     string               `bson:"vlan-filter" json:"vlan-filter"`
	SgtCheck                       string               `bson:"sgt-check" json:"sgt-check"`
	Sgt                            []SecurityGroupTag   `bson:"sgt" json:"sgt"`
}

type Interfaces struct {
	Name string `bson:"name" json:"name"`
}

type Addresses struct {
	Name string `bson:"name" json:"name"`
}

type VendorMacAddresses struct {
	Id string `bson:"id" json:"id"`
}

type Tags struct {
	Name string `bson:"name" json:"name"`
}

type Browsers struct {
	UserAgentString string `bson:"user-agent-string" json:"user-agent-string"`
}

type LogFields struct {
	FieldId string `bson:"field-id" json:"field-id"`
}

type SecurityGroupTag struct {
	Id int `bson:"id" json:"id"`
}

type Address struct {
	Name                string      `bson:"name" json:"name"`
	UUID                string      `bson:"uuid" json:"uuid"`
	Type                string      `bson:"type" json:"type"`
	SubType             string      `bson:"sub-type" json:"sub-type"`
	ClearpassSpt        string      `bson:"clearpass-spt" json:"clearpass-spt"`
	Macaddr             []Macaddr   `bson:"macaddr" json:"macaddr"`
	StartIP             string      `bson:"start-ip" json:"start-ip"`
	EndIP               string      `bson:"end-ip" json:"end-ip"`
	Country             string      `bson:"country" json:"country"`
	CacheTTL            int         `bson:"cache-ttl" json:"cache-ttl"`
	Sdn                 string      `bson:"sdn" json:"sdn"`
	FssoGroup           []Addresses `bson:"fsso-group" json:"fsso-group"`
	Interface           string      `bson:"interface" json:"interface"`
	ObjType             string      `bson:"obj-type" json:"obj-type"`
	TagDetectionLevel   string      `bson:"tag-detection-level" json:"tag-detection-level"`
	TagType             string      `bson:"tag-type" json:"tag-type"`
	Dirty               string      `bson:"dirty" json:"dirty"`
	Comment             string      `bson:"comment" json:"comment"`
	AssociatedInterface string      `bson:"associated-interface" json:"associated-interface"`
	Color               int         `bson:"color" json:"color"`
	Filter              string      `bson:"filter" json:"filter"`
	SdnAddrType         string      `bson:"sdn-addr-type" json:"sdn-addr-type"`
	NodeIPOnly          string      `bson:"node-ip-only" json:"node-ip-only"`
	ObjID               string      `bson:"obj-id" json:"obj-id"`
	List                []IpList    `bson:"list" json:"list"`
	Tagging             []Tagging   `bson:"tagging" json:"tagging"`
	AllowRouting        string      `bson:"allow-routing" json:"allow-routing"`
	FabricObject        string      `bson:"fabric-object" json:"fabric-object"`
}

type Macaddr struct {
	Macaddr string `bson:"macaddr" json:"macaddr"`
}

type IpList struct {
	Ip string `bson:"ip" json:"ip""`
}

type Tagging struct {
	Name     string `bson:"name" json:"name"`
	Category string `json:"category" json:"category"`
	Tags     []Tags `bson:"tags" json:"tags"`
}

type Firewall struct {
	SystemInfo   System     `bson:"system_info" json:"system_info"`
	SubnetList   []Subnet   `bson:"subnet_list" json:"subnet_list"`
	SystemIpList []SystemIp `bson:"system_ip_list" json:"system_ip_list"`
	HostList     []Host     `bson:"host_list" json:"host_list"`
	Policy       []Policy   `bson:"policy" json:"policy"`
	Addresses    []Address  `bson:"addresses" json:"addresses"`
}
