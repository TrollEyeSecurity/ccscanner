package shodan

import (
	"encoding/json"
	"fmt"
)


type HostData struct {
	RegionCode *string `json:"region_code"`
	Tags []string `json:"tags,omitempty"`
	IP *int `json:"ip,omitempty"`
	AreaCode *int `json:"area_code"`
	Domains []string `json:"domains"`
	Hostnames []string `json:"hostnames"`
	CountryCode *string `json:"country_code"`
	DmaCode *int `json:"dma_code"`
	PostalCode *string `json:"postal_code"`
	Org *string `json:"org"`
	Services   []*Service `json:"data"`
}


type SSL struct {
	AcceptableCAs []SslAcceptableCA `json:"acceptable_cas"`
	Alpn []string `json:"alpn"`
	Cert SslCert `json:"cert"`
	Chain []string `json:"chain"`
	Cipher SslCipher `json:"cipher"`
	DHparams *SslDHParams `json:"dhparams,omitempty"`
	TLSExt   []SslTlsExt `json:"tlsext"`
	Unstable []string    `json:"unstable,omitempty"`
	Versions []string `json:"versions"`
}

type SslAcceptableCA struct {
	Components SslCertComponents `json:"components"`
	Hash       int               `json:"hash"`
	Raw        string            `json:"raw"`
}

type SslCert struct {
	Expired     bool           `json:"expired"`
	Expires     string         `json:"expires"`
	Extensions  []SslExtension `json:"extensions"`
	Fingerprint SslFingerprint `json:"fingerprint"`
	Issued      string         `json:"issued"`
	Issuer      SslIssuer      `json:"issuer"`
	Pubkey      Pubkey         `json:"pubkey"`
	Serial      json.Number    `json:"serial,Number"`
	SigAlg      string         `json:"sig_alg"`
	Subject     SslSubject     `json:"subject"`
	Version     int            `json:"version"`
}

type SslCertComponents struct {
	C            string `json:"C,omitempty"`
	CN           string `json:"CN,omitempty"`
	DC           string `json:"DC,omitempty"`
	L            string `json:"L,omitempty"`
	O            string `json:"O,omitempty"`
	OU           string `json:"OU,omitempty"`
	SN           string `json:"SN,omitempty"`
	ST           string `json:"ST,omitempty"`
	EmailAddress string `json:"emailAddress,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
}

type SslCipher struct {
	Bits    int    `json:"bits"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type SslDHParams struct {
	Bits        int         `json:"bits"`
	Fingerprint string      `json:"fingerprint,omitempty"`
	Generator   interface{} `json:"generator"`
	Prime       string      `json:"prime"`
	PublicKey   string      `json:"public_key"`
}

type SslExtension struct {
	Critical bool   `json:"critical,omitempty"`
	Data     string `json:"data"`
	Name     string `json:"name"`
}

type SslFingerprint struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

type Pubkey struct {
	Bits int    `json:"bits"`
	Type string `json:"type"`
}

type SslSubject struct {
	SslCertComponents
	BusinessCategory string `json:"businessCategory,omitempty"`
	Description      string `json:"description,omitempty"`
	JurisdictionC    string `json:"jurisdictionC,omitempty"`
	JurisdictionSt   string `json:"jurisdictionST,omitempty"`
	PostalCode       string `json:"postalCode,omitempty"`
	Street           string `json:"street,omitempty"`
}

type SslIssuer struct {
	SslCertComponents
	Name                string `json:"name,omitempty"`
	UID                 string `json:"UID,omitempty"`
	DNQualifier         string `json:"dnQualifier,omitempty"`
	SubjectAltName      string `json:"subjectAltName,omitempty"`
	UnstructuredName    string `json:"unstructuredName,omitempty,omitempty"`
	UnstructuredAddress string `json:"unstructuredAddress,omitempty,omitempty"`
	PostalCode          string `json:"postalCode,omitempty,omitempty"`
	Street              string `json:"street,omitempty,omitempty"`
	Undef               string `json:"UNDEF,omitempty"`
}

type SslTlsExt struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type Shodan struct {
	Crawler string `json:"crawler"`
	Id *string `json:"id"`
	Module string `json:"module,omitempty"`
	Ptr bool `json:"ptr"`
	Options CrawlerOptions `json:"options"`
}

type CrawlerOptions struct {
	Hostname string `json:"hostname,omitempty"`
	Referrer string `json:"referrer,omitempty"`
	Scan string `json:"scan,omitempty"`
}

type Vulnerability struct {
	CVSS interface{} `json:"cvss"`
	References []string `json:"references"`
	Summary string `json:"summary"`
	Verified bool `json:"verified"`
}

type Location struct {
	Latitude *float32 `json:"latitude"`
	Longitude *float32 `json:"longitude"`
	City *string `json:"city"`
	CountryCode *string `json:"country_code"`
	CountryCode3 *string `json:"country_code3"`
	CountryName *string `json:"country_name"`
	AreaCode *int `json:"area_code"`
	RegionCode *string `json:"region_code"`
	DmaCode *int `json:"dma_code"`
	PostalCode *string `json:"postal_code"`
}

type Host struct {
	Ports      []int      `json:"ports"`
	Vulns      []string   `json:"vulns"`
	LastUpdate string     `json:"last_update"`
	Services   []*Service `json:"data"`
	Location
	HostInfo
}

type HostInfo struct {
	IPstr string `json:"ip_str"`
	ASN *string `json:"asn,omitempty"`
	OS *string `json:"os"`
	Org *string `json:"org"`
	ISP *string `json:"isp"`
	Hostnames []string `json:"hostnames"`
	Tags []string `json:"tags,omitempty"`
	HTML string `json:"html,omitempty"`
}


// Service from search results
type Service struct {
	HostInfo
	Location Location `json:"location"`
	Data string `json:"data"`
	IP *int `json:"ip,omitempty"`
	IPv6 *string `json:"ipv6,omitempty"`
	Port int `json:"port"`
	Timestamp string `json:"timestamp"`
	Hash int `json:"hash"`
	Domains []string `json:"domains"`
	Link *string `json:"link,omitempty"`
	Opts map[string]interface{} `json:"opts"`
	Uptime *int `json:"uptime,omitempty"`
	Transport string `json:"transport"`
	Product interface{} `json:"product,omitempty"`
	Version interface{} `json:"version,omitempty"`
	CPE interface{} `json:"cpe,omitempty"`
	Title *string `json:"title,omitempty"`
	DeviceType *string `json:"devicetype,omitempty"`
	Info *string `json:"info,omitempty"`
	Shodan Shodan `json:"_shodan"`
	Vulns map[string]Vulnerability `json:"vulns,omitempty"`
	SSL *SSL `json:"ssl,omitempty"`
	Cassandra *Cassandra `json:"cassandra,omitempty"`
	DB2 *DB2 `json:"db2,omitempty"`
	DNS *DNS `json:"dns,omitempty"`
	Docker *Docker `json:"docker,omitempty"`
	Elastic *Elastic `json:"elastic,omitempty"`
	Etcd *Etcd `json:"etcd,omitempty"`
	EthernetIP *EthernetIP `json:"ethernetip,omitempty"`
	FTP *FTP `json:"ftp,omitempty"`
	Hive *Hive `json:"hive,omitempty"`
	HTTP *HTTP `json:"http,omitempty"`
	ISAKMP *ISAKMP `json:"isakmp,omitempty"`
	Lantronix *Lantronix `json:"lantronix,omitempty"`
	Monero *Monero `json:"monero,omitempty"`
	MongoDB *Mongo `json:"mongodb,omitempty"`
	MQTT *MQTT `json:"mqtt,omitempty"`
	Netbios *Netbios `json:"netbios,omitempty"`
	NTP *NTP `json:"ntp,omitempty"`
	Redis *Redis `json:"redis,omitempty"`
	RIP *RIP `json:"rip,omitempty"`
	Rsync *Rsync `json:"rsync,omitempty"`
	SMB *SMB `json:"smb,omitempty"`
	SNMP *SNMP `json:"snmp,omitempty"`
	SSH *SSH `json:"ssh,omitempty"`
	Vertx *Vertx `json:"vertx,omitempty"`
	Minecraft *Minecraft `json:"minecraft"`
	InfluxDb *InfluxDb `json:"influx_db"`
	CoAP *CoAP `json:"coap"`
}

func (s *Service) ProductString() string {
	if s.Product == nil {
		return ""
	}
	return fmt.Sprint(s.Product)
}

func (s *Service) CpeList() []string {
	if s.CPE == nil {
		return []string{}
	}

	switch s.CPE.(type) {
	case string:
		return []string{s.CPE.(string)}
	case []string:
		return s.CPE.([]string)
	default:
		return []string{}
	}
}

func (s *Service) VersionString() string {
	if s.Version == nil {
		return ""
	}
	return fmt.Sprint(s.Version)
}

func (s *Service) IPString() string {
	if s.IP != nil {
		return s.IPstr
	} else {
		return *s.IPv6
	}
}

func (s *Service) IpAndPort() string {
	return fmt.Sprintf("%s:%d", s.IPString(), s.Port)
}

type Cassandra struct {
	Name string `json:"name"`
	Keyspaces []string `json:"keyspaces"`
	Partitioner string `json:"partitioner"`
	Snitch string `json:"snitch"`
}

type DB2 struct {
	ExternalName string `json:"external_name"`
	ServerPlatform string `json:"server_platform"`
	InstanceName string `json:"instance_name"`
	Version string `json:"db2_version"`
}

type DNS struct {
	Recursive bool `json:"recursive"`
	ResolverHostname *string `json:"resolver_hostname"`
	ResolverID *string `json:"resolver_id"`
	Software *string `json:"software"`
}

type Docker struct {
	APIVersion string `json:"ApiVersion"`
	Arch string `json:"Arch"`
	BuildTime string `json:"BuildTime,omitempty"`
	Components   []DockerComponent `json:"Components,omitempty"`
	Containers   []DockerContainer `json:"Containers,omitempty"`
	Engine       string            `json:"Engine,omitempty"`
	Experimental bool              `json:"Experimental,omitempty"`
	GitCommit string `json:"GitCommit"`
	GoVersion string `json:"GoVersion"`
	KernelVersion string `json:"KernelVersion"`
	MinApiversion string `json:"MinAPIVersion,omitempty"`
	EulerVersion string `json:"EulerVersion,omitempty"`
	OS         string         `json:"Os"`
	PkgVersion string         `json:"PkgVersion,omitempty"`
	Platform   DockerPlatform `json:"Platform,omitempty"`
	Version string `json:"Version"`
}

type DockerComponent struct {
	Details DockerComponentDetails `json:"Details"`
	Name    string                 `json:"Name"`
	Version string                 `json:"Version"`
}

type DockerContainer struct {
	Command         string                    `json:"Command"`
	Created         int                       `json:"Created"`
	FinishedAt      int                       `json:"FinishedAt,omitempty"`
	HostConfig      DockerContainerHostConfig `json:"HostConfig,omitempty"`
	ID              string                    `json:"Id"`
	Image           string                    `json:"Image"`
	ImageID         string                    `json:"ImageID,omitempty"`
	Labels          interface{}               `json:"Labels,omitempty"`
	Mounts          interface{}               `json:"Mounts,omitempty"`
	Names           []string                  `json:"Names"`
	NetworkSettings interface{}               `json:"NetworkSettings,omitempty"`
	Ports           interface{}               `json:"Ports"`
	StartedAt       int                       `json:"StartedAt,omitempty"`
	State           string                    `json:"State,omitempty"`
	Status          string                    `json:"Status"`
}

type DockerComponentDetails struct {
	APIVersion    string `json:"ApiVersion,omitempty"`
	Arch          string `json:"Arch,omitempty"`
	BuildTime     string `json:"BuildTime,omitempty"`
	Experimental  string `json:"Experimental,omitempty"`
	GitCommit     string `json:"GitCommit"`
	GoVersion     string `json:"GoVersion,omitempty"`
	KernelVersion string `json:"KernelVersion,omitempty"`
	MinApiversion string `json:"MinAPIVersion,omitempty"`
	Os            string `json:"Os,omitempty"`
}

type DockerContainerHostConfig struct {
	NetworkMode string `json:"NetworkMode,omitempty"`
}

type DockerPlatform struct {
	Name string `json:"Name"`
}

type Elastic struct {
	Cluster ElasticCluster `json:"cluster"`
	Nodes ElasticNode `json:"nodes"`
	Indices map[string]ElasticIndex `json:"indices"`
}

type ElasticCluster struct {
	ClusterName string           `json:"cluster_name,omitempty"`
	ClusterUUID string           `json:"cluster_uuid,omitempty"`
	Indices     ElasticIndices   `json:"indices,omitempty"`
	Nodes       ElasticNodes     `json:"nodes,omitempty"`
	NodesMore   ElasticNodesMore `json:"_nodes,omitempty"`
	Status      string           `json:"status,omitempty"`
	Timestamp   int              `json:"timestamp,omitempty"`
}

type ElasticNodesMore struct {
	Failed     int              `json:"failed"`
	Failures   []ElasticFailure `json:"failures,omitempty"`
	Successful int              `json:"successful"`
	Total      int              `json:"total"`
}

type ElasticFailure struct {
	CausedBy ElasticFailureCausedBy `json:"caused_by"`
	NodeID   string                 `json:"node_id"`
	Reason   string                 `json:"reason"`
	Type     string                 `json:"type"`
}

type ElasticFailureCausedBy struct {
	CausedBy *ElasticFailureCausedBy `json:"caused_by,omitempty"`
	Reason   string                  `json:"reason"`
	Type     string                  `json:"type"`
}

type ElasticNode struct {
	ClusterName string                     `json:"cluster_name"`
	Nodes       map[string]ElasticNodeInfo `json:"nodes"`
	NodesStat   ElasticNodeStat            `json:"_nodes,omitempty"`
}

type ElasticNodeStat struct {
	Failed     int              `json:"failed"`
	Failures   []ElasticFailure `json:"failures,omitempty"`
	Successful int              `json:"successful"`
	Total      int              `json:"total"`
}

type ElasticAttributes struct {
	AwsAvailabilityZone  string `json:"aws_availability_zone,omitempty"`
	BoxType              string `json:"box_type,omitempty"`
	Client               string `json:"client,omitempty"`
	Data                 string `json:"data,omitempty"`
	FaultDomain          string `json:"fault_domain,omitempty"`
	Local                string `json:"local,omitempty"`
	Master               string `json:"master,omitempty"`
	MaxLocalStorageNodes string `json:"max_local_storage_nodes,omitempty"`
	MlEnabled            string `json:"ml.enabled,omitempty"`
	MlMachineMemory      string `json:"ml.machine_memory,omitempty"`
	MlMaxOpenJobs        string `json:"ml.max_open_jobs,omitempty"`
	Rack                 string `json:"rack,omitempty"`
	Role                 string `json:"role,omitempty"`
	UpdateDomain         string `json:"update_domain,omitempty"`
	XpackInstalled       string `json:"xpack.installed,omitempty"`
}

type ElasticCPUdata struct {
	CacheSizeInBytes int    `json:"cache_size_in_bytes,omitempty"`
	CoresPerSocket   int    `json:"cores_per_socket"`
	Mhz              int    `json:"mhz,omitempty"`
	Model            string `json:"model,omitempty"`
	TotalCores       int    `json:"total_cores"`
	TotalSockets     int    `json:"total_sockets"`
	Vendor           string `json:"vendor,omitempty"`
}

type ElasticNodeHTTP struct {
	BoundAddress            interface{} `json:"bound_address"`
	MaxContentLengthInBytes int         `json:"max_content_length_in_bytes"`
	PublishAddress          string      `json:"publish_address"`
}

type ElasticIngest struct {
	Processors        []ElasticProcessor     `json:"processors"`
	ProcessorStats    map[string]interface{} `json:"processor_stats"`
	NumberOfPipelines int                    `json:"number_of_pipelines"`
}

type ElasticJVM struct {
	GcCollectors                          []string      `json:"gc_collectors,omitempty"`
	InputArguments                        []string      `json:"input_arguments,omitempty"`
	Mem                                   ElasticJvmMem `json:"mem,omitempty"`
	MemoryPools                           []string      `json:"memory_pools,omitempty"`
	Pid                                   int           `json:"pid,omitempty"`
	StartTimeInMillis                     int           `json:"start_time_in_millis,omitempty"`
	UsingCompressedOrdinaryObjectPointers string        `json:"using_compressed_ordinary_object_pointers,omitempty"`
	VMName                                string        `json:"vm_name,omitempty"`
	VMVendor                              string        `json:"vm_vendor,omitempty"`
	VMVersion                             string        `json:"vm_version,omitempty"`
	Version                               string        `json:"version,omitempty"`
}

type ElasticModule struct {
	Classname            string   `json:"classname"`
	Description          string   `json:"description"`
	ElasticsearchVersion string   `json:"elasticsearch_version,omitempty"`
	ExtendedPlugins      []string `json:"extended_plugins,omitempty"`
	HasNativeController  bool     `json:"has_native_controller,omitempty"`
	Isolated             bool     `json:"isolated,omitempty"`
	JavaVersion          string   `json:"java_version,omitempty"`
	Jvm                  bool     `json:"jvm,omitempty"`
	Name                 string   `json:"name"`
	RequiresKeystore     bool     `json:"requires_keystore,omitempty"`
	Site                 bool     `json:"site,omitempty"`
	Version              string   `json:"version"`
}

type ElasticNetwork struct {
	PrimaryInterface        ElasticPrimaryInterface `json:"primary_interface,omitempty"`
	RefreshIntervalInMillis int                     `json:"refresh_interval_in_millis"`
}

type ElasticNodeInfo struct {
	ThreadPool          map[string]interface{} `json:"thread_pool,omitempty"`
	Settings            map[string]interface{} `json:"settings,omitempty"`
	Attributes          ElasticAttributes      `json:"attributes,omitempty"`
	Build               string                 `json:"build,omitempty"`
	BuildFlavor         string                 `json:"build_flavor,omitempty"`
	BuildHash           string                 `json:"build_hash,omitempty"`
	BuildType           string                 `json:"build_type,omitempty"`
	HTTP                ElasticNodeHTTP        `json:"http,omitempty"`
	HTTPAddress         string                 `json:"http_address,omitempty"`
	Host                string                 `json:"host,omitempty"`
	IP                  string                 `json:"ip,omitempty"`
	Ingest              ElasticIngest          `json:"ingest,omitempty"`
	JVM                 ElasticJVM             `json:"jvm"`
	Modules             []ElasticModule        `json:"modules,omitempty"`
	Name                string                 `json:"name"`
	Network             ElasticNetwork         `json:"network,omitempty"`
	OS                  ElasticOsInfo          `json:"os"`
	Plugins             []ElasticPlugin        `json:"plugins,omitempty"`
	Process             ElasticProcess         `json:"process"`
	Roles               []string               `json:"roles,omitempty"`
	TotalIndexingBuffer int                    `json:"total_indexing_buffer,omitempty"`
	Transport           ElasticTransport       `json:"transport,omitempty"`
	TransportAddress    string                 `json:"transport_address,omitempty"`
	Version             string                 `json:"version"`
}

type ElasticOsInfo struct {
	AllocatedProcessors     int            `json:"allocated_processors,omitempty"`
	Arch                    string         `json:"arch,omitempty"`
	AvailableProcessors     int            `json:"available_processors"`
	CPU                     ElasticCPUdata `json:"cpu,omitempty"`
	Mem                     ElasticOsMem   `json:"mem,omitempty"`
	Name                    string         `json:"name,omitempty"`
	PrettyName              string         `json:"pretty_name,omitempty"`
	RefreshIntervalInMillis int            `json:"refresh_interval_in_millis"`
	Swap                    ElasticSwap    `json:"swap,omitempty"`
	Version                 string         `json:"version,omitempty"`
}

type ElasticPlugin struct {
	Classname            string   `json:"classname,omitempty"`
	Description          string   `json:"description"`
	ElasticsearchVersion string   `json:"elasticsearch_version,omitempty"`
	ExtendedPlugins      []string `json:"extended_plugins,omitempty"`
	HasNativeController  bool     `json:"has_native_controller,omitempty"`
	Isolated             bool     `json:"isolated,omitempty"`
	JavaVersion          string   `json:"java_version,omitempty"`
	JVM                  bool     `json:"jvm,omitempty"`
	Name                 string   `json:"name"`
	RequiresKeystore     bool     `json:"requires_keystore,omitempty"`
	Site                 bool     `json:"site,omitempty"`
	URL                  string   `json:"url,omitempty"`
	Version              string   `json:"version"`
}

type ElasticPrimaryInterface struct {
	Address    string `json:"address"`
	MacAddress string `json:"mac_address"`
	Name       string `json:"name"`
}

type ElasticProcessor struct {
	Type string `json:"type"`
}

type ElasticSwap struct {
	TotalInBytes int `json:"total_in_bytes"`
}

type ElasticTransport struct {
	BoundAddress   interface{}            `json:"bound_address"`
	Profiles       map[string]interface{} `json:"profiles,omitempty"`
	PublishAddress string                 `json:"publish_address"`
}

type ElasticJvmMem struct {
	DirectMaxInBytes   int `json:"direct_max_in_bytes"`
	HeapInitInBytes    int `json:"heap_init_in_bytes"`
	HeapMaxInBytes     int `json:"heap_max_in_bytes"`
	NonHeapInitInBytes int `json:"non_heap_init_in_bytes"`
	NonHeapMaxInBytes  int `json:"non_heap_max_in_bytes"`
	HeapUsedInBytes    int `json:"heap_used_in_bytes"`
}

type ElasticOsMem struct {
	FreeInBytes  int `json:"free_in_bytes,omitempty"`
	FreePercent  int `json:"free_percent,omitempty"`
	TotalInBytes int `json:"total_in_bytes"`
	UsedInBytes  int `json:"used_in_bytes,omitempty"`
	UsedPercent  int `json:"used_percent,omitempty"`
}

type ElasticProcess struct {
	ID                      int                        `json:"id"`
	MaxFileDescriptors      int                        `json:"max_file_descriptors,omitempty"`
	Mlockall                bool                       `json:"mlockall"`
	RefreshIntervalInMillis int                        `json:"refresh_interval_in_millis"`
	CPU                     ElasticCPULoad             `json:"cpu,omitempty"`
	OpenFileDescriptors     ElasticOpenFileDescriptors `json:"open_file_descriptors,omitempty"`
}
type ElasticIndex struct {
	Primaries ElasticIndexStats `json:"primaries"`
	Total     ElasticIndexStats `json:"total"`
	UUID      string            `json:"uuid,omitempty"`
}

type ElasticIndexStats struct {
	Indexing ElasticIndexing `json:"indexing,omitempty"`
}

type ElasticIndexing struct {
	DeleteCurrent        int  `json:"delete_current"`
	DeleteTimeInMillis   int  `json:"delete_time_in_millis"`
	DeleteTotal          int  `json:"delete_total"`
	IndexCurrent         int  `json:"index_current"`
	IndexFailed          int  `json:"index_failed,omitempty"`
	IndexTimeInMillis    int  `json:"index_time_in_millis"`
	IndexTotal           int  `json:"index_total"`
	IsThrottled          bool `json:"is_throttled"`
	NoopUpdateTotal      int  `json:"noop_update_total"`
	ThrottleTimeInMillis int  `json:"throttle_time_in_millis"`
}

type ElasticCompletion struct {
	SizeInBytes int `json:"size_in_bytes"`
}

type ElasticNodeCount struct {
	Client           int `json:"client,omitempty"`
	CoordinatingOnly int `json:"coordinating_only,omitempty"`
	VotingOnly       int `json:"voting_only,omitempty"`
	Data             int `json:"data,omitempty"`
	DataOnly         int `json:"data_only,omitempty"`
	Ingest           int `json:"ingest,omitempty"`
	Master           int `json:"master,omitempty"`
	MasterData       int `json:"master_data,omitempty"`
	MasterOnly       int `json:"master_only,omitempty"`
	ML               int `json:"ml"`
	Total            int `json:"total"`
}

type ElasticCPULoad struct {
	Percent int `json:"percent"`
}

type ElasticCpuItem struct {
	CacheSizeInBytes int    `json:"cache_size_in_bytes"`
	CoresPerSocket   int    `json:"cores_per_socket"`
	Count            int    `json:"count"`
	Mhz              int    `json:"mhz"`
	Model            string `json:"model,omitempty"`
	TotalCores       int    `json:"total_cores"`
	TotalSockets     int    `json:"total_sockets"`
	Vendor           string `json:"vendor,omitempty"`
}

type ElasticIndexDocs struct {
	Count   int `json:"count"`
	Deleted int `json:"deleted"`
}

type ElasticFielddata struct {
	Evictions         int `json:"evictions"`
	MemorySizeInBytes int `json:"memory_size_in_bytes"`
}

type ElasticFilterCache struct {
	Evictions         int `json:"evictions"`
	MemorySizeInBytes int `json:"memory_size_in_bytes"`
}

type ElasticFS struct {
	AvailableInBytes     int    `json:"available_in_bytes,omitempty"`
	DiskIoOp             int    `json:"disk_io_op,omitempty"`
	DiskIoSizeInBytes    int    `json:"disk_io_size_in_bytes,omitempty"`
	DiskQueue            string `json:"disk_queue,omitempty"`
	DiskReadSizeInBytes  int    `json:"disk_read_size_in_bytes,omitempty"`
	DiskReads            int    `json:"disk_reads,omitempty"`
	DiskServiceTime      string `json:"disk_service_time,omitempty"`
	DiskWriteSizeInBytes int    `json:"disk_write_size_in_bytes,omitempty"`
	DiskWrites           int    `json:"disk_writes,omitempty"`
	FreeInBytes          int    `json:"free_in_bytes,omitempty"`
	Spins                string `json:"spins,omitempty"`
	TotalInBytes         int    `json:"total_in_bytes,omitempty"`
}

type ElasticIdcache struct {
	MemorySizeInBytes int `json:"memory_size_in_bytes"`
}

type ElasticShardIndex struct {
	Primaries   ElasticIndexMetric `json:"primaries"`
	Replication ElasticIndexMetric `json:"replication"`
	Shards      ElasticIndexMetric `json:"shards"`
}

type ElasticIndexMetric struct {
	Avg float64 `json:"avg"`
	Max float64 `json:"max"`
	Min float64 `json:"min"`
}

type ElasticIndices struct {
	Completion  ElasticCompletion    `json:"completion"`
	Count       int                  `json:"count"`
	Docs        ElasticIndexDocs     `json:"docs"`
	Fielddata   ElasticFielddata     `json:"fielddata"`
	FilterCache ElasticFilterCache   `json:"filter_cache,omitempty"`
	IDCache     ElasticIdcache       `json:"id_cache,omitempty"`
	Percolate   ElasticPercolate     `json:"percolate,omitempty"`
	QueryCache  ElasticQueryCache    `json:"query_cache,omitempty"`
	Segments    ElasticSegments      `json:"segments"`
	Shards      ElasticIndicesShards `json:"shards"`
	Store       ElasticStore         `json:"store"`
}

type ElasticIndicesShards struct {
	Index       ElasticShardIndex `json:"index,omitempty"`
	Primaries   int               `json:"primaries,omitempty"`
	Replication float64           `json:"replication,omitempty"`
	Total       int               `json:"total,omitempty"`
}

type ElasticJVMdata struct {
	MaxUptimeInMillis int                 `json:"max_uptime_in_millis"`
	Mem               ElasticJvmMem       `json:"mem"`
	Threads           int                 `json:"threads"`
	Versions          []ElasticJvmVersion `json:"versions,omitempty"`
}

type ElasticJvmVersion struct {
	Count     int    `json:"count"`
	VMName    string `json:"vm_name"`
	VMVendor  string `json:"vm_vendor"`
	VMVersion string `json:"vm_version"`
	Version   string `json:"version"`
}

type ElasticOSname struct {
	Count int    `json:"count"`
	Name  string `json:"name,omitempty"`
}

type ElasticNetworkTypes struct {
	HTTPTypes      map[string]interface{} `json:"http_types"`
	TransportTypes map[string]interface{} `json:"transport_types"`
}

type ElasticNodes struct {
	Count          ElasticNodeCount       `json:"count"`
	FS             ElasticFS              `json:"fs"`
	JVM            ElasticJVMdata         `json:"jvm"`
	NetworkTypes   ElasticNetworkTypes    `json:"network_types,omitempty"`
	OS             ElasticOS              `json:"os"`
	Plugins        []ElasticPlugin        `json:"plugins,omitempty"`
	Process        ElasticProcess         `json:"process"`
	Versions       []string               `json:"versions"`
	Ingest         ElasticIngest          `json:"ingest,omitempty"`
	PackagingTypes []PackagingType        `json:"packaging_types"`
	DiscoveryTypes map[string]interface{} `json:"discovery_types"`
}

type ElasticOpenFileDescriptors struct {
	Avg int `json:"avg"`
	Max int `json:"max"`
	Min int `json:"min"`
}

type ElasticOS struct {
	AllocatedProcessors int                 `json:"allocated_processors,omitempty"`
	AvailableProcessors int                 `json:"available_processors"`
	CPU                 []ElasticCpuItem    `json:"cpu,omitempty"`
	Mem                 ElasticOsMem        `json:"mem"`
	Names               []ElasticOSname     `json:"names,omitempty"`
	PrettyNames         []ElasticPrettyName `json:"pretty_names,omitempty"`
}

type ElasticPercolate struct {
	Current           int    `json:"current"`
	MemorySize        string `json:"memory_size"`
	MemorySizeInBytes int    `json:"memory_size_in_bytes"`
	Queries           int    `json:"queries"`
	TimeInMillis      int    `json:"time_in_millis"`
	Total             int    `json:"total"`
}

type ElasticPrettyName struct {
	Count      int    `json:"count"`
	PrettyName string `json:"pretty_name"`
}

type ElasticQueryCache struct {
	CacheCount        int `json:"cache_count"`
	CacheSize         int `json:"cache_size"`
	Evictions         int `json:"evictions"`
	HitCount          int `json:"hit_count"`
	MemorySizeInBytes int `json:"memory_size_in_bytes"`
	MissCount         int `json:"miss_count"`
	TotalCount        int `json:"total_count"`
}

type ElasticSegments struct {
	Count                       int                    `json:"count"`
	DocValuesMemoryInBytes      int                    `json:"doc_values_memory_in_bytes,omitempty"`
	FileSizes                   map[string]interface{} `json:"file_sizes,omitempty"`
	FixedBitSetMemoryInBytes    int                    `json:"fixed_bit_set_memory_in_bytes"`
	IndexWriterMaxMemoryInBytes int                    `json:"index_writer_max_memory_in_bytes,omitempty"`
	IndexWriterMemoryInBytes    int                    `json:"index_writer_memory_in_bytes"`
	MaxUnsafeAutoIDTimestamp    int                    `json:"max_unsafe_auto_id_timestamp,omitempty"`
	MemoryInBytes               int                    `json:"memory_in_bytes"`
	NormsMemoryInBytes          int                    `json:"norms_memory_in_bytes,omitempty"`
	PointsMemoryInBytes         int                    `json:"points_memory_in_bytes,omitempty"`
	StoredFieldsMemoryInBytes   int                    `json:"stored_fields_memory_in_bytes,omitempty"`
	TermVectorsMemoryInBytes    int                    `json:"term_vectors_memory_in_bytes,omitempty"`
	TermsMemoryInBytes          int                    `json:"terms_memory_in_bytes,omitempty"`
	TermsOffheapMemoryInBytes   int                    `json:"terms_offheap_memory_in_bytes,omitempty"`
	VersionMapMemoryInBytes     int                    `json:"version_map_memory_in_bytes"`
}

type ElasticStore struct {
	SizeInBytes          int `json:"size_in_bytes"`
	ThrottleTimeInMillis int `json:"throttle_time_in_millis,omitempty"`
}

type PackagingType struct {
	Count  int    `json:"count"`
	Flavor string `json:"flavor"`
	Type   string `json:"type"`
}

type Etcd struct {
	ClientUrls []string `json:"clientURLs"`
	ID string `json:"id"`
	LeaderInfo EtcdLeaderInfo `json:"leaderInfo"`
	Name string `json:"name"`
	PeerUrls []string `json:"peerURLs"`
	RecvAppendRequestCnt int     `json:"recvAppendRequestCnt"`
	RecvBandwidthRate    float64 `json:"recvBandwidthRate,omitempty"`
	RecvPkgRate          float64 `json:"recvPkgRate,omitempty"`
	SendAppendRequestCnt int     `json:"sendAppendRequestCnt"`
	SendBandwidthRate    float64 `json:"sendBandwidthRate,omitempty"`
	SendPkgRate          float64 `json:"sendPkgRate,omitempty"`
	StartTime string `json:"startTime"`
	State   string `json:"state"`
	Version string `json:"version"`
}

type EtcdLeaderInfo struct {
	Leader    string `json:"leader"`
	StartTime string `json:"startTime"`
	Uptime    string `json:"uptime"`
}

type EthernetIP struct {
	Command       int `json:"command"`
	CommandLength int `json:"command_length"`
	CommandStatus int `json:"command_status"`
	DeviceType string `json:"device_type"`
	EncapsulationLength int    `json:"encapsulation_length"`
	IP                  string `json:"ip"`
	ItemCount int `json:"item_count"`
	Options int `json:"options"`
	ProductCode int `json:"product_code"`
	ProductName       string `json:"product_name"`
	ProductNameLength int    `json:"product_name_length"`
	Raw string `json:"raw"`
	RevisionMajor int `json:"revision_major"`
	RevisionMinor int `json:"revision_minor"`
	SenderContext string `json:"sender_context"`
	Serial int `json:"serial"`
	Session int `json:"session"`
	SocketAddr string `json:"socket_addr"`
	State int `json:"state"`
	Status int `json:"status"`
	TypeID int `json:"type_id"`
	VendorID interface{} `json:"vendor_id"` // can be int
	Version int `json:"version"`
}

type FTP struct {
	Anonymous bool `json:"anonymous"`
	Features map[string]FtpFeature `json:"features"`
	FeaturesHash *int `json:"features_hash"`
}

type FtpFeature struct {
	Parameters []string `json:"parameters"`
}

type Hive struct {
	Databases []HiveDatabase `json:"databases"`
}

type HiveDatabase struct {
	Name string `json:"name"`
	Tables []HiveTable `json:"tables"`
}

type HiveTable struct {
	Name       string              `json:"name"`
	Properties []map[string]string `json:"properties"`
}

type HTTP struct {
	Components map[string]HttpComponent `json:"components,omitempty"`
	Favicon *HttpFavicon `json:"favicon,omitempty"`
	HTML string `json:"html"`
	HTMLHash int `json:"html_hash"`
	Host string `json:"host"`
	Location string `json:"location"`
	Redirects []HttpRedirect `json:"redirects"`
	Robots *string `json:"robots"`
	RobotsHash *int `json:"robots_hash"`
	Securitytxt *string `json:"securitytxt"`
	SecuritytxtHash *int `json:"securitytxt_hash"`
	Server *string `json:"server"`
	Sitemap *string `json:"sitemap"`
	SitemapHash *int `json:"sitemap_hash"`
	Title *string `json:"title"`
	WAF   string  `json:"waf,omitempty"`
}

type HttpComponent struct {
	Categories []string `json:"categories"`
}

type HttpRedirect struct {
	Data     string `json:"data"`
	HTML     string `json:"html,omitempty"`
	Host     string `json:"host"`
	Location string `json:"location"`
}

type HttpFavicon struct {
	Data string `json:"data"`
	Hash int `json:"hash"`
	Location string `json:"location"`
}

type ISAKMP struct {
	Aggressive   *ISAKMP `json:"aggressive,omitempty"`
	ExchangeType int     `json:"exchange_type"`
	Flags IsakmpFlags `json:"flags"`
	InitiatorSPI string `json:"initiator_spi"`
	Length int `json:"length"`
	MsgID string `json:"msg_id"`
	NextPayload int `json:"next_payload"`
	ResponderSPI string `json:"responder_spi"`
	VendorIds []string `json:"vendor_ids"`
	Version string `json:"version"`
}

type IsakmpFlags struct {
	Authentication bool `json:"authentication"`
	Commit         bool `json:"commit"`
	Encryption     bool `json:"encryption"`
}

type Lantronix struct {
	Gateway *string `json:"gateway"`
	IP *string `json:"ip"`
	Mac string `json:"mac"`
	Password *string `json:"password"`
	Type *string `json:"type"`
	Version string `json:"version"`
}
type Monero struct {
	Credits uint64 `json:"credits"`
	TopHash string `json:"top_hash"`
	AltBlocksCount         int    `json:"alt_blocks_count"`
	BlockSizeLimit         int    `json:"block_size_limit"`
	BlockSizeMedian        int    `json:"block_size_median,omitempty"`
	BlockWeightLimit       int    `json:"block_weight_limit,omitempty"`
	BlockWeightMedian      int    `json:"block_weight_median,omitempty"`
	BootstrapDaemonAddress string `json:"bootstrap_daemon_address,omitempty"`
	Connections               []MoneroConnection `json:"connections"`
	CumulativeDifficulty      int                `json:"cumulative_difficulty"`
	CumulativeDifficultyTop64 int                `json:"cumulative_difficulty_top64,omitempty"`
	DatabaseSize              int                `json:"database_size,omitempty"`
	Difficulty      int `json:"difficulty"`
	DifficultyTop64 int `json:"difficulty_top64,omitempty"`
	FreeSpace       int `json:"free_space,omitempty"`
	GreyPeerlistSize int `json:"grey_peerlist_size"`
	Height                 int `json:"height"`
	HeightWithoutBootstrap int `json:"height_without_bootstrap,omitempty"`
	IncomingConnectionsCount int    `json:"incoming_connections_count"`
	Mainnet                  bool   `json:"mainnet,omitempty"`
	Nettype                  string `json:"nettype,omitempty"`
	Offline                  bool   `json:"offline,omitempty"`
	OutgoingConnectionsCount int  `json:"outgoing_connections_count"`
	RPCConnectionsCount      int  `json:"rpc_connections_count,omitempty"`
	Stagenet                 bool `json:"stagenet,omitempty"`
	StartTime                int  `json:"start_time"`
	Status string `json:"status"`
	Target int `json:"target"`
	TargetHeight int `json:"target_height"`
	Testnet bool `json:"testnet"`
	TopBlockHash string `json:"top_block_hash"`
	TxCount int `json:"tx_count"`
	TxPoolSize           int    `json:"tx_pool_size"`
	Untrusted            bool   `json:"untrusted,omitempty"`
	UpdateAvailable      bool   `json:"update_available,omitempty"`
	Version              string `json:"version,omitempty"`
	WasBootstrapEverUsed bool   `json:"was_bootstrap_ever_used,omitempty"`
	WhitePeerlistSize        int    `json:"white_peerlist_size"`
	WideCumulativeDifficulty string `json:"wide_cumulative_difficulty,omitempty"`
	WideDifficulty           string `json:"wide_difficulty,omitempty"`
}

type MoneroConnection struct {
	Address         string `json:"address"`
	AvgDownload     int    `json:"avg_download"`
	AvgUpload       int    `json:"avg_upload"`
	ConnectionID    string `json:"connection_id"`
	CurrentDownload int    `json:"current_download"`
	CurrentUpload   int    `json:"current_upload"`
	Height          int    `json:"height"`
	Host            string `json:"host"`
	IP              string `json:"ip"`
	Incoming        bool   `json:"incoming"`
	LiveTime        int    `json:"live_time"`
	LocalIP         bool   `json:"local_ip"`
	Localhost       bool   `json:"localhost"`
	PeerID          string `json:"peer_id"`
	Port            string `json:"port"`
	PruningSeed     int    `json:"pruning_seed,omitempty"`
	RPCPort         int    `json:"rpc_port,omitempty"`
	RecvCount       int    `json:"recv_count"`
	RecvIdleTime    int    `json:"recv_idle_time"`
	SendCount       int    `json:"send_count"`
	SendIdleTime    int    `json:"send_idle_time"`
	State           string `json:"state"`
	SupportFlags    int    `json:"support_flags"`
}

type Mongo struct {
	Authentication bool `json:"authentication"`
	BuildInfo MongoBuildInfo `json:"buildInfo"`
	ListDatabases MongoListDatabases `json:"listDatabases,omitempty"`
	ServerStatus map[string]interface{} `json:"serverStatus,omitempty"`
}

type MongoListDatabases struct {
	Databases             []MongoDatabase `json:"databases"`
	Ok                    float64         `json:"ok"`
	TotalSize             float64         `json:"totalSize"`
	TotalUncompressedSize float64         `json:"totalUncompressedSize,omitempty"`
}

type MongoBuildInfo struct {
	Allocator         string                `json:"allocator,omitempty"`
	Bits              int                   `json:"bits"`
	BuildEnvironment  MongoBuildEnvironment `json:"buildEnvironment,omitempty"`
	CompilerFlags     string                `json:"compilerFlags,omitempty"`
	CompilerName      string                `json:"compiler name,omitempty"`
	CompilerVersion   string                `json:"compiler version,omitempty"`
	Debug             bool                  `json:"debug,omitempty"`
	GitVersion        string                `json:"gitVersion"`
	JavascriptEngine  string                `json:"javascriptEngine,omitempty"`
	LoaderFlags       string                `json:"loaderFlags,omitempty"`
	MaxBsonObjectSize int                   `json:"maxBsonObjectSize,omitempty"`
	MemorySanitize    bool                  `json:"memory_sanitize,omitempty"`
	Modules           []string              `json:"modules,omitempty"`
	Ok                float64               `json:"ok"`
	OpenSslversion    string                `json:"OpenSSLVersion,omitempty"`
	Openssl           MongoOpenSSl          `json:"openssl,omitempty"`
	PcreJit           bool                  `json:"pcre-jit,omitempty"`
	PsmdbVersion      string                `json:"psmdbVersion,omitempty"`
	SonarVersion      string                `json:"sonarVersion,omitempty"`
	Sonardb           bool                  `json:"sonardb,omitempty"`
	StorageEngines    []string              `json:"storageEngines,omitempty"`
	SysInfo           string                `json:"sysInfo"`
	TargetMinOs       string                `json:"targetMinOS,omitempty"`
	Timestamp         string                `json:"timestamp,omitempty"`
	TokukvVersion     string                `json:"tokukvVersion,omitempty"`
	TokumxVersion     string                `json:"tokumxVersion,omitempty"`
	Version           string                `json:"version"`
	VersionArray      []int                 `json:"versionArray,omitempty"`
}

type MongoBuildEnvironment struct {
	Bits       int    `json:"bits,omitempty"`
	Cc         string `json:"cc,omitempty"`
	Ccflags    string `json:"ccflags,omitempty"`
	Cxx        string `json:"cxx,omitempty"`
	Cxxflags   string `json:"cxxflags,omitempty"`
	Distarch   string `json:"distarch,omitempty"`
	Distmod    string `json:"distmod,omitempty"`
	Linkflags  string `json:"linkflags,omitempty"`
	TargetArch string `json:"target_arch,omitempty"`
	TargetOs   string `json:"target_os"`
}

type MongoDatabase struct {
	Collections []string `json:"collections"`
	Empty       bool     `json:"empty,omitempty"`
	Name        string   `json:"name"`
	Size        float64  `json:"size,omitempty"`
	SizeOnDisk  float64  `json:"sizeOnDisk"`
}

type MongoOpenSSl struct {
	Compiled string `json:"compiled,omitempty"`
	Running  string `json:"running"`
}


type MQTT struct {
	Code int `json:"code"`
	Messages []MqttMessage `json:"messages"`
}

type MqttMessage struct {
	Payload *string `json:"payload"`
	Topic   string  `json:"topic"`
}

type Netbios struct {
	MAC string `json:"mac"`
	Names []NetbiosName `json:"names"`
	Networks []string `json:"networks"`
	Raw []string `json:"raw"`
	Servername string `json:"servername"`
	Username *string `json:"username"`
}

type NetbiosName struct {
	Flags  int    `json:"flags"`
	Name   string `json:"name"`
	Suffix int    `json:"suffix"`
}

var documentedKeys = []string{
	"monlist", "system", "version", "clock", "clock_offset", "delay", "frequency", "jitter", "leap", "noise", "offset",
	"poll", "precision", "reftime", "root_delay", "rootdelay", "rootdisp", "stability", "stratum",
}

type NTP struct {
	Monlist interface{} `json:"monlist"`
	System string `json:"system,omitempty"`
	Version interface{} `json:"version"`

	RefId       string      `json:"refid"`
	State       int         `json:"state"`
	Clock       string      `json:"clock,omitempty"`
	ClockOffset float64     `json:"clock_offset"`
	Delay       float64     `json:"delay"`
	MinTC       int         `json:"mintc,omitempty"`
	TC          int         `json:"tc,omitempty"`
	Peer        uint64      `json:"peer,omitempty"`
	Processor   string      `json:"processor,omitempty"`
	Frequency   interface{} `json:"frequency,omitempty"`
	Jitter      float64     `json:"jitter,omitempty"`
	SysJitter   interface{} `json:"sys_jitter,omitempty"`
	ClkJitter   interface{} `json:"clk_jitter,omitempty"`
	ClkWander   interface{} `json:"clk_wander,omitempty"`
	Phase       interface{} `json:"phase"`
	Leap        int         `json:"leap"`
	Noise       float64     `json:"noise,omitempty"`
	Offset      interface{} `json:"offset,omitempty"`
	Poll        int         `json:"poll"`
	Precision   int         `json:"precision"`
	Reftime     interface{} `json:"reftime"`
	RootDelay   float64     `json:"root_delay"`
	Rootdelay   interface{} `json:"rootdelay,omitempty"`
	RootDisp    interface{} `json:"rootdisp,omitempty"`
	Stability   float64     `json:"stability,omitempty"`
	Stratum     int         `json:"stratum"`
	Extra       map[string]interface{}
}

type ntpOverhead NTP

func (n *NTP) UnmarshalJSON(bytes []byte) (err error) {
	overhead := ntpOverhead{}

	if err = json.Unmarshal(bytes, &overhead); err == nil {
		*n = NTP(overhead)
	}

	extraValues := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &extraValues); err == nil {
		for _, key := range documentedKeys {
			delete(extraValues, key)
		}
		n.Extra = extraValues
	}

	return err
}

type Redis struct {
	CPU RedisCpuData `json:"cpu"`
	Clients interface{} `json:"clients"`
	Cluster interface{} `json:"cluster,omitempty"`
	Keys    RedisKeys   `json:"keys,omitempty"`
	Keyspaces map[string]string `json:"keyspace"`
	Memory    map[string]interface{} `json:"memory"`
	Pacluster map[string]interface{} `json:"pacluster,omitempty"`
	Persistence map[string]interface{} `json:"persistence,omitempty"`
	Replication map[string]interface{} `json:"replication,omitempty"`
	Server        RedisServer        `json:"server"`
	SSL           *RedisSSL          `json:"ssl,omitempty"`
	OomPrevention RedisOomPrevention `json:"oom-prevention"`
	Stats map[string]interface{} `json:"stats,omitempty"`
}

type RedisCpuData struct {
	UsedCPUSys          float64 `json:"used_cpu_sys"`
	UsedCPUSysChildren  float64 `json:"used_cpu_sys_children"`
	UsedCPUUser         float64 `json:"used_cpu_user"`
	UsedCPUUserChildren float64 `json:"used_cpu_user_children"`
}

type RedisKeys struct {
	Data []string `json:"data"`
	More bool `json:"more"`
}

type RedisServer struct {
	ArchBits        int         `json:"arch_bits"`
	AtomicvarAPI    string      `json:"atomicvar_api,omitempty"`
	ConfigFile      string      `json:"config_file,omitempty"`
	ConfiguredHz    int         `json:"configured_hz,omitempty"`
	Executable      string      `json:"executable,omitempty"`
	GccVersion      string      `json:"gcc_version,omitempty"`
	Hz              int         `json:"hz,omitempty"`
	LruClock        int         `json:"lru_clock"`
	MultiplexingAPI string      `json:"multiplexing_api"`
	Os              string      `json:"os"`
	ProcessID       int         `json:"process_id"`
	RedisBuildID    interface{} `json:"redis_build_id,omitempty"`
	RedisGitDirty   int         `json:"redis_git_dirty"`
	RedisGitSHA1    interface{} `json:"redis_git_sha1"`
	RedisMode       string      `json:"redis_mode"`
	RedisVersion    string      `json:"redis_version"`
	RlecVersion     string      `json:"rlec_version,omitempty"`
	RunID           string      `json:"run_id"`
	TCPPort         int         `json:"tcp_port"`
	UptimeInDays    int         `json:"uptime_in_days"`
	UptimeInSeconds int         `json:"uptime_in_seconds"`
}

type RedisSSL struct {
	SSLConnectionsToCurrentCertificate  int    `json:"ssl_connections_to_current_certificate"`
	SSLConnectionsToPreviousCertificate int    `json:"ssl_connections_to_previous_certificate"`
	SSLCurrentCertificateNotAfterDate   string `json:"ssl_current_certificate_not_after_date"`
	SSLCurrentCertificateNotBeforeDate  string `json:"ssl_current_certificate_not_before_date"`
	SSLCurrentCertificateSerial         int    `json:"ssl_current_certificate_serial"`
	SSLEnabled                          string `json:"ssl_enabled"`
}

type RedisOomPrevention struct {
	On                                 string `json:"oom_prevention_on"`
	PeakUsedMemoryTotal                uint64 `json:"peak_used_memory_total"`
	PreventionThreshold                uint64 `json:"oom_prevention_threshold"`
	UsedMemoryRdb                      uint64 `json:"used_memory_rdb"`
	UsedMemoryAof                      uint64 `json:"used_memory_aof"`
	UsedMemoryTotal                    uint64 `json:"used_memory_total"`
	CurrentUsecondsWithOomPreventionOn uint64 `json:"current_useconds_with_oom_prevention_on"`
	TotalUsecondsWithOomPreventionOn   uint64 `json:"total_useconds_with_oom_prevention_on"`
	ThresholdHuman                     string `json:"oom_prevention_threshold_human"`
	UsedMemoryRdbHuman                 string `json:"used_memory_rdb_human"`
	UsedMemoryAofHuman                 string `json:"used_memory_aof_human"`
	UsedMemoryTotalHuman               string `json:"used_memory_total_human"`
	PeakUsedMemoryTotalHuman           string `json:"peak_used_memory_total_human"`
}

type RIP struct {
	Addresses []RipAddress `json:"addresses"`
	Command int `json:"command"`
	Version int `json:"version"`
}

type RipAddress struct {
	Addr string `json:"addr"`
	Family  interface{} `json:"family"`
	Metric  int         `json:"metric"`
	NextHop interface{} `json:"next_hop"`
	Subnet  *string     `json:"subnet"`
	Tag     *int        `json:"tag"`
}

type Rsync struct {
	Authentication bool `json:"authentication"`
	Modules map[string]string `json:"modules"`
}

type SMB struct {
	Anonymous bool `json:"anonymous"`
	Capabilities []string `json:"capabilities"`
	OS string `json:"os,omitempty"`
	Raw []string `json:"raw"`
	Shares []SmbShare `json:"shares,omitempty"`
	SmbVersion int `json:"smb_version"`
	Software string `json:"software,omitempty"`
}

type SmbShare struct {
	Comments  string    `json:"comments"`
	Files     []SmbFile `json:"files,omitempty"`
	Name      string    `json:"name"`
	Special   bool      `json:"special"`
	Temporary bool      `json:"temporary"`
	Type      string    `json:"type"`
}

type SmbFile struct {
	Directory bool   `json:"directory"`
	Name      string `json:"name"`
	ReadOnly  bool   `json:"read-only"`
	Size      int    `json:"size"`
}

type SNMP struct {
	Contact string `json:"contact"`
	Description string `json:"description"`
	Location *string `json:"location"`
	Name *string `json:"name"`

	Uptime       string `json:"uptime"`
	ObjectId     string `json:"objectid"`
	Services     string `json:"services"`
	OrLastChange string `json:"orlastchange"`
	OrDescr      string `json:"ordescr"`
	OrUptime     string `json:"oruptime"`
	OrId         string `json:"orid"`
}


type SSH struct {
	Cipher string `json:"cipher"`
	Fingerprint string `json:"fingerprint"`
	Hassh       string `json:"hassh"`
	Kex SshKex `json:"kex"`
	Key string `json:"key"`
	Mac string `json:"mac"`
	Type string `json:"type"`
}

type SshKex struct {
	CompressionAlgorithms   []string `json:"compression_algorithms"`
	EncryptionAlgorithms    []string `json:"encryption_algorithms"`
	KexAlgorithms           []string `json:"kex_algorithms"`
	KexFollows              bool     `json:"kex_follows"`
	Languages               []string `json:"languages"`
	MacAlgorithms           []string `json:"mac_algorithms"`
	ServerHostKeyAlgorithms []string `json:"server_host_key_algorithms"`
	Unused                  int      `json:"unused"`
}

type Vertx struct {
	FirmwareData string `json:"firmware_data"`
	FirmwareVersion string `json:"firmware_version"`
	InternalIP string `json:"internal_ip"`
	MAC string `json:"mac"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type Minecraft struct {
	Version     MinecraftServerVersion `json:"version"`
	Players     MinecraftPlayersInfo   `json:"players"`
	ForgeData   MinecraftForgeInfo     `json:"forgeData"`
	ModInfo     MinecraftModInfo       `json:"modinfo,omitempty"`
	Description string                 `json:"description"`
	Favicon     string                 `json:"favicon,omitempty"`
	Whitelisted bool                   `json:"whitelisted,omitempty"`
}

type MinecraftServerVersion struct {
	Protocol int    `json:"protocol"`
	Name     string `json:"name"`
}

type MinecraftPlayersInfo struct {
	Max    int `json:"max"`
	Online int `json:"online"`
}

type MinecraftForgeInfo struct {
	Channels          []MinecraftForgeChannel `json:"channels"`
	Mods              []MinecraftMod          `json:"mods"`
	FmlNetworkVersion int                     `json:"fmlNetworkVersion"`
}

type MinecraftForgeChannel struct {
	Res      string `json:"res"`
	Version  string `json:"version"`
	Required bool   `json:"required"`
}

type MinecraftMod struct {
	ModMarker string `json:"modmarker"`
	ModId     string `json:"modId"`
}

type MinecraftModInfo struct {
	Type    string        `json:"type"`
	ModList []ModInfoItem `json:"modList"`
}

type ModInfoItem struct {
	Version string `json:"version"`
	ModId   string `json:"modId"`
}

type MinecraftPlayer struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type InfluxDb struct {
	Uptime          string   `json:"uptime"`
	GoMaxProcs      int      `json:"go_max_procs"`
	GoVersion       string   `json:"go_version"`
	GoOS            string   `json:"go_os"`
	GoArch          string   `json:"go_arch"`
	NetworkHostname string   `json:"network_hostname"`
	Version         string   `json:"version"`
	BindAddress     string   `json:"bind_address"`
	Build           string   `json:"build"`
	Databases       []string `json:"databases"`
}

type CoAP struct {
	Resources map[string]interface{} `json:"resources"`
}