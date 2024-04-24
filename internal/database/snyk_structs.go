package database

import "time"

type CodeResults struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name            string `json:"name"`
				SemanticVersion string `json:"semanticVersion"`
				Version         string `json:"version"`
				Rules           []struct {
					ID               string `json:"id"`
					Name             string `json:"name"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
					Help struct {
						Markdown string `json:"markdown"`
						Text     string `json:"text"`
					} `json:"help"`
					Properties struct {
						Tags               []string `json:"tags"`
						Categories         []string `json:"categories"`
						ExampleCommitFixes []struct {
							CommitURL string `json:"commitURL"`
							Lines     []struct {
								Line       string `json:"line"`
								LineNumber int    `json:"lineNumber"`
								LineChange string `json:"lineChange"`
							} `json:"lines"`
						} `json:"exampleCommitFixes"`
						ExampleCommitDescriptions []interface{} `json:"exampleCommitDescriptions"`
						Precision                 string        `json:"precision"`
						RepoDatasetSize           int           `json:"repoDatasetSize"`
						Cwe                       []string      `json:"cwe"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Message   struct {
				Text      string   `json:"text"`
				Markdown  string   `json:"markdown"`
				Arguments []string `json:"arguments"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI       string `json:"uri"`
						URIBaseID string `json:"uriBaseId"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						EndLine     int `json:"endLine"`
						StartColumn int `json:"startColumn"`
						EndColumn   int `json:"endColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Fingerprints struct {
				Num0 string `json:"0"`
				Num1 string `json:"1"`
			} `json:"fingerprints"`
			CodeFlows []struct {
				ThreadFlows []struct {
					Locations []struct {
						Location struct {
							ID               int `json:"id"`
							PhysicalLocation struct {
								ArtifactLocation struct {
									URI       string `json:"uri"`
									URIBaseID string `json:"uriBaseId"`
								} `json:"artifactLocation"`
								Region struct {
									StartLine   int `json:"startLine"`
									EndLine     int `json:"endLine"`
									StartColumn int `json:"startColumn"`
									EndColumn   int `json:"endColumn"`
								} `json:"region"`
							} `json:"physicalLocation"`
						} `json:"location"`
					} `json:"locations"`
				} `json:"threadFlows"`
			} `json:"codeFlows"`
			Properties struct {
				PriorityScore        int `json:"priorityScore"`
				PriorityScoreFactors []struct {
					Label bool   `json:"label"`
					Type  string `json:"type"`
				} `json:"priorityScoreFactors"`
			} `json:"properties"`
		} `json:"results"`
		Properties struct {
			Coverage []struct {
				IsSupported bool   `json:"isSupported"`
				Lang        string `json:"lang"`
				Files       int    `json:"files"`
				Type        string `json:"type"`
			} `json:"coverage"`
		} `json:"properties"`
	} `json:"runs"`
}

type OpenSourceResults struct {
	Vulnerabilities []struct {
		ID     string   `json:"id"`
		Title  string   `json:"title"`
		CVSSv3 string   `json:"CVSSv3"`
		Credit []string `json:"credit"`
		Semver struct {
			Vulnerable       []string    `json:"vulnerable"`
			HashesRange      []string    `json:"hashesRange"`
			VulnerableHashes interface{} `json:"vulnerableHashes"`
		} `json:"semver"`
		Exploit  string        `json:"exploit"`
		FixedIn  []string      `json:"fixedIn"`
		Patches  []interface{} `json:"patches"`
		Insights struct {
			TriageAdvice interface{} `json:"triageAdvice"`
		} `json:"insights"`
		Language   string        `json:"language"`
		Severity   string        `json:"severity"`
		CvssScore  float64       `json:"cvssScore"`
		Functions  []interface{} `json:"functions"`
		Malicious  bool          `json:"malicious"`
		IsDisputed bool          `json:"isDisputed"`
		ModuleName string        `json:"moduleName"`
		References []struct {
			URL   string `json:"url"`
			Title string `json:"title"`
		} `json:"references"`
		CvssDetails []struct {
			Assigner         string    `json:"assigner"`
			Severity         string    `json:"severity"`
			CvssV3Vector     string    `json:"cvssV3Vector"`
			CvssV3BaseScore  float64   `json:"cvssV3BaseScore"`
			ModificationTime time.Time `json:"modificationTime"`
		} `json:"cvssDetails"`
		Description string `json:"description"`
		EpssDetails struct {
			Percentile   string `json:"percentile"`
			Probability  string `json:"probability"`
			ModelVersion string `json:"modelVersion"`
		} `json:"epssDetails"`
		Identifiers struct {
			Cve []string `json:"CVE"`
			Cwe []string `json:"CWE"`
		} `json:"identifiers"`
		PackageName          string        `json:"packageName"`
		Proprietary          bool          `json:"proprietary"`
		CreationTime         time.Time     `json:"creationTime"`
		FunctionsNew         []interface{} `json:"functions_new"`
		AlternativeIds       []interface{} `json:"alternativeIds"`
		DisclosureTime       time.Time     `json:"disclosureTime"`
		PackageManager       string        `json:"packageManager"`
		PublicationTime      time.Time     `json:"publicationTime"`
		ModificationTime     time.Time     `json:"modificationTime"`
		SocialTrendAlert     bool          `json:"socialTrendAlert"`
		SeverityWithCritical string        `json:"severityWithCritical"`
		From                 []string      `json:"from"`
		UpgradePath          []interface{} `json:"upgradePath"`
		IsUpgradable         bool          `json:"isUpgradable"`
		IsPatchable          bool          `json:"isPatchable"`
		Name                 string        `json:"name"`
		Version              string        `json:"version"`
	} `json:"vulnerabilities"`
	Ok              bool   `json:"ok"`
	DependencyCount int    `json:"dependencyCount"`
	Org             string `json:"org"`
	Policy          string `json:"policy"`
	IsPrivate       bool   `json:"isPrivate"`
	LicensesPolicy  struct {
		Severities struct {
		} `json:"severities"`
		OrgLicenseRules struct {
			AGPL10 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"AGPL-1.0"`
			AGPL30 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"AGPL-3.0"`
			Artistic10 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"Artistic-1.0"`
			Artistic20 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"Artistic-2.0"`
			CDDL10 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"CDDL-1.0"`
			CPOL102 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"CPOL-1.02"`
			EPL10 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"EPL-1.0"`
			GPL20 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"GPL-2.0"`
			GPL30 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"GPL-3.0"`
			LGPL20 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"LGPL-2.0"`
			LGPL21 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"LGPL-2.1"`
			LGPL30 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"LGPL-3.0"`
			MPL11 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"MPL-1.1"`
			MPL20 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"MPL-2.0"`
			MSRL struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"MS-RL"`
			SimPL20 struct {
				LicenseType  string `json:"licenseType"`
				Severity     string `json:"severity"`
				Instructions string `json:"instructions"`
			} `json:"SimPL-2.0"`
		} `json:"orgLicenseRules"`
	} `json:"licensesPolicy"`
	PackageManager string `json:"packageManager"`
	IgnoreSettings struct {
		AdminOnly                  bool `json:"adminOnly"`
		ReasonRequired             bool `json:"reasonRequired"`
		DisregardFilesystemIgnores bool `json:"disregardFilesystemIgnores"`
	} `json:"ignoreSettings"`
	Summary          string `json:"summary"`
	FilesystemPolicy bool   `json:"filesystemPolicy"`
	Filtered         struct {
		Ignore []interface{} `json:"ignore"`
		Patch  []interface{} `json:"patch"`
	} `json:"filtered"`
	UniqueCount        int    `json:"uniqueCount"`
	TargetFile         string `json:"targetFile"`
	ProjectName        string `json:"projectName"`
	DisplayTargetFile  string `json:"displayTargetFile"`
	HasUnknownVersions bool   `json:"hasUnknownVersions"`
	Path               string `json:"path"`
}
