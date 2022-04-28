package gvm

import "encoding/xml"

type CreateConfigResponse struct {
	XMLName    xml.Name `xml:"create_config_response"`
	Text       string   `xml:",chardata"`
	Status     string   `xml:"status,attr"`
	StatusText string   `xml:"status_text,attr"`
	ID         string   `xml:"id,attr"`
}

type ModifyConfigResponse struct {
	XMLName    xml.Name `xml:"modify_config_response"`
	Text       string   `xml:",chardata"`
	Status     string   `xml:"status,attr"`
	StatusText string   `xml:"status_text,attr"`
}

type CreateTarget struct {
	XMLName      xml.Name `xml:"create_target"`
	Name         string   `xml:"name,attr"`
	Hosts        string   `xml:"hosts,attr"`
	AliveTests   string   `xml:"alive_tests,attr"`
	ExcludeHosts string   `xml:"exclude_hosts,attr"`
}

type CreateTargetResponse struct {
	XMLName    xml.Name `xml:"create_target_response"`
	Text       string   `xml:",chardata"`
	Status     string   `xml:"status,attr"`
	StatusText string   `xml:"status_text,attr"`
	ID         string   `xml:"id,attr"`
}

type CreateTaskResponse struct {
	XMLName    xml.Name `xml:"create_task_response"`
	Text       string   `xml:",chardata"`
	Status     string   `xml:"status,attr"`
	StatusText string   `xml:"status_text,attr"`
	ID         string   `xml:"id,attr"`
}

type StartTaskResponse struct {
	XMLName    xml.Name `xml:"start_task_response"`
	Text       string   `xml:",chardata"`
	Status     string   `xml:"status,attr"`
	StatusText string   `xml:"status_text,attr"`
	ReportID   string   `xml:"report_id"`
}

type GetTasksResponse struct {
	XMLName        xml.Name `xml:"get_tasks_response"`
	Text           string   `xml:",chardata"`
	Status         string   `xml:"status,attr"`
	StatusText     string   `xml:"status_text,attr"`
	ApplyOverrides string   `xml:"apply_overrides"`
	Task           struct {
		Text  string `xml:",chardata"`
		ID    string `xml:"id,attr"`
		Owner struct {
			Text string `xml:",chardata"`
			Name string `xml:"name"`
		} `xml:"owner"`
		Name             string `xml:"name"`
		Comment          string `xml:"comment"`
		CreationTime     string `xml:"creation_time"`
		ModificationTime string `xml:"modification_time"`
		Writable         string `xml:"writable"`
		InUse            string `xml:"in_use"`
		Permissions      struct {
			Text       string `xml:",chardata"`
			Permission struct {
				Text string `xml:",chardata"`
				Name string `xml:"name"`
			} `xml:"permission"`
		} `xml:"permissions"`
		UserTags struct {
			Text  string `xml:",chardata"`
			Count string `xml:"count"`
		} `xml:"user_tags"`
		Alterable string `xml:"alterable"`
		Config    struct {
			Text  string `xml:",chardata"`
			ID    string `xml:"id,attr"`
			Name  string `xml:"name"`
			Type  string `xml:"type"`
			Trash string `xml:"trash"`
		} `xml:"config"`
		Target struct {
			Text  string `xml:",chardata"`
			ID    string `xml:"id,attr"`
			Name  string `xml:"name"`
			Trash string `xml:"trash"`
		} `xml:"target"`
		HostsOrdering string `xml:"hosts_ordering"`
		Scanner       struct {
			Text  string `xml:",chardata"`
			ID    string `xml:"id,attr"`
			Name  string `xml:"name"`
			Type  string `xml:"type"`
			Trash string `xml:"trash"`
		} `xml:"scanner"`
		Status   string `xml:"status"`
		Progress struct {
			Text         string `xml:",chardata"`
			HostProgress struct {
				Text string `xml:",chardata"`
				Host string `xml:"host"`
			} `xml:"host_progress"`
		} `xml:"progress"`
		ReportCount struct {
			Text     string `xml:",chardata"`
			Finished string `xml:"finished"`
		} `xml:"report_count"`
		Trend    string `xml:"trend"`
		Schedule struct {
			Text     string `xml:",chardata"`
			ID       string `xml:"id,attr"`
			Name     string `xml:"name"`
			NextTime string `xml:"next_time"`
			Trash    string `xml:"trash"`
		} `xml:"schedule"`
		SchedulePeriods string `xml:"schedule_periods"`
		CurrentReport   struct {
			Text   string `xml:",chardata"`
			Report struct {
				Text      string `xml:",chardata"`
				ID        string `xml:"id,attr"`
				Timestamp string `xml:"timestamp"`
				ScanStart string `xml:"scan_start"`
				ScanEnd   string `xml:"scan_end"`
			} `xml:"report"`
		} `xml:"current_report"`
		Observers       string `xml:"observers"`
		AverageDuration string `xml:"average_duration"`
		ResultCount     string `xml:"result_count"`
		Preferences     struct {
			Text       string `xml:",chardata"`
			Preference []struct {
				Text        string `xml:",chardata"`
				Name        string `xml:"name"`
				ScannerName string `xml:"scanner_name"`
				Value       string `xml:"value"`
			} `xml:"preference"`
		} `xml:"preferences"`
	} `xml:"task"`
	Filters struct {
		Text     string `xml:",chardata"`
		ID       string `xml:"id,attr"`
		Term     string `xml:"term"`
		Keywords struct {
			Text    string `xml:",chardata"`
			Keyword []struct {
				Text     string `xml:",chardata"`
				Column   string `xml:"column"`
				Relation string `xml:"relation"`
				Value    string `xml:"value"`
			} `xml:"keyword"`
		} `xml:"keywords"`
	} `xml:"filters"`
	Sort struct {
		Text  string `xml:",chardata"`
		Field struct {
			Text  string `xml:",chardata"`
			Order string `xml:"order"`
		} `xml:"field"`
	} `xml:"sort"`
	Tasks struct {
		Text  string `xml:",chardata"`
		Max   string `xml:"max,attr"`
		Start string `xml:"start,attr"`
	} `xml:"tasks"`
	TaskCount struct {
		Text     string `xml:",chardata"`
		Filtered string `xml:"filtered"`
		Page     string `xml:"page"`
	} `xml:"task_count"`
}

type GetReportsResponse struct {
	XMLName    xml.Name `xml:"get_reports_response"`
	Text       string   `xml:",chardata"`
	Status     string   `xml:"status,attr"`
	StatusText string   `xml:"status_text,attr"`
	Report     struct {
		Text        string `xml:",chardata"`
		ID          string `xml:"id,attr"`
		FormatID    string `xml:"format_id,attr"`
		Extension   string `xml:"extension,attr"`
		ContentType string `xml:"content_type,attr"`
		Owner       struct {
			Text string `xml:",chardata"`
			Name string `xml:"name"`
		} `xml:"owner"`
		Name             string `xml:"name"`
		Comment          string `xml:"comment"`
		CreationTime     string `xml:"creation_time"`
		ModificationTime string `xml:"modification_time"`
		Writable         string `xml:"writable"`
		InUse            string `xml:"in_use"`
		Task             struct {
			Text string `xml:",chardata"`
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		} `xml:"task"`
		ReportFormat struct {
			Text string `xml:",chardata"`
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		} `xml:"report_format"`
	} `xml:"report"`
	Filters struct {
		Text     string `xml:",chardata"`
		ID       string `xml:"id,attr"`
		Term     string `xml:"term"`
		Keywords struct {
			Text    string `xml:",chardata"`
			Keyword []struct {
				Text     string `xml:",chardata"`
				Column   string `xml:"column"`
				Relation string `xml:"relation"`
				Value    string `xml:"value"`
			} `xml:"keyword"`
		} `xml:"keywords"`
	} `xml:"filters"`
	Sort struct {
		Text  string `xml:",chardata"`
		Field struct {
			Text  string `xml:",chardata"`
			Order string `xml:"order"`
		} `xml:"field"`
	} `xml:"sort"`
	Reports struct {
		Text  string `xml:",chardata"`
		Start string `xml:"start,attr"`
		Max   string `xml:"max,attr"`
	} `xml:"reports"`
	ReportCount struct {
		Text     string `xml:",chardata"`
		Filtered string `xml:"filtered"`
		Page     string `xml:"page"`
	} `xml:"report_count"`
}

type GetFeedsResponse struct {
	XMLName    xml.Name `xml:"get_feeds_response"`
	Text       string   `xml:",chardata"`
	Status     string   `xml:"status,attr"`
	StatusText string   `xml:"status_text,attr"`
	Feed       []struct {
		Text             string `xml:",chardata"`
		Type             string `xml:"type"`
		Name             string `xml:"name"`
		Version          string `xml:"version"`
		Description      string `xml:"description"`
		CurrentlySyncing struct {
			Text      string `xml:",chardata"`
			Timestamp string `xml:"timestamp"`
		} `xml:"currently_syncing"`
	} `xml:"feed"`
}

/*

type GetReportsResponse struct {
	XMLName    xml.Name `xml:"get_reports_response"`
	Text       string   `xml:",chardata"`
	Status     string   `xml:"status,attr"`
	StatusText string   `xml:"status_text,attr"`
	Report     struct {
		Text        string `xml:",chardata"`
		ID          string `xml:"id,attr"`
		FormatID    string `xml:"format_id,attr"`
		Extension   string `xml:"extension,attr"`
		ContentType string `xml:"content_type,attr"`
		Owner       struct {
			Text string `xml:",chardata"`
			Name string `xml:"name"`
		} `xml:"owner"`
		Name             string `xml:"name"`
		Comment          string `xml:"comment"`
		CreationTime     string `xml:"creation_time"`
		ModificationTime string `xml:"modification_time"`
		Writable         string `xml:"writable"`
		InUse            string `xml:"in_use"`
		Task             struct {
			Text string `xml:",chardata"`
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		} `xml:"task"`
		ReportFormat struct {
			Text string `xml:",chardata"`
			ID   string `xml:"id,attr"`
			Name string `xml:"name"`
		} `xml:"report_format"`
		Report struct {
			Text string `xml:",chardata"`
			ID   string `xml:"id,attr"`
			Gmp  struct {
				Text    string `xml:",chardata"`
				Version string `xml:"version"`
			} `xml:"gmp"`
			Sort struct {
				Text  string `xml:",chardata"`
				Field struct {
					Text  string `xml:",chardata"`
					Order string `xml:"order"`
				} `xml:"field"`
			} `xml:"sort"`
			Filters struct {
				Text     string   `xml:",chardata"`
				ID       string   `xml:"id,attr"`
				Term     string   `xml:"term"`
				Filter   []string `xml:"filter"`
				Keywords struct {
					Text    string `xml:",chardata"`
					Keyword []struct {
						Text     string `xml:",chardata"`
						Column   string `xml:"column"`
						Relation string `xml:"relation"`
						Value    string `xml:"value"`
					} `xml:"keyword"`
				} `xml:"keywords"`
			} `xml:"filters"`
			SeverityClass struct {
				Text          string `xml:",chardata"`
				ID            string `xml:"id,attr"`
				Name          string `xml:"name"`
				FullName      string `xml:"full_name"`
				SeverityRange []struct {
					Text string `xml:",chardata"`
					Name string `xml:"name"`
					Min  string `xml:"min"`
					Max  string `xml:"max"`
				} `xml:"severity_range"`
			} `xml:"severity_class"`
			ScanRunStatus string `xml:"scan_run_status"`
			Hosts         struct {
				Text  string `xml:",chardata"`
				Count string `xml:"count"`
			} `xml:"hosts"`
			ClosedCves struct {
				Text  string `xml:",chardata"`
				Count string `xml:"count"`
			} `xml:"closed_cves"`
			Vulns struct {
				Text  string `xml:",chardata"`
				Count string `xml:"count"`
			} `xml:"vulns"`
			Os struct {
				Text  string `xml:",chardata"`
				Count string `xml:"count"`
			} `xml:"os"`
			Apps struct {
				Text  string `xml:",chardata"`
				Count string `xml:"count"`
			} `xml:"apps"`
			SslCerts struct {
				Text  string `xml:",chardata"`
				Count string `xml:"count"`
			} `xml:"ssl_certs"`
			Task struct {
				Text    string `xml:",chardata"`
				ID      string `xml:"id,attr"`
				Name    string `xml:"name"`
				Comment string `xml:"comment"`
				Target  struct {
					Text    string `xml:",chardata"`
					ID      string `xml:"id,attr"`
					Trash   string `xml:"trash"`
					Name    string `xml:"name"`
					Comment string `xml:"comment"`
				} `xml:"target"`
				Progress string `xml:"progress"`
			} `xml:"task"`
			Scan struct {
				Text string `xml:",chardata"`
				Task string `xml:"task"`
			} `xml:"scan"`
			Timestamp      string `xml:"timestamp"`
			ScanStart      string `xml:"scan_start"`
			Timezone       string `xml:"timezone"`
			TimezoneAbbrev string `xml:"timezone_abbrev"`
			Ports          struct {
				Text  string `xml:",chardata"`
				Start string `xml:"start,attr"`
				Max   string `xml:"max,attr"`
				Count string `xml:"count"`
				Port  []struct {
					Text     string `xml:",chardata"`
					Host     string `xml:"host"`
					Severity string `xml:"severity"`
					Threat   string `xml:"threat"`
				} `xml:"port"`
			} `xml:"ports"`
			Results struct {
				Text   string `xml:",chardata"`
				Start  string `xml:"start,attr"`
				Max    string `xml:"max,attr"`
				Result []struct {
					Text  string `xml:",chardata"`
					ID    string `xml:"id,attr"`
					Name  string `xml:"name"`
					Owner struct {
						Text string `xml:",chardata"`
						Name string `xml:"name"`
					} `xml:"owner"`
					ModificationTime string `xml:"modification_time"`
					Comment          string `xml:"comment"`
					CreationTime     string `xml:"creation_time"`
					Host             struct {
						Text  string `xml:",chardata"`
						Asset struct {
							Text    string `xml:",chardata"`
							AssetID string `xml:"asset_id,attr"`
						} `xml:"asset"`
						Hostname string `xml:"hostname"`
					} `xml:"host"`
					Port string `xml:"port"`
					Nvt  struct {
						Text     string `xml:",chardata"`
						Oid      string `xml:"oid,attr"`
						Type     string `xml:"type"`
						Name     string `xml:"name"`
						Family   string `xml:"family"`
						CvssBase string `xml:"cvss_base"`
						Tags     string `xml:"tags"`
						Refs     struct {
							Text string `xml:",chardata"`
							Ref  []struct {
								Text string `xml:",chardata"`
								Type string `xml:"type,attr"`
								ID   string `xml:"id,attr"`
							} `xml:"ref"`
						} `xml:"refs"`
					} `xml:"nvt"`
					ScanNvtVersion string `xml:"scan_nvt_version"`
					Threat         string `xml:"threat"`
					Severity       string `xml:"severity"`
					Qod            struct {
						Text  string `xml:",chardata"`
						Value string `xml:"value"`
						Type  string `xml:"type"`
					} `xml:"qod"`
					Description      string `xml:"description"`
					OriginalThreat   string `xml:"original_threat"`
					OriginalSeverity string `xml:"original_severity"`
					Detection        struct {
						Text   string `xml:",chardata"`
						Result struct {
							Text    string `xml:",chardata"`
							ID      string `xml:"id,attr"`
							Details struct {
								Text   string `xml:",chardata"`
								Detail []struct {
									Text  string `xml:",chardata"`
									Name  string `xml:"name"`
									Value string `xml:"value"`
								} `xml:"detail"`
							} `xml:"details"`
						} `xml:"result"`
					} `xml:"detection"`
				} `xml:"result"`
			} `xml:"results"`
			ResultCount struct {
				Text     string `xml:",chardata"`
				Full     string `xml:"full"`
				Filtered string `xml:"filtered"`
				Debug    struct {
					Text     string `xml:",chardata"`
					Full     string `xml:"full"`
					Filtered string `xml:"filtered"`
				} `xml:"debug"`
				Hole struct {
					Text     string `xml:",chardata"`
					Full     string `xml:"full"`
					Filtered string `xml:"filtered"`
				} `xml:"hole"`
				Info struct {
					Text     string `xml:",chardata"`
					Full     string `xml:"full"`
					Filtered string `xml:"filtered"`
				} `xml:"info"`
				Log struct {
					Text     string `xml:",chardata"`
					Full     string `xml:"full"`
					Filtered string `xml:"filtered"`
				} `xml:"log"`
				Warning struct {
					Text     string `xml:",chardata"`
					Full     string `xml:"full"`
					Filtered string `xml:"filtered"`
				} `xml:"warning"`
				FalsePositive struct {
					Text     string `xml:",chardata"`
					Full     string `xml:"full"`
					Filtered string `xml:"filtered"`
				} `xml:"false_positive"`
			} `xml:"result_count"`
			Severity struct {
				Text     string `xml:",chardata"`
				Full     string `xml:"full"`
				Filtered string `xml:"filtered"`
			} `xml:"severity"`
			Host []struct {
				Text  string `xml:",chardata"`
				Ip    string `xml:"ip"`
				Asset struct {
					Text    string `xml:",chardata"`
					AssetID string `xml:"asset_id,attr"`
				} `xml:"asset"`
				Start     string `xml:"start"`
				End       string `xml:"end"`
				PortCount struct {
					Text string `xml:",chardata"`
					Page string `xml:"page"`
				} `xml:"port_count"`
				ResultCount struct {
					Text string `xml:",chardata"`
					Page string `xml:"page"`
					Hole struct {
						Text string `xml:",chardata"`
						Page string `xml:"page"`
					} `xml:"hole"`
					Warning struct {
						Text string `xml:",chardata"`
						Page string `xml:"page"`
					} `xml:"warning"`
					Info struct {
						Text string `xml:",chardata"`
						Page string `xml:"page"`
					} `xml:"info"`
					Log struct {
						Text string `xml:",chardata"`
						Page string `xml:"page"`
					} `xml:"log"`
					FalsePositive struct {
						Text string `xml:",chardata"`
						Page string `xml:"page"`
					} `xml:"false_positive"`
				} `xml:"result_count"`
				Detail []struct {
					Text   string `xml:",chardata"`
					Name   string `xml:"name"`
					Value  string `xml:"value"`
					Source struct {
						Text        string `xml:",chardata"`
						Type        string `xml:"type"`
						Name        string `xml:"name"`
						Description string `xml:"description"`
					} `xml:"source"`
					Extra string `xml:"extra"`
				} `xml:"detail"`
			} `xml:"host"`
			ScanEnd string `xml:"scan_end"`
			Errors  struct {
				Text  string `xml:",chardata"`
				Count string `xml:"count"`
				Error []struct {
					Text string `xml:",chardata"`
					Host struct {
						Text  string `xml:",chardata"`
						Asset struct {
							Text    string `xml:",chardata"`
							AssetID string `xml:"asset_id,attr"`
						} `xml:"asset"`
					} `xml:"host"`
					Port        string `xml:"port"`
					Description string `xml:"description"`
					Nvt         struct {
						Text     string `xml:",chardata"`
						Oid      string `xml:"oid,attr"`
						Type     string `xml:"type"`
						Name     string `xml:"name"`
						CvssBase string `xml:"cvss_base"`
					} `xml:"nvt"`
					ScanNvtVersion string `xml:"scan_nvt_version"`
					Severity       string `xml:"severity"`
				} `xml:"error"`
			} `xml:"errors"`
			ReportFormat string `xml:"report_format"`
		} `xml:"report"`
	} `xml:"report"`
	Filters struct {
		Text     string `xml:",chardata"`
		ID       string `xml:"id,attr"`
		Term     string `xml:"term"`
		Keywords struct {
			Text    string `xml:",chardata"`
			Keyword []struct {
				Text     string `xml:",chardata"`
				Column   string `xml:"column"`
				Relation string `xml:"relation"`
				Value    string `xml:"value"`
			} `xml:"keyword"`
		} `xml:"keywords"`
	} `xml:"filters"`
	Sort struct {
		Text  string `xml:",chardata"`
		Field struct {
			Text  string `xml:",chardata"`
			Order string `xml:"order"`
		} `xml:"field"`
	} `xml:"sort"`
	Reports struct {
		Text  string `xml:",chardata"`
		Start string `xml:"start,attr"`
		Max   string `xml:"max,attr"`
	} `xml:"reports"`
	ReportCount struct {
		Text     string `xml:",chardata"`
		Filtered string `xml:"filtered"`
		Page     string `xml:"page"`
	} `xml:"report_count"`
}
*/
