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

type StopTaskResponse struct {
	Status     string `xml:"status,attr"`
	StatusText string `xml:"status_text,attr"`
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
		LastReport      struct {
			Text   string `xml:",chardata"`
			Report struct {
				Text        string `xml:",chardata"`
				ID          string `xml:"id,attr"`
				Timestamp   string `xml:"timestamp"`
				ScanStart   string `xml:"scan_start"`
				ScanEnd     string `xml:"scan_end"`
				ResultCount struct {
					Text          string `xml:",chardata"`
					Hole          string `xml:"hole"`
					Info          string `xml:"info"`
					Log           string `xml:"log"`
					Warning       string `xml:"warning"`
					FalsePositive string `xml:"false_positive"`
				} `xml:"result_count"`
				Severity string `xml:"severity"`
			} `xml:"report"`
		} `xml:"last_report"`
		CurrentReport struct {
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
