package nmap

import "encoding/xml"

type Nmaprun struct {
	XMLName          xml.Name `xml:"nmaprun"`
	Scanner          string   `xml:"scanner,attr"`
	Args             string   `xml:"args,attr"`
	Start            string   `xml:"start,attr"`
	Startstr         string   `xml:"startstr,attr"`
	Version          string   `xml:"version,attr"`
	Xmloutputversion string   `xml:"xmloutputversion,attr"`
	Scaninfo         struct {
		Type        string `xml:"type,attr"`
		Protocol    string `xml:"protocol,attr"`
		Numservices string `xml:"numservices,attr"`
		Services    string `xml:"services,attr"`
	} `xml:"scaninfo"`
	Verbose struct {
		Level string `xml:"level,attr"`
	} `xml:"verbose"`
	Debugging struct {
		Level string `xml:"level,attr"`
	} `xml:"debugging"`
	Taskbegin []struct {
		Task string `xml:"task,attr"`
		Time string `xml:"time,attr"`
	} `xml:"taskbegin"`
	Taskprogress []struct {
		Task      string `xml:"task,attr"`
		Time      string `xml:"time,attr"`
		Percent   string `xml:"percent,attr"`
		Remaining string `xml:"remaining,attr"`
		Etc       string `xml:"etc,attr"`
	} `xml:"taskprogress"`
	Taskend []struct {
		Task      string `xml:"task,attr"`
		Time      string `xml:"time,attr"`
		Extrainfo string `xml:"extrainfo,attr"`
	} `xml:"taskend"`
	Prescript struct {
		Script struct {
			ID     string `xml:"id,attr"`
			Output string `xml:"output,attr"`
		} `xml:"script"`
	} `xml:"prescript"`
	Host []struct {
		Starttime string `xml:"starttime,attr"`
		Endtime   string `xml:"endtime,attr"`
		Status    struct {
			State     string `xml:"state,attr"`
			Reason    string `xml:"reason,attr"`
			ReasonTtl string `xml:"reason_ttl,attr"`
		} `xml:"status"`
		Address []struct {
			Addr     string `xml:"addr,attr"`
			Addrtype string `xml:"addrtype,attr"`
			Vendor   string `xml:"vendor,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Hostname struct {
				Name string `xml:"name,attr"`
				Type string `xml:"type,attr"`
			} `xml:"hostname"`
		} `xml:"hostnames"`
		Ports struct {
			Extraports struct {
				State        string `xml:"state,attr"`
				Count        string `xml:"count,attr"`
				Extrareasons struct {
					Reason string `xml:"reason,attr"`
					Count  string `xml:"count,attr"`
				} `xml:"extrareasons"`
			} `xml:"extraports"`
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				Portid   string `xml:"portid,attr"`
				State    struct {
					State     string `xml:"state,attr"`
					Reason    string `xml:"reason,attr"`
					ReasonTtl string `xml:"reason_ttl,attr"`
				} `xml:"state"`
				Service struct {
					Name       string   `xml:"name,attr"`
					Product    string   `xml:"product,attr"`
					Version    string   `xml:"version,attr"`
					Method     string   `xml:"method,attr"`
					Conf       string   `xml:"conf,attr"`
					Servicefp  string   `xml:"servicefp,attr"`
					Tunnel     string   `xml:"tunnel,attr"`
					Extrainfo  string   `xml:"extrainfo,attr"`
					Devicetype string   `xml:"devicetype,attr"`
					Ostype     string   `xml:"ostype,attr"`
					Cpe        []string `xml:"cpe"`
				} `xml:"service"`
				Script []struct {
					ID     string `xml:"id,attr"`
					Output string `xml:"output,attr"`
					Table  []struct {
						Key   string `xml:"key,attr"`
						Table []struct {
							Key  string `xml:"key,attr"`
							Elem []struct {
								Key string `xml:"key,attr"`
							} `xml:"elem"`
							Table []struct {
								Key  string `xml:"key,attr"`
								Elem []struct {
									Key string `xml:"key,attr"`
								} `xml:"elem"`
							} `xml:"table"`
						} `xml:"table"`
						Elem []struct {
							Key string `xml:"key,attr"`
						} `xml:"elem"`
					} `xml:"table"`
					Elem []struct {
						Key string `xml:"key,attr"`
					} `xml:"elem"`
				} `xml:"script"`
			} `xml:"port"`
		} `xml:"ports"`
		Os struct {
			Portused []struct {
				State  string `xml:"state,attr"`
				Proto  string `xml:"proto,attr"`
				Portid string `xml:"portid,attr"`
			} `xml:"portused"`
			Osmatch []struct {
				Name     string `xml:"name,attr"`
				Accuracy string `xml:"accuracy,attr"`
				Line     string `xml:"line,attr"`
				Osclass  []struct {
					Type     string   `xml:"type,attr"`
					Vendor   string   `xml:"vendor,attr"`
					Osfamily string   `xml:"osfamily,attr"`
					Osgen    string   `xml:"osgen,attr"`
					Accuracy string   `xml:"accuracy,attr"`
					Cpe      []string `xml:"cpe"`
				} `xml:"osclass"`
			} `xml:"osmatch"`
			Osfingerprint struct {
				Fingerprint string `xml:"fingerprint,attr"`
			} `xml:"osfingerprint"`
		} `xml:"os"`
		Uptime struct {
			Seconds  string `xml:"seconds,attr"`
			Lastboot string `xml:"lastboot,attr"`
		} `xml:"uptime"`
		Distance struct {
			Value string `xml:"value,attr"`
		} `xml:"distance"`
		Tcpsequence struct {
			Index      string `xml:"index,attr"`
			Difficulty string `xml:"difficulty,attr"`
			Values     string `xml:"values,attr"`
		} `xml:"tcpsequence"`
		Ipidsequence struct {
			Class  string `xml:"class,attr"`
			Values string `xml:"values,attr"`
		} `xml:"ipidsequence"`
		Tcptssequence struct {
			Class  string `xml:"class,attr"`
			Values string `xml:"values,attr"`
		} `xml:"tcptssequence"`
		Times struct {
			Srtt   string `xml:"srtt,attr"`
			Rttvar string `xml:"rttvar,attr"`
			To     string `xml:"to,attr"`
		} `xml:"times"`
		Hostscript struct {
			Text   string `xml:",chardata"`
			Script []struct {
				Text   string `xml:",chardata"`
				ID     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
				Table  []struct {
					Text string   `xml:",chardata"`
					Key  string   `xml:"key,attr"`
					Elem []string `xml:"elem"`
				} `xml:"table"`
			} `xml:"script"`
		} `xml:"hostscript"`
	} `xml:"host"`
	Runstats struct {
		Finished struct {
			Time    string `xml:"time,attr"`
			Timestr string `xml:"timestr,attr"`
			Elapsed string `xml:"elapsed,attr"`
			Summary string `xml:"summary,attr"`
			Exit    string `xml:"exit,attr"`
		} `xml:"finished"`
		Hosts struct {
			Up    string `xml:"up,attr"`
			Down  string `xml:"down,attr"`
			Total string `xml:"total,attr"`
		} `xml:"hosts"`
	} `xml:"runstats"`
}
