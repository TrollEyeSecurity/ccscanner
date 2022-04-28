package owaspzap

import "encoding/xml"

type ContextConfiguration struct {
	XMLName xml.Name `xml:"configuration"`
	Text    string   `xml:",chardata"`
	Context struct {
		Text       string   `xml:",chardata"`
		Name       string   `xml:"name"`
		Desc       string   `xml:"desc"`
		Inscope    string   `xml:"inscope"`
		Incregexes []string `xml:"incregexes"`
		Tech       struct {
			Text    string   `xml:",chardata"`
			Include []string `xml:"include"`
		} `xml:"tech"`
		Urlparser struct {
			Text   string `xml:",chardata"`
			Class  string `xml:"class"`
			Config string `xml:"config"`
		} `xml:"urlparser"`
		Postparser struct {
			Text   string `xml:",chardata"`
			Class  string `xml:"class"`
			Config string `xml:"config"`
		} `xml:"postparser"`
		Authentication struct {
			Text        string `xml:",chardata"`
			Type        string `xml:"type"`
			Strategy    string `xml:"strategy"`
			Pollurl     string `xml:"pollurl"`
			Polldata    string `xml:"polldata"`
			Pollheaders string `xml:"pollheaders"`
			Pollfreq    string `xml:"pollfreq"`
			Pollunits   string `xml:"pollunits"`
			Loggedin    string `xml:"loggedin"`
			Form        struct {
				Text         string `xml:",chardata"`
				Loginurl     string `xml:"loginurl"`
				Loginbody    string `xml:"loginbody"`
				Loginpageurl string `xml:"loginpageurl"`
			} `xml:"form"`
		} `xml:"authentication"`
		Users []struct {
			Text string `xml:",chardata"`
			User string `xml:"user"`
		} `xml:"users"`
		Forceduser string `xml:"forceduser"`
		Session    struct {
			Text string `xml:",chardata"`
			Type string `xml:"type"`
		} `xml:"session"`
		Authorization struct {
			Text  string `xml:",chardata"`
			Type  string `xml:"type"`
			Basic struct {
				Text   string `xml:",chardata"`
				Header string `xml:"header"`
				Body   string `xml:"body"`
				Logic  string `xml:"logic"`
				Code   string `xml:"code"`
			} `xml:"basic"`
		} `xml:"authorization"`
	} `xml:"context"`
}

type jsonResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	ContextID string `json:"contextId"`
	Result    string `json:"Result"`
	UserID    string `json:"userId"`
	Scan      string `json:"scan"`
	Status    string `json:"status"`
}
