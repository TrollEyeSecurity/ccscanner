package certificates

import (
	"crypto/tls"
	"strconv"
)

func AnalyzeCertsForNames(ip *string, service *int)  (*[]string, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	port := strconv.Itoa(*service)
	host := *ip +":"+ port
	conn, err := tls.Dial("tcp", host, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var potentialNames []string
	for _, cert := range conn.ConnectionState().PeerCertificates {
		if cert.IsCA{
			continue
		}
		if cert.DNSNames != nil {
			potentialNames = append(potentialNames, cert.DNSNames...)
			continue
		}
		potentialNames = append(potentialNames, cert.Subject.CommonName)
	}
	conn.Close()
	return &potentialNames, nil
}