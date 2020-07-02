package names

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/CriticalSecurity/ccscanner/pkg/certificates"
	"github.com/CriticalSecurity/ccscanner/pkg/shodan"
	"net"
)

func DoLookup(ip *string, shodanKey *string) *NameData {
	nd := &NameData{}
	lookupList, _ := net.LookupAddr(*ip)
	nd.ValidNames = append(nd.ValidNames, lookupList...)
	if IsPrivateIP(net.ParseIP(*ip)) == false {
		resp, _ := shodan.LoopkupIp(ip, shodanKey)
		shodanResponse := shodan.HostData{}
		DecoderError := json.NewDecoder(resp.Body).Decode(&shodanResponse)
		if DecoderError != nil {
			return nil
		}
		for _, service := range shodanResponse.Services {
			if service.SSL != nil {
				potentialNames, certErr := certificates.AnalyzeCertsForNames(ip, &service.Port)
				if certErr != nil {
					continue
				}
				for _, name := range *potentialNames {
					ipaddr, ipErr := net.LookupIP(name)
					if ipErr != nil {
						continue
					}
					theyMatch := ipaddr[0].String() == *ip
					if theyMatch {
						nd.ValidNames = append(nd.ValidNames, name)
					} else {
						nd.InvalidNames = append(nd.InvalidNames, name)
					}
				}
			}
		}
		resp.Body.Close()
	}
	return nd
}

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

type ConnectionState struct {
	PeerCertificates []*x509.Certificate // certificate chain presented by remote peer
}
