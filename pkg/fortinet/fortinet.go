package fortinet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/httpClient"
	"github.com/TrollEyeSecurity/ccscanner/pkg/macLookup"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"strings"
	"time"
)

func Discovery(content *database.TaskContent, secretData *database.TaskSecret, taskId *primitive.ObjectID) {
	var status string
	var percent int
	status = "PROGRESS"
	percent = 0
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("urlinspection mongo-client error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	_, updateError := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"status", status}, {"percent", percent}}}},
	)
	if updateError != nil {
		err := fmt.Errorf("fortios task-update error %v", updateError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	var firewall Firewall
	apiKey := secretData.FortiosApiKey
	/* -------------------------------------------------------------------------------------------------------------- */
	subnetList, subnetListErr := GetNetworks(&content.Hostname, &content.Port, &apiKey)
	if subnetListErr != nil {
		err1 := fmt.Errorf("fortios subnetList error: %v", subnetListErr)
		sentry.CaptureException(err1)
		log.Println(err1)
		return
	}
	percent = 16
	firewall.Subnets = *subnetList
	_, updateError2 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", percent}}}},
	)
	if updateError2 != nil {
		err := fmt.Errorf("fortios task-update error %v", updateError2)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	/* -------------------------------------------------------------------------------------------------------------- */
	system, systemErr := GetSystemInfo(&content.Hostname, &content.Port, &apiKey)
	if systemErr != nil {
		err1 := fmt.Errorf("fortios system error: %v", systemErr)
		sentry.CaptureException(err1)
		log.Println(err1)
		return
	}
	percent = 32
	firewall.System = *system
	_, updateError3 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", percent}}}},
	)
	if updateError3 != nil {
		err := fmt.Errorf("fortios task-update error %v", updateError3)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	/* -------------------------------------------------------------------------------------------------------------- */
	systemsIps, systemsIpsErr := GetSystemIps(&content.Hostname, &content.Port, &apiKey)
	if systemsIpsErr != nil {
		err1 := fmt.Errorf("fortios systemsIps error: %v", systemsIpsErr)
		sentry.CaptureException(err1)
		log.Println(err1)
		return
	}
	percent = 48
	firewall.SystemIps = *systemsIps
	_, updateError4 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", percent}}}},
	)
	if updateError4 != nil {
		err := fmt.Errorf("fortios task-update error %v", updateError4)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	/* -------------------------------------------------------------------------------------------------------------- */
	hostList, hostListErr := GetArp(&content.Hostname, &content.Port, &apiKey)
	if hostListErr != nil {
		err1 := fmt.Errorf("fortios hostList error: %v", hostListErr)
		sentry.CaptureException(err1)
		log.Println(err1)
		return
	}
	percent = 64
	firewall.Hosts = *hostList
	_, updateError5 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", percent}}}},
	)
	if updateError5 != nil {
		err := fmt.Errorf("fortios task-update error %v", updateError5)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	/* -------------------------------------------------------------------------------------------------------------- */
	firewallPolicy, firewallPolicyErr := GetPolicy(&content.Hostname, &content.Port, &apiKey)
	if firewallPolicyErr != nil {
		err1 := fmt.Errorf("fortios firewallPolicy error: %v", firewallPolicyErr)
		sentry.CaptureException(err1)
		log.Println(err1)
		return
	}
	firewall.Policy = *firewallPolicy
	percent = 80
	_, updateError6 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", percent}}}},
	)
	if updateError6 != nil {
		err := fmt.Errorf("fortios task-update error %v", updateError6)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
	/* -------------------------------------------------------------------------------------------------------------- */

	firewallAddresses, firewallAddressesErr := GetAddresses(&content.Hostname, &content.Port, &apiKey)
	if firewallAddressesErr != nil {
		err1 := fmt.Errorf("fortios firewallAddresses error: %v", firewallAddressesErr)
		sentry.CaptureException(err1)
		log.Println(err1)
		return
	}
	firewall.Addresses = *firewallAddresses
	/* -------------------------------------------------------------------------------------------------------------- */
	percent = 100
	status = "SUCCESS"
	firewallBytes, jsonMarshalErr := json.Marshal(firewall)
	if jsonMarshalErr != nil {
		err1 := fmt.Errorf("fortios json.Marshal error: %v", jsonMarshalErr)
		sentry.CaptureException(err1)
		log.Println(err1)
		return
	}
	result := base64.StdEncoding.EncodeToString(firewallBytes)
	_, updateError7 := tasksCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", *taskId}},
		bson.D{{"$set", bson.D{{"percent", percent}, {"status", status}, {"net_recon_result", result}}}},
	)
	if updateError7 != nil {
		err := fmt.Errorf("fortios task-update error %v", updateError7)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
		MongoClient.Disconnect(context.TODO())
		return
	}
}

func GetNetworks(hostname *string, port *int, secret *string) (*[]Subnet, error) {
	baseUrl := fmt.Sprintf("https://%s:%d", *hostname, *port)
	path := fmt.Sprintf("/api/v2/monitor/router/ipv4?access_token=%s", *secret)
	method := "GET"
	contentType := "application/json"
	hdr := make(map[string]string)
	resp, err := httpClient.Request(&baseUrl, &path, nil, &method, &contentType, &hdr)
	if err != nil {
		return nil, err
	}
	data := NetworkRouterResponse{}
	NewDecoderError := json.NewDecoder(resp.Body).Decode(&data)
	if NewDecoderError != nil {
		resp.Body.Close()
		err1 := fmt.Errorf("can\"t decode get networks")
		sentry.CaptureException(err1)
		log.Println(err1)
		return nil, err1
	}
	var subnetList []Subnet
	for _, network := range data.Results {
		if network.Type == "connect" {
			subNet := Subnet{Subnet: network.IpMask, SourceInterface: network.Interface}
			subnetList = append(subnetList, subNet)
		}
	}
	return &subnetList, nil
}

func GetSystemInfo(hostname *string, port *int, secret *string) (*System, error) {
	baseUrl := fmt.Sprintf("https://%s:%d", *hostname, *port)
	path := fmt.Sprintf("/api/v2/monitor/system/status?access_token=%s", *secret)
	method := "GET"
	contentType := "application/json"
	hdr := make(map[string]string)
	resp, err := httpClient.Request(&baseUrl, &path, nil, &method, &contentType, &hdr)
	if err != nil {
		return nil, err
	}
	data := SystemStatusResponse{}
	NewDecoderError := json.NewDecoder(resp.Body).Decode(&data)
	if NewDecoderError != nil {
		resp.Body.Close()
		err1 := fmt.Errorf("can\"t decode get systems ips")
		sentry.CaptureException(err1)
		log.Println(err1)
		return nil, err1
	}
	system := System{SystemModel: fmt.Sprintf("%s %s", data.Results.ModelName, data.Results.ModelNumber), SystemSerial: data.Serial, SystemSwVersion: fmt.Sprintf("FortiOS %s-%d", data.Version, data.Build), SystemType: "firewall"}
	return &system, nil
}

func GetSystemIps(hostname *string, port *int, secret *string) (*[]SystemIp, error) {
	baseUrl := fmt.Sprintf("https://%s:%d", *hostname, *port)
	path := fmt.Sprintf("/api/v2/monitor/system/interface?include_vlan=true&include_aggregate=true&access_token=%s", *secret)
	method := "GET"
	contentType := "application/json"
	hdr := make(map[string]string)
	resp, err := httpClient.Request(&baseUrl, &path, nil, &method, &contentType, &hdr)
	if err != nil {
		return nil, err
	}
	data := SystemInterfaces{}
	NewDecoderError := json.NewDecoder(resp.Body).Decode(&data)
	if NewDecoderError != nil {
		resp.Body.Close()
		err1 := fmt.Errorf("can\"t decode get systems ips")
		sentry.CaptureException(err1)
		log.Println(err1)
		return nil, err1
	}
	var systemIpList []SystemIp
	for _, v := range data.Results {
		if v.Ip == "0.0.0.0" {
			continue
		}
		systemIpList = append(systemIpList, SystemIp{Interface: v.Id, SystemIpAddress: fmt.Sprintf("%s/%d", v.Ip, v.Mask), NetMask: fmt.Sprintf("%d", v.Mask), LastSeen: time.Now()})
	}
	return &systemIpList, nil
}

func GetArp(hostname *string, port *int, secret *string) (*[]Host, error) {
	baseUrl := fmt.Sprintf("https://%s:%d", *hostname, *port)
	path := fmt.Sprintf("/api/v2/monitor/network/arp?access_token=%s", *secret)
	method := "GET"
	contentType := "application/json"
	hdr := make(map[string]string)
	resp, err := httpClient.Request(&baseUrl, &path, nil, &method, &contentType, &hdr)
	if err != nil {
		return nil, err
	}
	data := NetworkArpResponse{}
	NewDecoderError := json.NewDecoder(resp.Body).Decode(&data)
	if NewDecoderError != nil {
		resp.Body.Close()
		err1 := fmt.Errorf("can\"t decode get arp")
		sentry.CaptureException(err1)
		log.Println(err1)
		return nil, err1
	}
	var hostList []Host
	for _, hostData := range data.Results {
		mac := strings.Replace(hostData.Mac, ":", "", -1)
		first6 := mac[0:6]
		vendor := macLookup.VendorLookup(&first6)
		host := Host{AdjacencyInterface: hostData.Interface, HostAddress: hostData.Ip, MacAddress: mac, MacVendor: *vendor}
		hostList = append(hostList, host)
	}
	return &hostList, nil
}

func GetPolicy(hostname *string, port *int, secret *string) (*[]Policy, error) {
	baseUrl := fmt.Sprintf("https://%s:%d", *hostname, *port)
	path := fmt.Sprintf("/api/v2/cmdb/firewall/policy?access_token=%s", *secret)
	method := "GET"
	contentType := "application/json"
	hdr := make(map[string]string)
	resp, err := httpClient.Request(&baseUrl, &path, nil, &method, &contentType, &hdr)
	if err != nil {
		return nil, err
	}
	data := PolicyResponse{}
	NewDecoderError := json.NewDecoder(resp.Body).Decode(&data)
	if NewDecoderError != nil {
		resp.Body.Close()
		err1 := fmt.Errorf("can\"t decode get arp")
		sentry.CaptureException(err1)
		log.Println(err1)
		return nil, err1
	}
	return &data.Results, nil
}

func GetAddresses(hostname *string, port *int, secret *string) (*[]Address, error) {
	baseUrl := fmt.Sprintf("https://%s:%d", *hostname, *port)
	path := fmt.Sprintf("/api/v2/cmdb/firewall/address?access_token=%s", *secret)
	method := "GET"
	contentType := "application/json"
	hdr := make(map[string]string)
	resp, err := httpClient.Request(&baseUrl, &path, nil, &method, &contentType, &hdr)
	if err != nil {
		return nil, err
	}
	data := AddressResponse{}
	NewDecoderError := json.NewDecoder(resp.Body).Decode(&data)
	if NewDecoderError != nil {
		resp.Body.Close()
		err1 := fmt.Errorf("can\"t decode get arp")
		sentry.CaptureException(err1)
		log.Println(err1)
		return nil, err1
	}
	return &data.Results, nil
}
