package common

import (
	"bytes"
	"context"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func GetUuid() *string {
	cmd := exec.Command("sudo", "dmidecode", "--string", "system-uuid")
	out, CommandErr := cmd.Output()
	if CommandErr != nil {
		err := fmt.Errorf("get-uuid error %v: %v", CommandErr, string(out))
		log.Println(err)
		// return nil, err
	}
	cmd.Process.Kill()
	s := string(out)
	t := strings.Replace(s, "-", "", -1)
	r := strings.TrimSuffix(t, "\n")
	return &r
}

func GetCpuStatus() (*[]float64, error) {
	var cpuStats []float64
	CommandMpstatStats, CommandMpstatError := CommandMpstat()
	if CommandMpstatError != nil {
		return nil, CommandMpstatError
	}
	cpuStats = *CommandMpstatStats
	return &cpuStats, nil
}

func GetScannerData() (*ScannerData, error) {
	uuid := GetUuid()
	cpuStatus, GetCpuStatusError := GetCpuStatus()
	if GetCpuStatusError != nil {
		return nil, GetCpuStatusError
	}
	s := syscall.Statfs_t{}
	syscall1Err := syscall.Statfs("/", &s)
	if syscall1Err != nil {
		return nil, syscall1Err
	}
	m := runtime.MemStats{}
	runtime.ReadMemStats(&m)
	fs := syscall.Statfs_t{}
	syscall2Err := syscall.Statfs("/", &fs)
	if syscall2Err != nil {
		return nil, syscall2Err
	}
	sd := ScannerData{
		Version:  Version,
		Uuid:     *uuid,
		Load:     *cpuStatus,
		Mode:     *database.GetCurrentMode(),
		Hostname: *GetFqdn(),
		CpuCors:  runtime.NumCPU(),
		Ram:      m.TotalAlloc,
		Disk:     s,
		IpData:   *getIpData(),
		IpAddr:   *GetOutboundIP(),
		Tasks:    *database.GetCurrentTasks(),
	}
	return &sd, nil
}

type ScannerData struct {
	Version  string           `json:"version"`
	Uuid     string           `json:"uuid"`
	Load     []float64        `json:"load"`
	Hostname string           `json:"hostname"`
	CpuCors  int              `json:"cores"`
	Ram      uint64           `json:"ram"`
	Disk     syscall.Statfs_t `json:"disk"`
	IpData   []IpData         `json:"ip_data"`
	IpAddr   net.IP           `json:"ip_addr"`
	Tasks    []database.Task  `json:"tasks"`
	Mode     string           `json:"mode"`
}

type LinkData struct {
	Token    string `json:"token"`
	Uuid     string `json:"uuid"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

func GetOutboundIP() *net.IP {
	conn, netDialErr := net.Dial("udp", "255.255.255.255:80")
	if netDialErr != nil {
		err := fmt.Errorf("common get-outbound-ip error %v", netDialErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	conn.Close()
	return &localAddr.IP
}

func CommandMpstat() (*[]float64, error) {
	cmd := exec.Command("mpstat")
	out, CommandErr := cmd.Output()
	if CommandErr != nil {
		err := fmt.Errorf("command-mpstat error %v: %v", CommandErr, string(out))
		return nil, err
	}
	cmd.Process.Kill()
	result := bytes.Split(out, []byte("\n"))
	validLine := bytes.Split(result[3], []byte("all"))
	testArray := strings.Fields(string(validLine[len(validLine)-1]))
	var t2 = []float64{}
	for _, v := range testArray {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			t2 = append(t2, n)
		}
	}
	return &t2, nil
}

func GetFqdn() *string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname := "unknown"
		return &hostname
	}
	addrs, err := net.LookupIP(hostname)
	if err != nil {
		return &hostname
	}
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ip, err := ipv4.MarshalText()
			if err != nil {
				return &hostname
			}
			hosts, err := net.LookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				return &hostname
			}
			fqdn := hosts[0]
			hostname := strings.TrimSuffix(fqdn, ".")
			return &hostname
		}
	}
	return &hostname
}

type IpData struct {
	IDX          int    `json:"idx"`
	IP           net.IP `json:"ip"`
	IntName      string `json:"int_name"`
	HardwareAddr string `json:"hardware_addr"`
}

func getIpData() *[]IpData {
	var IntList []IpData
	ifaces, InterfacesErr := net.Interfaces()
	if InterfacesErr != nil {
		err := fmt.Errorf("common get-ip-data error %v: %v", InterfacesErr, ifaces)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("Interfaces Error 1: %s", InterfacesErr)
	}
	for _, i := range ifaces {
		addrs, InterfacesErr2 := i.Addrs()
		if InterfacesErr2 != nil {
			err := fmt.Errorf("common get-ip-data error %v: %v", InterfacesErr2, addrs)
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(err)
			}
			log.Fatalf("Interfaces Error 2: %s", InterfacesErr2)
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ipdata := IpData{
				IDX:          i.Index,
				IP:           ip,
				IntName:      i.Name,
				HardwareAddr: i.HardwareAddr.String(),
			}
			IntList = append(IntList, ipdata)
		}
	}
	return &IntList
}

func Maintenance() {
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("maintenance error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
	}
	opts := options.Find().SetSort(bson.D{{"_id", -1}}).SetLimit(1)
	systemCollection := MongoClient.Database("core").Collection("system")
	cursor, _ := systemCollection.Find(context.TODO(), bson.D{{"_id", "configuration"}}, opts)
	var results []bson.M
	cursor.All(context.TODO(), &results)
	_, ConfigurationError := systemCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", "configuration"}},
		bson.D{{"$set", bson.D{{"_id", "configuration"}, {"mode", "maintenance"}}}},
	)
	if ConfigurationError != nil {
		err := fmt.Errorf("maintenance error %v", ConfigurationError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("Configuration Error: %s", ConfigurationError)
	}
	for {
		tasks := database.GetCurrentTasks()
		if len(*tasks) == 0 {
			break
		}
		time.Sleep(3 * time.Minute)
	}

	/*
		updateSystemCmd := exec.Command(
			"apt",
			"-qq",
			"update")

		updateSystemCmdErr := updateSystemCmd.Start()

		if updateSystemCmdErr != nil {
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(updateSystemCmdErr)
			}
			log.Fatal(updateSystemCmdErr)
		}
		waitUpdateSystemCmdErr := updateSystemCmd.Wait()
		if waitUpdateSystemCmdErr != nil {
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(waitUpdateSystemCmdErr)
			}
			log.Fatal(waitUpdateSystemCmdErr)
		}

		upgradeSystemCmd := exec.Command(
			"DEBIAN_FRONTEND=noninteractive",
			"apt",
			"-qq",
			"-o Dpkg::Options::=\"--force-confnew\"",
			"--allow-downgrades",
			"--allow-remove-essential",
			"--allow-change-held-packages ",
			"dist-upgrade",
			"-y")

		upgradeSystemCmdErr := upgradeSystemCmd.Start()
		if upgradeSystemCmdErr != nil {
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(upgradeSystemCmdErr)
			}
			log.Fatal(upgradeSystemCmdErr)
		}

		waitUpgradeSystemCmdErr := upgradeSystemCmd.Wait()
		if waitUpgradeSystemCmdErr != nil {
			if sentry.CurrentHub().Client() != nil {
				sentry.CaptureException(waitUpgradeSystemCmdErr)
			}
			log.Fatal(waitUpgradeSystemCmdErr)
		}
	*/
	_, ConfigurationError1 := systemCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", "configuration"}},
		bson.D{{"$set", bson.D{{"_id", "configuration"}, {"mode", "running"}}}},
	)
	if ConfigurationError1 != nil {
		err := fmt.Errorf("maintenance error %v", ConfigurationError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("Configuration Error: %s", ConfigurationError)
	}
	// Reboot()
	return
}

func Reboot() {
	rebootCmd := exec.Command("/usr/sbin/shutdown", "-r", "now")
	startErr := rebootCmd.Start()
	if startErr != nil {
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(startErr)
		}
		log.Fatal(startErr)
	}
	return
}

func SetModeRunning() {
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("maintenance error %v", MongoClientError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
	}
	opts := options.Find().SetSort(bson.D{{"_id", -1}}).SetLimit(1)
	systemCollection := MongoClient.Database("core").Collection("system")
	cursor, _ := systemCollection.Find(context.TODO(), bson.D{{"_id", "configuration"}}, opts)
	var results []bson.M
	cursor.All(context.TODO(), &results)
	_, ConfigurationError := systemCollection.UpdateOne(context.TODO(),
		bson.D{{"_id", "configuration"}},
		bson.D{{"$set", bson.D{{"_id", "configuration"}, {"mode", "running"}}}},
	)
	if ConfigurationError != nil {
		err := fmt.Errorf("maintenance error %v", ConfigurationError)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("Configuration Error: %s", ConfigurationError)
	}
}
