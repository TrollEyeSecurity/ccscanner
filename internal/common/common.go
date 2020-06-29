package common

import (
	"bytes"
	"fmt"
	"github.com/CriticalSecurity/cc-scanner/internal/database"
	"github.com/getsentry/sentry-go"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func GetUuid() *string {
	uuid := getLinuxUuid("/etc/machine-id")
	return &uuid
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
		Version:  0.1,
		Uuid:     *uuid,
		Load:     *cpuStatus,
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
	Version  float64          `json:"version"`
	Uuid     string           `json:"uuid"`
	Load     []float64        `json:"load"`
	Hostname string           `json:"hostname"`
	CpuCors  int              `json:"cores"`
	Ram      uint64           `json:"ram"`
	Disk     syscall.Statfs_t `json:"disk"`
	IpData   []IpData         `json:"ip_data"`
	IpAddr   net.IP           `json:"ip_addr"`
	Tasks    []database.Task  `json:"tasks"`
}

type LinkData struct {
	Token    string `json:"token"`
	Uuid     string `json:"uuid"`
	Hostname string `json:"hostname"`
}

func getLinuxUuid(productUuidFile string) string {
	dat, _ := ioutil.ReadFile(productUuidFile)
	return strings.TrimSuffix(string(dat), "\n")
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
