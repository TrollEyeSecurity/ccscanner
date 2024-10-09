package common

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"github.com/TrollEyeSecurity/ccscanner/pkg/gvm"
	"github.com/getsentry/sentry-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func GetUuid() *string {
	arch := runtime.GOARCH
	if arch == "arm64" {
		pi, s := IsRpi()
		if pi {
			return s
		}
	}

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
		Gvm:      gvm.IsGvmReady(),
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
	Gvm      bool             `json:"gvm"`
}

type LinkData struct {
	Token    string `json:"token"`
	Uuid     string `json:"uuid"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

func GetOutboundIP() *net.IP {
	conn, netDialErr := net.Dial("udp", "1.1.1.1:80")
	if netDialErr != nil {
		err := fmt.Errorf("common get-outbound-ip error %v", netDialErr)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Println(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
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
		hostname = "unknown"
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
			hostname = strings.TrimSuffix(fqdn, ".")
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

func Maintenance(wg *sync.WaitGroup) {
	defer wg.Done()
	defer time.Sleep(time.Millisecond * 4)
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

func SetModeMaintenance() {
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
}

func CheckRunningTasks() {
	MongoClient, MongoClientError := database.GetMongoClient()
	defer MongoClient.Disconnect(context.TODO())
	if MongoClientError != nil {
		err := fmt.Errorf("database get-current-tasks error %v", MongoClient)
		if sentry.CurrentHub().Client() != nil {
			sentry.CaptureException(err)
		}
		log.Fatalf("MongoClient Error: %s", MongoClientError)
	}
	tasksCollection := MongoClient.Database("core").Collection("tasks")
	RunningTasksCount, _ := tasksCollection.CountDocuments(context.TODO(), bson.M{"status": bson.M{"$ne": "DONE"}})
	fmt.Println(RunningTasksCount)
}

func IsRpi() (bool, *string) {
	var pi bool
	var serialStr string
	file, ferr := os.Open("/proc/cpuinfo")
	if ferr != nil {
		panic(ferr)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	r, _ := regexp.Compile("^Serial")
	for scanner.Scan() {
		match := r.MatchString(scanner.Text())
		if match {
			s := strings.Split(scanner.Text(), ": ")[1]
			serialStr = strings.TrimSuffix(s, "\n")

			serialStr = serialStr + serialStr
		}
		piStr := strings.Contains(scanner.Text(), "Raspberry Pi 5")
		if piStr {
			pi = true
		}
	}
	if serr := scanner.Err(); serr != nil {
		if serr != io.EOF {
			panic(serr)
		}
	}

	return pi, &serialStr
}
