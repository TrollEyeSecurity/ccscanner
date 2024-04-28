package ovpn

import (
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/phonehome"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

func ProcessOvpnConfig(ovpnConfig phonehome.OvpnConfig, wg *sync.WaitGroup) {
	defer wg.Done()
	defer time.Sleep(time.Millisecond * 4)
	cmd := exec.Command("systemctl", "status", "--no-pager", "openvpn@client.service")
	_, err := cmd.CombinedOutput()
	status := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				status = 1
			}
			if exitErr.ExitCode() == 2 {
				status = 2
			}
			if exitErr.ExitCode() == 3 {
				status = 3
			}
			if exitErr.ExitCode() == 4 {
				status = 4
			}
		} else {
			status = 99
			fmt.Printf("failed to run systemctl: %v", err)
		}
	}
	if status == 0 && ovpnConfig.OvpnConnect == false {
		disableCmd := exec.Command("sudo", "systemctl", "disable", "--now", "openvpn@client.service")
		disableCmd.Run()
		return
	}
	statusCodes := map[int]bool{
		3: true,
		4: true,
	}
	if statusCodes[status] && ovpnConfig.OvpnConnect == true {
		e := writeOvpnConfig(&ovpnConfig.OvpnConfig)
		if e != nil {
			return
		}
		enableCmd := exec.Command("sudo", "systemctl", "enable", "--now", "openvpn@client.service")
		enableCmd.Run()
		return
	}
}

func writeOvpnConfig(data *string) error {
	echoDataCmd := exec.Command("echo", *data)
	ovpnClientFile, err := os.Create("/tmp/client.conf")
	if err != nil {
		log.Println(err)
		return err
	}
	echoDataCmd.Stdout = ovpnClientFile
	echoDataCmdError := echoDataCmd.Run()
	if echoDataCmdError != nil {
		log.Println(echoDataCmdError)
		return echoDataCmdError
	}
	ovpnClientFile.Close()
	mvCmd := exec.Command("sudo", "mv", "/tmp/client.conf", "/etc/openvpn/client.conf")
	mvCmdError := mvCmd.Run()
	if mvCmdError != nil {
		log.Println(mvCmdError)
		return mvCmdError
	}
	return nil
}
