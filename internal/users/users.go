package users

import (
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

func ProcessUsers(allowedUsers [][]string) {
	for _, u := range allowedUsers {
		if u[1] != "" {
			username := strings.Split(u[0], "@")[0]
			_, lookupError := user.Lookup(username)
			if lookupError != nil {
				userAddCmd := exec.Command("sudo", "useradd", "--create-home", "--shell", "/bin/bash", username)
				userAddCmdError := userAddCmd.Run()
				if userAddCmdError != nil {
					log.Println(userAddCmdError)
				}
				userModCmd := exec.Command("sudo", "usermod", "-aG", "sudo,docker", username)
				userModCmdError := userModCmd.Run()
				if userModCmdError != nil {
					log.Println(userModCmdError)
				}
				createSshDirCmd := exec.Command("sudo", "mkdir", "/home/"+username+"/.ssh")
				createSshDirCmdError := createSshDirCmd.Run()
				if createSshDirCmdError != nil {
					log.Println(createSshDirCmdError)
				}
				sshKeyCmd := exec.Command("echo", u[1])
				authorizedKeysFile, err := os.Create("/tmp/authorized_keys")
				if err != nil {
					log.Println(err)
				}
				sshKeyCmd.Stdout = authorizedKeysFile
				sshKeyCmdError := sshKeyCmd.Run()
				if sshKeyCmdError != nil {
					log.Println(sshKeyCmdError)
				}
				authorizedKeysFile.Close()
				mvCmd := exec.Command("sudo", "mv", "/tmp/authorized_keys", "/home/"+username+"/.ssh/")
				mvCmdError := mvCmd.Run()
				if mvCmdError != nil {
					log.Println(mvCmdError)
				}
				chownCmd := exec.Command("sudo", "chown", username+":"+username, "-R", "/home/"+username+"")
				chownCmdError := chownCmd.Run()
				if chownCmdError != nil {
					log.Println(chownCmdError)
				}
			}
		}
	}
}
