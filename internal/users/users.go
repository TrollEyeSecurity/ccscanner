package users

import (
	"bufio"
	"errors"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

func ProcessUsers(allowedUsers [][]string) {

	currentUsers, currentUsersError := getCurrentUsers()
	if currentUsersError != nil {
		log.Println(currentUsersError)
	}
	for _, u := range allowedUsers {
		if u[1] != "" {
			splitEmailAddress := strings.Split(u[0], "@")[0]
			userName := strings.Replace(splitEmailAddress, ".", "_", 1)
			if contains(currentUsers, userName) {
				currentUsers = removeUser(userName, currentUsers)
			}
			User, _ := user.Lookup(userName)
			if User == nil {
				userAddCmd := exec.Command("sudo", "useradd", "--create-home", "--shell", "/bin/bash", userName)
				userAddCmdError := userAddCmd.Run()
				if userAddCmdError != nil {
					log.Println("userAddCmdError: " + userAddCmdError.Error())
				}
				userModCmd := exec.Command("sudo", "usermod", "-aG", "sudo,docker", userName)
				userModCmdError := userModCmd.Run()
				if userModCmdError != nil {
					log.Println("userModCmdError: " + userModCmdError.Error())
				}
				createSshDirCmd := exec.Command("sudo", "mkdir", "/home/"+userName+"/.ssh")
				createSshDirCmdError := createSshDirCmd.Run()
				if createSshDirCmdError != nil {
					log.Println("createSshDirCmdError: " + createSshDirCmdError.Error())
				}
				sshKeyCmd := exec.Command("echo", u[1])
				authorizedKeysFile, err := os.Create("/tmp/authorized_keys")
				if err != nil {
					log.Println("authorizedKeysFile: " + err.Error())
				}
				sshKeyCmd.Stdout = authorizedKeysFile
				sshKeyCmdError := sshKeyCmd.Run()
				if sshKeyCmdError != nil {
					log.Println("sshKeyCmdError: " + sshKeyCmdError.Error())
				}
				authorizedKeysFile.Close()
				mvCmd := exec.Command("sudo", "mv", "/tmp/authorized_keys", "/home/"+userName+"/.ssh/")
				mvCmdError := mvCmd.Run()
				if mvCmdError != nil {
					log.Println("mvCmdError: " + mvCmdError.Error())
				}
				chownCmd := exec.Command("sudo", "chown", userName+":"+userName, "-R", "/home/"+userName+"")
				chownCmdError := chownCmd.Run()
				if chownCmdError != nil {
					log.Println("chownCmdError: " + chownCmdError.Error())
				}
			}
		}
	}
	if len(currentUsers) > 0 {
		for _, User := range currentUsers {
			// so I don't kill my dev box or client admin
			keepUser := map[string]bool{
				"arozar":        true,
				"administrator": true,
				"ubuntu":        true,
			}
			if keepUser[User] {
				continue
			}
			userDelCmd := exec.Command("sudo", "userdel", "--remove", "--force", User)
			userDelCmdError := userDelCmd.Run()
			if userDelCmdError != nil {
				log.Println(userDelCmdError)
			}
		}
	}
}

func getCurrentUsers() ([]string, error) {
	path := "/etc/passwd"
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	lines := bufio.NewReader(file)
	var currentUsers []string
	for {
		line, _, err := lines.ReadLine()
		if err != nil {
			break
		}
		name, entry, err := parseLine(string(copyBytes(line)))
		if err != nil {
			return nil, err
		}
		intVar, _ := strconv.Atoi(entry.Gid)
		if between(intVar, 1000, 60000) {
			currentUsers = append(currentUsers, name)
		}
	}
	file.Close()
	return currentUsers, nil
}

func between(i, min, max int) bool {
	if (i >= min) && (i <= max) {
		return true
	} else {
		return false
	}
}

func parseLine(line string) (string, Passwd, error) {
	fs := strings.Split(line, ":")
	if len(fs) != 7 {
		return "", Passwd{}, errors.New("Unexpected number of fields in /etc/passwd")
	}
	return fs[0], Passwd{fs[1], fs[2], fs[3], fs[4], fs[5], fs[6]}, nil
}

func copyBytes(x []byte) []byte {
	y := make([]byte, len(x))
	copy(y, x)
	return y
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func removeUser(userName string, currentUsers []string) []string {
	for index, element := range currentUsers {
		if element == userName {
			currentUsers = append(currentUsers[:index], currentUsers[index+1:]...)
		}
	}
	return currentUsers
}
