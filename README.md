# Command Center Scanner #
[Command Center](https://www.critical-sec.com/command-center/) is a full featured vulnerability management platform for penetration testing teams. Command Center Scanner is the client application designed to perform tasks during penetration tests and security audits using
Docker containers.


## Installing from dpkg file ##
The only officially supported  operating system is Ubuntu 20.04 LTS (Focal Fossa)

Assuming a minimal base server install was successful, do the following.

### Example using version 1.0.2 as the latest ###
`export latest=1.0.2`

`curl -L https://github.com/CriticalSecurity/ccscanner/releases/download/v$latest/ccscanner_$latest-0ubuntu_amd64.deb -O`

`sudo apt update`

`sudo apt install runc containerd libsensors-config libsensors5 docker.io sysstat`

`sudo dpkg --install ccscanner_$latest-0ubuntu_amd64.deb`

## Linking to Command Center or your own Centralized Scan Manager ##

`cclink --url=BASEURL --token=LINKING_TOKEN`

After linking the scanner to [Command Center](https://www.critical-sec.com/command-center/) or your own centralized scan manager you can manage the two services with `systemd`.

`systemctl enable ccscanner.service && systemctl start ccscanner.service`

`systemctl enable cctaskmanager.service && systemctl start cctaskmanager.service`

## Building from source ##

`git clone https://github.com/CriticalSecurity/ccscanner.git`

`cd ccscanner-master`

`make clean && make build`

Three binary files will be put in the `bin` directory.

`ccscanner` - ccscanner is main program file that will contact [Command Center](https://www.critical-sec.com/command-center/) or your own centralized scan manager developed to use ccscanner.

`cctaskmanager` - cctaskmanager handles the tasks stored in the mongo database.

`cclink` -  cclink links the scanner to [Command Center](https://www.critical-sec.com/command-center/).