#!/usr/bin/env bash
ccscanner -mode_maintenance

function cleanup_permissions() {
    sudo chown ccscanner:ccscanner -R /etc/ccscanner/
    sudo chown 1001:1001 -R /etc/ccscanner/.gvm/
    sudo chmod 777 -R /etc/ccscanner/.gvm/
    sudo chown ccscanner:ccscanner /etc/ccscanner/.config/gvm-tools.conf
}

function docker_commands() {
    docker-compose -f /etc/ccscanner/docker-compose-ccscanner.yml stop
    docker container prune -f
    docker image prune -af
    cleanup_permissions
    docker-compose -f /etc/ccscanner/docker-compose-ccscanner.yml --profile disable pull
    docker-compose -f /etc/ccscanner/docker-compose-ccscanner.yml up -d
}

while :
do
  if ccscanner -running_tasks | grep 0; then
     echo "ready for updates"
     break
  fi
  sleep 5
done

echo "sleeping for 60 secs"
sleep 60

sudo systemctl stop ccscanner.service cc-dast-taskmanager.service cc-gvm-taskmanager.service cc-infrastructure-taskmanager.service cc-nmap-taskmanager.service cc-sast-taskmanager.service cc-url-taskmanager.service

sudo DEBIAN_FRONTEND=noninteractive apt update && sudo DEBIAN_FRONTEND=noninteractive apt dist-upgrade -y

docker_commands

sudo systemctl enable --now ccscanner.service cc-dast-taskmanager.service cc-gvm-taskmanager.service cc-infrastructure-taskmanager.service cc-nmap-taskmanager.service cc-sast-taskmanager.service cc-url-taskmanager.service

cleanup_permissions

ccscanner -mode_running

sudo reboot
