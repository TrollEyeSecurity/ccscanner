# Command Center Scanner #
[Command Center](https://www.trolleyesecurity.com/command-center/) is a vulnerability and attack surface management tool. Command Center Scanner is the client application designed to perform tasks during penetration tests with
containers.

## Building from source ##

`git clone https://github.com/TrollEyeSecurity/ccscanner.git`

`cd ccscanner-master`

`make clean && make build`

Three binary files will be put in the `bin` directory.

`ccscanner` - ccscanner is main program file that will contact [Command Center](https://www.trolleyesecurity.com/command-center/).

`cctaskmanager` - cctaskmanager handles the tasks stored in the mongo database.

`cclink` -  cclink links the scanner to [Command Center](https://www.trolleyesecurity.com/command-center/).


## Setting up a scanner for the first time. ##

The following instructions assume you are starting with a base `Ubuntu Server 22.04` installation. Users are managed by [Command Center](https://www.trolleyesecurity.com/command-center/). All users will be deleted outside of `ubuntu`, `administrator`, or pentester accounts from [Command Center](https://www.trolleyesecurity.com/command-center/).

1) Create the following file `/etc/apt/sources.list.d/trolleyesecurity.list`.

`sudo vim /etc/apt/sources.list.d/trolleyesecurity.list`

Add the repo information:

`deb [trusted=yes] https://apt.trolleyesecurity.com/ /`

2) Update the apt cache and install ccscanner:

`sudo apt update && sudo apt install ccscanner -y`

3) Add the current user to the docker group:

`sudo usermod -aG docker $USER && su $USER`

4) Install gvm-tools globally:

`sudo pip install gvm-tools`

5) Pull the images related to ccscanner:

`docker-compose -f /etc/ccscanner/docker-compose-core.yml pull`

6) Start the mongoDB service:

`docker-compose -f /etc/ccscanner/docker-compose-core.yml up -d mongoDB`

---

#### steps 7 -12 are optional if you plan to use GVM vulnerability scanning ####

7) Pull all the gvm22.4 images:

`docker-compose -f /etc/ccscanner/docker-compose-gvm22.4.yml pull`


8) Make sure file permissions will allow for gvmd to write to the correct directory:

```
sudo chown ccscanner:ccscanner -R /etc/ccscanner/
sudo chown 1001:1001 -R /etc/ccscanner/.gvm/
sudo chmod 777 -R /etc/ccscanner/.gvm/
```

9) Start the gvm22.4 services:

`docker-compose -f /etc/ccscanner/docker-compose-gvm22.4.yml up -d`

10) Create a new random password for the gvmd admin user:

`docker-compose -f /etc/ccscanner/docker-compose-gvm22.4.yml exec -u gvmd gvmd gvmd --user=admin --new-password=<password>`

11)
Edit the gvm-tools.conf for the ccscanner service account:

`sudo vim /etc/ccscanner/.config/gvm-tools.conf`

Add the admin information.
```
[gmp]
username=admin
password=new-password
```

12) Make sure the ccscanner service account has ownership:

`sudo chown ccscanner:ccscanner /etc/ccscanner/.config/gvm-tools.conf`

---

13) Link the scanner to Command Center:

`sudo cclink -url https://ROOT_URL/ -token TOKEN_FROM_ZONE`


14) Enable and start the ccscanner services:

`sudo systemctl enable --now ccscanner.service cctaskmanager.service`


---
To log into the GSA web UI, setup an ssh tunnel to the scanner:

`ssh -L 9392:127.0.0.1:9392 firstname_lastname@scanner_ip`

Now browse to: http://127.0.0.1:9392/login


---

### Run Kali Linux container with open port | (you may need to modify the `ufw`.) ###

```
docker run --rm -p 4444:4444 -it trolleye/kali-linux:latest

OR

docker run --rm --net=host -it trolleye/kali-linux:latest
```

---

## Standalone mode ##

ccscanner can be used without [Command Center](https://www.trolleyesecurity.com/command-center/).

First you have to tell `ccscanner` it is linked.

`cclink -fakeLink`

### Using ccscanner in a Jenkins pipeline  ###


Enable and start the `cctaskmanager` service.

`sudo systemctl enable --now cctaskmanager.service`

#### Run OWASPZAP using the cli ####

```
ccscanner -dastRootUrl https://app.example.com \
            -dastConfig app.example.context \
            -dastHtml app.example.context.results.html \
            -maxChildren 5 \
            -urlList urllist.txt
```

---

## Trouble shooting ##

Check the status of running containers:

```
docker container list

CONTAINER ID   IMAGE                            COMMAND                  CREATED             STATUS             PORTS                        NAMES
1c6b85d1732a   greenbone/gsa:stable             "/usr/local/bin/entr…"   58 minutes ago      Up 37 minutes      127.0.0.1:9392->80/tcp       ccscanner_gsa_1
f0aba441e52a   greenbone/gvmd:stable            "/usr/local/bin/entr…"   58 minutes ago      Up 37 minutes                                   ccscanner_gvmd_1
ef6739989f98   greenbone/ospd-openvas:stable    "/usr/local/bin/entr…"   58 minutes ago      Up 37 minutes                                   ccscanner_ospd-openvas_1
aae36445e1ba   greenbone/notus-scanner:stable   "/usr/local/bin/entr…"   58 minutes ago      Up 37 minutes                                   ccscanner_notus-scanner_1
23b9d178259d   greenbone/mqtt-broker            "/bin/sh -c 'mosquit…"   58 minutes ago      Up 38 minutes      127.0.0.1:1883->1883/tcp     ccscanner_mqtt-broker_1
b069c0365bb3   greenbone/pg-gvm:stable          "/usr/local/bin/entr…"   58 minutes ago      Up 38 minutes                                   ccscanner_pg-gvm_1
3e3e2121aeb9   greenbone/redis-server           "/bin/sh -c 'rm -f /…"   58 minutes ago      Up 38 minutes                                   ccscanner_redis-server_1
484ec4f40d39   mongo:latest                     "docker-entrypoint.s…"   About an hour ago   Up About an hour   127.0.0.1:27017->27017/tcp   ccscanner_mongoDB_1
```

View the logs of a given container:

`docker container logs CONTAINER_ID`

```
# For example, looking at the greenbone/gvmd:stable container.
docker container logs f0aba441e52a
```

Use `mongosh` to access the mongodb database.

```
avery_rozar@scanner-1644285200:~$ mongosh
Current Mongosh Log ID:	63d45d507c5b58bfa5ce0994
Connecting to:		mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+1.6.2
Using MongoDB:		6.0.3
Using Mongosh:		1.6.2

For mongosh info see: https://docs.mongodb.com/mongodb-shell/

test> use core
switched to db core
core> tasks = db.tasks
core.tasks
core> tasks.find()

tasks.delete({_id: ""})

tasks.deleteMany({})
```

ccscanner stdout logs to `/var/log/[messages|syslog]` ## depends on standard logs per OS.

```
sudo tail -f /var/log/messages

```