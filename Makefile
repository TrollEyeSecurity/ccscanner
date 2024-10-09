VERSION=2.0.22
GOCMD=go
GOBUILD=$(GOCMD) build

SCANNER=ccscanner/main.go
CCLINKMAIN=cclink/main.go
DASTMAIN=cc-dast-taskmanager/main.go
GVMMAIN=cc-gvm-taskmanager/main.go
INFRASTRUCTUREMAIN=cc-infrastructure-taskmanager/main.go
NMAPMAIN=cc-nmap-taskmanager/main.go
SASTMAIN=cc-sast-taskmanager/main.go
URLMAIN=cc-url-taskmanager/main.go

CCSCANNER_BIN=ccscanner
CCLINK_BIN=cclink
DAST_BIN=cc-dast-taskmanager
GVM_BIN=cc-gvm-taskmanager
INFRASTRUCTURE_BIN=cc-infrastructure-taskmanager
NMAP_BIN=cc-nmap-taskmanager
SAST_BIN=cc-sast-taskmanager
URL_BIN=cc-url-taskmanager
CMD=cmd/

clean:
	rm -rf bin/cc*

build_amd_dpkg:
	mkdir bin/
	$(GOBUILD) -o bin/$(CCSCANNER_BIN) $(CMD)$(CCLINKMAIN)
	$(GOBUILD) -o bin/$(CCLINK_BIN) $(CMD)$(LINKMAIN)
	$(GOBUILD) -o bin/$(DAST_BIN) $(CMD)$(DASTMAIN)
	$(GOBUILD) -o bin/$(GVM_BIN) $(CMD)$(GVMMAIN)
	$(GOBUILD) -o bin/$(INFRASTRUCTURE_BIN) $(CMD)$(INFRASTRUCTUREMAIN)
	$(GOBUILD) -o bin/$(NMAP_BIN) $(CMD)$(NMAPMAIN)
	$(GOBUILD) -o bin/$(SAST_BIN) $(CMD)$(SASTMAIN)
	$(GOBUILD) -o bin/$(URL_BIN) $(CMD)$(URLMAIN)
	mkdir -p dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin
	cp bin/cc* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin/
	cp -R  dpkg-skel/ccscanner_VERSION-0ubuntu_amd64/* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/
	dpkg-deb --build dpkg/ccscanner_$(VERSION)-0ubuntu_amd64
	mv dpkg/ccscanner_$(VERSION)-0ubuntu_amd64.deb .

build_arm_dpkg:
	$(GOBUILD) -o bin/$(CCSCANNER_BIN) $(CMD)$(SCANNER)
	$(GOBUILD) -o bin/$(CCLINK_BIN) $(CMD)$(CCLINKMAIN)
	$(GOBUILD) -o bin/$(DAST_BIN) $(CMD)$(DASTMAIN)
	$(GOBUILD) -o bin/$(GVM_BIN) $(CMD)$(GVMMAIN)
	$(GOBUILD) -o bin/$(INFRASTRUCTURE_BIN) $(CMD)$(INFRASTRUCTUREMAIN)
	$(GOBUILD) -o bin/$(NMAP_BIN) $(CMD)$(NMAPMAIN)
	$(GOBUILD) -o bin/$(SAST_BIN) $(CMD)$(SASTMAIN)
	$(GOBUILD) -o bin/$(URL_BIN) $(CMD)$(URLMAIN)
	mkdir -p dpkg/ccscanner_$(VERSION)-0ubuntu_arm64/usr/bin
	cp arm_bin/cc* dpkg/ccscanner_$(VERSION)-0ubuntu_arm64/usr/bin/
	cp -R  dpkg-skel/ccscanner_VERSION-0ubuntu_arm64/* dpkg/ccscanner_$(VERSION)-0ubuntu_arm64/
	dpkg-deb --build dpkg/ccscanner_$(VERSION)-0ubuntu_arm64
	mv dpkg/ccscanner_$(VERSION)-0ubuntu_arm64.deb .