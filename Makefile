VERSION=2.0.22
GOCMD=go
GOBUILD=$(GOCMD) build

SCANNER=ccscanner/main.go
DASTMAIN=cc-dast-taskmanager/main.go
GVMMAIN=cc-gvm-taskmanager/main.go
INFRASTRUCTUREMAIN=cc-infrastructure-taskmanager/main.go
NMAPMAIN=cc-nmap-taskmanager/main.go
SASTMAIN=cc-sast-taskmanager/main.go
URLMAIN=cc-url-taskmanager/main.go
CCLINKMAIN=cclink/main.go

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
	rm -rf arm_bin/cc*
	rm -rf amd_bin/cc*


build_amd_dpkg:
	$(GOBUILD) -o amd_bin/$(CCSCANNER_BIN) $(CMD)$(CCLINKMAIN)
	$(GOBUILD) -o amd_bin/$(CCLINK_BIN) $(CMD)$(LINKMAIN)
	$(GOBUILD) -o amd_bin/$(DAST_BIN) $(CMD)$(DASTMAIN)
	$(GOBUILD) -o amd_bin/$(GVM_BIN) $(CMD)$(GVMMAIN)
	$(GOBUILD) -o amd_bin/$(INFRASTRUCTURE_BIN) $(CMD)$(INFRASTRUCTUREMAIN)
	$(GOBUILD) -o amd_bin/$(NMAP_BIN) $(CMD)$(NMAPMAIN)
	$(GOBUILD) -o amd_bin/$(SAST_BIN) $(CMD)$(SASTMAIN)
	$(GOBUILD) -o amd_bin/$(URL_BIN) $(CMD)$(URLMAIN)
	mkdir -p dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin
	cp amd_bin/cc* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin/
	cp -R  dpkg-skel/ccscanner_VERSION-0ubuntu_amd64/* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/
	dpkg-deb --build dpkg/ccscanner_$(VERSION)-0ubuntu_amd64
	mv dpkg/ccscanner_$(VERSION)-0ubuntu_amd64.deb .

build_arm_dpkg:
	$(GOBUILD) -o arm_bin/$(CCSCANNER_BIN) $(CMD)$(SCANNER)
	$(GOBUILD) -o arm_bin/$(CCLINK_BIN) $(CMD)$(CCLINKMAIN)
	$(GOBUILD) -o arm_bin/$(DAST_BIN) $(CMD)$(DASTMAIN)
	$(GOBUILD) -o arm_bin/$(GVM_BIN) $(CMD)$(GVMMAIN)
	$(GOBUILD) -o arm_bin/$(INFRASTRUCTURE_BIN) $(CMD)$(INFRASTRUCTUREMAIN)
	$(GOBUILD) -o arm_bin/$(NMAP_BIN) $(CMD)$(NMAPMAIN)
	$(GOBUILD) -o arm_bin/$(SAST_BIN) $(CMD)$(SASTMAIN)
	$(GOBUILD) -o arm_bin/$(URL_BIN) $(CMD)$(URLMAIN)
	mkdir -p dpkg/ccscanner_$(VERSION)-0ubuntu_arm64/usr/bin
	cp arm_bin/cc* dpkg/ccscanner_$(VERSION)-0ubuntu_arm64/usr/bin/
	cp -R  dpkg-skel/ccscanner_VERSION-0ubuntu_arm64/* dpkg/ccscanner_$(VERSION)-0ubuntu_arm64/
	dpkg-deb --build dpkg/ccscanner_$(VERSION)-0ubuntu_arm64
	mv dpkg/ccscanner_$(VERSION)-0ubuntu_arm64.deb .