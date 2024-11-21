VERSION=2.0.27
GOCMD=/usr/local/go/bin/go
GOBUILD=$(GOCMD) build

CCSCANNER_MAIN=ccscanner/main.go
CCLINK_MAIN=cclink/main.go
CCDAST_MAIN=cc-dast-taskmanager/main.go
CCGVM_MAIN=cc-gvm-taskmanager/main.go
CCINFRASTRUCTURE_MAIN=cc-infrastructure-taskmanager/main.go
CCNMAP_MAIN=cc-nmap-taskmanager/main.go
CCSAST_MAIN=cc-sast-taskmanager/main.go
CCURL_MAIN=cc-url-taskmanager/main.go

CCSCANNER_BIN=ccscanner
CCLINK_BIN=cclink
CCDAST_BIN=cc-dast-taskmanager
CCGVM_BIN=cc-gvm-taskmanager
CCINFRASTRUCTURE_BIN=cc-infrastructure-taskmanager
CCNMAP_BIN=cc-nmap-taskmanager
CCSAST_BIN=cc-sast-taskmanager
CCURL_BIN=cc-url-taskmanager
CMD=cmd/

clean:
	rm -rf bin/cc*

build_amd_dpkg:
	mkdir bin/
	$(GOBUILD) -o bin/$(CCSCANNER_BIN) $(CMD)$(CCSCANNER_MAIN)
	$(GOBUILD) -o bin/$(CCLINK_BIN) $(CMD)$(CCLINK_MAIN)
	$(GOBUILD) -o bin/$(CCDAST_BIN) $(CMD)$(CCDAST_MAIN)
	$(GOBUILD) -o bin/$(CCGVM_BIN) $(CMD)$(CCGVM_MAIN)
	$(GOBUILD) -o bin/$(CCINFRASTRUCTURE_BIN) $(CMD)$(CCINFRASTRUCTURE_MAIN)
	$(GOBUILD) -o bin/$(CCNMAP_BIN) $(CMD)$(CCNMAP_MAIN)
	$(GOBUILD) -o bin/$(CCSAST_BIN) $(CMD)$(CCSAST_MAIN)
	$(GOBUILD) -o bin/$(CCURL_BIN) $(CMD)$(CCURL_MAIN)
	mkdir -p dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin
	cp bin/cc* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin/
	cp -R  dpkg-skel/ccscanner_VERSION-0ubuntu_amd64/* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/
	dpkg-deb --build dpkg/ccscanner_$(VERSION)-0ubuntu_amd64
	mv dpkg/ccscanner_$(VERSION)-0ubuntu_amd64.deb .

build_arm_dpkg:
	$(GOBUILD) -o bin/$(CCSCANNER_BIN) $(CMD)$(CCSCANNER_MAIN)
	$(GOBUILD) -o bin/$(CCLINK_BIN) $(CMD)$(CCLINK_MAIN)
	$(GOBUILD) -o bin/$(CCDAST_BIN) $(CMD)$(CCDAST_MAIN)
	$(GOBUILD) -o bin/$(CCGVM_BIN) $(CMD)$(CCGVM_MAIN)
	$(GOBUILD) -o bin/$(CCINFRASTRUCTURE_BIN) $(CMD)$(CCINFRASTRUCTURE_MAIN)
	$(GOBUILD) -o bin/$(CCNMAP_BIN) $(CMD)$(CCNMAP_MAIN)
	$(GOBUILD) -o bin/$(CCSAST_BIN) $(CMD)$(CCSAST_MAIN)
	$(GOBUILD) -o bin/$(CCURL_BIN) $(CMD)$(CCURL_MAIN)
	mkdir -p dpkg/ccscanner_$(VERSION)-0ubuntu_arm64/usr/bin
	cp bin/cc* dpkg/ccscanner_$(VERSION)-0ubuntu_arm64/usr/bin/
	cp -R  dpkg-skel/ccscanner_VERSION-0ubuntu_arm64/* dpkg/ccscanner_$(VERSION)-0ubuntu_arm64/
	dpkg-deb --build dpkg/ccscanner_$(VERSION)-0ubuntu_arm64
	mv dpkg/ccscanner_$(VERSION)-0ubuntu_arm64.deb .