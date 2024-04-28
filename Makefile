VERSION=2.0.18
GOCMD=go
GOBUILD=$(GOCMD) build
SCANNER=ccscanner/main.go
TASKMANAGER=cctaskmanager/main.go
LINK=cclink/main.go
CCSCANNER_BIN=ccscanner
CCTASKMANAGER_BIN=cctaskmanager
CCLINK_BIN=cclink
CMD=cmd/

clean:
	rm -rf bin/*

build:
	$(GOBUILD) -o bin/$(CCSCANNER_BIN) $(CMD)$(SCANNER)
	$(GOBUILD) -o bin/$(CCTASKMANAGER_BIN) $(CMD)$(TASKMANAGER)
	$(GOBUILD) -o bin/$(CCLINK_BIN) $(CMD)$(LINK)

build_dpkg:
	$(GOBUILD) -o bin/$(CCSCANNER_BIN) $(CMD)$(SCANNER)
	$(GOBUILD) -o bin/$(CCTASKMANAGER_BIN) $(CMD)$(TASKMANAGER)
	$(GOBUILD) -o bin/$(CCLINK_BIN) $(CMD)$(LINK)
	mkdir -p dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin
	cp bin/cc* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin/
	cp -R  dpkg-skel/ccscanner_VERSION-0ubuntu_amd64/* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/
	dpkg-deb --build dpkg/ccscanner_$(VERSION)-0ubuntu_amd64
	mv dpkg/ccscanner_$(VERSION)-0ubuntu_amd64.deb .