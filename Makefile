VERSION=2.0.3
GOCMD=go
GOBUILD=$(GOCMD) build
SCANNER=ccscanner.go
TASKMANAGER=cctaskmanager/cctaskmanager.go
LINK=cclink/cclink.go
CCSCANNER_BIN=ccscanner
CCTASKMANAGER_BIN=cctaskmanager
CCLINK_BIN=cclink
UTILITIES=utilities/

clean:
	rm -rf bin/*

build:
	$(GOBUILD) -o bin/$(CCSCANNER_BIN) $(SCANNER)
	$(GOBUILD) -o bin/$(CCTASKMANAGER_BIN) $(UTILITIES)$(TASKMANAGER)
	$(GOBUILD) -o bin/$(CCLINK_BIN) $(UTILITIES)$(LINK)
	mkdir -p dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin
	cp bin/cc* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/usr/bin/
	cp -R  dpkg-skel/ccscanner_VERSION-0ubuntu_amd64/* dpkg/ccscanner_$(VERSION)-0ubuntu_amd64/
	dpkg-deb --build dpkg/ccscanner_$(VERSION)-0ubuntu_amd64
	mv dpkg/ccscanner_$(VERSION)-0ubuntu_amd64.deb .