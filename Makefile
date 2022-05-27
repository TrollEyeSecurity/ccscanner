VERSION=1.1.33
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
	$(GOBUILD) -o bin/$(CCSCANNER_BIN) -i $(SCANNER)
	$(GOBUILD) -o bin/$(CCTASKMANAGER_BIN) -i $(UTILITIES)$(TASKMANAGER)
	$(GOBUILD) -o bin/$(CCLINK_BIN) -i $(UTILITIES)$(LINK)