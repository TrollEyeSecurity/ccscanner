VERSION=2.0
GOCMD=go
GOBUILD=$(GOCMD) build
CCSCANNER_BIN=ccscanner
CCTASKMANAGER_BIN=cctaskmanager
CCLINK_BIN=cclink

clean:
	rm -rf bin/*

build:
	$(GOBUILD) -o bin/$(CCSCANNER_BIN)
	$(GOBUILD) -o bin/$(CCTASKMANAGER_BIN)
	$(GOBUILD) -o bin/$(CCLINK_BIN)