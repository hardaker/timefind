.PHONY: build check-version

export GOPATH := ${PWD}
export GO15VENDOREXPERIMENT := 1

default: build

check-version:
	@go version > /dev/null || (echo "Go not found. You need to install go: http://golang.org/doc/install"; false)
	@go version | grep -q 'go version go1.[5-9]' || (echo "Go version 1.5.x (or higher) is required: http://golang.org/doc/install"; false)

build: check-version
	go build -o ./bin/timefind ./src/timefind
	cp ./src/timefind/README ./bin/README.timefind
	go build -o ./bin/indexer ./src/indexer
	cp ./src/indexer/README ./bin/README.indexer

clean:
	rm -rf bin/timefind bin/indexer
	rm -rf bin/README.*
