.PHONY: all test coverage format singletest

all: get build install

get:
	go mod download

build:
	go build ./...

install:
	go install ./...

format:
	gofmt -w -s .

test:
	go test ./... -v -coverprofile .coverage.txt
	go tool cover -func .coverage.txt

singletest:
	go test -run $(testname) $(package) -v

coverage: test
	go tool cover -html=.coverage.txt
