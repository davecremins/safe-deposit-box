.PHONY: all get build install format vet test cover-check singletest coverage bench

COVERAGE_MIN ?= 80

all: get build install

get:
	go mod download

build:
	go build ./...

install:
	go install ./...

format:
	gofmt -w -s .

vet:
	go vet ./...

test:
	go test ./... -race -coverprofile .coverage.txt
	go tool cover -func .coverage.txt

# Fails when total statement coverage drops below COVERAGE_MIN percent.
cover-check: test
	@go tool cover -func .coverage.txt | awk -v min=$(COVERAGE_MIN) \
		'/^total:/ { sub("%", "", $$3); if ($$3 + 0 < min) { printf "coverage %s%% is below %s%%\n", $$3, min; exit 1 } else { printf "coverage %s%% (min %s%%)\n", $$3, min } }'

singletest:
	go test -run $(testname) $(package) -v

coverage: test
	go tool cover -html=.coverage.txt

bench:
	go test ./safe/ -run '^$$' -bench . -benchmem
