BINARY  := spoofer
MODULE  := github.com/saif/spoofer

.PHONY: build test vet lint clean install run

debug:
	go build -gcflags="all=-N -l" -o $(BINARY) .

build:
	go build -o $(BINARY) ./engine/engine.go

install:
	go install ./cmd/spoofer

run: build
	sudo ./$(BINARY)

test:
	go test ./... -count=1

vet:
	go vet ./...

lint: vet
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping"

clean:
	rm -f $(BINARY)
