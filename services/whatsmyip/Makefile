BINARY:=whatsmyip
IMAGE:=whatsmyip:latest

.PHONY: build docker clean

build:
	go build -o bin/$(BINARY) ./cmd/whatsmyip


docker: build
	docker build -t $(IMAGE) .

podman: build
	podman build -t $(IMAGE) .

podman-run:
	podman run --rm -p 8080:8080 $(IMAGE)

clean:
	rm -rf bin
