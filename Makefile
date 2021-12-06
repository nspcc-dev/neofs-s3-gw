#!/usr/bin/make -f

# Common variables
REPO ?= $(shell go list -m)
VERSION ?= $(shell git describe --tags 2>/dev/null || cat VERSION 2>/dev/null || echo "develop")
BINDIR = bin

# Binaries to build
CMDS = $(addprefix neofs-, $(notdir $(wildcard cmd/*)))
BINS = $(addprefix $(BINDIR)/, $(CMDS))

# Variables for docker
REPO_BASENAME = $(shell basename `go list -m`)
HUB_IMAGE ?= "nspccdev/$(REPO_BASENAME)"
HUB_TAG ?= "$(shell echo ${VERSION} | sed 's/^v//')"

.PHONY: help all dep clean format test cover lint docker/lint image-push image dirty-image

# Make all binaries
all: $(BINS)

$(BINS): $(BINDIR) dep
	@echo "⇒ Build $@"
	CGO_ENABLED=0 \
	go build -v -trimpath \
	-ldflags "-X $(REPO)/internal/version.Version=$(VERSION)" \
	-o $@ ./cmd/$(subst neofs-,,$(notdir $@))

$(BINDIR):
	@echo "⇒ Ensure dir: $@"
	@mkdir -p $@

# Pull go dependencies
dep:
	@printf "⇒ Download requirements: "
	@CGO_ENABLED=0 \
	go mod download && echo OK
	@printf "⇒ Tidy requirements: "
	@CGO_ENABLED=0 \
	go mod tidy -v && echo OK

# Run tests
test:
	@go test ./... -cover

# Run tests with race detection and produce coverage output
cover:
	@go test -v -race ./... -coverprofile=coverage.txt -covermode=atomic
	@go tool cover -html=coverage.txt -o coverage.html

# Reformat code
format:
	@echo "⇒ Processing gofmt check"
	@gofmt -s -w ./
	@echo "⇒ Processing goimports check"
	@goimports -w ./

# Build clean Docker image
image: dep
	@echo "⇒ Build NeoFS S3 Gateway docker image "
	@docker build \
		--build-arg REPO=$(REPO) \
		--build-arg VERSION=$(VERSION) \
		--rm \
		-f Dockerfile \
		-t $(HUB_IMAGE):$(HUB_TAG) .

# Push Docker image to the hub
image-push:
	@echo "⇒ Publish image"
	@docker push $(HUB_IMAGE):$(HUB_TAG)

# Build dirty Docker image
dirty-image:
	@echo "⇒ Build NeoFS S3 Gateway dirty docker image "
	@docker build \
		--build-arg REPO=$(REPO) \
		--build-arg VERSION=$(VERSION) \
		--rm \
		-f Dockerfile.dirty \
		-t $(HUB_IMAGE)-dirty:$(HUB_TAG) .

# Run linters
lint:
	@golangci-lint --timeout=5m run

# Run linters in Docker
docker/lint:
	docker run --rm -it \
	-v `pwd`:/src \
	-u `stat -c "%u:%g" .` \
	--env HOME=/src \
	golangci/golangci-lint:v1.40 bash -c 'cd /src/ && make lint'

# Show current version
version:
	@echo $(VERSION)

# Show this help prompt
help:
	@echo '  Usage:'
	@echo ''
	@echo '    make <target>'
	@echo ''
	@echo '  Targets:'
	@echo ''
	@awk '/^#/{ comment = substr($$0,3) } comment && /^[a-zA-Z][a-zA-Z0-9_-]+ ?:/{ print "   ", $$1, comment }' $(MAKEFILE_LIST) | column -t -s ':' | grep -v 'IGNORE' | sort -u

# Clean up
clean:
	rm -rf $(BINDIR)

protoc:
	# Protoc generate
	@for f in `find . -type f -name '*.proto' -not -path './vendor/*'`; do \
		echo "⇒ Processing $$f "; \
		protoc \
			--go_out=paths=source_relative:. $$f; \
	done
	rm -rf vendor
