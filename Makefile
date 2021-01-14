VERSION ?= "$(shell git describe --tags 2>/dev/null || git rev-parse --short HEAD | sed 's/^v//')"
BUILD_VERSION ?= "$(shell git describe --abbrev=0 --tags | sed 's/^v//')"

.PHONY: help format deps

# Show this help prompt
help:
	@echo '  Usage:'
	@echo ''
	@echo '    make <target>'
	@echo ''
	@echo '  Targets:'
	@echo ''
	@awk '/^#/{ comment = substr($$0,3) } comment && /^[a-zA-Z][a-zA-Z0-9_-]+ ?:/{ print "   ", $$1, comment }' $(MAKEFILE_LIST) | column -t -s ':' | grep -v 'IGNORE' | sort | uniq

# Show current version
version:
	@echo $(BUILD_VERSION)

# Reformat code
format:
	@[ ! -z `which goimports` ] || (echo "install goimports" && exit 2)
	@for f in `find . -type f -name '*.go' -not -path './vendor/*' -not -name '*.pb.go' -prune`; do \
		echo "⇒ Processing $$f"; \
		goimports -w $$f; \
	done

# Make sure that all files added to commit
deps:
	@printf "⇒ Ensure vendor: "
	@go mod tidy -v && echo OK || (echo fail && exit 2)
	@printf "⇒ Download requirements: "
	@go mod download && echo OK || (echo fail && exit 2)
	@printf "⇒ Store vendor localy: "
	@go mod vendor && echo OK || (echo fail && exit 2)

# Build current docker image
image-build: deps
	@echo "⇒ Build docker-image"
	@docker build \
		--build-arg VERSION=$(BUILD_VERSION) \
		 -f Dockerfile \
		 -t nspccdev/neofs-s3-gate:$(BUILD_VERSION) .