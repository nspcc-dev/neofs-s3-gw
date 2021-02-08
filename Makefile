-include .env
-include help.mk

HUB_IMAGE=nspccdev/neofs

VERSION ?= "$(shell git describe --tags 2>/dev/null || git rev-parse --short HEAD | sed 's/^v//')"
BUILD_VERSION ?= "$(shell git describe --abbrev=0 --tags | sed 's/^v//')"

.PHONY: format deps image publish

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

# Check and ensure dependencies
deps:
	@printf "⇒ Ensure vendor: "
	@go mod tidy -v && echo OK || (echo fail && exit 2)
	@printf "⇒ Download requirements: "
	@go mod download && echo OK || (echo fail && exit 2)
	@printf "⇒ Store vendor localy: "
	@go mod vendor && echo OK || (echo fail && exit 2)

# Build current docker image
image: deps
	@echo "⇒ Build docker-image"
	@docker build \
		--build-arg VERSION=$(BUILD_VERSION) \
		 -f Dockerfile \
		 -t $(HUB_IMAGE)-s3-gate:$(BUILD_VERSION) .

# Publish docker image
publish:
	@echo "${B}${G}⇒ publish docker image ${R}"
	@docker push $(HUB_IMAGE)-s3-gate:$(VERSION)