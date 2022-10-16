.PHONY: help

# Show this help prompt
help:
	@echo '  Usage:'
	@echo ''
	@echo '    make <target>'
	@echo ''
	@echo '  Targets:'
	@echo ''
	@awk '/^#/{ comment = substr($$0,3) } comment && /^[a-zA-Z][a-zA-Z0-9.%_/-]+ ?:/{ print "   ", $$1, comment }' $(MAKEFILE_LIST) | column -t -s ':' | grep -v 'IGNORE' | sort | uniq

# Show help for docker/% IGNORE
help.docker/%:
	$(eval TARGETS:=$(notdir all lint) ${BINS})
	@echo '  Usage:'
	@echo ''
	@echo '    make docker/% -- Run `make %` in Golang container'
	@echo ''
	@echo '  Supported docker targets:'
	@echo ''
	@$(foreach bin, $(TARGETS), echo '   ' $(bin);)
