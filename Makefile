ifndef VERSION
$(error VERSION is undefined)
endif

TAG?=latest
ORG?=cccs

ifneq ($(ORG)x, x)
ORG:=$(ORG)/
endif
ifneq ($(REGISTRY)x, x)
ORG:=$(REGISTRY)/
endif

.PHONY: default
default: build

.PHONY: build
build:
	docker build \
		--pull \
		--build-arg version=$(VERSION) \
		--build-arg branch=stable \
		-t $(REGISTRY)$(ORG)assemblyline-service-cape:$(TAG)\
		-f ./Dockerfile \
		.
