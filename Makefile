# Use bash as a shell command (bash or dash is required,
# we need arithmetic in the shell)
SHELL = /bin/bash

# Include our auto incrementer
include ./hack/Makefile.buildver

DOCKER_REGISTRY	?= radixdev.azurecr.io

DOCKER_FILES	= operator pipeline

VERSION 	?= latest

DATE = $(shell date +%F_%T)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
HASH := $(shell git rev-parse HEAD)

.PHONY: test
test:	
	go test -cover `go list ./... | grep -v 'pkg/client\|apis/radix'`

define make-docker-build
  	build-$1:
	  	$(call buildver, %1)
		docker build -t $(DOCKER_REGISTRY)/radix-$1:$(VERSION) --build-arg date="$(DATE)" --build-arg branch="$(BRANCH)" --build-arg commitid="$(HASH)" -f $1.Dockerfile .
  	build:: build-$1
endef

define make-docker-push
  	push-$1:
		docker push $(DOCKER_REGISTRY)/radix-$1:$(VERSION)
  	push:: push-$1
endef

define make-docker-deploy
  	deploy-$1:
		make build-$1
		make push-$1
endef

$(foreach element,$(DOCKER_FILES),$(eval $(call make-docker-build,$(element))))
$(foreach element,$(DOCKER_FILES),$(eval $(call make-docker-push,$(element))))
$(foreach element,$(DOCKER_FILES),$(eval $(call make-docker-deploy,$(element))))

# need to connect to kubernetes and container registry first - docker login radixdev.azurecr.io -u radixdev -p <%password%>
deploy-operator-kc:
	make deploy-operator
	# update docker image version in deploy file - file name should be a variable
	kubectl get deploy radix-operator -o yaml > oldRadixOperatorDef.yaml 
	sed -E "s/(image: radixdev.azurecr.io\/radix-operator).*/\1:$(VERSION)/g" ./oldRadixOperatorDef.yaml > newRadixOperatorDef.yaml
	kubectl apply -f newRadixOperatorDef.yaml
	rm oldRadixOperatorDef.yaml newRadixOperatorDef.yaml

ROOT_PACKAGE=github.com/statoil/radix-operator
CUSTOM_RESOURCE_NAME=radix
CUSTOM_RESOURCE_VERSION=v1

.PHONY: code-gen
code-gen: 
	vendor/k8s.io/code-generator/generate-groups.sh all $(ROOT_PACKAGE)/pkg/client $(ROOT_PACKAGE)/pkg/apis $(CUSTOM_RESOURCE_NAME):$(CUSTOM_RESOURCE_VERSION)
	
HAS_GOMETALINTER := $(shell command -v gometalinter;)
HAS_DEP          := $(shell command -v dep;)
HAS_GIT          := $(shell command -v git;)

vendor:
ifndef HAS_GIT
	$(error You must install git)
endif
ifndef HAS_DEP
	go get -u github.com/golang/dep/cmd/dep
endif
ifndef HAS_GOMETALINTER
	go get -u github.com/alecthomas/gometalinter
	gometalinter --install
endif
	dep ensure

.PHONY: bootstrap
bootstrap: vendor

fix: 
	sed -i "" 's/spt.Token/spt.Token()/g' ./vendor/k8s.io/client-go/plugin/pkg/client/auth/azure/azure.go