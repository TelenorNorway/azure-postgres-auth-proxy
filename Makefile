.PHONY: $(shell sed -n -e '/^$$/ { n ; /^[^ .\#][^ ]*:/ { s/:.*$$// ; p ; } ; }' $(MAKEFILE_LIST))

root_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

IMAGE ?= ghcr.io/telenornorway/azure-postgres-auth-proxy
TAG ?= latest

help:
	 @echo "$$(grep -hE '^\S+:.*##' $(MAKEFILE_LIST) | sed -e 's/:.*##\s*/:/' -e 's/^\(.\+\):\(.*\)/\\x1b[36m\1\\x1b[m:\2/' | column -c2 -t -s :)"

build: ## Build the app
	go build -o bin/app .

docker-build: ## Build the app docker image
	docker build -t ${IMAGE}:${TAG} .

test: ## Run tests
	go test -v ./...