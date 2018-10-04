.PHONY: all test clean build cover compile goxc bintray

GO ?= go
BIN_NAME=www
GO_XC = ${GOPATH}/bin/goxc -os="freebsd openbsd netbsd darwin linux windows"
GOXC_FILE = .goxc.json
GOXC_FILE_LOCAL = .goxc.local.json
VERSION=$(shell git describe --tags --always)

all: clean build

build:
	${GO} build -ldflags "-s -w";

build-linux:
	for arch in 386 amd64 arm arm64 ppc64 ppc64le mips mipsle mips64 mips64le; do \
		mkdir -p build/$${arch}; \
		GOOS=linux GOARCH=$${arch} ${GO} build -ldflags "-s -w -X main.version=${VERSION}" -o build/$${arch}/www; \
	done

clean:
	${GO} clean -i
	@rm -rf ${BIN_NAME} ${BIN_NAME}.debug *.out build debian

compile: goxc

cover:
	${GO} test -cover && \
    ${GO} test -coverprofile=coverage.out  && \
    ${GO} tool cover -html=coverage.out

goxc:
	$(shell echo '{\n  "ConfigVersion": "0.9",' > $(GOXC_FILE))
	$(shell echo '  "AppName": "www",' >> $(GOXC_FILE))
	$(shell echo '  "ArtifactsDest": "build",' >> $(GOXC_FILE))
	$(shell echo '  "PackageVersion": "${VERSION}",' >> $(GOXC_FILE))
	$(shell echo '  "TaskSettings": {' >> $(GOXC_FILE))
	$(shell echo '    "bintray": {' >> $(GOXC_FILE))
	$(shell echo '      "downloadspage": "bintray.md",' >> $(GOXC_FILE))
	$(shell echo '      "package": "www",' >> $(GOXC_FILE))
	$(shell echo '      "repository": "www",' >> $(GOXC_FILE))
	$(shell echo '      "subject": "nbari"' >> $(GOXC_FILE))
	$(shell echo '    }\n  },' >> $(GOXC_FILE))
	$(shell echo '  "BuildSettings": {' >> $(GOXC_FILE))
	$(shell echo '    "LdFlags": "-X main.version=${VERSION}"' >> $(GOXC_FILE))
	$(shell echo '  }\n}' >> $(GOXC_FILE))
	$(shell echo '{\n "ConfigVersion": "0.9",' > $(GOXC_FILE_LOCAL))
	$(shell echo ' "TaskSettings": {' >> $(GOXC_FILE_LOCAL))
	$(shell echo '  "bintray": {\n   "apikey": "$(BINTRAY_APIKEY)"' >> $(GOXC_FILE_LOCAL))
	$(shell echo '  }\n } \n}' >> $(GOXC_FILE_LOCAL))
	${GO_XC}

bintray:
	${GO_XC} bintray

test:
	${GO} test -race -v

docker:
	docker build -t www --build-arg VERSION=${VERSION} .

docker-no-cache:
	docker build --no-cache -t www --build-arg VERSION=${VERSION} .

linux:
	docker run --entrypoint "/bin/bash" -it --privileged www
