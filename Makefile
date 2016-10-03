.PHONY: build check-version symlink-vendor

SHELL=/bin/bash

#
# XXX make sure to tag your releases! See CONTRIBUTING.
#
VERSION=$(shell git describe --tags --abbrev=0)
VERSION_FULL=$(shell git describe --tags)

# test equality
VERSION_MATCH=$(shell ([ "$(VERSION)" == "$(VERSION_FULL)" ] && echo "1") || echo "0")

DESTDIR=
PREFIX=$(DESTDIR)/usr
BINDIR=$(PREFIX)/bin
DOCDIR=$(DESTDIR)/share/timefind-$(VERSION)

export GOPATH := ${PWD}
export GO15VENDOREXPERIMENT := 1

SYMLINK_VENDOR=0
VENDOR_DIRS=

all:: check-version symlink-vendor bin/timefind bin/timefind_indexer symlink-clean

check-version:
	@go version > /dev/null || (echo "Go not found. You need to install go: http://golang.org/doc/install"; false)
ifneq ($(OLDGO),1)
	$(eval GOVERSION := $(shell go version | egrep -o 'go1.[0-9](.[0-9])?' | sed 's/go//'))
	@go version | grep -q 'go version go1.[5-9]' || \
		(echo "go1.5 (or higher) is recommended, you are running go$(GOVERSION)"; \
		 echo "Run \"make OLDGO=1\" to compile using go$(GOVERSION)"; false)
endif

symlink-vendor:
ifeq ($(OLDGO),1)
	$(eval VENDOR_DIRS := $(sort $(dir $(filter %/, $(wildcard ./src/vendor/*/)))))
	@$(foreach dir, $(VENDOR_DIRS), \
		echo "creating symlink from ./src/$(notdir $(dir:%/=%)) to $(dir)"; \
		ln -f -s vendor/$(notdir $(dir:%/=%)) ./src/$(notdir $(dir:%/=%));)
endif

test:
	pushd src/timefind; go test ./...

bin/timefind: clean
	go build -o ./bin/timefind ./src/timefind

bin/timefind_indexer: clean
	go build -o ./bin/timefind_indexer ./src/timefind/indexer

symlink-clean:
ifeq ($(OLDGO),1)
	@$(foreach dir, $(VENDOR_DIRS), \
		echo "removing symlink from ./src/$(notdir $(dir:%/=%))"; \
		rm ./src/$(notdir $(dir:%/=%));)
endif

# build is really "install.local"
# and for if you run locally
build:
	make install_programs BINDIR=./bin
	make install_READMEs DOCDIR=./bin


#
# install is what is used for the .rpm
#
install: install_programs install_READMEs install_LICENSE

install_programs: bin/timefind bin/timefind_indexer
	-mkdir -p $(BINDIR)
	cp ./bin/timefind $(BINDIR)
	cp ./bin/timefind_indexer $(BINDIR)/timefind_indexer
	cp ./src/timefind_lander_indexer/timefind_lander_indexer $(BINDIR)

install_READMEs:
	-mkdir -p $(DOCDIR)
	cp ./src/timefind/README $(DOCDIR)/README.timefind
	cp ./src/indexer/README $(DOCDIR)/README.timefind_indexer

install_LICENSE:
	-mkdir -p $(DOCDIR)
	cp ./COPYRIGHT ./LICENSE $(DOCDIR)

clean:
	rm -rf bin/timefind bin/timefind_indexer

#
# release stuff
#
TV=timefind-$(VERSION)
tar.gz:
ifneq ($(VERSION_MATCH),1)
	$(error Repository tag is "$(VERSION_FULL)"! Expecting something like "$(VERSION)". Did you properly tag your release? (See CONTRIBUTING for more information))

else
	ln -s . $(TV)
	tar \
		--transform='flags=r;s|README\.timefind|README|' \
		--exclude "$(TV)/src/timefind/timefind" \
		--exclude "$(TV)/src/timefind/indexer/indexer" \
		--exclude "$(TV)/src/timefind/indexer/tests" \
		--exclude "$(TV)/src/vendor/xi2.org/x/xz/testdata" \
		-czvf timefind-$(VERSION).tar.gz \
		$(TV)/CHANGELOG \
		$(TV)/CONTRIBUTORS \
		$(TV)/COPYRIGHT \
		$(TV)/LICENSE \
		$(TV)/Makefile \
		$(TV)/README.timefind \
		$(TV)/src/timefind \
		$(TV)/src/timefind_lander_indexer \
		$(TV)/src/vendor
	rm -f $(TV)
endif

RPM_DIST=$(shell rpm --eval '%{dist}')

rpms:
	cp timefind-$(VERSION).tar.gz $$HOME/rpmbuild/SOURCES
	cp timefind.spec  $$HOME/rpmbuild/SPECS
	( cd $$HOME/rpmbuild; rpmbuild -ba SPECS/timefind.spec; )
	cp $$HOME/rpmbuild/RPMS/x86_64/timefind-$(VERSION)-1$(RPM_DIST).x86_64.rpm .
	cp $$HOME/rpmbuild/SRPMS/timefind-$(VERSION)-1$(RPM_DIST).src.rpm .

#cp $$HOME/rpmbuild/RPMS/noarch/timefind-$(VERSION)-1$(RPM_DIST).noarch.rpm .
#	cp $$HOME/rpmbuild/SRPMS/timefind-$(VERSION)-1$(RPM_DIST).src.rpm .

RELEASE_FILES=timefind-$(VERSION).tar.gz \
		timefind-$(VERSION)-1$(RPM_DIST).x86_64.rpm \
		timefind-$(VERSION)-1$(RPM_DIST).src.rpm
release:
	cp $(RELEASE_FILES) $$HOME/WORKING/ANT/WWW/ant_2015/software/timefind
	cd $$HOME/WORKING/ANT/WWW/ant_2015/software/timefind && git add $(RELEASE_FILES)
	mv $(RELEASE_FILES) RELEASE

