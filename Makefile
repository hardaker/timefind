.PHONY: build check-version

VERSION=1.0.2.4
DESTDIR=
PREFIX=$(DESTDIR)/usr
BINDIR=$(PREFIX)/bin
DOCDIR=$(DESTDIR)/usr/share/timefind-$(VERSION)

export GOPATH := ${PWD}
export GO15VENDOREXPERIMENT := 1

all::

check-version:
	@go version > /dev/null || (echo "Go not found. You need to install go: http://golang.org/doc/install"; false)
	@go version | grep -q 'go version go1.[5-9]' || (echo "Go version 1.5.x (or higher) is required: http://golang.org/doc/install"; false)

all:: bin/timefind bin/timefind_indexer

bin/timefind:
	go build -o ./bin/timefind ./src/timefind

bin/timefind_indexer:
	go build -o ./bin/timefind_indexer ./src/indexer

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
	ln -s . $(TV)
	tar czvf timefind-$(VERSION).tar.gz $(TV)/CHANGELOG $(TV)/CONTRIBUTORS $(TV)/COPYRIGHT $(TV)/LICENSE \
		$(TV)/Makefile $(TV)/README \
		$(TV)/src/indexer $(TV)/src/timefind $(TV)/src/vendor $(TV)/src/urutil \
		$(TV)/src/timefind_lander_indexer
	rm -f $(TV)

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

