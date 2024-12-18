PACKAGE = sargon
VERSION = 2.1

PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin

SOURCES = \
 main.go\
 access/access.go\
 auth/container_create.go\
 auth/volume_create.go\
 auth/service_create.go\
 diag/diag.go\
 server/action.go\
 server/authz.go\
 server/ldap.go\
 server/netgroup.go\
 server/type.go\
 wildmat/wildmat.go

all:
	@go mod download
	@go build

clean:
	@go clean

install: sargon
	@GOBIN=$(DESTDIR)$(BINDIR) go install .

DISTDIR   = $(PACKAGE)-$(VERSION)
DISTFILES = go.mod $(SOURCES) $(MANPAGE) README.md LICENSE Makefile sargon.schema sargon.ldif

distdir:
	@if [ "$$(sed -r -n -e '/^var[[:space:]]Version[[:space:]]*=[[:space:]]*/{' -e s/// -e 's/`//g' -e 'p}' main.go)" != "$(VERSION)" ]; then \
		echo >&2 "Version mismatch between Makefile and main.go"; \
		exit 1; \
	fi
	@test -d $(DISTDIR) || mkdir $(DISTDIR)
	@tar cf - $(DISTFILES) | tar Cxf $(DISTDIR) -

dist: distdir
	@tar zcf $(DISTDIR).tar.gz $(DISTDIR)
	@rm -rf $(DISTDIR)

distcheck: dist
	@tar xfz $(DISTDIR).tar.gz
	@if $(MAKE) -C $(DISTDIR) $(DISTCHECKFLAGS); then \
	  echo "$(DISTDIR).tar.gz ready for distribution"; \
	  rm -rf $(DISTDIR); \
        else \
          exit 2; \
	fi

