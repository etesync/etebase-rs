PREFIX ?= /usr
DESTDIR ?= /
# Set MODE to release to build with release
MODE ?= debug

PKGNAME = etesync

BUILDDIR = ./target

DST_LIBRARY_DIR = "$(DESTDIR)$(PREFIX)/lib"
DST_PKGCONFIG_DIR = "$(DST_LIBRARY_DIR)/pkgconfig"
DST_CMAKECONFIG_DIR = "$(DST_LIBRARY_DIR)/cmake/EteSync"
DST_INCLUDE_DIR = "$(DESTDIR)$(PREFIX)/include/$(PKGNAME)"

LIBRARY_FILE = "$(BUILDDIR)/$(MODE)/lib$(PKGNAME).so"
HEADER_FILE = "$(BUILDDIR)/$(PKGNAME).h"
PKGCONFIG_FILE = "$(BUILDDIR)/$(PKGNAME).pc"
CMAKECONFIG_FILE = "EteSyncConfig.cmake"

.PHONY: default all clean

all: build

pkgconfig: $(PKGCONFIG_FILE)

$(PKGCONFIG_FILE): $(PKGNAME).pc.in
	mkdir -p $(BUILDDIR)
	sed "s#@prefix@#$(PREFIX)#g" $< > "$(BUILDDIR)/$(PKGNAME).pc"

build-release: pkgconfig
	cargo build --release

build-debug: pkgconfig
	cargo build

build: build-$(MODE)

install:
	install -Dm644 $(PKGCONFIG_FILE) -t $(DST_PKGCONFIG_DIR)
	install -Dm644 $(CMAKECONFIG_FILE) -t $(DST_CMAKECONFIG_DIR)
	install -Dm644 $(HEADER_FILE) -t $(DST_INCLUDE_DIR)
	install -Dm755 $(LIBRARY_FILE) -t $(DST_LIBRARY_DIR)

check: build
	cargo check
	cd c_tests && $(MAKE) check

clean:
	cargo clean
	cd c_tests && $(MAKE) clean
	rm -f $(BUILDDIR)/$(PKGNAME).pc
