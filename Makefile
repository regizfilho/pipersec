BIN := vpnctl
GUI_BIN := vpnctl-gui
PREFIX ?= /usr/local
VERSION ?= 1.0.0
DEB_ROOT := dist/deb-root

.PHONY: build test install uninstall package deb

build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -ldflags="-s -w" -o bin/$(BIN) ./cmd/vpnctl
	go build -buildvcs=false -trimpath -ldflags="-s -w" -o bin/$(GUI_BIN) ./cmd/vpnctl-gui

test:
	go test ./...

install: build
	install -Dm755 bin/$(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	install -Dm755 bin/$(GUI_BIN) $(DESTDIR)$(PREFIX)/bin/$(GUI_BIN)
	install -Dm644 packaging/vpnctl.desktop $(DESTDIR)$(PREFIX)/share/applications/vpnctl.desktop
	install -Dm644 packaging/br.com.codepiper.PiperSec.metainfo.xml $(DESTDIR)$(PREFIX)/share/metainfo/br.com.codepiper.PiperSec.metainfo.xml
	install -Dm644 packaging/br.com.codepiper.PiperSec.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/br.com.codepiper.PiperSec.svg

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	rm -f $(DESTDIR)$(PREFIX)/bin/$(GUI_BIN)
	rm -f $(DESTDIR)$(PREFIX)/share/applications/vpnctl.desktop
	rm -f $(DESTDIR)$(PREFIX)/share/metainfo/br.com.codepiper.PiperSec.metainfo.xml
	rm -f $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/br.com.codepiper.PiperSec.svg

package: test build
	mkdir -p dist
	zip -r dist/vpnctl-linux-amd64.zip cmd internal docs packaging README.md LICENSE Makefile go.mod $(wildcard go.sum) bin/$(BIN) bin/$(GUI_BIN)

deb: build
	rm -rf $(DEB_ROOT)
	mkdir -p $(DEB_ROOT)/DEBIAN $(DEB_ROOT)/usr/bin $(DEB_ROOT)/usr/share/applications $(DEB_ROOT)/usr/share/metainfo $(DEB_ROOT)/usr/share/icons/hicolor/scalable/apps
	install -Dm755 bin/$(BIN) $(DEB_ROOT)/usr/bin/$(BIN)
	install -Dm755 bin/$(GUI_BIN) $(DEB_ROOT)/usr/bin/$(GUI_BIN)
	install -Dm755 packaging/pipersec $(DEB_ROOT)/usr/bin/pipersec
	install -Dm644 packaging/vpnctl.desktop $(DEB_ROOT)/usr/share/applications/br.com.codepiper.PiperSec.desktop
	install -Dm755 packaging/pipersec.py $(DEB_ROOT)/usr/lib/pipersec/pipersec.py
	install -Dm755 packaging/postinst $(DEB_ROOT)/DEBIAN/postinst
	install -Dm644 packaging/br.com.codepiper.PiperSec.metainfo.xml $(DEB_ROOT)/usr/share/metainfo/br.com.codepiper.PiperSec.metainfo.xml
	install -Dm644 packaging/br.com.codepiper.PiperSec.svg $(DEB_ROOT)/usr/share/icons/hicolor/scalable/apps/br.com.codepiper.PiperSec.svg
	sed 's/@VERSION@/$(VERSION)/' packaging/debian-control > $(DEB_ROOT)/DEBIAN/control
	dpkg-deb --build --root-owner-group $(DEB_ROOT) dist/vpnctl_$(VERSION)_amd64.deb
