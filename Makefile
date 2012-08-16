PREFIX=/usr/local
BINDIR=${PREFIX}/bin
CONFDIR=${PREFIX}/etc/prads
MANDIR=${PREFIX}/share/man/man1
DOCUTIL=rst2man
INSTALLGROUP=root

ifeq ($(UNAME), FreeBSD)
DOCUTIL=rst2man.py
INSTALLGROUP=wheel
endif

build:
	@echo "You need libpcre-dev and libpcap-dev to compile this program."
	${MAKE} CONFDIR=${CONFDIR} -C src/

clean:
	${MAKE} -C src/ $@
	rm -f doc/prads.1 doc/prads.1.gz
	rm -f doc/prads-wirefuzz.1 doc/prads-wirefuzz.1.gz
	rm -f doc/prads-asset-report.1 doc/prads-asset-report.1.gz
	rm -f doc/prads2snort.1 doc/prads2snort.1.gz

.PHONY: man
man: doc/prads.1.gz doc/prads-asset-report.1.gz doc/prads-wirefuzz.1.gz doc/prads2snort.1.gz

doc/%.1.gz: doc/%.1
	@>$@<$< gzip -9

doc/%.1: doc/%.man
	${DOCUTIL} $< >$@

install: man
	# binaries
	install -d ${DESTDIR}${BINDIR}
	install -m 755 -o root -g ${INSTALLGROUP} src/prads ${DESTDIR}${BINDIR}/prads
	install -m 755 -o root -g ${INSTALLGROUP} tools/prads-asset-report ${DESTDIR}${BINDIR}/prads-asset-report
	install -m 755 -o root -g ${INSTALLGROUP} tools/prads2snort ${DESTDIR}${BINDIR}/prads2snort
	# config
	install -d ${DESTDIR}${CONFDIR}
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/prads.conf ${DESTDIR}${CONFDIR}/
	# fingerprints
	#install -m 644 -o root -g ${INSTALLGROUP} etc/osi.fp ${DESTDIR}${CONFDIR}/
	#install -m 644 -o root -g ${INSTALLGROUP} etc/oso.fp ${DESTDIR}${CONFDIR}/
	#install -m 644 -o root -g ${INSTALLGROUP} etc/osu.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g ${INSTALLGROUP} etc/tcp-syn.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g ${INSTALLGROUP} etc/tcp-synack.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g ${INSTALLGROUP} etc/tcp-fin.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g ${INSTALLGROUP} etc/tcp-rst.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g ${INSTALLGROUP} etc/tcp-stray-ack.fp ${DESTDIR}${CONFDIR}/
	# signatures
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/eth.sig ${DESTDIR}${CONFDIR}/
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/icmp-data.sig ${DESTDIR}${CONFDIR}/
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/mac.sig ${DESTDIR}${CONFDIR}/
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/mtu.sig ${DESTDIR}${CONFDIR}/
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/os.sig ${DESTDIR}${CONFDIR}/
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/tcp-clients.sig ${DESTDIR}${CONFDIR}/
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/tcp-service.sig ${DESTDIR}${CONFDIR}/
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/udp-service.sig ${DESTDIR}${CONFDIR}/
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/service-string.sig ${DESTDIR}${CONFDIR}/
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/web-application.sig ${DESTDIR}${CONFDIR}/
	# ports 
	install -d ${DESTDIR}${CONFDIR}
	install -C -m 644 -o root -g ${INSTALLGROUP} etc/udp.ports ${DESTDIR}${CONFDIR}/
	install -d ${DESTDIR}${CONFDIR}/init.d
	install -m 755 -o root -g ${INSTALLGROUP} doc/prads.rc ${DESTDIR}${CONFDIR}/init.d/
	# man pages
	install -d ${DESTDIR}${MANDIR}
	install -m 644 -o root -g ${INSTALLGROUP} doc/prads.1.gz ${DESTDIR}${MANDIR}/
	install -m 644 -o root -g ${INSTALLGROUP} doc/prads-asset-report.1.gz ${DESTDIR}${MANDIR}/
	install -m 644 -o root -g ${INSTALLGROUP} doc/prads2snort.1.gz ${DESTDIR}${MANDIR}/


.PHONY: build clean install
