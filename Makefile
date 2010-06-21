PREFIX=/usr/local
BINDIR=${PREFIX}/bin
CONFDIR=${PREFIX}/etc/prads
MANDIR=${PREFIX}/share/man/man1

build:
	@echo "You need libpcre-dev and libpcap-dev to compile this program."
	${MAKE} CONFDIR=${CONFDIR} -C src/

clean:
	${MAKE} -C src/ $@
	rm -f doc/prads.1 doc/prads.1.gz

.PHONY: man
man: doc/prads.1.gz doc/prads-asset-report.1.gz doc/prads-wirefuzz.1.gz doc/prads2snort.1.gz

doc/%.1.gz: doc/%.1
	@>$@<$< gzip -9

doc/%.1: doc/%.man
	rst2man $< >$@

install: man
	# binaries
	install -d ${DESTDIR}${BINDIR}
	install -m 755 -o root -g root src/prads ${DESTDIR}${BINDIR}/prads
	install -m 755 -o root -g root tools/prads-asset-report ${DESTDIR}${BINDIR}/prads-asset-report
	install -m 755 -o root -g root tools/prads2snort ${DESTDIR}${BINDIR}/prads2snort
	# config
	install -d ${DESTDIR}${CONFDIR}
	install -m 644 -o root -g root etc/prads.conf ${DESTDIR}${CONFDIR}/
	# fingerprints
	#install -m 644 -o root -g root etc/osi.fp ${DESTDIR}${CONFDIR}/
	#install -m 644 -o root -g root etc/oso.fp ${DESTDIR}${CONFDIR}/
	#install -m 644 -o root -g root etc/osu.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/tcp-syn.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/tcp-synack.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/tcp-fin.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/tcp-rst.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/tcp-stray-ack.fp ${DESTDIR}${CONFDIR}/
	# signatures
	install -m 644 -o root -g root etc/eth.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/icmp-data.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/mac.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/mtu.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/os.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/tcp-clients.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/tcp-service.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/udp-service.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/service-string.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/web-application.sig ${DESTDIR}${CONFDIR}/
	# ports 
	install -m 644 -o root -g root etc/udp.ports ${DESTDIR}${CONFDIR}/
	# man pages
	install -m 644 -o root -g root doc/prads.1.gz ${DESTDIR}${MANDIR}/
	install -m 644 -o root -g root doc/prads-asset-report.1.gz ${DESTDIR}${MANDIR}/
	install -m 644 -o root -g root doc/prads2snort.1.gz ${DESTDIR}${MANDIR}/

.PHONY: build clean install
