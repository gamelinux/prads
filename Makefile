PREFIX=/usr/local
BINDIR=${PREFIX}/bin
CONFDIR=${PREFIX}/etc/prads

build:
	@echo "You need libpcre-dev and libpcap-dev to compile this program."
	${MAKE} -C src/

clean:
	${MAKE} -C src/ $@

install: 
	# binary
	install -d ${DESTDIR}${BINDIR}
	install -m 755 -o root -g root src/prads ${DESTDIR}${BINDIR}/prads
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

.PHONY: build clean install
