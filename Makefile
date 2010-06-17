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
	install -m 644 -o root -g root etc/os.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/osa.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/osi.fp ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/osu.fp ${DESTDIR}${CONFDIR}/
	# signatures
	install -m 644 -o root -g root etc/mac.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/mtu.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/tcp-clients.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/tcp-service.sig ${DESTDIR}${CONFDIR}/
	install -m 644 -o root -g root etc/udp-service.sig ${DESTDIR}${CONFDIR}/

.PHONY: build clean install
