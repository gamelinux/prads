PREFIX=/usr/local
SBINDIR=${PREFIX}/sbin
CONFDIR=${PREFIX}/etc/prads
PMDIR=${PREFIX}/lib/site_perl/
LOGDIR=/var/log/prads/

build:
	@echo "You need libpcre-dev and libpcap-dev to compile this program."
	${MAKE} -C src/

clean:
	${MAKE} -C src/ $@

install: 
	# binary
	install -d ${DESTDIR}${SBINDIR}
	# perl version
	install -m 755 -o root -g root perl/sbin/prads.pl ${DESTDIR}${SBINDIR}/prads.pl
	# C version
	install -m 755 -o root -g root src/prads ${DESTDIR}${SBINDIR}/prads
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
	# perl modules
	install -d ${DESTDIR}${PMDIR}
	install -m 644 -o root -g root lib/NetPacket.pm ${DESTDIR}${PMDIR}/
	install -m 644 -o root -g root lib/NetPacket/ARP.pm ${DESTDIR}${PMDIR}/NetPacket/
	install -m 644 -o root -g root lib/NetPacket/IP.pm ${DESTDIR}${PMDIR}/NetPacket/
	install -m 644 -o root -g root lib/NetPacket/IGMP.pm ${DESTDIR}${PMDIR}/NetPacket/
	install -m 644 -o root -g root lib/NetPacket/UDP.pm ${DESTDIR}${PMDIR}/NetPacket/
	install -m 644 -o root -g root lib/NetPacket/Ethernet.pm ${DESTDIR}${PMDIR}/NetPacket/
	install -m 644 -o root -g root lib/NetPacket/ICMP.pm ${DESTDIR}${PMDIR}/NetPacket/
	install -m 644 -o root -g root lib/NetPacket/TCP.pm ${DESTDIR}${PMDIR}/NetPacket/
	# prads.db
	install -d ${LOGDIR}

.PHONY: build clean install
