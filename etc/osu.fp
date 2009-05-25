# If possible - UDP sigs for OS fingerprinting :)
# $dest_port:$fplen:$gttl:$df:$ipopts:$ipflags:$foffset

# Linux
20:64:1:.:2:0:@Linux:2.6

# Windows
20:255:0:.:0:0:@Windows:MS ?
20:128:0:.:0:0:@Windows:MS
20:64:0:.:0:0:@Windows:MS
20:32:0:.:0:0:@Windows:MS
# FreeBSD

# UNKNOWN
20:64:0:.:0:0:@nmap:udp scan from Linux

#20:32:1:.:2:0:?
#20:64:1:.:2:0:?
0:64:0:.:1:0
20:128:0:.:0:0
20:128:1:.:2:0
20:255:0:.:0:0
20:255:1:.:2:0
20:32:0:.:0:0
20:64:0:.:0:0
20:64:1:.:2:0
255:64:0:.:0:1480

