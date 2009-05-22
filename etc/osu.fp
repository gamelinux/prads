# If possible - UDP sigs for OS fingerprinting :)
# $dest_port:$fplen:$gttl:$df:$ipopts:$ipflags:$foffset

# Linux
20:64:1:.:2:0:@Linux:2.6

# Windows
20:128:0:.:0:0:@Windows:New

# FreeBSD


# UNKNOWN
20:64:0:.:0:0:@nmap:udp scan from Linux
