# If possible - UDP sigs for OS fingerprinting :)
# $fplen:$gttl:$df:$ipopts:$ipflags:$foffset
# Supports wildcarding on all fields, etc: *:*:*:*:*:*:*:*:@SomeOS:1.1
# Example: 20:*:0:.:0:0:@Windows:MS?

# Linux
20:64:1:.:2:0:@Linux:2.6

# Windows
20:255:0:.:0:0:@Windows:MS ?
20:128:0:.:0:0:@Windows:MS
20:32:0:.:0:0:@Windows:MS
# FreeBSD

# Sun
20:255:1:.:2:0:@Sun:Solaris

# UNKNOWN
20:64:0:.:0:0:@Misc:nmap udp scan?
#20:64:0:0:0:0:I:@Misc:nmap udp scan?

#
#20:32:1:.:2:0:?
#20:64:1:.:2:0:?
#0:64:0:.:1:0
#20:128:0:.:0:0
#20:128:1:.:2:0
#20:255:0:.:0:0
#20:255:1:.:2:0
#20:32:0:.:0:0
#20:64:0:.:0:0
#20:64:1:.:2:0
#255:64:0:.:0:1480
#0:64:0:.:0:1480
#0:64:0:.:0:2960
#0:64:0:.:0:4440
#0:64:0:.:1:1480
#0:64:0:.:1:2960


