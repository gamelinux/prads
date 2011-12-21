# PRADS DHCP SIGNATURES
# 
# 53-OPTION:TTL:ALL-OPTIONS:55-OPTIONS:60-OPTIONS:OS:OS Details
#
# 53-OPTION is : DHCP_TYPE_DISCOVER, DHCP_TYPE_REQUEST, DHCP_TYPE_DECLINE, DHCP_TYPE_RELEASE or DHCP_TYPE_INFORM
# TTL is: IP TTL
# OPTIONS is list of all options in thire original order
# 55-OPTIONS: is a list of all options in the DHCP_OPTION_OPTIONREQ
# 60-OPTIONS: vendor code/string (as : could be in the string, we need to do something with that)
# OS: Linux, FreeBSD, Cisco, MicroSoft, Mac, etc
# OS Details: Might be "Ubuntu 10.4", "Windows Vista SP1", "Windows XP SP3", "Android 2.3.3 GT-I9100 Build/GINGERBREAD", "iPhone OS 3.0"

# CentOS4
# IP ttl : 16
# Options: 53(1),50,55(1,28,2,3,15,6,12,40,41,42),255
1:16:53,50,55,255:1,28,2,3,15,6,12,40,41,42:.:Linux:CentOS 4

# OpenBSD3.8
# IP ttl : 16
# Options: 12,53(1),55(1,28,3,15,6,12),255
1:16:12,53,55,255:1,28,3,15,6,12:.:OpenBSD:OpenBSD 3.8

# Windows XP SP3
# IP ttl : 128
# Options: 53(1),116,61,50,12,60(MSFT 5.0),55(1,15,3,6,44,46,47,31,33,121,249,43),43,255
1:128:53,116,61,50,12,60,55,43,255:1,15,3,6,44,46,47,31,33,121,249,43:MSFT 5.0:Windows:Windows XP SP3

# Ubuntu 10.04.3 LTS
# IP ttl : 128
# Options: 53(1),50,12,55(1,28,2,3,15,6,119,12,44,47,26,121,42),255
1:128:53,50,12,55,255:1,28,2,3,15,6,119,12,44,47,26,121,42:.:Linux:Ubuntu 10.04

# Ubuntu 10.04.3 LTS
# IP ttl : 64
# Options: 53(7),54,12,255
7:64:53,54,12,255:.:.:Linux:Ubuntu 10.04

# Ubuntu 10.04.3 LTS
# IP ttl : 128
# Options: 53(3),54,50,12,55(1,28,2,3,15,6,119,12,44,47,26,121,42),255
3:128:53,54,50,12,55,255:1,28,2,3,15,6,119,12,44,47,26,121,42:.:Linux:Ubuntu 10.04

