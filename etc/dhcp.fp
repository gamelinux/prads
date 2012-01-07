# PRADS DHCP SIGNATURES
# 
# 53-OPTION:TTL:ALL-OPTIONS:55-OPTIONS:60-OPTIONS:OS:OS Details
#
# 53-OPTION possible : DHCP_TYPE_DISCOVER, DHCP_TYPE_REQUEST, DHCP_TYPE_DECLINE, DHCP_TYPE_RELEASE or DHCP_TYPE_INFORM
# DHCP_TYPE_DISCOVER      1 // a client broadcasts to locate servers
# DHCP_TYPE_OFFER         2 // a server offers an IP address to the device
# DHCP_TYPE_REQUEST       3 // client accepts offers from DHCP server
# DHCP_TYPE_DECLINE       4 // client declines the offer from this DHCP server
# DHCP_TYPE_ACK           5 // server to client + committed IP address
# DHCP_TYPE_NAK           6 // server to client to state net address incorrect
# DHCP_TYPE_RELEASE       7 // graceful shutdown from client to Server
# DHCP_TYPE_INFORM        8 // client to server asking for local info
#
# TTL is: IP TTL
#
# OPTIONS is list of all options in thire original order
#
# 55-OPTIONS: is a list of all options in the DHCP_OPTION_OPTIONREQ
#
# 60-OPTIONS: vendor code/string (as : could be in the string, we need to do something with that)
#
# OS: Linux, FreeBSD, Cisco, MicroSoft, Mac, etc
# OS Details: Might be "Ubuntu 10.4", "Windows Vista SP1", "Windows XP SP3", "Android 2.3.3 GT-I9100 Build/GINGERBREAD", "iPhone OS 3.0"

# Linux based OSes
####################
# RedHat4/CentOS4/ADIOS4/Fedora Core 3/4/5
1:16:53,50,55,255:1,28,2,3,15,6,12,40,41,42:.:Linux:Redhat4/CentOS4/ADIOS4/Fedora3,4,5
3:16:53,54,50,55,255:1,28,2,3,15,6,12,40,41,42:.:Linux:Redhat4/CentOS4/ADIOS4/Fedora3
# Ubuntu 10.04.3 LTS
1:128:53,50,12,55,255:1,28,2,3,15,6,119,12,44,47,26,121,42:.:Linux:Ubuntu 10.04
3:128:53,54,50,12,55,255:1,28,2,3,15,6,119,12,44,47,26,121,42:.:Linux:Ubuntu 10.04
7:64:53,54,12,255:.:.:Linux:Ubuntu 10.04
# Linspire Linspire 5.0-69
1:64:53,12,55,255:1,28,2,3,15,6,12,44,47:.:Linux:Linspire 5.0-69
# Linux, OpenWrt Backfire (10.03.1-rc4, r24045)
1:64:53,61,60,50,57,55,255:1,3,6,12,15,17,28,42:udhcp 1.15.3:Linux:OpenWrt Backfire (10.03)
3:64:53,61,60,50,54,55,255:1,3,6,12,15,17,28,42:udhcp 1.15.3:Linux:OpenWrt Backfire (10.03)
7:64:53,61,54,255:.:.:Linux:OpenWrt Backfire (10.03)
# Gentoo 2005
1:64:53,57,51,55,12,60:1,3,6,12,15,17,23,28,29,31,33,40,41,42:Linux 2.6.11-gentoo-r3 i686:Linux:Gentoo 2005
3:64:53,57,54,50,51,55,12:1,3,6,12,15,17,23,28,29,31,33,40,41,42:.:Linux:Gentoo 2005
# Gentoo 2006
1:64:53,57,50,51,55,12,60:1,3,6,12,15,17,23,28,29,31,33,40,41,42,119:Linux 2.6.17-gentoo-r8 i686:Linux:Gentoo 2006
3:64:53,57,50,51,55,12,60:1,3,6,12,15,17,23,28,29,31,33,40,41,42,119:Linux 2.6.17-gentoo-r8 i686:Linux:Gentoo 2006
# Knoppix 3.8.2/4.0.2/5.0.1 - (and distros based on knoppix, like PHLAK 0.3)
1:16:53,255:.:.:Linux:Knoppix 3.8.2/4.0.2/5.0.1
# SLAX 5.1.8
1:64:53,57,51,55,60,61:1,3,6,12,15,17,23,28,29,31,33,40,41,42,119:Linux 2.6.16 i686:Linux:SLAX 5.1.8
# Novell's SUSE Linux Enterprise Desktop 10 (SLED 10)
1:16:53,51,50,12,55,255:1,28,2,3,15,6,12,40,41:.:Linux:SUSE Linux Enterprise Desktop 10
# Arudis live cd (Based on Zenwalk 1.2)
1:64:53,57,51,55,60,61:1,3,6,12,15,17,23,28,29,31,33,40,41,42:Linux 2.6.13.2 i686:Linux:Arudis

# *BSD based OSes
####################
# OpenBSD3.8
1:16:12,53,55,255:1,28,3,15,6,12:.:OpenBSD:3.8
1:16:12,50,53,55,255:1,28,3,15,6,12:.:OpenBSD:3.8

# Windows based OSes
####################
# Windows 95b/ 95 GOLD
1:32:53,61,50,12,255:.:.:Windows:95b
3:32:53,61,50,54,12,55,43,255:1,3,15,6,44,46,47:.:Windows:95b
# Windows 98
1:128:53,61,50,12,55,255:1,3,6,15,44,46,47,57:.:Windows:98 
3:128:53,61,50,54,12,55,255:1,3,6,15,44,46,47,57:.:Windows:98
3:128:53,61,50,12,55,255:1,3,6,15,44,46,47,57:.:Windows:98
# Windows 98 SE
1:128:53,61,50,12,60,55,255:1,15,3,6,44,46,47,43,77:MSFT 98:Windows:98 SE
3:128:53,61,50,54,12,81,60,55,255:1,15,3,6,44,46,47,43,77:MSFT 98:Windows:98 SE
# Win ME
1:128:53,251,61,50,12,60,55,255:1,15,3,6,44,46,47,31,33,43,77:MSFT 98:Windows:ME
3:128:53,61,50,12,60,55,255:1,15,3,6,44,46,47,31,33,43,77:MSFT 98:Windows:ME
3:128:53,61,12,60,55,255:1,15,3,6,44,46,47,31,33,43,77:MSFT 98:Windows:ME
# Windows NT 4 (SP1 - SP5) / Gold
1:128:53,61,50,12,55,255:1,15,3,44,46,47,6:.:Windows:NT 4
# Windows 2000 server
1:128:53,251,61,50,12,60,55,255:1,15,3,6,44,46,47,31,33,43:MSFT 5.0:Windows:2000 Server
# Windows XP SP3 / Vista
1:128:53,116,61,12,60,55,43,255:1,15,3,6,44,46,47,31,33,249,43:MSFT 5.0:Windows:XP SP3
1:128:53,116,61,50,12,60,55,43,255:1,15,3,6,44,46,47,31,33,121,249,43:MSFT 5.0:Windows:XP SP3
1:128:53,116,61,12,60,55,43,255:1,15,3,6,44,46,47,31,33,121,249,43:MSFT 5.0:Windows:XP SP3
3:128:53,61,12,81,60,55,43,255:1,15,3,6,44,46,47,31,33,249,43:MSFT 5.0:Windows:XP SP3
3:128:53,61,50,12,81,60,55,43,255:1,15,3,6,44,46,47,31,33,249,43:MSFT 5.0:Windows:XP SP3
3:128:53,61,50,54,12,81,60,55,43,255:1,15,3,6,44,46,47,31,33,249,43:MSFT 5.0:Windows:XP SP3
6:128:53,54,255:.:.:Windows:XP SP3
8:128:53,61,12,60,55,255:1,15,3,6,44,46,47,31,33,249,43,252:MSFT 5.0:Windows:XP SP3
8:128:53,61,12,60,55,43,255:1,15,3,6,44,46,47,31,33,249,43,252:MSFT 5.0:Windows:XP SP3
#Windows 7
1:128:53,61,12,60,55,255:1,15,3,6,44,46,47,31,33,121,249,43:MSFT 5.0:Windows:7


