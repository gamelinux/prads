#
# prads - FIN signatures
# --------------------------
#
# .-------------------------------------------------------------------------.
# | The purpose of this file is to cover signatures for FIN packets         |
# | This database is looking for a caring maintainer.                       |
# `-------------------------------------------------------------------------'
#
# (C) Copyright 2009-2010 by Edward Fjellskål <edward@redpill-linpro.com>
#
# Submit all additions to the authors.
#
# IMPORTANT INFORMATION ABOUT THE INTERDEPENDENCY OF FIN
# ----------------------------------------------------------------
#
# Bla bla... :)
#
# IMPORTANT INFORMATION ABOUT DIFFERENCES IN COMPARISON TO SYN:
# ----------------------------------------------------------------
#
# Bla bla... :)

## Linux
#smallvalue(500>):54:1:52:N,N,T0:ATFN
#*:64:1:52:N,N,T:ATFN:Linux:2.6
14:64:1:52:N,N,T:ATFN:Linux:2.6
46:64:1:52:N,N,T:ATFN:Linux:2.6
54:64:1:52:N,N,T:ATFN:Linux:2.6
62:60:1:52:N,N,T:ATFN:Linux:2.6
80:64:1:52:N,N,T:ATFN:Linux:2.6
91:64:1:52:N,N,T:ATFN:Linux:2.6
108:64:1:52:N,N,T:ATFN:Linux:2.6
159:64:1:52:N,N,T:ATFN:Linux:2.6
216:64:1:52:N,N,T:ATFN:Linux:2.6

S4:64:1:*:.:AFDN:Linux:2.6 arm

32736:64:1:40:.:AFN:Linux:2.0

#54:64:1:*:N,N,T:ATFDN:Linux:Nagios

313:64:1:32:N,N,T:ZATFN:Linux:2.6 (Newer 5) IPv6
82:64:1:32:N,N,T:ZATFN:Linux:2.6 (Newer 7) IPv6
70:64:1:32:N,N,T:ZATFN:Linux:2.6 (Newer 7) IPv6

## Freebsd
8326:64:1:52:N,N,T:ATFN!:Freebsd:freebsd.org
8305:64:1:52:N,N,T:ATFN:Freebsd:7.2 (UC)

## Windows
*:128:1:*:.:AFDN:Windows:2008 Server (UC)
#64053:128:1:*(437):.:AFDN
#*:128:1:*:.:AFDN:Windows: 2008 Server (UC)
#62993:110:1:*(579):.:AFDN

# 87.238.43.133,[fin:17089:126:1:*(454):.:AFDN],[distance:2]
# 87.238.50.235,[fin:260:128:1:52:N,N,T0:ATFN],[uptime:379hrs],[distance:0]
# 87.238.45.226,[fin:65397:128:1:52:N,N,T0:ATFN],[uptime:57hrs],[distance:0]



## Solaris
32806:64:1:52:N,N,T:ATFN:Solaris:Sun OpenStorage 7310

# Cisco Iron Port
16560:64:1:40:.:AFN:Cisco:AsyncOS phoebe 7.1.x (Iron Port)

# signatures from Eric Kollmann
64292:128:1:40:.:AFN:Windows:Windows XP
64560:128:1:40:.:AFN:Windows:Windows XP
252:128:1:40:.:AFN:Windows:Windows 7/2008 R2
6432:64:1:40:.:AFN:Netgear:Netgear WNR3500

