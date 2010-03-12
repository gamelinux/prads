############################################################################
#
# Perl Passive Asset Detection System - Signature List
#
# This contains a database of device signatures to be used with
# the Perl Passive Asset Detection System.
#
# Format:
# singel port
# <[port]>,<version info>,<signature>
# multiport # should this be changed ?
# <[port,port,port,port]>,<version info>,<signature>
# port-range
# <[port:port]>,<version info>,<signature>
#
# Service:  This describes the service name used by the signature.
# Examples would include SSH, HTTP, SMTP, etc.
#
# Version Info:  This contains a NMAP-like template for the service
# discovered by the signature.  The field follows this format:
#       v/vendorproductname/version/info/
#
# Signature:  This is a PCRE compatable regular expression without the
# surrounding /'s.  The signature should have one or two sets of ()'s
# depending on the Version Info field.
#
############################################################################

# How can we best do this ?
# check on binary content ? and not txt?

# Standard Query response - no error
#53,v/DNS///,^..\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00
domain,v/DNS SQR No Error///,\x81\x80\x00\x01\x00
# Standard Query response - no such name
#53,v/DNS///,^..\x84\x03\x00\x01\x00\x00\x00\x01\x00\x00
domain,v/DNS SQR No Such Name///,\x84\x03\x00\x01\x00\x00\x00
# Bind version:

#53,v/DNS///,A\?
#53,v/DNS///,MX\?
#53,v/DNS///,NXDomain\*-\[\|domain\]
#53,v/DNS///,PTR\?

#UDP port 137 NETBIOS
#137,v/NETBIOS///,REGEXP

#openvpn
#1194,v/OpenVPN///,REGEXP

# SSL Signatures
#ssl,v/Generic TLS 1.0 SSL///,^\x16\x03\x01..\x02\0\0.\x03\x01
#ssl,v/OpenSSL///,^\x16\x03\0\0J\x02\0\0F\x03\0

# SMB Sigantures
#smb,v/Windows SMB///,\xffSMBr
#smb,v/Windows SMB///,\xffSMBr


# syslog port 514 udp
syslog,v/Syslog: DAEMON.ERR///,^\x3c\x32\x37\x3e
syslog,v/Syslog: DAEMON.ERR///,^\x3c\x32\x37\x3e



