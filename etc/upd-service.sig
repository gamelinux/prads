############################################################################
#
# Perl Passive Asset Detection System - Signature List
#
# This contains a database of device signatures to be used with
# the Perl Passive Asset Detection System.
#
# Format:
# <service>,<version info>,<signature>
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

dns,v/DNS///,A\?
#dns,v/DNS///,MX\?
#dns,v/DNS///,NXDomain\*-\[\|domain\]
#dns,v/DNS///,PTR\?


#openvpn
