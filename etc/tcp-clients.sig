############################################################################
#
# PRADS - Passive Real-time Asset Detection System
#  - TCP client signature list
#
# This contains a database of device signatures to be used with
# Passive Real-time Asset Detection System.
#
# Format:
# <service>,<version info>,<signature>
#
# Service: This describes the service name used by the signature.
# Examples would include SSH, HTTP, SMTP, etc.
#
# Version Info:  This contains a NMAP-like template for the service
# discovered by the signature.  The field follows this format:
#   v/vendorproductname/version/info/
#
# Signature:  This is a PCRE compatable regular expression without the
# surrounding /'s.  The signature should have one or two sets of ()'s
# depending on the Version Info field. 
#
# Matching: The matching rutine starts with the first signature in this
# file and ends with the last signature in this file. If a match is
# found, no more signatures will be checked.
# The signatures that you think will match the most in your environment,
# should be on top in this file. Wildcards/Fallback (.* etc) signatures
# should be the last signatures in a match signature group.
#
############################################################################

####### OFTEN USED CLIENTS #################################################
############################################################################

####### User-Agent Section START ###########################################
# From tests 28 jan 2010: Seems like fallback sigs does better overall
# performance vs detection. Fallback would get close to 100% agents, while
# spesific agents would just match for single agents. Though performace
# showing that 6 spesific sigs uses 22% time in client_tcp4() while using
# the 3 fallback sigs, uses 24 % on my test pcaps in client_tcp4().
# Conclusion: Higher detection rate and a small increase in resources
### Often used User-Agents
# Mozilla
#www,v/Mozilla Browser/$1/$2/,User-Agent\x3a Mozilla\/(.*)\r\n
### Moderate used User-Agents
# Opera
#www,v/Opera/$1/$2/,User-Agent\x3a Opera\/(.*)\r\n
### Little used User-Agents
## CUPS
#www,v/Cups Client/$1//,User-Agent\x3a CUPS\/(.*)\r\n
## Perl
#www,v/Perl LWP/$1/$2,lwp-request\/([.\d]+) libwww-perl/([.\d]+)
#www,v/Perl LWP/$1//,User-Agent\x3a lwp-request\/([.\d]+)
## Mozilla
#smtp,v/Mozilla/$1/$2/,User-Agent: (Mozilla-)?Thunderbird (.*)

### User-Agent fallbacks
misc,v/User-Agent: $1//,User-Agent\x3A (.*)\0x1F
misc,v/User-Agent: $1//,User-Agent\x3a (.*)\r
misc,v/User-Agent: $1//,User-Agent\x3a (.*)\n
####### User-Agent Section END #############################################

####### MODERATE USED CLIENTS ##############################################
############################################################################

####### SSH Section START ##################################################
# SSH
ssh,v/OpenSSH/$2/Protocol $1/,SSH-([.\d]+)-OpenSSH[_-](\S+)
ssh,v/libssh/$2/Protocol $1/,SSH-([.\d]+)-libssh-(\S+)
####### SSH Section END ####################################################

####### TLS/SSL Section START ##############################################
ssl,v/TLS 1.0 Client Hello///,^\x16\x03\x01..\x01...\x03\x01
ssl,v/TLS 1.0 Client Key Exchange///,^\x16\x03\x01..\x10...\x14\x03\x01..
ssl,v/SSL 2.0 Client Hello///,^..\x01\x03\x01..\0\0
#ssl,v/OpenSSL///,^\x16\x03\0\0J\x02\0\0F\x03\0
####### TLS/SSL Section END ################################################

####### LITTLE USED CLIENTS ################################################
############################################################################

####### SMTP Section START #################################################
#smtp,v/X-Mailer/$1//,X-Mailer: (.*)
####### SMTP Section END #################################################

#mysql,v/MySQL Login Request(Char:latin1)///,^..\x00\x01\..[\x03\x01]\x00\x00\x00\x00.\x08
#mysql,v/MySQL Request Query (SET NAMES)///,^.\x00\x00\x00\x03SET NAMES utf8$
#mysql,v/MySQL Request Query (SELECT)///,^..\x00\x00\x03\x53\x45\x4c\x45\x43\x54\x20\x60


############################################################################

