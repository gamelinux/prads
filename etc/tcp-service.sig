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
#	v/vendorproductname/version/info/
#
# Signature:  This is a PCRE compatable regular expression without the
# surrounding /'s.  The signature should have one or two sets of ()'s
# depending on the Version Info field.
#
# $Id: ppads-signature-list,v 0.1 2008/09/09 22:18:09 edward Exp $
#
############################################################################
# Test sigs for Client applications
#www,v/Mozilla Gecko/$2/$1,Mozilla/[.\d]+ \((.*)\) Gecko\/([.\d]+)
#www,v/Perl LWP/$1/$2,lwp-request/([.\d]+) libwww-perl/([.\d]+)
#www,v/HTTP Browser/$3//,^.+\[(.{26})\] \"(.+)HTTP/1..\".*(\".+\")$
#www,v/Mozilla Browser/$1/$2/,User-Agent\x3a Mozilla\/([\S]+) (.*)

ssh,v/OpenSSH/$2/Protocol $1/,SSH-([.\d]+)-OpenSSH[_-](\S+)
ssh,v/Cisco SSH/$2/Protocol $1/,SSH-([.\d]+)-Cisco[_-](\S+)
ssh,v/Sun SSH/$2/Protocol $1/,SSH-([.\d]+)-Sun_SSH[_-](\S+)
ssh,v/Cisco IDS SSH/$2/Protocol $1/,SSH-([.\d]+)-CiscoIDS\/LoginServer[_-](\S+)
ssh,v/libssh/$2/Protocol $1/,SSH-([.\d]+)-libssh-(\S+)

# WWW Signatures
www,v/Apache/$1//,Server: Apache\/([\S]+)[\r\n]
www,v/Apache/$1/$2/,Server: Apache\/([\S]+)[\s]+\((.*)\)
www,v/Apache/$1/$2/,Server: Apache\/([\S]+)[\s]+([\S]+)
www,v/Apache///,Server: Apache[\r\n]
www,v/Stronghold/$1/$2/,Server: Stronghold\/([\S]+) ([\S]+)
www,v/Microsoft-IIS/$1//,Server: Microsoft-IIS\/([\S]+)[\r\n]
www,v/Netscape Enterprise/$1//,Server: Netscape-Enterprise\/([\S]+)
www,v/NetCache//$1/,Server: NetCache (\(.*\))
www,v/Switch and Data - EdgePrism/$1//,Server:  EdgePrism\/([\S]+)
www,v/thttp/$1/$2/,Server: thttpd\/([\S]+) ([\S]+)
www,v/Apache Tomcat/$1/$2/,Server: Apache Tomcat\/([\S]+) (\(.*\))
www,v/Apache Coyote/$1//,Server: Apache[ -]{1}Coyote\/([\S]+)
www,v/DoubleClick Adserver///,Server: DCLK-HttpSvr
www,v/Resin JSP Engine/$1//,Server: Resin\/([\S]+)
www,v/Akamai Ghost///,Server: AkamaiGHost
www,v/Footprint Distributor/$1//,Server: Footprint Distributor V([\S]+)
www,v/AOLserver/$1//,Server: AOLserver\/([\S]+)
www,v/IBM WebSphere Application Server/$1//,Server: WebSphere Application Server\/([\S]+)
www,v/Netscape Brew/$1//,Server: Netscape-Brew\/([\S]+)
www,v/swcd/$1//,Server: swcd\/([\S]+)[\r\n]
www,v/TrueSpectra Image Server/$1//,Server: TrueSpectra Image Server Version ([\S]+)
www,v/Oracle Apache Server/$1/$2/,Server: Oracle HTTP Server Powered by Apache\/([\S]+) (\([\S]+\))
www,v/Enhydra Application Server/$1//,Server: Enhydra-MultiServer\/([\S]+)
www,v/Zeus Web Server/$1//,Server: Zeus\/([\S]+)
www,v/Inktomi Traffic Cache/$2/$1/,Via: HTTP/1.. ([\S]+) \(Traffic-Server\/([\S]+)
www,v/Cougar/$1//,Server: Cougar\/([\S]+)[\r\n]
www,v/GWS/$1//,Server: GWS\/([\S]+)[\r\n]
www,v/Apache AdvancedExtranetServer/$1/$2/,Server: Apache-AdvancedExtranetServer\/([\S]+) \(([\S|\s]+)\)
www,v/IBM HTTP Server/$1/$2/,Server: IBM_HTTP_Server\/([\S]+) ([\S]+)
www,v/Boa Web Server/$1//,Server: Boa\/([\S]+)
www,v/Netscape Enterprise/$1/AOL/,Server: Netscape-Enterprise\/([\S]+) AOL
#www,v/Squid/$1//,Server: squid\/([\S]+)[\r\n]
#www,v/Varnish/$1//,Via: ([\S]+)varnish[\r\n]
#Need to polish the Zope sig - this is just the raw string:
#www,v/Zope/$1//,Server: Zope/(Zope 2.9.1-, python 2.4.2, linux2) ZServer/1.1
www,v/Server: $1///,Server: (.*)\r\n

wwwproxy,v/Squid/$1//,Server: squid\/([\S]+)[\r\n]
wwwproxy,v/Varnish/$1//,Via: ([\S]+)varnish[\r\n]

# Fallback WWW Signature
#www,v/Unknown HTTP//$1/,^(HTTP/\d.\d)

# SSL Signatures
ssl,v/Generic TLS 1.0 SSL///,^\x16\x03\x01..\x02\0\0.\x03\x01
ssl,v/OpenSSL///,^\x16\x03\0\0J\x02\0\0F\x03\0

# SMB Sigantures
smb,v/Windows SMB///,\xffSMBr

# Mail Signatures
imap,v/Microsoft Exchange Server IMAP/$1/$2/,\* OK Microsoft Exchange Server ([\S]+) IMAP4rev1 server version ([\S]+)
imap,v/Cyrus IMAP4 Server/$1//,\* OK [-.\w]+ Cyrus IMAP4 v([-.\w]+) server ready
imap,v/UW IMAP Server/$1//,\* OK \[CAPABILITY IMAP4REV1 .*IMAP4rev1 (200\d\.[-.\w]+) ati

# POP Signatures
pop3,v/CommuniGate Pro POP3/$1//,OK CommuniGate Pro POP3 Server (.*) ready

# Generic CVSup server
cvsup,v/CVSup server///,CVSup server ready

# SQL signatures
sql,v/MySQL/$1//,([3-6]\.[0-1]\.\d\d-\w.+)

# Citrix ICA. Included signature wasn't hitting, this seems to fix it.
#ica,v/Citrix ICA Protocol///,\x7f\x7ICA\x00


# FTP Signatures
ftp,v/Microsoft FTP Server/$1//,Microsoft FTP Service \(Version ([\S]+)\).
ftp,v/Microsoft FTP Server Unknown Version///,220 Microsoft FTP Service
ftp,v/NcFTPd Server//$1/,NcFTPd Server \((.*)\) ready.
ftp,v/vsFTPd///,FTP server \(vsftpd\)
ftp,v/vsFTPd/$1//,220 \(vsFTPd ([\S]+)\)
ftp,v/ProFTPD Server/$1//,220 ProFTPD ([\S]+) Server
ftp,v/ProFTPD Server//$1/,220 ProFTPD \[(.*)\]
ftp,v/ProFTPD Server///,220 ProFTPD Server
ftp,v/WU-FTPD Server/$1//,FTP server \(Version wu-([\S]+)
ftp,v/Compaq Tru64 FTP Server/$2/$1/,220 ([-.\w]+) FTP server \(Compaq Tru64 UNIX Version ([\S]+)\) ready.[\r\n]
ftp,v/War-FTPD FTP Server/$2/$1/,220- ([\S]+) WAR-FTPD ([\S]+) Ready[\r\n]
ftp,v/Flash FTP Server/$1//,220 Flash FTP Server ([\S]+) ready
ftp,v/SFTPD//$1/,220- ([\S]+) FTP Server (SFTPD)
ftp,v/FreeBSD ftpd/$2/$1/,220 ([-.\w]+) FTP server \(Version (6.0\w+)\) ready.\r\n
ftp,v/FTP Generic//$1/,220 Welcome to ([\S]+)
ftp,v/FTP Generic//$1/,220 ([-.\w]+) FTP server ready
ftp,v/FTP Generic///,220 FTP server ready
ftp,v/GNU FTP Generic///,220 GNU FTP server ready
ftp,v/FTP Generic//$1,220 ([\S]+) FTP Server Ready

# Remote Access Systems
vnc,v/VNC//Protocol $1/,RFB ([\S]+)\n
rdp,v/Remote Desktop Protocol//Windows 2000 Server/,\x03\0\0\x0b\x06\xd0\0\0\x12.\0
rdp,v/Remote Desktop Protocol//Netmeeting Remote Assistance/,\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X
ica,v/Citrix ICA Protocol///,/7f/7fICA/00
pcanywhere,v/PCAnywhere///,^\0X\x08\0\}\x08\r\n\0\.\x08.*\.\.\.\r\n

# IRC
irc,v/Dancer IRCD/$1//,running version dancer-ircd-([\S]+)

# SMTP
smtp,v/Postfix SMTP//$1/,^220 ([-.\w]+) ESMTP Postfix
smtp,v/Lotus Notes SMTP//$1/,^220 ([-.\w]+) Lotus SMTP MTA Service Ready\r\n
smtp,v/Lotus Domino SMTP/$2/$1,220 ([\S]+) ESMTP Service \(Lotus Domino Release ([\S]+)\)
smtp,v/Microsoft Exchange SMTP/$2/$1/,220 ([-.\w]+) Microsoft ESMTP MAIL Service, Version: ([\S]+)
smtp,v/Microsoft Exchange SMTP/$2/$1/,220 ([\S]+) ESMTP Server \(Microsoft Exchange Internet Mail Service ([\S]+)\) ready
smtp,v/Sendmail SMTP/$2/$1/,220 ([-.\w]+) ESMTP Sendmail (.*);
smtp,v/Maillennium SMTP/MULTIBOX//$1/,220 ([-.\w]+) - Maillennium ESMTP/MULTIBOX
smtp,v/IMail NT-ESMTP/$2/$1/,220 ([-.\w]+) \(IMail ([^)]+)\) NT-ESMTP Server
smtp,v/SMTPD ?//$2/,220 \[SMTPD]: ([-.\w]+) hello
smtp,v/Kerio MailServer/$2/$1/,220 ([-.\w]+) Kerio MailServer ([\S]+) ESMTP
smtp,v/Kerio MailServer/$2/$1/,220 ([\S]+) esmtp Kerio MailServer ([\S]+) ESMTP ready
smtp,v/Sendmail EDS Secure SMTP//$1/,220 ([-.\w]+) ESMTP Sendmail EDS Secure;
smtp,v/Proxy SMTP Service/$1/$2/,220 ([-.\w]+) SMTP Proxy Service Ready \(Version: ([^)]+)\)
smtp,v/Proxy SMTP Service///,220 SMTP Proxy Server Ready
smtp,v/Yahoo! SMTP Service//$1/,220 YSmtp ([\S]+) ESMTP service ready
smtp,v/SurgeMail/$2/$1/,220 ([-.\w]+) SurgeSMTP \(Version ([\S]+)\) http:\/\/surgemail.com
smtp,v/PowerMTA SMTP/$2/$1/,220 ([\S]+) \(PowerMTA ([\S|\s]+)\) ESMTP service ready
smtp,v/Exim/$2/$1/,220 ([\S]+) SMTP Exim ([\S]+)
smtp,v/Exim/$2/$1/,220-([\S]+) SMTP Exim ([\S]+)
smtp,v/LSMTP for Windows NT/$2/$1/,220 ([\S]+) \(LSMTP for Windows NT ([\S]+)\) ESMTP server ready
smtp,v/Postini Perimeter Manager/$2/$1/,220 ([\S]+) ESMTP ([\S]+) ready.  CA Business and Professions Code
smtp,v/Sun iPlanet Messaging Server//$1/,220 ([\S]+) -- Server ESMTP \(Iplanet Messaging Server\)
smtp,v/Sigaba Secure Email Gateway//$1/,220 ([\S]+) ESMTP Sigaba Gateway;
smtp,v/Terrace MailWatcher/$2/$1/,220 ([\S]+) ESMTP Terrace MailWatcher ([\S]+)
smtp,v/CheckPoint Firewall-1 SMTP Proxy///,220 CheckPoint FireWall-1 secure ESMTP server
smtp,v/MailPass SMTP Server/$2/$1/,220 ([\S]+) MailPass SMTP server ([\S]+)
smtp,v/CommuniGate Pro/$2/$1/,220 ([\S]+) ESMTP CommuniGate Pro ([\S]+)
smtp,v/MailSite SMTP Server/$2/$1/,220 ([\S]+)[\s]+MailSite ESMTP Receiver Version ([\S]+) Ready
smtp,v/MailEnable SMTP Server/$2/$1/,220 ([\S]+) ESMTP MailEnable Service, Version:[\s]+([\S]+)-- ready
smtp,v/InterMail SMTP Server/$2/$2/,220 ([\S]+) ESMTP server \(InterMail ([\S]+)
smtp,v/Perl SMTP::Server Module///,220 MacGyver SMTP Ready.
smtp,v/McAfee WebShield SMTP Proxy/$2/$1/,220 ([\S]+) WebShield SMTP ([\S]+) [\S]+ Network Associates, Inc.
smtp,v/Trend Micro InterScan/$2/$1/,220 ([\S]+) Trend Micro InterScan Messaging Security Suite, Version:[\s]+([\S]+) ready
smtp,v/Worldmail/$2/$1/,220 ([\S]+) ESMTP Service \(Worldmail ([\S]+)\) ready
smtp,v/Novell GroupWise/$2/$1/,220 ([\S]+) GroupWise Internet Agent (\S+)
smtp,v/$2 - Server SMTP//$1/,220 ([\S]+) -- Server ESMTP \(([.*]+)\)
smtp,v/Generic SMTP - Possible Postfix//$1/,220 ([-.\w]+) ESMTP\r\n
smtp,v/Generic SMTP//$1/,220 ([\S]+) Simple Mail Transfer Service Ready
smtp,v/Generic SMTP/$2/$1/,220 ([\S]+) SMTP Server \(([\S]+)\)
smtp,v/Generic SMTP//$1/,220 ([\S]+) SMTP
smtp,v/Generic SMTP//$1/,220 ([-.\w]+) ESMTP Server[\r\n]
smtp,v/Generic SMTP//$1/,220 ([\S]+) ESMTP Service
smtp,v/Generic SMTP//$1/,220[\s]+([-.\w]+) SMTP Server is ready to process
smtp,v/Generic SMTP/$2/$1/,220 ([\S]+) ESMTP ([\S]+)

# P2P signatures
bit,v/Bittorrent///,^\x13BitTorrent\x20protocol

# Database signatures
razor,v/Razor///,sn\=[DNC]\x26srl\=

# DNS Signatures
dns,v/TCP DNS Server///,^[\x02-\xFF]...\x84\x80

# Munin
munin,v/Munin Node/$1//, munin node at (.*)

# Subversion
svn,v/Subversion server http///,\( success \( 2 2 \( \) \( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops partial-replay \) \) \)
