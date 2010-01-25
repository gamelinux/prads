# Web clients
## Mozilla
www,v/Mozilla Gecko/$2/$1,Mozilla\/([.\d]+).*Gecko\/([.\d]+)
www,v/Mozilla Browser/$1/$2/,User-Agent\x3a Mozilla\/([\S]+) (.*)[\r\n]+
#User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5

## Perl
www,v/Perl LWP/$1/$2,lwp-request\/([.\d]+) libwww-perl/([.\d]+)
www,v/Perl LWP/$1//,User-Agent\x3a lwp-request\/([.\d]+)

## Opera
www,v/Opera/$1/$2/,User-Agent\x3a Opera\/([\S]+) (.*)\r\n

## CUPS
www,v/Cups Client/$1//,User-Agent\x3a CUPS\/([\S]+)\r\n

## User Agent: Ubuntu APT-HTTP/1.3 (0.7.20.2ubuntu6)

## Unknown/Failback
# User-Agent: Java/1.4.1_04
#www,v/HTTP Browser/$3//,^.+\[(.{26})\] \"(.+)HTTP/1..\".*(\".+\")$
www,v/User Agent: $1///,User-Agent\x3a (.*)\r\n

# RSS
# Liferea/1.7.2-svn
# Apple-PubSub/65.11

# SSH
ssh,v/OpenSSH/$2/Protocol $1/,SSH-([.\d]+)-OpenSSH[_-](\S+)
ssh,v/libssh/$2/Protocol $1/,SSH-([.\d]+)-libssh-(\S+)

# TLS/SSL Signatures
ssl,v/TLS 1.0 Client Hello///,^\x16\x03\x01..\x01...\x03\x01
ssl,v/TLS 1.0 Client Key Exchange///,^\x16\x03\x01..\x10...\x14\x03\x01..
ssl,v/SSL 2.0 Client Hello///,^..\x01\x03\x01..\0\0
#ssl,v/OpenSSL///,^\x16\x03\0\0J\x02\0\0F\x03\0

# Others
# User Agent: ClamAV/0.95.3 (OS: linux-gnu, ARCH: x86_64, CPU: x86_64)

# Mail Clients
smtp,v/Mozilla-Thunderbird/$1/$2/,User-Agent: Mozilla-Thunderbird ([.\d]+) \((X11\/\d+)\)
smtp,v/Thunderbird/$1/$2/,User-Agent: Thunderbird ([.\d]+) \((Macintosh\/\d+)\)
smtp,v/Thunderbird/$1/$2/,User-Agent: Thunderbird ([.\d]+) \((Windows\/\d+)\)
# X-Mailer: Zimbra 6.0.4_GA_2038.RHEL5_64 (ZimbraWebClient - FF3.0 (Linux)/6.0.4_GA_2038.RHEL5_64)
smtp,v/Zimbra Web Client/$1//,X-Mailer: Zimbra (.*)\n
# X-Mailer: YahooMailRC/240.3 YahooMailWebService/0.8.100.260964
#smtp,v/Yahoo Mail Web Service///,X-Mailer: YahooMailRC\/[.\d]+ YahooMailWebService/[.\d]+
# X-Mailer: Microsoft Office Outlook 12.0
smtp,v/Microsoft Office Outlook/$1//,X-Mailer: Microsoft Office Outlook ([.\d]+)

# MySQL - Experimental !
mysql,v/MySQL Login Request(Char:latin1)///,^..\x00\x01\..[\x03\x01]\x00\x00\x00\x00.\x08
mysql,v/MySQL Request Ping///,^\x01\x00\x00\x00\x0e$
mysql,v/MySQL Request Query (SET NAMES)///,^.\x00\x00\x00\x03SET NAMES utf8$
mysql,v/MySQL Request Query (SELECT)///,^..\x00\x00\x03\x53\x45\x4c\x45\x43\x54\x20\x60
mysql,v/MySQL Request Unknown///,^\x09\x00\x00.\x4e\x41\x51\x5e\x4b\x50\x5b\x5c\00$
mysql,v/MySQL Request Sleep///,^\x05\x00\x00\x00\x00\x00\x00\x01\x00
mysql,v/MySQL Request Quit///,^\x01\x00\x00\x00\x01$

# P2P / Torrent

# IM
## Pidgin
im,v/Pidgin Instant Messaging/$1//,User Agent: pidgin\/([\S]+)

