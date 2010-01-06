# Web clients
## Mozilla
www,v/Mozilla Gecko/$2/$1,Mozilla\/([.\d]+).*Gecko\/([.\d]+)
www,v/Mozilla Browser/$1/$2/,User-Agent\x3a Mozilla\/([\S]+) (.*)[\r\n]+
## Perl
www,v/Perl LWP/$1/$2,lwp-request\/([.\d]+) libwww-perl/([.\d]+)
www,v/Perl LWP/$1//,User-Agent\x3a lwp-request\/([.\d]+)
## Opera
www,v/Opera/$1/$2/,User-Agent\x3a Opera\/([\S]+) (.*)\r\n
## CUPS
www,v/Cups Client/$1//,User-Agent\x3a CUPS\/([\S]+)\r\n
## Pidgin
im,v/Pidgin Instant Messaging/$1//,User Agent: pidgin\/([\S]+)
## Unknown/Failback
#www,v/HTTP Browser/$3//,^.+\[(.{26})\] \"(.+)HTTP/1..\".*(\".+\")$
www,v/User Agent: $1///,User-Agent\x3a (.*)\r\n

# SSH
ssh,v/OpenSSH/$2/Protocol $1/,SSH-([.\d]+)-OpenSSH[_-](\S+)
ssh,v/libssh/$2/Protocol $1/,SSH-([.\d]+)-libssh-(\S+)

# TLS/SSL Signatures
ssl,v/TLS 1.0 Client Hello///,^\x16\x03\x01..\x01...\x03\x01
ssl,v/TLS 1.0 Client Key Exchange///,^\x16\x03\x01..\x10...\x14\x03\x01..
ssl,v/SSL 2.0 Client Hello///,^..\x01\x03\x01..\0\0
#ssl,v/OpenSSL///,^\x16\x03\0\0J\x02\0\0F\x03\0

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

