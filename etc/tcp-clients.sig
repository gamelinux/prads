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

# P2P / Torrent

# IM

