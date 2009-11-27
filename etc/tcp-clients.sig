# Web clients
www,v/Mozilla Gecko/$2/$1,Mozilla/[.\d]+ \((.*)\) Gecko\/([.\d]+)
www,v/Perl LWP/$1/$2,lwp-request/([.\d]+) libwww-perl/([.\d]+)
#www,v/HTTP Browser/$3//,^.+\[(.{26})\] \"(.+)HTTP/1..\".*(\".+\")$
www,v/Mozilla Browser/$1/$2/,User-Agent\x3a Mozilla\/([\S]+) (.*)
www,v/Opera/$1/$2/,User-Agent\x3a Opera\/([\S]+) (.*)\r\n
www,v/User Agent: $1///,User-Agent\x3a (.*)\r\n

# SSH
ssh,v/OpenSSH/$2/Protocol $1/,SSH-([.\d]+)-OpenSSH[_-](\S+)
ssh,v/libssh/$2/Protocol $1/,SSH-([.\d]+)-libssh-(\S+)
# SSL Signatures
ssl,v/Generic TLS 1.0 SSL///,^\x16\x03\x01..\x02\0\0.\x03\x01
ssl,v/OpenSSL///,^\x16\x03\0\0J\x02\0\0F\x03\0

