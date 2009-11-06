www,v/Mozilla Gecko/$2/$1,Mozilla/[.\d]+ \((.*)\) Gecko\/([.\d]+)
www,v/Perl LWP/$1/$2,lwp-request/([.\d]+) libwww-perl/([.\d]+)
www,v/HTTP Browser/$3//,^.+\[(.{26})\] \"(.+)HTTP/1..\".*(\".+\")$
www,v/Mozilla Browser/$1/$2/,User-Agent\x3a Mozilla\/([\S]+) (.*)
