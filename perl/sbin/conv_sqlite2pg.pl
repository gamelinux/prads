#!/usr/bin/perl
# sqlite3 prads.db .dump | conv_sqlite2pg.pl | psql -U prads

print "\\set ON_ERROR_STOP\n";
while(<>){
   if(/PRAGMA/){ next }
   if(/CREATE TABLE/){ next }
   s/INSERT INTO "asset"/INSERT INTO asset(ipaddress,service,timestamp,os_fingerprint,mac_address,os,os_details,link,distance,hostname)/;
   my ($time) = /VALUES\('[^']*',[^,]*,'(\d*)',/;
   s/VALUES\('([^']*)',([^,]*),'(\d*)',/VALUES\('\1',\2, 'epoch'::TIMESTAMP + '\3'::INTERVAL,/;
   print;
}
