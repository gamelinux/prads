#!/usr/bin/perl -w
# ----------------------------------------------------------------------
# prads2db.pl
# Copyright (C) 2011-2012, Edward Fjellskål <edwardfjellskaal@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# ----------------------------------------------------------------------

use strict;
use warnings;
use POSIX qw(setsid);
use DateTime;
use Getopt::Long qw/:config auto_version auto_help/;
use DBI;

=head1 NAME

 prads2db.pl - Load prads assets into DB

=head1 VERSION

0.2.0

=head1 SYNOPSIS

 $ prads2db.pl [options]

  OPTIONS:

   --file         : set the prads-asset.log file to read from 
   --daemon       : enables daemon mode
   --debug        : enable debug messages (default: 0 - disabled)
   --help         : this help message
   --version      : show prads2db.pl version

=cut

our $VERSION       = 0.1;
our $DEBUG         = 0;
our $DAEMON        = 0;
our $TIMEOUT       = 1;
my  $PFILE         = "/var/log/prads-asset.log";
my  $LOGFILE       = q(/var/log/prads2db.log);
my  $PIDFILE       = q(/var/run/prads2db.pid);
our $DB_NAME       = "prads";
our $DB_HOST       = "127.0.0.1";
our $DB_PORT       = "3306";
our $DB_USERNAME   = "prads";
our $DB_PASSWORD   = "prads";
our $DBI           = "DBI:mysql:$DB_NAME:$DB_HOST:$DB_PORT";
our $TABLE_NAME    = "prads";
our $AUTOCOMMIT    = 0;

GetOptions(
   'file=s'        => \$PFILE,
   'debug'         => \$DEBUG,
   'daemon'        => \$DAEMON,
);

# Signal handlers
use vars qw(%sources);
#$SIG{"HUP"}   = \&recreate_merge_table;
$SIG{"INT"}   = sub { game_over() };
$SIG{"TERM"}  = sub { game_over() };
$SIG{"QUIT"}  = sub { game_over() };
$SIG{"KILL"}  = sub { game_over() };
#$SIG{"ALRM"}  = sub { dir_watch(); alarm $TIMEOUT; };

warn "[*] Starting prads2db.pl\n";

# Prepare to meet the world of Daemons
if ( $DAEMON ) {
   print "[*] Daemonizing...\n";
   chdir ("/") or die "chdir /: $!\n";
   open (STDIN, "/dev/null") or die "open /dev/null: $!\n";
   open (STDOUT, "> $LOGFILE") or die "open > $LOGFILE: $!\n";
   defined (my $dpid = fork) or die "fork: $!\n";
   if ($dpid) {
      # Write PID file
      open (PID, "> $PIDFILE") or die "open($PIDFILE): $!\n";
      print PID $dpid, "\n";
      close (PID);
      exit 0;
   }
   setsid ();
   open (STDERR, ">&STDOUT");
}

our $dbh;
# Connect to the DB
connect_db();
# Setup the prads table, if not exist
setup_db();

# Start file_watch() which looks for new dns data and puts them into db
warn "[*] Looking for passive DNS data in file: $PFILE\n";
file_watch($PFILE);
exit;

=head1 FUNCTIONS

=head2 setup_db

 Checks if the pdns table exists, if not make it.

=cut

sub setup_db {

   if (checkif_table_exist($TABLE_NAME)) {
      return;
   } else {
      if (new_table($TABLE_NAME)) {
         die "[E] Table $TABLE_NAME does not exist, and we could not create it! Sorry!\n";
      }
   }
}

=head2 file_watch

 This sub looks for new DNS data in a file.
 Takes $filename to watch as input.

=cut

sub file_watch {
   my $logfile = shift;
   my $startsize = 0;
   my $pos = 0;
   #infinite loop
   while (1) {
      $startsize = (stat $logfile)[7];

      if (defined $startsize) {
          if (!defined $pos) {
             # Initial run.
             $pos = $startsize;
          }
    
          if ($startsize < $pos) {
             # Log rotated
             #parseLogfile ($rotlogfile, $pos, (stat $rotlogfile)[7]);
             $pos = 0;
          }
    
          parseLogfile ($logfile, $pos, $startsize);
          $pos = $startsize;
      }
      sleep $TIMEOUT;
   }
}

sub parseLogfile {
    my ($fname, $start, $stop) = @_;
    open (LOGFILE, $fname) or return;
    seek (LOGFILE, $start, 0) or exit 2;

    LINE:
    while (tell (LOGFILE) < $stop) {
       my $line =<LOGFILE>;
       chomp ($line);
       next if ( not defined $line || $line =~ /^asset,vlan,port,proto/);
       #my @elements = split/\|\|/,$line;

       # 211.211.211.1,0,44163,6,SYN,[S4:56:1:60:M1460,S,T,N,W7:.:Linux:2.6 (newer, 7):link:ethernet/modem:uptime:1597hrs],8,1320426783
       # 211.211.211.1,0,0,0,ARP,[00:90:7F:3E:AF:94,(Watchguard)],0,1300470771
       if ($line =~ /^([\w\.:]+),([\d]{1,4}),([\d]{1,5}),([\d]{1,3}),(\S+?),\[(.*)\],([\d]{1,3}),(\d{10})$/) {
          my ($ip, $vlan, $port, $proto, $service, $meta, $dist, $ts) = ($1, $2, $3, $4, $5, $6, $7, $8);
          put_asset_to_db($ip, $vlan, $port, $proto, $service, $meta, $dist, $ts);
       } else {
            warn "[*] Error: Not valid prads format encountered: '$fname'";
            next LINE;
       }
    }
    close(LOGFILE);
}

sub put_asset_to_db {
    # 208.115.111.68,0,44163,6,SYN,[S4:56:1:60:M1460,S,T,N,W7:.:Linux:2.6 (newer, 7):link:ethernet/modem:uptime:1597hrs],8,1320426783
    my ($ip, $vlan, $port, $proto, $service, $meta, $dist, $ts) = @_;
    #my $quoted_meta = $dbh->quote($meta);
    $meta =~ s/(')/\\$1/g;
    $meta =~ s/:uptime:\d+hrs//; # removes the uptime which changes
    my ($sql, $sth);

    eval{
      $sql = qq[
             INSERT INTO $TABLE_NAME (
               IP,VLAN,PORT,PROTO,SERVICE,META,DIST,FIRST_SEEN,LAST_SEEN
             ) VALUES (
               '$ip','$vlan','$port','$proto','$service','$meta','$dist',FROM_UNIXTIME($ts),FROM_UNIXTIME($ts)
             ) ON DUPLICATE KEY UPDATE LAST_SEEN=FROM_UNIXTIME($ts)
             ];
      warn "$sql\n" if $DEBUG;

      connect_db();

      $sth = $dbh->prepare($sql);
      $sth->execute;
      $sth->finish;
   };
   if ($@) {
      # Failed
      warn "$sql\n";
      return 1;
   }
   return 0;
}

sub connect_db {
    while (not defined $dbh) {
      print "[*] Connecting to database...\n";
      if ($dbh = DBI->connect($DBI,$DB_USERNAME,$DB_PASSWORD, {RaiseError => 0})) {
          print "[*] Re-connection to DB OK...\n";
      } else {
          print "[E] $DBI::errstr\n"; 
          print "[*] Sleeping for 60sec\n";
          sleep 60;
      }
    }
}

sub new_table {
   my ($tablename) = shift;
   my ($sql, $sth);
   warn "[*] Creating $TABLE_NAME...\n";
   eval{
      $sql = "                                                      \
        CREATE TABLE IF NOT EXISTS $tablename                       \
        (                                                           \
        ID            BIGINT(20) UNSIGNED  NOT NULL AUTO_INCREMENT, \
        IP            varchar(39)          NOT NULL DEFAULT   '',   \
        VLAN          int(4)               NOT NULL DEFAULT  '0',   \
        PORT          int(5)               NOT NULL DEFAULT  '0',   \
        PROTO         int(3)               NOT NULL DEFAULT  '0',   \
        SERVICE       varchar(20)          NOT NULL DEFAULT   '',   \
        META          varchar(255)         NOT NULL DEFAULT   '',   \
        DIST          int(3)               NOT NULL DEFAULT  '0',   \
        FIRST_SEEN    DATETIME             NOT NULL,                \
        LAST_SEEN     DATETIME             NOT NULL,                \
        PRIMARY KEY (ID),                                           \
        UNIQUE KEY MARQ (IP,VLAN,PROTO,SERVICE,META),               \
        KEY ip_idx (IP),                                            \
        KEY service_idx (SERVICE),                                  \
        KEY meta_idx (META)                                         \
        )                                                           \
      ";
      $sth = $dbh->prepare($sql);
      $sth->execute;
      $sth->finish;
   };
   if ($@) {
      # Failed
      return 1;
   }
   return 0;
}

=head2 checkif_table_exist

 Checks if a table exists. Takes $tablename as input and
 returns 1 if $tablename exists, and 0 if not.

=cut

sub checkif_table_exist {
    my $tablename = shift;
    my ($sql, $sth);
    eval {
       $sql = "select count(*) from $TABLE_NAME where 1=0";
       $dbh->do($sql);
    };
    if ($dbh->err) {
       warn "[W] Table $TABLE_NAME does not exist.\n" if $DEBUG;
       return 0;
    }
    else{
       return 1;
    }
}

=head2 game_over

 Terminates the program in a sainfull way.

=cut

sub game_over {
    warn "[*] Terminating...\n";
    $dbh->disconnect;
    unlink ($PIDFILE);
    exit 0;
}

=head1 AUTHOR

 Edward Fjellskaal <edwardfjellskaal@gmail.com>

=head1 COPYRIGHT

 This library is free software, you can redistribute it and/or modify
 it under the terms of GPL; either version 2 of the License, or
 (at your option) any later version.

=cut
