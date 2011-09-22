#!/usr/bin/perl -w

use strict;
use warnings;
use POSIX qw(setsid);
use DateTime;
use Getopt::Long qw/:config auto_version auto_help/;
use DBI;

=head1 NAME

prads2db.pl - Load prads assets into mysql db

=head1 VERSION

0.1

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
our $TIMEOUT       = 5;
our $HOSTNAME      = q(aruba);
my  $PFILE         = "/var/log/prads-asset.log";
my  $LOGFILE       = q(/var/log/prads2db.log);
my  $PIDFILE       = q(/var/run/prads2db.pid);
my  $STATEFILE     = q(/var/lib/prads/prads2db-state.log);
my  $pos           = undef;
my  $assets        = 0;
our $DB_NAME       = "pradsdb";
our $DB_HOST       = "127.0.0.1";
our $DB_PORT       = "3306";
our $DB_USERNAME   = "prads";
our $DB_PASSWORD   = "pradspw";
our $DBI           = "DBI:mysql:$DB_NAME:$DB_HOST:$DB_PORT";
our $AUTOCOMMIT    = 0;
my  $ASSET         = {};

GetOptions(
   'file=s'        => \$PFILE,
   'debug=s'       => \$DEBUG,
   'daemon'        => \$DAEMON,
);

# Signal handlers
use vars qw(%sources);
#$SIG{"HUP"}   = \&recreate_merge_table;
#$SIG{"INT"}   = sub { game_over() };
#$SIG{"TERM"}  = sub { game_over() };
#$SIG{"QUIT"}  = sub { game_over() };
#$SIG{"KILL"}  = sub { game_over() };
#$SIG{"ALRM"}  = sub { dir_watch(); alarm $TIMEOUT; };

warn "[*] Starting prads2db.pl...\n";

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

warn "[*] Connecting to database...\n";
#my $dbh = DBI->connect($DBI,$DB_USERNAME,$DB_PASSWORD, {RaiseError => 1}) or die "$DBI::errstr";

# Check to see if we have all we need in th DB
check_db();

# Start tail_file() which tails the asset file and inserts asssets to db
warn "[*] Looking for asset data in: $PFILE \n" if $DEBUG;
tail_file($PFILE,$STATEFILE);
exit;

sub check_db {
   return;
}

sub tail_file {
   my ($TFILE, $STATEF) = @_;

   #infinite loop
   while (1) {
      my ($pos, $assets) = get_state($STATEF);
      my $startsize = (stat $TFILE)[7];
      $pos = $startsize if (not defined $pos || $startsize < $pos);
      $assets += parseLogfile($TFILE, $pos, $startsize); 
      $pos = $startsize;
      save_state($pos,$assets,$STATEF);
      sleep $TIMEOUT;
   }
   return;
}

sub get_state {
   my $statefile = shift;
   my $pos = 0;
   my $assets = 0;

   if (-f "$statefile") {
      open (IN, "$statefile") or die("Can't open $statefile !");;
      if (<IN> =~ /^(\d+):(\d+)/) {
         ($pos, $assets) = ($1, $2);
      }
      close IN;
   }
   return ($pos, $assets);
}

sub save_state {
   my ($pos, $assets, $statefile) = @_;

   if(-l $statefile) {
      die("$statefile is a symbolic link, refusing to touch it.");
   }
   open (OUT, ">$statefile") or die("Can't write to $statefile !");
   print OUT "$pos:$assets\n";
   close OUT;
}

sub parseLogfile {
    my ($fname, $start, $stop) = @_;
    my $assets = 0;

    open (LOGFILE, $fname) or exit 3;
    seek (LOGFILE, $start, 0) or exit 2;

    while (tell (LOGFILE) < $stop) {
       my $line =<LOGFILE>;
       chomp ($line);
       next if ( not defined $line || $line =~ /^asset,vlan,port,proto/);

       if ($line =~ /^([\w\.:]+),([\d]{1,4}),([\d]{1,5}),([\d]{1,3}),(\S+?),\[(.*)\],([\d]{1,3}),(\d{10})/) {
          my ($sip, $vlan, $sport, $proto, $service, $s_info, $distance, $discovered) = ($1, $2, $3, $4, $5, $6, $7, $8);
          insert_to_db($sip, $vlan, $sport, $proto, $service, $s_info, $distance, $discovered);
          $assets++;
       }
    }
    close(LOGFILE);
    return $assets;
}

sub insert_to_db {
   my ($sip, $vlan, $sport, $proto, $service, $s_info, $distance, $discovered) = @_;
   print "$sip, $vlan, $sport, $proto, $service, $s_info, $distance, $discovered\n";
}


