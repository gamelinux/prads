#!/usr/bin/perl
# ---------------------------------------------------------------------
# prads-asset-report.pl
#
# Edward Fjellskål <edward@redpill-linpro.com>
#
# This script will generate a formatted report based on the data
# produced by Passive Real-time Asset Detection System (PRADS).
#
# Copyright (C) 2004 Matt Shelton <matt@mattshelton.com>
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
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
my $version	= '0.2';
my $date	= '2010-04-14';

# ---------------------------------------------------------------------
#use strict;
#use warnings;
print_header();
eval("use Getopt::Long"); die "[!] ERROR:  Getopt::Long module must be installed!\n" if $@;
eval("use Socket"); die "[!] ERROR:  Socket module must be insalled!\n" if $@;
use vars qw ($opt_h $opt_r $opt_w $opt_n $opt_p);

# Variable Declarations
my $report_file		= "/var/log/prads-asset.log";

# Data Structure:
# %asset_storage = (
#	<IP Address> => {
#		ARP      => [ $mac, $discovered, $vendor ],
#		ICMP     => ICMP,
#		TCP      => [ $port, $service, $app, $discovered ]
#			},
#	}
# )
my %asset_storage	= ();

# Parse Command Line
GetOptions(
    'r=s'   => \$opt_r,
    'w=s'   => \$opt_w,
    'n'     => \$opt_n,
    'p'     => \$opt_p,
    'i=s'   => \$opt_i,
    'h|?'   => \$opt_h,
    'help'  => \$opt_h
);
usage() if $opt_h;
$report_file = $opt_r if ($opt_r);

# --------------------------------------------
# MAIN
# --------------------------------------------

# Open Report File
open (REPORT, "<$report_file") or die "[!] ERROR:  Unable to open $report_file - $!\n";

# Read in Report File
while (<REPORT>) {
    chomp;
    next if (/^asset,vlan,port,proto/);

    R_REPORT: {
        # asset,vlan,port,proto,service,[service-info],distance,discovered
        /^([\w\.:]+),([\d]{1,4}),([\d]{1,5}),([\d]{1,3}),(\S+?),\[(.*)\],([\d]{1,3}),(\d{10})/ && do {
        ($sip, $vlan, $sport, $proto, $service, $s_info, $distance, $discovered) = ($1, $2, $3, $4, $5, $6, $7, $8);

        if ($opt_i) {
            next if not $opt_i eq $sip;
        }
        $asset=$_;
        $os = $details = "";

        if ( $service =~ /SYN/ ) {
            # 65535:128:1:48:M1460,N,N,S:.:Windows:2000 SP4, XP SP1+
            #if ($s_info =~ /.*:.*:.*:.*:.*:.*:(.*):(.*):.*:.*:.*:.*hrs/) {
            if ($s_info =~ /:[\d]{2,4}:\d:.*:.*:.*:(\w+):(.*):link/) {
                $os = $1;
                $details = $2;
                #print "$os - $details\n";
            }
        } elsif ( $service =~ /SERVER/ || $service =~ /CLIENT/ ) {
            $s_info =~ s/^(\w+):(.*)$/$2/;
        }

        # Assign this line to the asset data structure.
        if ($service =~ /ARP/) {
    	    # ARP
    	    #if ($service =~ /ARP/) {
    	    #    $vendor = $1;
    	    #} else {
    	        $vendor = "unknown";
    	    #}
    	    push ( @{ $asset_storage{$sip}->{"ARP"} }, [ $s_info, $discovered, $vendor ]);
    
        } elsif ($proto == 1) {
    	    # ICMP
    	    $asset_storage{$sip}->{"ICMP"} = "ICMP";
    
        } elsif ($proto == 6) {
    	    # TCP
            if ( $service =~ /SERVER/ || $service =~ /CLIENT/ ) {
            	push (@{$asset_storage{$sip}{"TCP"}}, [ $sport, $service, $s_info, $discovered ]);
            } elsif ( $service =~ /SYN/ ) {
                push (@{$asset_storage{$sip}{"OS"}}, [ $service, $os, $details, $discovered ]);
            } 
        } elsif ($proto == 17) {
            # UDP
            if ( $service =~ /SERVER/ || $service =~ /CLIENT/ ) {
                push (@{$asset_storage{$sip}{"UDP"}}, [ $sport, $service, $s_info, $discovered ]);
            }
        }
        last R_REPORT;
        };
    }
}
# Close Report File
close (REPORT);

# Open output file if specified on the command line.
if ($opt_w) {
    open (STDOUT, ">$opt_w") or die "[!] ERROR:  $!\n";
}

# Print out this record.
my $asset;
my $id = 1;
foreach $asset (sort (keys (%asset_storage))) {
    my ($mac);
    my ($icmp);
    my (@sorted);
    my ($i);

    # Output Asset Header
    print "$id ------------------------------------------------------\n";
    print "IP:   $asset\n";

    # Output DNS Name
    unless ($opt_n) {
    	if ($opt_p) {
    	    # Check to see if this is a RFC 1918 address.
    	    unless (check_rfc1918($asset)) {
    		my ($peer_host) = gethostbyaddr(inet_aton($asset), AF_INET());
    		print "DNS:  $peer_host\n" if ($peer_host);
    	    }
    	} else {
    	    my ($peer_host) = gethostbyaddr(inet_aton($asset), AF_INET());
    	    print "DNS:  $peer_host\n" if ($peer_host);
    	}
    }

    my ($os,$desc,$confidence,$timestamp,$flux) = guess_asset_os($asset);
    print "OS:   $os $desc ($confidence%) $flux\n";
    # Output OS and details
    #$i = 0;
    #foreach $_ ( @ { $asset_storage{$asset}->{"OS"}}) {
    #    my ($date) = from_unixtime($_->[3]);
    #    printf("OS %-1s:   %-1s ", $_->[0], $_->[1]);
    #    if ($_->[2] ne "unknown") {
    #        printf("- %-18s", $_->[2]);
    #    } else {
    #        printf("                  ");
    #    }
    #    printf(" (%-19s)\n", $date);
    #    $i++;
    #}

    # Output MAC Addresses
    $i = 0;
    foreach $_ ( @ { $asset_storage{$asset}->{"ARP"}}) {
        if ($i == 0) {
            my ($date) = from_unixtime($_->[1]);
    	    printf("MAC(s):   %-18s (%-19s)\n", $_->[0], $date);
    	    printf("VENDOR:   %-18s\n", $_->[2]) if ($_->[2] ne "unknown");
    	    $i++;
    	} else {
    	    my ($date) = from_unixtime($_->[1]);
    	    printf("%-09s %-18s (%-19s)\n", "", $_->[0], $date);
    	    printf("%-09s %-18s\n", $_->[2]) if ($_->[2] ne "unknown");
    	}
    }

    # Output ICMP Status
    if ($asset_storage{$asset}->{"ICMP"}) {
        print "ICMP:     Enabled\n";
    }
    print "\n";

    # Output TCP Status
    if ($asset_storage{$asset}->{"TCP"}) {
    	printf("%-5s %-10s %-30s\n", "Port", "Service", "TCP-Application");
        @sorted = sort {$$a[0] <=> $$b[0]} @{$asset_storage{$asset}->{"TCP"}};
    
        foreach $_ (@sorted) {
            next if ($_->[3] < $timestamp);
	        printf("%-5d %-10s %-30s\n", $_->[0], $_->[1], $_->[2])
        }
        #if ($asset_storage{$asset}->{"TCP"}) {
	    print "\n";
    }

    # Output UDP Status
    if ($asset_storage{$asset}->{"UDP"}) {
        printf("%-5s %-10s %-30s\n", "Port", "Service", "UDP-Application");
        @sorted = sort {$$a[0] <=> $$b[0]} @{$asset_storage{$asset}->{"UDP"}};
    
    foreach $_ (@sorted) {
        next if ($_->[3] < $timestamp);
        printf("%-5d %-10s %-30s\n", $_->[0], $_->[1], $_->[2])
    }
    #if ($asset_storage{$asset}->{"UDP"}) {
        print "\n";
    }


    $id++;
}

# Close output file if specified on the command line.
if ($opt_w) {
    close (STDOUT);
}

sub check_last_os_switch {
    my $asset = shift;
    my $ctimestamp = 0;
    my $syn = 0;

    #foreach $OS (@ {$asset_storage{$asset}->{"OS"}}) {
    foreach $OS (sort { $a <=> $b } (@ {$asset_storage{$asset}->{"OS"}})) {
        if ($OS->[0] =~ /^SYN$/ ) {
            $syn += 1;
#print "S : $OS->[0] $OS->[1] $OS->[2] $OS->[3] $syn\n";
            $ctimestamp = $OS->[3] if ($OS->[3] > $ctimestamp);
        }
    }

    if ($syn == 0) {
        foreach $OS (sort { $a <=> $b } (@ {$asset_storage{$asset}->{"OS"}})) {
            if ($OS->[0] =~ /^SYNACK$/ ) {
                $syn += 1;
#print "SA: $OS->[0] $OS->[1] $OS->[2] $OS->[3]\n";
                $ctimestamp = $OS->[3] if ($OS->[3] > $ctimestamp);
            }
        }
    }
#print "R : $ctimestamp\n";
    push my @return, ($ctimestamp, $syn);
    return @return;
}

sub guess_asset_os {
    my $asset = shift;
    my ($OS, $DETAILS, $CONFIDENCE, $TS, $FLUX) = ("unknown", "unknown", 0, 0, 0);
    push my @prefiltered, ($OS, $DETAILS, $CONFIDENCE, $TS, $FLUX);
    my %countos;
    my %countdesc;

    # look for latest os switch...
    ($TS,$FLUX) = check_last_os_switch($asset);
#print "TS: $TS\n";
    # Lets look back the last 12 hours...
    # The OS might have sent a synack long before a syn
    # if thats what made the timestamp. And we also might
    # have missed some servies :)
    $TS = $TS - 43200; 

    foreach $OS (@ {$asset_storage{$asset}->{"OS"}}) {
        next if ($OS->[3] < $TS);
#print "OS: $OS->[0]\n";
        if ($OS->[0] =~ /^SYNACK$/ ) {
            $countos{ $OS->[1] }{"count"} += 4;
        } elsif ($OS->[0] =~ /^SYN$/ ) {
            $countos{$OS->[1]}{"count"} += 6;
        } elsif ($OS->[0] =~ /^ACK$/ || $OS->[0] =~ /^FIN$/ || $OS->[0] =~ /^RST$/ ) {
            $countos{$OS->[1]}{"count"} += 1;
        }
    }

    my ($os, $os1, $os2);
    my $int = 0;
    for my $os (sort { $countos{$a} <=> $countos{$b} } keys %countos) {
        next if ($os =~ /unknown/ );
        if ($int == 0) {
            $os1 = $os;
        } else {
            $os2 = $os;
            last;
        }
        $int +=1;
        #print "$countos{$os}{count}\t$os\n";
    }
    if (not defined $os1) {
        if (not defined $os2) {
            $OS = "unknown";
        } else {
            $OS = $os2;
        }
    } else {
        $OS = $os1;
    }

    push my @midfiltered, ("unknown", "unknown", 0, $TS, $FLUX);
    return @midfiltered unless $OS;
    return @midfiltered if ($OS =~ /unknown/);

    #if ( $countos{$os1}{count} > $countos{$os2}{count} ) {
    #    $OS = $os1;
    #} elsif ( $countos{$os1}{count} == $countos{$os2}{count} ) {
    #    # sort on last timestamp or something...
    #    # in the future
    #    $OS = $os1;
    #}

    foreach my $DESC (@ {$asset_storage{$asset}->{"OS"}}) {
        next if ($DESC->[3] < $TS);
        next if not $DESC->[1] =~ /$OS/;
        if ($DESC->[0] =~ /^SYN$/) {
            $DETAILS = $DESC->[2];
            last
        } elsif ($DESC->[0] =~ /^SYNACK$/) {
            $DETAILS = $DESC->[2];
        } else {
            $DETAILS = $DESC->[2];
        }
    }

    if (not defined $DETAILS) {
        foreach my $DESC (@ {$asset_storage{$asset}->{"OS"}}) {
            next if ($DESC->[3] < $TS);
            next if not $DESC->[1] =~ /$OS/;
            if ($DESC->[0] =~ /^RST$/) {
                $DETAILS = $DESC->[2];
                last
            } elsif ($DESC->[0] =~ /^ACK$/) {
                $DETAILS = $DESC->[2];
            } else {
                $DETAILS = $DESC->[2];
            }
        }
    }

    if ( not defined $OS ) {
        $DETAILS = "unknown";
        $CONFIDENCE = 0;
        $OS = "unknown";
    } else {
        $CONFIDENCE = 20 + (10 * $countos{$OS}{count});
        $CONFIDENCE = 100 if $CONFIDENCE > 100;
    }
    push my @postfiltered, ($OS, $DETAILS, $CONFIDENCE, $TS, $FLUX);
    return @postfiltered;
}


# --------------------------------------------
# FUNCTION	: from_unixtime
# DESCRIPTION	: This function will convert
#		: a unix timestamp into a
#		: normal date.
# INPUT		: 0 - UNIX timestamp
# RETURN	: 0 - Formatted Time
# --------------------------------------------
sub from_unixtime {
    my ($unixtime) = $_[0];
    my ($time);

    my ($sec, $min, $hour, $dmon, $mon, $year,
	$wday, $yday, $isdst) = localtime($unixtime);
    $time = sprintf("%04d/%02d/%02d %02d:%02d:%02d",
	$year + 1900, $mon + 1, $dmon, $hour, $min, $sec);

    return $time;
}

# --------------------------------------------
# FUNCTION	: check_rfc1918
# DESCRIPTION	: This function will check to
#		: see if a address is a RFC
#		: 1918 address.
# INPUT		: 0 - IP Address
# RETURN	: 1 - Yes
# --------------------------------------------
sub check_rfc1918 {
    my ($ip) = $_[0];

    return 1 if (check_ip($ip, "10.0.0.0/8"));
    return 1 if (check_ip($ip, "172.16.0.0/12"));
    return 1 if (check_ip($ip, "192.168.0.0/16"));
    return 0;
}

# --------------------------------------------
# FUNCTION	: check_ip
# DESCRIPTION	: This function will check to
#		: see if a address falls
#		: within a network CIDR block.
# INPUT		: 0 - IP Address
#		: 1 - CIDR Network
# RETURN	: 1 - Yes
# --------------------------------------------
sub check_ip {
    my ($i)	= $_[0];
    my ($n)	= $_[1];

    return ($i eq $n) unless $n =~ /^(.*)\/(.*)$/;
    return (((unpack('N',pack('C4',split(/\./,$i))) ^ unpack('N',pack('C4'
			,split(/\./,$1)))) & (0xFFFFFFFF << (32 - $2))) == 0);
}
# --------------------------------------------
# FUNCTION	: usage
# --------------------------------------------
sub usage {
    print <<__EOT__;
 Usage:
  -r <file>   : PRADS Raw Report File
  -w <file>   : Output file
  -i <IP>     : Just get info for this IP
  -n          : Do not convert IP addresses to names.
  -p          : Do not convert RFC 1918 IP addresses to names.

__EOT__
    exit;
}

# --------------------------------------------
# FUNCTION	: print_header
# --------------------------------------------
sub print_header {
    print <<__EOT__;
\n prads-asset-report - PRADS Text Reporting Module
 $version - $date
 Edward Fjellskaal <edward\@redpill-linpro.com>
 http://prads.projects.linpro.no/

__EOT__
}
