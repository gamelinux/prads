#!/usr/bin/perl -w

# This file is a part of PRADS.
#
# Copyright (C) 2010, Edward Fjellskål <edwardfjellskaal@gmail.com>
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
#

use strict;
use warnings;

use Getopt::Long qw(:config no_ignore_case bundling);
use XML::Writer;
use IO::File;
use Switch;

=head1 NAME

prads2snort.pl - Some one needs to populate the host_attribute.xml file!

=head1 VERSION

0.1

=head1 SYNOPSIS

 $ prads2snort.pl [options]

 OPTIONS:

 -i|--infile     : file to feed prads2snort.pl
 -o|--outfile    : file to write host_attribute data to (host_attribute.xml)
 -h|--help       : this help message
 --version       : show prads2snort.pl version

=cut

our $VERSION                = 0.01;
our $DEBUG                  = 0;
our $FORCE                  = 0;
our $assetcnt               = 0;
our $INFILE                 = qq(/tmp/prads-asset.log);
our $OUTFILE                = qq(hosts_attribute.xml);
our %ASSETDB;

Getopt::Long::GetOptions(
    'infile|i=s'            => \$INFILE,
    'outfile|o=s'           => \$OUTFILE,
    'force|f'               => \$FORCE,
    'version'               => \$VERSION,
);

print_header();
parse_asset_file();
make_attribute_table();
print_footer();
exit 0;

################################################################################
############# F - U - N - C - T - I - O - N - S - ##############################
################################################################################

=head1 FUNCTIONS

=head2 parse_asset_file

 Opens the asset file, parses it, and stor info in a hash

=cut

sub parse_asset_file {
    # Open prads asset file
    open (ASSETFILE, "<$INFILE") or die "[!] ERROR: Unable to open file: $INFILE - $!\n";

    while (<ASSETFILE>) {
        chomp;
        next if (/^asset,vlan,port,proto/ || /^#/);
    
        R_REPORT: {
            # asset,vlan,port,proto,service,[service-info],distance,discovered
            /^([\d\.:]+),([\d]{1,4}),([\d]{1,5}),([\d]{1,3}),(\S+?),\[(.*)\],([\d]{1,3}),(\d{10})/ && do {
            my ($sip, $vlan, $sport, $proto, $service, $s_info, $distance, $discovered) = ($1, $2, $3, $4, $5, $6, $7, $8);
    
            my $asset=$_;
            my $os = my $details = my $services = "unknown";
    
            if ( $service =~ /SYN/ || $service =~ /^ACK$/ || $service =~ /^RST$/ || $service =~ /^FIN$/ ) {
                if ($s_info =~ /:[\d]{2,4}:\d:.*:.*:.*:(\w+):(.*):link/) {
                    $os = $1;
                    $details = $2;
                    print "SYN(+ACK):$os - $details\n" if $DEBUG;
                } elsif ($s_info =~ /:[\d]{2,4}:\d:.*:.*:.*:(\w+):(.*):uptime/) {
                    $os = $1;
                    $details = $2;
                    print "RST/ACK/FIN:$os - $details\n" if $DEBUG;
                } else {
                    switch ($s_info) {
                        case /:Linux:/ {
                            $os = "Linux";
                            $s_info =~ /:Linux:(.*):?/;
                            $details = $1 if defined $1;
                        }
                        case /:Windows:/ {
                            $os = "Windows";
                            $s_info =~ /:Windows:(.*):?/;
                            $details = $1 if defined $1;
                        }
                        case /:\w+BSD:/ {
                            $s_info =~ /:(\w+BSD):(.*):?/;
                            $os = $1 if defined $1;
                            $details = $2 if defined $2;
                        }
                        case /:MacOS:/ {
                            $os = "MacOS";
                            $s_info =~ /:MacOS:(.*):?/;
                            $details = $1 if defined $1;
                        }
                    }
                print "FALLBACK: $s_info\n" if $DEBUG;
                print "FALLBACK: $os - $details\n" if $DEBUG;
                }
            } elsif ( $service =~ /SERVER/ || $service =~ /CLIENT/ ) {
                $s_info =~ s/^(\w+):(.*)$/$2/;
                $services = $1;
            }
            # Assign this line to the asset data structure.
            if ($proto == 6) {
                # TCP
                if ( $service =~ /SERVER/ ) {
                    push (@{$ASSETDB{$sip}{"TCPSER"}}, [ $sport, $service, $services, $s_info, $discovered ]);
                } elsif ($service =~ /CLIENT/ ) {
                    push (@{$ASSETDB{$sip}{"TCPCLI"}}, [ $sport, $service, $services, $s_info, $discovered ]);
                } elsif ( $service =~ /SYN/ || $service =~ /^ACK$/ || $service =~ /^RST$/ || $service =~ /^FIN$/ ) {
                    push (@{$ASSETDB{$sip}{"OS"}}, [ $service, $os, $details, $discovered ]);
                }
            } elsif ($proto == 17) {
                # UDP
                if ( $service =~ /SERVER/ ) {
                    push (@{$ASSETDB{$sip}{"UDPSER"}}, [ $sport, $service, $services, $s_info, $discovered ]);
                } elsif ($service =~ /CLIENT/ ) {
                    push (@{$ASSETDB{$sip}{"UDPCLI"}}, [ $sport, $service, $services, $s_info, $discovered ]);
                }
            }
            last R_REPORT;
            };
        }
    }
    close (ASSETFILE);
}

=head2 make_attribute_table

 Makes a snort host_attribute xml table of the assets

=cut

sub make_attribute_table {
    my $asset;
    my ($xmlout, $putxml, $feed, $confidence);

    if (-e $OUTFILE && $FORCE == 0) {
        print "[*] File Exists! Use -f|--force to force writing...\n";
        print "[*] Exiting!\n";
        exit 1;
    }

    $xmlout = new IO::File($OUTFILE, O_WRONLY | O_TRUNC |O_CREAT) or
                die "[!] ERROR: Cannot open output file for writing  - $!\n";
    $putxml = new XML::Writer(OUTPUT => $xmlout, NEWLINES => 0, DATA_MODE => 1, DATA_INDENT => 1, UNSAFE => 1);
    $putxml->startTag('SNORT_ATTRIBUTES');
    $putxml->startTag('ATTRIBUTE_MAP');
        $putxml->startTag('ENTRY');
            $putxml->startTag('ID');
                $putxml->characters("31337");
            $putxml->endTag('ID');
            $putxml->startTag('VALUE');
                $putxml->characters("Edward Fjellskaal");
            $putxml->endTag('VALUE');
        $putxml->endTag('ENTRY');
    $putxml->endTag('ATTRIBUTE_MAP');

    $putxml->startTag('ATTRIBUTE_TABLE');

    foreach $asset (sort (keys (%ASSETDB))) {
        $assetcnt++;
        my ($os,$desc,$confidence) = guess_asset_os($asset);
        my $details = normalize_description($os, $desc);
        my ($frag3, $stream5) = get_policy($os, $desc);
        if ($os =~ /unknown/) {
            print "Unknown OS for $asset - Applying frag3=$frag3 and stream5=$stream5\n";
            #next;
        }
        $putxml->startTag('HOST');
            $putxml->startTag('IP');
                $putxml->characters("$asset");
            $putxml->endTag('IP');
            $putxml->startTag('OPERATING_SYSTEM');
                $putxml->startTag('NAME');
                    $putxml->startTag('ATTRIBUTE_VALUE');
                        $putxml->characters("$os");
                    $putxml->endTag('ATTRIBUTE_VALUE');
                    $putxml->startTag('CONFIDENCE');
                        $putxml->characters("$confidence");
                    $putxml->endTag('CONFIDENCE');
                $putxml->endTag('NAME');
                $putxml->startTag('VENDOR');
                    $putxml->startTag('ATTRIBUTE_VALUE');
                        $putxml->characters("$os");
                    $putxml->endTag('ATTRIBUTE_VALUE');
                    $putxml->startTag('CONFIDENCE');
                        $putxml->characters("$confidence");
                    $putxml->endTag('CONFIDENCE');
                $putxml->endTag('VENDOR');
                $putxml->startTag('VERSION');
                    $putxml->startTag('ATTRIBUTE_VALUE');
                        $putxml->characters("$details");
                    $putxml->endTag('ATTRIBUTE_VALUE');
                    $putxml->startTag('CONFIDENCE');
                        $putxml->characters("$confidence");
                    $putxml->endTag('CONFIDENCE');
                $putxml->endTag('VERSION');
                $putxml->startTag('FRAG_POLICY');
                    $putxml->characters("$frag3");
                $putxml->endTag('FRAG_POLICY');
                $putxml->startTag('STREAM_POLICY');
                    $putxml->characters("$stream5");
                $putxml->endTag('STREAM_POLICY');
            $putxml->endTag('OPERATING_SYSTEM');

            if ($ASSETDB{$asset}->{"TCPSER"} || $ASSETDB{$asset}->{"UDPSER"}) {
                $putxml->startTag('SERVICES');
                if ($ASSETDB{$asset}->{"TCPSER"}) {
                    make_service_attributes($asset, "tcp", "TCPSER", $putxml);
                }
                if ($ASSETDB{$asset}->{"UDPSER"}) {
                    make_service_attributes($asset, "udp", "UDPSER", $putxml);
                }
                $putxml->endTag('SERVICES');
            }
            # Commented out for now !
            #if ($ASSETDB{$asset}->{"TCPCLI"} || $ASSETDB{$asset}->{"UDPCLI"}) {
            #    $putxml->startTag('CLIENTS');
            #    if ($ASSETDB{$asset}->{"TCPCLI"}) {
            #        make_client_attributes($asset, "tcp", "TCPCLI", $putxml);
            #    }
            #    if ($ASSETDB{$asset}->{"UDPCLI"}) {
            #        make_client_attributes($asset, "udp", "UDPCLI", $putxml);
            #    }
            #    $putxml->endTag('CLIENTS');
            #}
        $putxml->endTag('HOST');
    }

    # End it all
    $putxml->endTag('ATTRIBUTE_TABLE');
    $putxml->endTag('SNORT_ATTRIBUTES');
    $putxml->end();
    $xmlout->close();
}

=head get_policy

 Gets the frag3 and stream5 policy

=cut

sub get_policy {
    my ($OS, $DESC) = @_;
    my ($frag3, $stream5) = ("BSD", "bsd");
    switch ($OS){
        case /Cisco/ {$frag3 = "Last"; $stream5 = "last";}
        case /IOS/ {$frag3 = "Last"; $stream5 = "last";}
        case /JetDirect/ {$frag3 = "BSD-right"; $stream5 = "bsd";}
        case /HPUX/ {
            switch ($DESC){
                case /10/ {$frag3 = "BSD"; $stream5 = "hpux10";}
                case /11/ {$frag3 = "First"; $stream5 = "hpux";} 
                else {$frag3 = "First"; $stream5 = "hpux";}
            }
        }
        case /IRIX/ {$frag3 = "BSD"; $stream5 = "irix";}
        case /Linux/ {
            switch ($DESC){
                case /2.2/ {$frag3 = "linux"; $stream5 = "old-linux";}
                case /2.0/ {$frag3 = "linux"; $stream5 = "old-linux";}
                else {$frag3 = "linux"; $stream5 = "linux";}
            }
        }
        case /MacOS/ {$frag3 = "First"; $stream5 = "macos";}
        case /^SunOS/ {$frag3 = "First"; $stream5 = "first";}
        case /Solaris/ {$frag3 = "Solaris"; $stream5 = "solaris";}
        case /Windows/ {
            switch ($DESC){
                case /200[3,8]/ {$frag3 = "Windows"; $stream5 = "win2003";}
                case /Vista/ {$frag3 = "Windows"; $stream5 = "vista";}
                else {$frag3 = "Windows"; $stream5 = "windows";}
            }   
        }
        #else {$frag3 = "BSD"; $stream5 = "bsd";}
    }
    push my @policy, ($frag3, $stream5, 90);
    return @policy;
}

=head2 normalize_description

 Normalized the description to something more snort lookalike

=cut

sub normalize_description {
    my ($OS, $DESC) = @_;
    switch ($OS) {
        case /Linux/ {
            switch ($DESC) {
                case /2\.6/ { return "2.6"; }
                case /2\.4/ { return "2.4"; }
                case /2\.2/ { return "2.2"; }
                case /2\.0/ { return "2.0"; }
                else { return $DESC; }
            }
        }
        case /Windows/ {
            switch ($DESC) {
                case /XP/ { return "XP"; }
                case /2003/ { return "Windows 2003"; }
                case /2008/ { return "Windows 2008"; }
                case /Vista/ { return "Vista"; }
                else { return $DESC; }
            }
        }
        else { return $DESC; }
    }
}

=head2 guess_asset_os

 Tries to guess the asset OS in an inteligent way..
 Snort OSes off importance:
  bsd, old-linux, linux, first, last, windows, solaris,
  win2003/win2k3, vista, hpux/hpux11, hpux10, irix, macos
 Prads OSes:
  
=cut

sub guess_asset_os {
    my $asset = shift;
    my ($OS, $DETAILS, $CONFIDENCE) = ("unknown", "unknown", 0);
    push my @prefiltered, ($OS, $DETAILS, $CONFIDENCE);
    my %countos;
    my %countdesc;

    foreach $OS (@ {$ASSETDB{$asset}->{"OS"}}) {
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
    
    return @prefiltered unless $OS;
    return @prefiltered if ($OS =~ /unknown/);

    #if ( $countos{$os1}{count} > $countos{$os2}{count} ) {
    #    $OS = $os1;
    #} elsif ( $countos{$os1}{count} == $countos{$os2}{count} ) {
    #    # sort on last timestamp or something...
    #    # in the future
    #    $OS = $os1;
    #}

    foreach my $DESC (@ {$ASSETDB{$asset}->{"OS"}}) {
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
        print "arrgggg\n";
        foreach my $DESC (@ {$ASSETDB{$asset}->{"OS"}}) {
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
    push my @filtered, ($OS, $DETAILS, $CONFIDENCE);
    return @filtered;
}

=head2 make_service_attributes

 Populates all server attributes

=cut

sub make_service_attributes {
    my ($asset, $proto, $key, $putxml) = @_;
    my @sorted = sort {$$a[0] <=> $$b[0]} @{$ASSETDB{$asset}->{"$key"}};
    #$proto =~ tr/A-Z/a-z/;
    my $confidence = 90;
    foreach $_ (@sorted) {
        my ($port, $service, $services, $details, $discovered) = ($_->[0], $_->[1], $_->[2], $_->[3], $_->[4]);
        if ($service =~ /SERVER/) {
            next if $services =~ /unknown/;
            next if $services =~ /@/;
            my ($serv, $vers) = get_server_and_version($details);
            $putxml->startTag('SERVICE');
                $putxml->startTag('PORT');
                    $putxml->startTag('ATTRIBUTE_VALUE');
                        $putxml->characters("$port"); # 22/80/443...
                    $putxml->endTag('ATTRIBUTE_VALUE');
                    $putxml->startTag('CONFIDENCE');
                        $putxml->characters("$confidence");
                    $putxml->endTag('CONFIDENCE');
                $putxml->endTag('PORT');
                $putxml->startTag('IPPROTO');
                    $putxml->startTag('ATTRIBUTE_VALUE');
                        $putxml->characters("$proto"); # tcp/udp/icmp...
                    $putxml->endTag('ATTRIBUTE_VALUE');
                    $putxml->startTag('CONFIDENCE');
                        $putxml->characters("$confidence");
                    $putxml->endTag('CONFIDENCE');
                $putxml->endTag('IPPROTO');
                $putxml->startTag('PROTOCOL');
                    $putxml->startTag('ATTRIBUTE_VALUE');
                        $putxml->characters("$services"); # http/ssh/smtp/ssl...
                    $putxml->endTag('ATTRIBUTE_VALUE');
                    $putxml->startTag('CONFIDENCE');
                        $putxml->characters("$confidence");
                    $putxml->endTag('CONFIDENCE');
                $putxml->endTag('PROTOCOL');
                $putxml->startTag('APPLICATION');
                    $putxml->startTag('ATTRIBUTE_VALUE');
                        $putxml->characters("$serv");
                    $putxml->endTag('ATTRIBUTE_VALUE');
                    $putxml->startTag('VERSION');
                        $putxml->startTag('ATTRIBUTE_VALUE');
                            $putxml->characters("$vers");
                        $putxml->endTag('ATTRIBUTE_VALUE');
                        $putxml->startTag('CONFIDENCE');
                            $putxml->characters("$confidence");
                        $putxml->endTag('CONFIDENCE');
                    $putxml->endTag('VERSION');
                $putxml->endTag('APPLICATION');
            $putxml->endTag('SERVICE'); 
        }
    }
}

=head2 make_client_attributes

 Populates all client attributes for an asset

=cut

sub make_client_attributes {
    my ($asset, $proto, $key, $putxml) = @_;
    my @sorted = sort {$$a[0] <=> $$b[0]} @{$ASSETDB{$asset}->{"$key"}};
    #$proto =~ tr/A-Z/a-z/;
    my $confidence = 90;
    foreach $_ (@sorted) {
        my ($port, $service, $services, $details, $discovered) = ($_->[0], $_->[1], $_->[2], $_->[3], $_->[4]);
        if ($service =~ /CLIENT/) {
            next if $services =~ /unknown/;
            next if $services =~ /^@/;
            $details =~ s/^(\w+)\d?(.*)/$2/;
            my $client = $2;
            $putxml->startTag('CLIENT');
                $putxml->startTag('PROTOCOL');
                    $putxml->startTag('ATTRIBUTE_VALUE');
                        $putxml->characters("$services"); # tcp/udp/
                    $putxml->endTag('ATTRIBUTE_VALUE');
                $putxml->endTag('PROTOCOL');
                $putxml->startTag('APPLICATION');
                    $putxml->startTag('ATTRIBUTE_VALUE');
                        $putxml->characters("$client"); # MS IE/Mozilla FX/..
                    $putxml->endTag('ATTRIBUTE_VALUE');
                    $putxml->startTag('VERSION');
                        $putxml->startTag('ATTRIBUTE_VALUE');
                            $putxml->characters("$details"); # 5.0/8.0/3.3
                        $putxml->endTag('ATTRIBUTE_VALUE');
                    $putxml->endTag('VERSION');
                $putxml->endTag('APPLICATION');
            $putxml->endTag('CLIENT');
        }
    }
}

=head2 get_server_and_version

 Tries to extract server and version from "details"

=cut

sub get_server_and_version {
    my $details = shift;
    my ($serv, $vers) = ("test","1234");
    
    switch ($details) {
        case /Apache/ {
            $serv = "Apache";
            if ($details =~ /([.\d]+)/) {
                $vers = $1;
                
            } else {
                $vers = "unknown";
            }
        }
        case /Microsoft-IIS/ {
            $serv = "Microsoft-IIS";
            if ($details =~ /([.\d]+)/) {
                $vers = $1;
            } else {
                $vers = "unknown";
            }
        }
        case /^Server/ {
            $details =~ /Server: (.*)/;
            $serv = $1;
            if ($details =~ /([.\d]+)/) {
                $vers = $1;
            } else {
                $vers = "unknown";
            }
        }
        case /Generic TLS 1\.0 SSL/ {
            $serv = "SSL";
            $vers = "TLS 1.0";
        }
        case /SSH/ {
            $details =~ /(\w*[Ss]{2}[Hh]{1}\w*)/;
            $serv = $1;
            if ($details =~ /([.\d]+)/) {
                $vers = $1;
            } else {
                $vers = "unknown";
            }
        }
        case /Zope/ {
            $serv = "Zope";
            if ($details =~ /([.\d]+).*/) {
                $vers = $1;
            } else {
                $vers = "unknown";
            }            
        }
        #case // {
        #}
        #case // {
        #}

        else {
            $vers =~ s/^(\w+)[\ :](.*)/$2/;
            my $serv = $1;
            if ($vers =~ /([.\d]+).*/) {
                $vers = $1;
            }
        }
    }
    push my @matches, ($serv, $vers);
    return @matches;
}

=head2 print_header

 Some info to go on top...

=cut

sub print_header {
    print "\n[*] Made by Edward Fjellskaal <edwardfjellskaal\@gmail.com> (c) 2010\n";
    print "[*] Reading PRADS log file: $INFILE\n";
    print "[*] Writing to snort attribute file: $OUTFILE\n\n";
}

=head2 print_footer

 Some info to go on bottom...

=cut

sub print_footer {
    print "\n[*] Processed $assetcnt hosts...\n";
    print "[*] Done...\n";
}

