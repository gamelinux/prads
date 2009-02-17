#!/usr/bin/perl -w

use strict;
use warnings;

use Getopt::Long qw/:config auto_version auto_help/;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::ARP;
use NetPacket::ICMP;
use NetPacket::TCP;
use NetPacket::UDP;

=head1 NAME

prads.pl - inspired by passive.sourceforge.net and http://lcamtuf.coredump.cx/p0f.shtml

=head1 VERSION

0.1

=head1 SYNOPSIS

 $ prads.pl [options]

 OPTIONS:

 --dev|-d       : network device (default: eth0)
 --signature|-s : path to signature file (default: signatures.txt)
 --debug        : enable debug messages (default: disabled)
 --help         : this help message
 --version      : show prads.pl version

=cut

our $VERSION       = 0.1;
our $DEBUG         = 0;
my $DEVICE         = q(eth0);
my $SIGNATURE_FILE = q(signatures.txt);
my %ERROR          = (
    init_dev => q(Unable to determine network device for monitoring - %s),
    lookup_net => q(Unable to look up device information for %s - %s),
    create_object => q(Unable to create packet capture on device %s - %s),
    compile_object => q(Unable to compile packet capture filter),
    compile_object => q(Unable to set packet capture filter),
    loop => q(Unable to perform packet capture),
);

GetOptions(
    'dev|d=s'       => \$DEVICE,
    'signature|s=s' => \$SIGNATURE_FILE,
    'debug'         => \$DEBUG,
    # bpf filter
);

warn "Starting prads.pl...\n";

warn "Initializing device\n" if $DEBUG;
$DEVICE = init_dev($DEVICE)
          or Getopt::Long::HelpMessage();

warn "Loading signatures\n" if $DEBUG;
my @SIGNATURES = load_signatures($SIGNATURE_FILE)
                 or Getopt::Long::HelpMessage();

warn "Creating object\n" if $DEBUG;
my $PCAP = create_object($DEVICE);

warn "Compiling Berkeley Packet Filter\n" if $DEBUG;
filter_object($PCAP);

warn "Looping over object\n" if $DEBUG;
Net::Pcap::loop($PCAP, -1, \&syn_packets, '') or die $ERROR{'loop'};

warn "Closing device\n" if $DEBUG;
Net::Pcap::close($PCAP);

exit;

=head1 FUNCTIONS

=head2 syn_packets

Callback function for C<Net::Pcap::loop>.

 * Strip ethernet encapsulation of captured packet 
 * Decode contents of TCP/IP packet contained within captured ethernet packet
 * Search through the signatures, print dst host, dst port, and ID String.
 * Collect pOSf data : ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks
   # Fingerprint entry format:
   #
   # wwww:ttt:D:ss:OOO...:QQ:OS:Details
   #
   # wwww     - window size (can be * or %nnn or Sxx or Txx)
   #            "Snn" (multiple of MSS) and "Tnn" (multiple of MTU) are allowed.
   # ttt      - initial TTL 
   # D        - don't fragment bit (0 - not set, 1 - set)
   # ss       - overall SYN packet size (* has a special meaning)
   # OOO      - option value and order specification (see below)
   # QQ       - quirks list (see below)
   # OS       - OS genre (Linux, Solaris, Windows)
   # details  - OS description (2.0.27 on x86, etc)

=cut

### Should rename top packets etc.
sub syn_packets {
    my ($user_data, $header, $packet) = @_;

    warn "Packet received - processing...\n" if($DEBUG);
#Check if arp - get mac and register...
    my $ethernet = NetPacket::Ethernet::strip($packet);
    my $eth      = NetPacket::Ethernet->decode($packet);

    unless(NetPacket::IP->decode($ethernet)) {
        warn "Not an IP packet..\n" if($DEBUG);
        warn "Done...\n\n" if($DEBUG);
        return;
    }

    my $ip       = NetPacket::IP->decode($ethernet);
#    my $tcp      = NetPacket::TCP->decode($ip->{'data'});
#    my $udp      = NetPacket::UDP->decode($ip->{'data'});

    #### Should check ifdef $ip, $tcp, $udp... then do...

    # OS finger printing
    # Collect necessary info from IP packet; if
    my $ttl    = $ip->{'ttl'};
    my $ipflags  = $ip->{'flags'}; # 2=dont fragment/1=more fragments, 0=nothing set
    my $ipopts   = $ip->{'options'}; # Not used in p0f

#    my $tstamp = $ip->{'hmm implement'}; # or get it from $tcp options

    # Check if this is a TCP packet
    if($ip->{proto} == 6) {
      warn "Packet is of type TCP...\n" if($DEBUG);
      # Collect necessary info from TCP packet; if
      my $tcp      = NetPacket::TCP->decode($ip->{'data'});
      my $winsize = $tcp->{'winsize'}; #
      my $tcpflags= $tcp->{'flags'};
      my $tcpopts = $tcp->{'options'}; # binary crap 'CEUAPRSF' 
      my $hex = unpack("H*", pack ("B*", $tcpopts));

      # Check if SYN is set and not ACK (Indicates an initial connection)
      if ($tcp->{'flags'} & SYN && $tcp->{'flags'} | ACK ) { 
        warn "Initial connection... Detecting OS...\n" if($DEBUG);
        my $fragment;
        if($ipflags == 2){
          $fragment=1; # Dont fragment
        }else{
          $fragment=0; # Fragment or more fragments
        }
      ##### THIS IS WHERE THE PASSIVE OS FINGERPRINTING MAGIC SHOULD BE
      warn "OS: ip:$ip->{'src_ip'} ttl=$ttl, DF=$fragment, ipflags=$ipflags, winsize=$winsize, tcpflags=$tcpflags, tcpoptsinhex=$hex\n" if($DEBUG);

      # Bogus/weak test, PoC - REWRITE
      # LINUX/*NIX
      if((64 >= $ttl) && ($ttl > 32)) {
         if ($fragment == 1) {
            if((5840 >= $winsize) && ($winsize >= 5488)) {
               print "OS Fingerprint: $ip->{'src_ip'}:$tcp->{'src_port'} - Linux 2.6 \n";
               print "                $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
            }else{
               print "OS Fingerprint: $ip->{'src_ip'}:$tcp->{'src_port'} - UNNKOWN / Linux ? \n";
               print "                $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
            }
         }elsif ($fragment == 0) {
               print "OS Fingerprint: $ip->{'src_ip'}:$tcp->{'src_port'} - UNNKOWN / Fragment / *NIX ? \n";
               print "                $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
         }
      # WINDOWS
      }elsif ((128 >= $ttl) && ($ttl > 64)) {
        if ($fragment == 1) {
           if((65535 >= $winsize ) && ($winsize >= 60000)) {
               print "OS Fingerprint: $ip->{'src_ip'}:$tcp->{'src_port'} - Windows 2000/2003/XP \n";
               print "                $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
            }else{
               print "OS Fingerprint: $ip->{'src_ip'}:$tcp->{'src_port'} - UNNKOWN / Windows ? \n";
               print "                $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
            }
         }elsif ($fragment == 0) {
               print "OS Fingerprint: $ip->{'src_ip'}:$tcp->{'src_port'} - UNNKOWN / Fragment / *Windows ? \n";
               print "                $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
         }
       # Others
       }else{
               print "OS Fingerprint: $ip->{'src_ip'}:$tcp->{'src_port'} - UNNKOWN / UNKNOWN \n";
               print "                $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
       }
 
    }else{
      warn "Not an initial connection... Skipping OS detection\n" if($DEBUG);
    }
#    # Skip further check for services
#    unless($tcp->{'data'} or $udp->{'data'}) {
    unless($tcp->{'data'}) {
        warn "No TCP data - Skipping asset detection\n" if($DEBUG);
        warn "Done...\n\n" if($DEBUG);
        return;
    }

#    # Check content(data) against signatures
    SIGNATURE:
    for my $s (@SIGNATURES) {
        my $re = $s->[2];
#
        if($tcp->{'data'} =~ /$re/) {
            my($vendor, $version, $info) = split m"/", eval $s->[1];
            printf("(%s) %s:%i -> (%s) %s:%i -> %s %s %s\n",
                $eth->{'src_mac'},  $ip->{'src_ip'},  $tcp->{'src_port'},
                $eth->{'dest_mac'}, $ip->{'dest_ip'}, $tcp->{'dest_port'},
                $vendor  || q(),
                $version || q(),
                $info    || q()
            );
            last SIGNATURE;
        }
    }
    }elsif ($ip->{proto} == 17) {
       warn "Packet is of type UDP...\n" if($DEBUG);
       my $udp      = NetPacket::UDP->decode($ip->{'data'});
       unless($udp->{'data'}) {
          warn "No UDP data - Skipping asset detection\n" if($DEBUG);
          warn "Done...\n\n" if($DEBUG);
          return;
       }
       # Make UDP asset detection here...
       warn "Detectin UDP asset...\n" if($DEBUG);
       warn "UDP ASSET DETECTION IS NOT IMPLEMENTED YET...\n" if($DEBUG);
    }
warn "Done...\n\n" if($DEBUG);
return;
}

=head2 check_tcp_options

Takes tcp options as input, and returns which args are set.

 Input format:
 $tcpoptions

 Output format.
 @tcpopts

=cut

sub check_tcp_options{
    my $opts = shift;
    my %options;
    return;
}


=head2 load_signatures

Loads signatures from file

 File format:
 <service>,<version info>,<signature>

 Example:
 www,v/Apache/$1/$2/,Server: Apache\/([\S]+)[\s]+([\S]+)

=cut

sub load_signatures {
    my $file = shift;
    my %signatures;

    open(my $FH, "<", $file) or die "Could not open '$file': $!";

    LINE:
    while (my $line = readline $FH) {
        chomp $line;
        $line =~ s/\#.*//;
        next LINE unless($line); # empty line
        my($service, $version, $signature) = split /,/, $line, 3;

        $version =~ s"^v/"";

        $signatures{$signature} = [$service, qq("$version"), qr{$signature}];
    }

    return map { $signatures{$_} }
            sort { length $b <=> length $a }
             keys %signatures;
}

=head2 init_dev

Use network device passed in program arguments or if no 
argument is passed, determine an appropriate network 
device for packet sniffing using the 
Net::Pcap::lookupdev method

=cut

sub init_dev {
    my $dev = shift;
#    my $err;

#    unless (defined $dev) {
#       #$dev = Net::Pcap::lookupdev(\$err);
#        die sprintf $ERROR{'init_dev'}, $err if defined $err;
#    }

    return $dev;
}

=head2 lookup_net

Look up network address information about network 
device using Net::Pcap::lookupnet - This also acts as a 
check on bogus network device arguments that may be 
passed to the program as an argument

=cut

sub lookup_net {
    my $dev = shift;
    my($err, $address, $netmask);

    Net::Pcap::lookupnet(
        $dev, \$address, \$netmask, \$err
    ) and die sprintf $ERROR{'lookup_net'}, $dev, $err;

    warn "lookup_net : $address, $netmask\n" if($DEBUG);
    return $address, $netmask;
}

=head2 create_object

Create packet capture object on device

=cut

sub create_object {
    my $dev = shift;
    my($err, $object);
    my $promisc = 1;    

    $object = Net::Pcap::open_live($dev, 1500, $promisc, 0, \$err)
              or die sprintf $ERROR{'create_object'}, $dev, $err;
    warn "create_object : $dev\n" if($DEBUG);
    return $object;
}

=head2 compile_object

Compile and set packet filter for packet capture 
object - For the capture of TCP packets with the SYN 
header flag set directed at the external interface of 
the local host, the packet filter of '(dst IP) && (tcp
[13] & 2 != 0)' is used where IP is the IP address of 
the external interface of the machine. Here we use 'tcp'
as a default BPF filter.

=cut

sub filter_object {
    my $object = shift;
    my($address, $netmask) = lookup_net($DEVICE);
    my $filter;
#    my $BPF = q(tcp and src net 192.168.0.0 mask 255.255.255.0);
#    my $BPF = q(ip and src net 87.238.45.0/24);
    my $BPF = q();

    Net::Pcap::compile(
        $object, \$filter, $BPF, 0, $netmask
    ) and die $ERROR{'compile_object_compile'};

    Net::Pcap::setfilter($object, $filter)
        and die $ERROR{'compile_object_setfilter'};
    warn "filter_object : $address, $netmask, $filter\n" if($DEBUG);
}

=head1 AUTHOR

Edward Fjellskål

Jan Henning Thorsen

=head1 COPYRIGHT

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
