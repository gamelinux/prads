#!/usr/bin/perl -w

use strict;
use warnings;
use FindBin;
use Getopt::Long qw/:config auto_version auto_help/;
use Net::Pcap;
use Data::Dumper;

use constant ETH_TYPE_ARP       => 0x0806;

BEGIN {

    # list of NetPacket:: modules
    my @modules = map { "NetPacket::$_" } qw/Ethernet IP ARP ICMP TCP UDP/;
    my $bundle  = 0;

    MODULE:
    for my $module (@modules) {

        # try to use installed version first
        eval "use $module";
        next MODULE unless($@);

        if($ENV{'DEBUG'}) {
            warn "$module is not installed. Using bundled version instead\n";
        }

        # use bundled version instead
        local @INC = ("$FindBin::Bin/../lib");
        eval "use $module";
        die $@ if($@);
        $bundle++;
    }

    if($ENV{'DEBUG'} and $bundle) {
        warn "Run this command to install missing modules:\n";
        warn "\$ perl -MCPAN -e'install NetPacket'\n";
    }
}

=head1 NAME

prads.pl - inspired by passive.sourceforge.net and http://lcamtuf.coredump.cx/p0f.shtml

=head1 VERSION

0.1

=head1 SYNOPSIS

 $ prads.pl [options]

 OPTIONS:

 --dev|-d                : network device (default: eth0)
 --service-signatures|-s : path to service-signatures file (default: /etc/prads/service.sig)
 --os-fingerprints|-o    : path to os-fingerprints file (default: /etc/prads/os.fp
 --debug                 : enable debug messages (default: disabled)
 --dump                  : Dumps all signatures and fingerprints then exits 
 --help                  : this help message
 --version               : show prads.pl version

=cut

our $VERSION       = 0.1;
our $DEBUG         = 0;
our $DUMP          = 0;
my $DEVICE         = q(eth0);
my $S_SIGNATURE_FILE        = q(/etc/prads/service.sig);
my $OS_SYN_FINGERPRINT_FILE = q(/etc/prads/os.fp);
my %pradshosts     = ();
my %ERROR          = (
    init_dev => q(Unable to determine network device for monitoring - %s),
    lookup_net => q(Unable to look up device information for %s - %s),
    create_object => q(Unable to create packet capture on device %s - %s),
    compile_object => q(Unable to compile packet capture filter),
    compile_object => q(Unable to set packet capture filter),
    loop => q(Unable to perform packet capture),
);

GetOptions(
    'dev|d=s'                => \$DEVICE,
    'service-signatures|s=s' => \$S_SIGNATURE_FILE,
    'os-fingerprints|o=s'    => \$OS_SYN_FINGERPRINT_FILE,
    'debug'                  => \$DEBUG,
    'dump'                   => \$DUMP,
    # bpf filter
);


if ($DUMP) {
   warn "\n ##### Dumps all signatures and fingerprints then exits ##### \n";

   warn "\n *** Loading OS fingerprints *** \n\n";
   my $OS_SYN_SIGS = load_os_syn_fingerprints($OS_SYN_FINGERPRINT_FILE);
   print Dumper $OS_SYN_SIGS;
#  print int keys @OS_SYN_SIGS;            # Would like to see the total sig count
 
   warn "\n *** Loading Service signatures *** \n\n";
   my @SERVICE_SIGNATURES = load_signatures($S_SIGNATURE_FILE);
   print Dumper @SERVICE_SIGNATURES; 
#  print int keys @SERVICE_SIGNATURES; # Would like to see the total serv-sig count

   exit 0;
}

warn "Starting prads.pl...\n";

warn "Loading OS fingerprints\n" if $DEBUG;
my $OS_SYN_SIGS = load_os_syn_fingerprints($OS_SYN_FINGERPRINT_FILE)
              or Getopt::Long::HelpMessage();

warn "Initializing device\n" if $DEBUG;
$DEVICE = init_dev($DEVICE)
          or Getopt::Long::HelpMessage();

warn "Loading Service signatures\n" if $DEBUG;
my @SERVICE_SIGNATURES = load_signatures($S_SIGNATURE_FILE)
                 or Getopt::Long::HelpMessage();

warn "Creating object\n" if $DEBUG;
my $PCAP = create_object($DEVICE);

warn "Compiling Berkeley Packet Filter\n" if $DEBUG;
filter_object($PCAP);

warn "Looping over object\n" if $DEBUG;
Net::Pcap::loop($PCAP, -1, \&packets, '') or die $ERROR{'loop'};

warn "Closing device\n" if $DEBUG;
Net::Pcap::close($PCAP);

exit;

=head1 FUNCTIONS

=head2 packets

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

# NetPacket::IP->decode gives us binary opts
# so get the interesting bits here
sub parse_opts {
    my ($opts) = @_;
    my ($scale, $mss, $sackok, $ts);
    print "opts: ". unpack("B*", $opts)."\n" if $DEBUG; 
    my ($kind, $rest, $size, $data, $count);
    while ($opts){
      ($kind, $rest) = unpack("C a*", $opts);
      $count++;
      if($kind == 0){
        # EOL
        last;
      }elsif($kind == 1){
        # NOP
        $opts = $rest;
      }else{
        ($size, $rest) = unpack "C a*", $rest;
        #print "$kind # $size\n";
        $size = $size - 2;
        print "rest: ". unpack("B*", $rest)."\n" if $DEBUG; 
        #($data, $rest) = unpack "C${size}a", $rest;
        if($kind == 2){
          ($mss, $rest) = unpack "S a*", $rest;
          print "MSS : $mss\n" if $DEBUG;
        }elsif($kind == 3){
          ($scale, $rest) = unpack "C3 a*", $rest;
          print "WSOPT: $scale\n" if $DEBUG;
        }elsif($kind == 4){
          # hey. ballsacks are OK.
          $sackok++;
        }elsif($kind == 8){
          # Timestamp.
          ($ts, $rest) = unpack "C$size a*", $rest;
        }else{
          # don't care
          ($data, $rest) = unpack "C$size a*", $rest;
        }
      }
      $opts = $rest;
      last if undef $opts;
    }
    return ($count, $scale, $mss, $sackok, $ts);
}
### Should rename top packets etc.
sub packets {
    my ($user_data, $header, $packet) = @_;
    warn "Packet received - processing...\n" if($DEBUG);

    my $ethernet = NetPacket::Ethernet::strip($packet);
    my $eth      = NetPacket::Ethernet->decode($packet);

    # Check if arp - get mac and register...
    if ($eth->{type} == ETH_TYPE_ARP) {
        my $arp = NetPacket::ARP->decode($eth->{data}, $eth);
        my $aip = $arp->{spa}; 
        my $h1 = hex(substr( $aip,0,2));
        my $h2 = hex(substr( $aip,2,2));
        my $h3 = hex(substr( $aip,4,2));
        my $h4 = hex(substr( $aip,6,2));
        my $host = "$h1.$h2.$h3.$h4";

        $pradshosts{"tstamp"} = time;
        print("ARP: mac=$arp->{sha} ip=$host timestamp=" . $pradshosts{"tstamp"} . "\n");
        return;
    }

    unless(NetPacket::IP->decode($ethernet)) {
        warn "Not an IP packet..\n" if($DEBUG);
        warn "Done...\n\n" if($DEBUG);
        return;
    }

    # We should now have us an IP packet... good!
    my $ip       = NetPacket::IP->decode($ethernet);
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
      my $seq     = $tcp->{'seqnum'};
      my $ack     = $tcp->{'acknum'};
      my ($optcnt, $scale, $mss, $sackok, $ts) = parse_opts($tcpopts);

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
        # port of p0f matching code
        my $sigs = $OS_SYN_SIGS; 
        # TX => WIN = (MSS+40 * X)
        # p0f matches by packet size, option count, quirks and don't fragment (ip->off & 0x4000 != 0
        # WindowSize : InitialTTL : DontFragmentBit : Overall Syn Packet Size : Ordered Options Values : Quirks : OS : Details
        # + option object count

        # OK, so this code is b0rked and I just took a look at the p0f implementation.
        my @wmatches = grep { 
          # SX => WIN = MSS * X
          /S(\d\d)/ and $1*$mss == $winsize or
          /T(\d\d)/ and $1*($mss+40) == $winsize or
          $_ eq $winsize;
        } keys %$sigs;
        my @tmatches = grep {
          $sigs->{$_}->{$ttl}
        } @wmatches;
        print Dumper @wmatches;


#    OS_SYN_SIGNATURE:
#    for my $s (@OS_SYN_SIGS) {
#        #print Dumper $s;
#        my $s_winsize = $s[1];
#        print "$s_winsize\n";
#        exit 0;
#        if($tcp->{'data'} =~ /$re/) {
#      last OS_SYN_SIGNATURE;  
#}

      # Bogus/weak test, PoC - REWRITE this to use @OS_SYN_SIGNATURE
      # LINUX/*NIX
      if((5840 >= $winsize) && ($winsize >= 5488)) {
         if ($fragment == 1) {
            if((64 >= $ttl) && ($ttl > 32)) {
               print "OS: $ip->{'src_ip'} - \"Linux 2.6\" (ttl: $ttl, winsize:$winsize, DF=$fragment)\n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
            }else{
               print "OS Fingerprint: $ip->{'src_ip'} - \"UNNKOWN / Linux ?\" (ttl: $ttl, winsize:$winsize, DF=$fragment)\n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
            }
         }elsif ($fragment == 0) {
               print "OS: $ip->{'src_ip'} - \"UNNKOWN / Fragment / *NIX ?\" \n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
         }
      # WINDOWS
      }elsif ((65535 >= $winsize ) && ($winsize >= 60000)) {
        if ($fragment == 1) {
           if ((128 >= $ttl) && ($ttl > 64)) {
               print "OS: $ip->{'src_ip'} - \"Windows 2000/2003/XP\" (ttl: $ttl, winsize:$winsize, DF=$fragment)\n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
            }elsif (60352 == $winsize) {
               print "OS: $ip->{'src_ip'} - \"Windows 98\" (ttl: $ttl, winsize:$winsize, DF=$fragment)\n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
            }else{
               print "OS: $ip->{'src_ip'} - \"UNNKOWN / Windows ?\" (ttl: $ttl, winsize:$winsize, DF=$fragment)\n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
            }
         
         }elsif ($fragment == 0) {
               print "OS Fingerprint: $ip->{'src_ip'} - \"UNNKOWN / Fragment / *Windows ?\" (ttl: $ttl, winsize:$winsize, DF=$fragment)\n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
         }
      # WINDOWS 2K ZA
      }elsif (16384 == $winsize ) {
        if ($fragment == 1) {
          if ((128 >= $ttl) && ($ttl > 64)) {
               print "OS: $ip->{'src_ip'} - \"Windows 2000 w/ZoneAlarm?\" (ttl: $ttl, winsize:$winsize, DF=$fragment)\n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
          }
        }
      # Windows 2000 SP4 or XP SP2
      }elsif (53760 == $winsize ) {
        if ($fragment == 1) {
          if ((64 >= $ttl) && ($ttl > 32)) {
               print "OS: $ip->{'src_ip'} - \"Windows 2000 SP4 or XP SP2\" (ttl: $ttl, winsize:$winsize, DF=$fragment)\n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
          }
        }

       # Others
       }else{
               print "OS: $ip->{'src_ip'} - \"UNNKOWN / UNKNOWN\" (ttl: $ttl, winsize:$winsize, DF=$fragment)\n";
#               print "                   $ip->{'dest_ip'}:$tcp->{'dest_port'} - (ttl: $ttl, winsize:$winsize, DF=$fragment) \n";
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

    # Check content(data) against signatures
    SIGNATURE:
    for my $s (@SERVICE_SIGNATURES) {
        my $re = $s->[2];

        if($tcp->{'data'} =~ /$re/) {
            my($vendor, $version, $info) = split m"/", eval $s->[1];
#            printf("(%s) %s:%i -> (%s) %s:%i -> %s %s %s\n",
            printf("Service: ip=%s port=%i -> \"%s %s %s\"\n",
#                $eth->{'src_mac'},  $ip->{'src_ip'},  $tcp->{'src_port'},
                $ip->{'src_ip'},  $tcp->{'src_port'},
#                $eth->{'dest_mac'}, $ip->{'dest_ip'}, $tcp->{'dest_port'},
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
       warn "Detecting UDP asset...\n" if($DEBUG);
       if ($udp->{src_port} == 53){
        printf ("Service: ip=%s port=%i protocol=%i -> \"Bind9.x\"\n",$ip->{'src_ip'}, $udp->{'src_port'}, $ip->{'proto'});
       }
       elsif ($udp->{src_port} == 1194){
        printf ("Service: ip=%s port=%i protocol=%i -> \"Openvpn 2.x\"\n",$ip->{'src_ip'}, $udp->{'src_port'}, $ip->{'proto'});
       }
       else {
        warn "UDP ASSET DETECTION IS NOT IMPLEMENTED YET...\n" if($DEBUG);
       }
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
	# One should check for a more or less sane signature file.
        my($service, $version, $signature) = split /,/, $line, 3;

        $version =~ s"^v/"";

        $signatures{$signature} = [$service, qq("$version"), qr{$signature}];
    }

    return map { $signatures{$_} }
            sort { length $b <=> length $a }
             keys %signatures;
}

=head2 load_os_syn_fingerprints

Loads SYN signatures from file

=cut

sub load_os_syn_fingerprints {
  my $file = shift;
# Fingerprint entry format:
# WindowSize : InitialTTL : DontFragmentBit : Overall Syn Packet Size : Ordered Options Values : Quirks : OS : Details
  my $re   = qr{^ ([0-9%*()ST]+) : (\d+) : (\d+) : ([0-9()*]+) : ([^:]+) : ([^\s]+) : ([^:]+) : ([^:]+) }x;
  my $rules = {};

  open(my $FH, "<", $file) or die "Could not open '$file': $!";

LINE:
  while (my $line = readline $FH) {
    chomp $line;
    $line =~ s/\#.*//;
    next LINE unless($line); # empty line

    my @elements = $line =~ $re;

    unless(@elements == 8) {
      die "Error: Not valid fingerprint format in: '$file'";
    }

    my($details, $human) = splice @elements, -2;
    my $tmp = $rules;

    for my $e (@elements) {
      $tmp->{$e} ||= {};
      $tmp = $tmp->{$e};
    }

    $tmp->{$details} = $human;
  }
  return $rules;
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