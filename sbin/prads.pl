#!/usr/bin/perl -w

use strict;
use warnings;
use FindBin;
use Getopt::Long qw/:config auto_version auto_help/;
use Net::Pcap;
use Data::Dumper;

use constant ETH_TYPE_ARP       => 0x0806;
use constant ARP_OPCODE_REPLY   => 2;

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
 --service-signatures|-s : path to service-signatures file (default: /etc/prads/tcp-service.sig)
 --os-fingerprints|-o    : path to os-fingerprints file (default: /etc/prads/os.fp
 --debug                 : enable debug messages 0-255 (default: disabled(0))
 --dump                  : Dumps all signatures and fingerprints then exits 
 --arp                   : Enables ARP discover check (Default off)
 --help                  : this help message
 --version               : show prads.pl version

=cut

our $VERSION       = 0.1;
our $DEBUG         = 0;
our $DUMP          = 0;
our $ARP           = 0;
our $SERVICE       = 0;
our $OS            = 0;
my $DEVICE         = q(eth0);
my $CONFIG         = q(/etc/prads/prads.conf);
my $S_SIGNATURE_FILE        = q(/etc/prads/tcp-service.sig);
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
    'config|c=s'             => \$CONFIG,
    'dev|d=s'                => \$DEVICE,
    'service-signatures|s=s' => \$S_SIGNATURE_FILE,
    'os-fingerprints|o=s'    => \$OS_SYN_FINGERPRINT_FILE,
    'debug=s'                => \$DEBUG,
    'dump'                   => \$DUMP,
    'arp'                    => \$ARP,
    'service'                => \$SERVICE,
    'os'                     => \$OS,
    # bpf filter
);

my $conf = load_config("$CONFIG");
#my @array = split(/\s+/, $conf->{array-param});
#my $variable = $conf->{variable};
#$OS       = $conf->{os_synack_fingerprint};
#$DEVICE   = $conf->{interface};
#$ARP      = $conf->{arp};
#$DEBUG    = $conf->{debug};

if ($DUMP) {
   print "\n ##### Dumps all signatures and fingerprints then exits ##### \n";

   print "\n *** Loading OS fingerprints *** \n\n";
   my $OS_SYN_SIGS = load_os_syn_fingerprints($OS_SYN_FINGERPRINT_FILE);
   print Dumper $OS_SYN_SIGS;

   print "\n *** Loading Service signatures *** \n\n";
   my @TCP_SERVICE_SIGNATURES = load_signatures($S_SIGNATURE_FILE);
   print Dumper @TCP_SERVICE_SIGNATURES; 

   print "\n *** Loading MTU signatures *** \n\n";
   my $MTU_SIGNATURES = load_mtu("/etc/prads/mtu.sig");
   print Dumper $MTU_SIGNATURES;

   exit 0;
}

warn "Starting prads.pl...\n";
print "Using $DEVICE\n";

warn "Loading OS fingerprints\n" if ($DEBUG>0);
my $OS_SYN_SIGS = load_os_syn_fingerprints($OS_SYN_FINGERPRINT_FILE)
              or Getopt::Long::HelpMessage();
my $OS_SYN_DB = {};

warn "Loading MTU fingerprints\n" if ($DEBUG>0);
my $MTU_SIGNATURES = load_mtu("/etc/prads/mtu.sig")
              or Getopt::Long::HelpMessage();

warn "Initializing device\n" if ($DEBUG>0);
$DEVICE = init_dev($DEVICE)
          or Getopt::Long::HelpMessage();

warn "Loading TCP Service signatures\n" if ($DEBUG>0);
my @TCP_SERVICE_SIGNATURES = load_signatures($S_SIGNATURE_FILE)
                 or Getopt::Long::HelpMessage();

warn "Loading UDP Service signatures\n" if ($DEBUG>0);
# Currently loading the wrong sig file :)
my @UDP_SERVICE_SIGNATURES = load_signatures($S_SIGNATURE_FILE)
                 or Getopt::Long::HelpMessage();

warn "Creating object\n" if ($DEBUG>0);
my $PCAP = create_object($DEVICE);

warn "Compiling Berkeley Packet Filter\n" if ($DEBUG>0);
filter_object($PCAP);

warn "Looping over object\n" if ($DEBUG>0);
Net::Pcap::loop($PCAP, -1, \&packets, '') or die $ERROR{'loop'};

warn "Closing device\n" if ($DEBUG>0);
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

sub packets {
    my ($user_data, $header, $packet) = @_;
    $pradshosts{"tstamp"} = time;
    warn "Packet received - processing...\n" if($DEBUG>50);

    #setup the storage hash.. could also let adding to DB be caller's job
    my $db = $OS_SYN_DB;
    my $ethernet = NetPacket::Ethernet::strip($packet);
    my $eth      = NetPacket::Ethernet->decode($packet);

    # Check if arp - get mac and register...
    if ($ARP == 1 && $eth->{type} == ETH_TYPE_ARP) {
        arp_check ($eth, $pradshosts{"tstamp"});
        return;
    }

    unless(NetPacket::IP->decode($ethernet)) {
        warn "Not an IP packet..\n" if($DEBUG>50);
        warn "Done...\n\n" if($DEBUG>50);
        return;
    }

    # We should now have us an IP packet... good!
    my $ip       = NetPacket::IP->decode($ethernet);

    # OS finger printing
    # Collect necessary info from IP packet; if
    my $ttl      = $ip->{'ttl'};
    my $ipopts   = $ip->{'options'}; # Not used in p0f
    my $len      = $ip->{'len'};     # total length of packet
    my $id       = $ip->{'id'};

    my $ipflags  = $ip->{'flags'};   # 2=dont fragment/1=more fragments, 0=nothing set
    my $df;
    if($ipflags == 2){
        $df = 1; # Dont fragment
    }else{
        $df = 0; # Fragment or more fragments
    }

    # Check if this is a TCP packet
    if($ip->{proto} == 6) {
      warn "Packet is of type TCP...\n" if($DEBUG>50);
      # Collect necessary info from TCP packet; if
      my $tcp      = NetPacket::TCP->decode($ip->{'data'});
      my $winsize = $tcp->{'winsize'}; #
      my $tcpflags= $tcp->{'flags'};
      my $tcpopts = $tcp->{'options'}; # binary crap 'CEUAPRSF' 
      my $seq     = $tcp->{'seqnum'};
      my $ack     = $tcp->{'acknum'};
      my $urg     = $tcp->{'urg'};
      my $data    = $tcp->{'data'};
      my $reserved= $tcp->{'reserved'};
      # Check if SYN is set and not ACK (Indicates an initial connection)
      if ($OS == 1 && ($tcpflags & SYN and ~$tcpflags & ACK)) { 
        warn "Initial connection... Detecting OS...\n" if($DEBUG>20);
        my ($optcnt, $scale, $mss, $sackok, $ts, $optstr, @quirks) = check_tcp_options($tcpopts);
        # MSS may be undefined
        $mss = '*' if not $mss;
        my $tot = ($len < 100)? $len : 0;
        my $t0 = (not defined $ts or $ts != 0)? 0:1;

        # parse rest of quirks
        push @quirks, check_quirks($id,$ipopts,$urg,$reserved,$ack,$tcpflags,$data);
        my $quirkstring = quirks_tostring(@quirks);

        my $src_ip = $ip->{'src_ip'};
        my $packet = "ip:$src_ip size=$len ttl=$ttl, DF=$df, ipflags=$ipflags, winsize=$winsize, tcpflags=$tcpflags, OC:$optcnt, WSC:$scale, MSS:$mss, SO:$sackok,T0:$t0, Q:$quirkstring O: $optstr ($seq/$ack) tstamp=" . $pradshosts{"tstamp"};
        print "OS: $packet\n" if($DEBUG);

        # We need to guess initial TTL
        my $gttl = normalize_ttl($ttl);
        my $dist = $gttl - $ttl;
        # Get link type
        my $link = get_mtu_link($mss);

        # do the actual work
        my $wss = $winsize;
        if ($mss =~ /^[+-]?\d+$/) {
            if (not $winsize % $mss){
                $wss = $winsize / $mss;
                $wss = "S$wss";
            }elsif(not $winsize % ($mss +40)){
                $wss = $winsize / ($mss + 40);
                $wss = "T$wss";
            }
        }
        my $fpstring = "$wss:$gttl:$df:$tot:$optstr:$quirkstring";

        # TODO: make a list of previously matched OS'es (NAT ips) and
        # check on $db->{$ip}->{$fingerprint}
        my $prev_found = $db->{$src_ip};
        print "found ". Dumper($prev_found). "\n" if $prev_found and $DEBUG;
        if(not $prev_found){
            my ($os, $details, @more) = os_find_match(
                                                      $tot, $optcnt, $t0, $df,\@quirks, $mss, $scale,
                                                      $winsize, $gttl, $optstr, $packet);
            if(not $os){
                print "$fpstring:UNKNOWN:UNKNOWN\n";
                my $match = { 
                    'ip' => $ip,
                    'fingerprint' => $fpstring,
                    'os' => 'UNKNOWN', 
                    'details' => 'UNKNOWN',
                    'packet' => $ip
                };
                $db->{$src_ip} = $match;
            }else{
                my $skip = 0;
                if(grep /^[^@]/, ($os, @more)){
                    $skip = 1;
                }
                do{ 
                    if(not ($skip and $os =~ /^@/)){
                        print "OS: ip:$src_ip - $os - $details [$winsize:$gttl:$df:$tot:$optstr:$quirkstring] distance:$dist link:$link timestamp=" . $pradshosts{"tstamp"} ."\n";
                        my $match = { 
                            'ip' => $src_ip,
                            'fingerprint' => $fpstring,
                            'os' => $os, 
                            'details' => $details,
                            'packet' => $ip
                        };
                        $db->{$src_ip} = $match; # may be unneccessary by ref
                    }
                    ($os, $details, @more) = @more;
                }while($os);
            }
        }
      }

    ### SERVICE: DETECTION
    if ($tcp->{'data'} && $SERVICE == 1) {
       # Check content(TCP data) against signatures
       tcp_service_check ($tcp->{'data'},$ip->{'src_ip'},$tcp->{'src_port'},$pradshosts{"tstamp"});
    }

    }elsif ($ip->{proto} == 17) {
    # Can one do UDP OS detection !??!
       warn "Packet is of type UDP...\n" if($DEBUG>30);
       my $udp      = NetPacket::UDP->decode($ip->{'data'});
       if ($udp->{'data'} && $SERVICE == 1) {
          udp_service_check ($udp->{'data'},$ip->{'src_ip'},$udp->{'src_port'},$pradshosts{"tstamp"});
       }

    }


warn "Done...\n\n" if($DEBUG>50);
return;
}

=head2 match_opts

Function to match options

=cut

sub match_opts {
    my ($o1, $o2) = @_;
    my @o1 = split /,/,$o1;
    my @o2 = split /,/,$o2;
    for(@o1){
        #print "$_:$o2[0]\n";
        if(/([MW])([\d*]*)/){
            if(not $o2[0] =~ /$1($2|\*)/){
                return 0;
            }
        }elsif($_ ne $o2[0]){
            return 0;
        }
        shift @o2;
    }
    return @o2 == 0;
}

=port of p0f find_match()
# WindowSize : InitialTTL : DontFragmentBit : Overall Syn Packet Size : Ordered Options Values : Quirks : OS : Details

returns: ($os, $details, [...])
or undef on fail

for each signature in db:
  match packet size (0 means >= PACKET_BIG (=200))
  match tcp option count
  match zero timestamp
  match don't fragment bit (ip->off&0x4000!= 0)
  match quirks

  check MSS (mod or no)
  check WSCALE

  -- do complex windowsize checks
  -- match options
  -- fuzzy match ttls

  -- do NAT checks
  == dump unknow packet

  TODO:
    NAT checks, unknown packets, error handling, refactor
=cut

sub os_find_match{
# Port of p0f matching code
    my ($tot, $optcnt, $t0, $df, $qq, $mss, $scale, $winsize, $gttl, $optstr, $packet) = @_;
    my @quirks = @$qq;
    my $sigs = $OS_SYN_SIGS; 

    #warn "Matching $packet\n" if $DEBUG;
    #sigs ($ss,$oc,$t0,$df,$qq,$mss,$wsc,$wss,$oo,$ttl)
    my $matches = $sigs;
    my $j = 0;
    my @ec = ('packet size', 'option count', 'zero timestamp', 'don\'t fragment bit');
    for($tot, $optcnt, $t0, $df){
        if($matches->{$_}){
            $matches = $matches->{$_};
            #print "REDUCE: $j:$_: " . Dumper($matches). "\n";
            $j++;

        }else{
            warn "Packet has no match for $ec[$j]:$_\n";
            warn "ERR: $packet\n";
            return;
        }
    }
    # we should have $matches now.
    warn "ERR: $packet:\n  No match in fp db, but should have a match.\n" and return if not $matches;

    #print "INFO: p0f tot:oc:t0:frag match: " . Dumper($matches). "\n";
    if(not @quirks) {
        $matches = $matches->{'.'};
        warn "ERR: $packet:\n  No quirks match.\n" and return if not defined $matches;
    }else{
        my $i;
        for(keys %$matches){
            my @qq = split //;
            next if @qq != @quirks;
            $i = 0;
            for(@quirks){
                if(grep /^$_$/,@qq){
                    $i++;
                }else{
                    last;
                }
            }
            $matches = $matches->{$_} and last if $i == @quirks;
        }
        warn "ERR: $packet:\n  No quirks match\n" and return if not $i;
    }
    #print "INFO: p0f quirks match: " . Dumper( $matches). "\n";

    # Maximum Segment Size
    my @mssmatch = grep {
        (/^\%(\d)*$/ and ($mss % $_) == 0) or
            (/^(\d)*$/ and $mss eq $_) or
            ($_ eq '*')
    } keys %$matches;
    #print "INFO: p0f mss match: " . Dumper(@mssmatch). "\n";
    warn "ERR: $packet:\n  No mss match in fp db.\n" and return if not @mssmatch;

    # WSCALE. There may be multiple simultaneous matches to search beyond this point.
    my (@wmatch,@fuzmatch);
    for my $s (@mssmatch){
        for my $wsc ($scale, '*'){
            my $t = $matches->{$s}->{$wsc};
            next if not $t;

            # WINDOWSIZE
            for my $wss (keys %$t){
                #print "INFO: wss:$winsize,$_, " . Dumper($t->{$_}) ."\n";
                if( ($wss =~ /S(\d*)/ and $1*$mss == $winsize) or
                    ($wss =~ /M(\d*)/ and $1*($mss+40) == $winsize) or
                    ($wss =~ /%(\d*)/ and $winsize % $1 == 0) or
                    ($wss eq $winsize) or
                    ($wss eq '*')
                  ){
                    push @wmatch, $t->{$wss};
                }else{
                    push @fuzmatch, $t->{$wss};
                }
            }
        }
    }
    if(not @wmatch and @fuzmatch){
        warn "warning: $packet:\nNo exact window match. Proceeding fuzzily\n";
        @wmatch = @fuzmatch;
    }
    if(not @wmatch){
        warn "ERR: $packet:\n  No window match in fp db.\n";
        warn "Closest matches: \n";
        for my $s (@mssmatch){
            print Data::Dumper->Dump([$matches->{$s}],["MSS$s"]);
        }

        return;
    }
    #print "INFO: wmatch: " . Dumper(@wmatch) ."\n";

    # TCP option sequence
    my @omatch;
    for my $h (@wmatch){
        for(keys %$h){
            #print "INFO: omatch:$optstr:$_ " .Dumper($h->{$_}) ."\n";
            push @omatch, $h->{$_} and last if match_opts($optstr,$_);
        }
    }
    my @os;
    for(@omatch){
        my $match = $_->{$gttl};
        #print "INFO: omatch: " .Dumper($match) ."\n";
        if($match){
            for(keys %$match){
                push @os, ($_, $match->{$_});
            }
        }
    }
    if(not @os){
        warn "ERR: $packet:\n  No options match in fp db.\n";
        print "Closest matches: " . Dumper (@wmatch) ."\n";
        return;
    }
    if(@os > 2){
        warn "Multiple matches. Possible conflict in rules?:\n";
    }
    return @os;
}

=head2 check_quirks

# Parse most quirks.
# quirk P (opts past EOL) and T(non-zero 2nd timestamp) are implemented in
# check_tcp_options, where it makes most sense.
# TODO: '!' : broken opts (?)

=cut

sub check_quirks {
    my ($id,$ipopts,$urg,$reserved,$ack,$tcpflags,$data) = @_;
    my @quirks;

    push @quirks, 'Z' if not $id;
    push @quirks, 'I' if $ipopts;
    push @quirks, 'U' if $urg;
    push @quirks, 'X' if $reserved;
    push @quirks, 'A' if $ack;
    push @quirks, 'F' if $tcpflags & ~(SYN|ACK);
    push @quirks, 'D' if $data;
    return @quirks;
}

=head2 quirks_tostring
 Function to make quirks into a string.
=cut

sub quirks_tostring {
    my @quirks = @_;
    my $quirkstring = '';
    for(@quirks){
        $quirkstring .= $_;
    }
    $quirkstring = '.' if not @quirks;
    return $quirkstring;
}


=head2 check_tcp_options

Takes tcp options as input, and returns which args are set.

 Input format:
 $tcpoptions

 Output format.
 ($count, $scale, $mss, $sackok, $ts, $optstr, $quirks);

=cut

sub check_tcp_options{
    # NetPacket::IP->decode gives us binary opts
    # so get the interesting bits here
    my ($opts) = @_;
    my ($scale, $mss, $sackok, $ts, $t2) = (0,undef,0,undef,0);
    print "opts: ". unpack("B*", $opts)."\n" if $DEBUG & 8;
    my ($kind, $rest, $size, $data, $count) = (0,0,0,0,0);
    my $optstr = '';
    my @quirks;
    while ($opts){
        ($kind, $rest) = unpack("C a*", $opts);
        last if not $kind;
        $count++;
        if($kind == 0){
            print "EOL\n" if $DEBUG & 8;
            $optstr .= "E,";
            # quirk if opts past EOL
            push @quirks, 'P' if $rest ne '';
            #last;
        }elsif($kind == 1){
            # NOP
            print "NOP\n" if $DEBUG & 8;
            $optstr .= "N,";
        }else{
            ($size, $rest) = unpack("C a*", $rest);
            #print "$kind # $size\n";
            $size = $size - 2;
            #($data, $rest) = unpack "C${size}a", $rest;
            if($kind == 2){
                ($mss, $rest) = unpack("n a*", $rest);
                $optstr .= "M$mss,";
                print "$size MSS: $mss\n" if $DEBUG & 8;
            }elsif($kind == 3){
                ($scale, $rest) = unpack("C a*", $rest);
                $optstr .= "W$scale,";
                print "WSOPT$size: $scale\n" if $DEBUG & 8;
            }elsif($kind == 4){
                # allsacks are OK.
                $optstr .= "S,";
                print "SACKOK\n" if $DEBUG & 8;
                $sackok++;
            }elsif($kind == 8){
                # Timestamp.
                my ($c, $t, $tsize) = (0,0,$size);
                while($tsize > 0){
                    ($c, $rest) = unpack("C a*", $rest);
                    # hack HACK: ts is 64bit and wraps our 32bit perl ints.
                    # it's ok tho: we don't care what the value is, as long as it's not 0
                    $t <<= 1;
                    $t |= $c;
                    $tsize--;
                }
                print "TS$size: $t\n" if $DEBUG & 8;
                if($t){
                    $optstr .= "T,";
                }else{
                    $optstr .= "T0,";
                }
                if(defined $ts and $t){
                    # non-zero second timestamp
                    push @quirks, 'T';
                }else{
                    $ts = $t;
                }
            }else{
                # unrecognized
                $optstr .= "?$kind,";
                ($rest) = unpack("x$count a*", $rest);
                print "unknown $kind:$size:" if $DEBUG & 8;
            }
            print "rest: ". unpack("B*", $rest)."\n" if $DEBUG & 8;
        }
        $opts = $rest;
        last if not defined $opts;
    }
    chop $optstr;
    $optstr = '.' if $optstr eq '';
    return ($count, $scale, $mss, $sackok, $ts, $optstr, @quirks);
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

=head2 load_mtu

Loads MTU signatures from file

 File format:
 <MTU>,<info>

 Example:
 1492,"pppoe (DSL)"

=cut

sub load_mtu {
    my $file = shift;
    my $signatures = {};

    open(my $FH, "<", $file) or die "Could not open '$file': $!";

    LINE:
    while (my $line = readline $FH) {
        chomp $line;
        $line =~ s/\#.*//;
        next LINE unless($line); # empty line
        # One should check for a more or less sane signature file.
        my($mtu, $info) = split /,/, $line, 2;
        $signatures->{$mtu} = $info;
    }
    return $signatures;
}

=head2 load_os_syn_fingerprints

Loads SYN signatures from file
optimize for lookup matching

=cut

sub load_os_syn_fingerprints {
    my $file = shift;
    # Fingerprint entry format:
    # WindowSize : InitialTTL : DontFragmentBit : Overall Syn Packet Size : Ordered Options Values : Quirks : OS : Details
    #my $re   = qr{^ ([0-9%*()ST]+) : (\d+) : (\d+) : ([0-9()*]+) : ([^:]+) : ([^\s]+) : ([^:]+) : ([^:]+) }x;
    my $rules = {};

    open(my $FH, "<", $file) or die "Could not open '$file': $!";

    my $lineno = 0;
    while (my $line = readline $FH) {
        $lineno++;
        chomp $line;
        $line =~ s/\#.*//;
        next unless($line); # empty line

        #my @elements = $line =~ $re;
        my @elements = split/:/,$line;
        unless(@elements == 8) {
            die "Error: Not valid fingerprint format in: '$file'";
        }
        my ($wss,$ttl,$df,$ss,$oo,$qq,$os,$detail) = @elements;
        #print "GRRRR $wss, $ttl, $df, $ss, $oo, $qq, $os, $detail\n";
        my $oc = 0;
        my $t0 = 0;
        my ($mss, $wsc) = ('*','*');
        if($oo eq '.'){
            $oc = 0;
        }else{
            my @opt = split /[, ]/, $oo;
            $oc = scalar @opt;
            for(@opt){
                if(/([MW])([\d%*]*)/){
                    if($1 eq 'M'){
                        $mss = $2;
                    }else{
                        $wsc = $2;
                    }
                }elsif(/T0/){
                    $t0 = 1;
                }
            }
        }

        my($details, $human) = splice @elements, -2;

        my $tmp = $rules;
        #print "Floppa: /",join("/",@ary),"/\n" if $. eq 354;
        for my $e ($ss,$oc,$t0,$df,$qq,$mss,$wsc,$wss,$oo,$ttl){
            $tmp->{$e} ||= {};
            $tmp = $tmp->{$e};
        }
        if($tmp->{$details}){
            print "$file:$lineno:Conflicting signature: '$line' overwrites earlier signature '$details:$tmp->{$details}'\n\n" if ($DEBUG);
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
#    my $err;
#    my $netmask = '255.255.255.255';
#    my $address = '0.0.0.0';

    Net::Pcap::lookupnet(
        $dev, \$address, \$netmask, \$err
    ) and die sprintf $ERROR{'lookup_net'}, $dev, $err;

#   warn "lookup_net : $address, $netmask\n";
    warn "lookup_net : $address, $netmask\n" if($DEBUG>0);
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
    warn "create_object : $dev\n" if($DEBUG>0);
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
    warn "filter_object : $address, $netmask, $filter\n" if($DEBUG>0);
}

=head2 normalize_ttl

Takes a ttl value as input, and guesses intial ttl

=cut

sub normalize_ttl {
    my $ttl = shift;
    my $gttl;
    # Only aiming for 255,128,64,32. But some strange ttls like
    # 200,60,30 exist, but are rare.
    $gttl = 255 if (($ttl >   128) && (255  >= $ttl));
    $gttl = 128 if ((128  >= $ttl) && ($ttl >    64));
    $gttl =  64 if (( 64  >= $ttl) && ($ttl >    32));
    $gttl =  32 if (( 32  >= $ttl) && ($ttl >=    1));
    return $gttl;
}

=head2 tcp_service_check

Takes input: $tcp->{'data'}, $ip->{'src_ip'}, $tcp->{'src_port'}, $pradshosts{"tstamp"}
Prints out service if found.

=cut

sub tcp_service_check {
    my ($tcp_data, $src_ip, $src_port,$tstamp) = @_;

    # Check content(tcp_data) against signatures
    SIGNATURE:
    for my $s (@TCP_SERVICE_SIGNATURES) {
        my $re = $s->[2];

        if($tcp_data =~ /$re/) {
            my($vendor, $version, $info) = split m"/", eval $s->[1];
            printf("Service: ip=%s port=%i -> \"%s %s %s\" timestamp=%i\n",
                $src_ip, $src_port,
                $vendor  || q(),
                $version || q(),
                $info    || q(),
                $tstamp || q()
            );
            last SIGNATURE;
        }
    }
}

=head2 udp_service_check

Takes input: $udp->{'data'}, $ip->{'src_ip'}, $udp->{'src_port'}, $pradshosts{"tstamp"}
Prints out service if found.

=cut

sub udp_service_check {
    my ($udp_data, $src_ip, $src_port,$tstamp) = @_;

       # Make UDP asset detection here... PoC CODE at the moment.
### When ready - call udp_service_check ($udp->{'data'},$ip->{'src_ip'},$udp->{'src_port'},$pradshosts{"tstamp"});
       #warn "Detecting UDP asset...\n" if($DEBUG);
       if ($src_port == 53){
        printf ("Service: ip=%s port=%i -> \"DNS\" timestamp=%i\n",$src_ip, $src_port, $tstamp);
       }
       elsif ($src_port == 1194){
        printf ("Service: ip=%s port=%i -> \"OpenVPN\" timestamp=%i\n",$src_ip, $src_port, $tstamp);
       }
       else {
        warn "UDP ASSET DETECTION IS NOT IMPLEMENTED YET...\n" if($DEBUG>20);
       }

#    # Check content(udp_data) against signatures
#    SIGNATURE:
#    for my $s (@UDP_SERVICE_SIGNATURES) {
#        my $re = $s->[2];
#
#        if($udp_data =~ /$re/) {
#            my($vendor, $version, $info) = split m"/", eval $s->[1];
#            printf("SERVICE: ip=%s port=%i -> \"%s %s %s\" timestamp=%i\n",
#                $src_ip, $src_port,
#                $vendor  || q(),
#                $version || q(),
#                $info    || q(),
#                $tstamp || q()
#            );
#            last SIGNATURE;
#        }
#    }
}

=head2 arp_check

Takes 'NetPacket::Ethernet->decode($packet)' and timestamp as input and prints out arp asset.

=cut

sub arp_check {
    my ($eth,$tstamp) = @_;

    my $arp = NetPacket::ARP->decode($eth->{data}, $eth);
    my $aip = $arp->{spa};
    my $h1 = hex(substr( $aip,0,2));
    my $h2 = hex(substr( $aip,2,2));
    my $h3 = hex(substr( $aip,4,2));
    my $h4 = hex(substr( $aip,6,2));
    my $host = "$h1.$h2.$h3.$h4";

    print("ARP: mac=$arp->{sha} ip=$host timestamp=" . $tstamp . "\n");
}

=head2 get_mtu_link

 Takes MSS as input, and returns a guessed Link for that MTU.

=cut

sub get_mtu_link {
    my $mss = shift;
    my $link = "UNKOWN";
#   if ($mss =~ m/^[0-9]+$/) { 
    if ($mss =~ /^[+-]?\d+$/) {
       my $mtu = $mss + 40;
       if (my $link = $MTU_SIGNATURES->{ $mtu }) {return $link}
    }
    return $link;
}

=head2 load_config

 Reads the configuration file and loads variables.
 Takes the config file as input, and returns a hash of config options.

=cut

sub load_config {
    my $file = shift;
    my $config;
    open(my $FH, "<",$file) or die "Could not open '$file': $!";
    while (my $line = <$FH>) {
        chomp($line);
        $line =~ s/\#.*//;
        next unless($line); # empty line
        if (my ($key, $value) = ($line =~ m/(\w+)\s*=\s*(.*)$/)) {
#        my ($key, $value) = ($line =~ m/(\w+)\s*=\s*(.*)$/);
           warn  "$key:$value\n";
           $config->{$key} = $value;
        }else {
          die "Error: Not valid configfile format in: '$file'";
        }
    }
    close $FH;
    return $config;
}

=head2 add_asset

Takes input: Category, $1 $2 $3 $4..... $N
Adds the asset to the internal list %pradshosts of assets, or if it exists, just updates the timestamp.

=cut

sub add_asset {
    my $assets = @_;
    if($assets =~ /^OS: /) {
#      $pradshosts{"tstamp"} = time;
    }
    elsif ($assets =~ /^ARP: /) {
    }
    elsif ($assets =~ /^SERVICE: /) {
    }
    elsif ($assets =~ /^OS: /) {
    }
}

=head1 AUTHOR

Edward Fjellskål

Jan Henning Thorsen

Kacper Wysocki

=head1 COPYRIGHT

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
