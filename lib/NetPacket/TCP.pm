#
# NetPacket::TCP - Decode and encode TCP (Transmission Control
# Protocol) packets. 
#
# Comments/suggestions to tpot@samba.org
#
# Encode and checksumming part, Stephanie Wehner, atrak@itsx.com
#
# $Id: TCP.pm,v 1.16 2001/08/01 02:31:27 tpot Exp $
#

package NetPacket::TCP;

#
# Copyright (c) 2001 Tim Potter.
#
# This package is free software and is provided "as is" without express 
# or implied warranty.  It may be used, redistributed and/or modified 
# under the terms of the Perl Artistic License (see
# http://www.perl.com/perl/misc/Artistic.html)
#
# Copyright (c) 1995,1996,1997,1998,1999 ANU and CSIRO on behalf of 
# the participants in the CRC for Advanced Computational Systems
# ('ACSys').
#
# ACSys makes this software and all associated data and documentation
# ('Software') available free of charge.  You may make copies of the 
# Software but you must include all of this notice on any copy.
#
# The Software was developed for research purposes and ACSys does not
# warrant that it is error free or fit for any purpose.  ACSys
# disclaims any liability for all claims, expenses, losses, damages
# and costs any user may incur as a result of using, copying or
# modifying the Software.
#
# Copyright (c) 2001 Stephanie Wehner
#

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use NetPacket;

my $myclass;

# TCP Flags

use constant FIN => 0x01;
use constant SYN => 0x02;
use constant RST => 0x04;
use constant PSH => 0x08;
use constant ACK => 0x10;
use constant URG => 0x20;
use constant ECE => 0x40;
use constant CWR => 0x80;

BEGIN {
    $myclass = __PACKAGE__;
    $VERSION = "0.04";
}
sub Version () { "$myclass v$VERSION" }

BEGIN {
    @ISA = qw(Exporter NetPacket);

# Items to export into callers namespace by default
# (move infrequently used names to @EXPORT_OK below)

    @EXPORT = qw(FIN SYN RST PSH ACK URG ECE CWR
    );

# Other items we are prepared to export if requested

    @EXPORT_OK = qw(tcp_strip 
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
    strip       => [qw(tcp_strip)],  
);

}

#
# Strip header from packet and return the data contained in it
#

undef &tcp_strip;
*tcp_strip = \&strip;

sub strip {
    my ($pkt, @rest) = @_;

    my $tcp_obj = NetPacket::TCP->decode($pkt);
    return $tcp_obj->{data};
}   

#
# Decode the packet
#

sub decode {
    my $class = shift;
    my($pkt, $parent, @rest) = @_;
    my $self = {};

    # Class fields

    $self->{_parent} = $parent;
    $self->{_frame} = $pkt;

    # Decode TCP packet

    if (defined($pkt)) {
	my $tmp;

	($self->{src_port}, $self->{dest_port}, $self->{seqnum}, 
	 $self->{acknum}, $tmp, $self->{winsize}, $self->{cksum}, 
	 $self->{urg}, $self->{options}) =
	     unpack("nnNNnnnna*", $pkt);

	# Extract flags
	
	$self->{hlen} = ($tmp & 0xf000) >> 12;
	$self->{reserved} = ($tmp & 0x0f00) >> 8;
	$self->{flags} = $tmp & 0x00ff;
	
	# Decode variable length header and remaining data

	my $olen = $self->{hlen} - 5;
	$olen = 0, if ($olen < 0);  # Check for bad hlen

        # Option length is number of 32 bit words

        $olen = $olen * 4;

	($self->{options}, $self->{data}) = unpack("a" . $olen . 
						   "a*", $self->{options});
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}

#
# Encode a packet
#

sub encode {

    my $self = shift;
    my ($ip) = @_;
    my ($packet,$tmp);

    # First of all, fix the checksum
    $self->checksum($ip);

    $tmp = $self->{hlen} << 12;
    $tmp = $tmp | (0x0f00 & ($self->{reserved} << 8));
    $tmp = $tmp | (0x00ff & $self->{flags});

    # Put the packet together
    $packet = pack('n n N N n n n n a* a*',
            $self->{src_port}, $self->{dest_port}, $self->{seqnum},
            $self->{acknum}, $tmp, $self->{winsize}, $self->{cksum},
            $self->{urg}, $self->{options},$self->{data});

    return($packet);

}

#
# TCP Checksum
#

sub checksum {

    my $self = shift;
    my ($ip) = @_;
    my ($packet,$zero,$tcplen,$tmp);
    my ($src_ip, $dest_ip,$proto,$count);

    $zero = 0;
    $proto = 6;
    $tcplen = ($self->{hlen} * 4)+ length($self->{data});

    $tmp = $self->{hlen} << 12;
    $tmp = $tmp | (0x0f00 & ($self->{reserved} << 8));
    $tmp = $tmp | (0x00ff & $self->{flags});

    # Pack pseudo-header for tcp checksum

    $src_ip = gethostbyname($ip->{src_ip});
    $dest_ip = gethostbyname($ip->{dest_ip});

    $packet = pack('a4a4nnnnNNnnnna*a*',
            $src_ip,$dest_ip,$proto,$tcplen,
            $self->{src_port}, $self->{dest_port}, $self->{seqnum},
            $self->{acknum}, $tmp, $self->{winsize}, $zero,
            $self->{urg}, $self->{options},$self->{data});

    $self->{cksum} = NetPacket::htons(NetPacket::in_cksum($packet));
}

#
# Module initialisation
#

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 NAME

C<NetPacket::TCP> - Assemble and disassemble TCP (Transmission Control
Protocol) packets.

=head1 SYNOPSIS

  use NetPacket::TCP;

  $tcp_obj = NetPacket::TCP->decode($raw_pkt);
  $tcp_pkt = NetPacket::TCP->encode($ip_pkt);
  $tcp_data = NetPacket::TCP::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::TCP> provides a set of routines for assembling and
disassembling packets using TCP (Transmission Control Protocol).  

=head2 Methods

=over

=item C<NetPacket::TCP-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::TCP-E<gt>encode($ip_obj)>

Return a TCP packet encoded with the instance data specified. 
Needs parts of the ip header contained in $ip_obj in order to calculate
the TCP checksum. 

=back

=head2 Functions

=over

=item C<NetPacket::TCP::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the TCP
packet.  This data is suitable to be used as input for other
C<NetPacket::*> modules.

This function is equivalent to creating an object using the
C<decode()> constructor and returning the C<data> field of that
object.

=back

=head2 Instance data

The instance data for the C<NetPacket::TCP> object consists of
the following fields.

=over

=item src_port

The source TCP port for the packet.

=item dest_port

The destination TCP port for the packet.

=item seqnum

The TCP sequence number for this packet.

=item acknum

The TCP acknowledgement number for this packet.

=item hlen

The header length for this packet.

=item reserved

The 6-bit "reserved" space in the TCP header.

=item flags

Contains the urg, ack, psh, rst, syn, fin, ece and cwr flags for this packet.

=item winsize

The TCP window size for this packet.

=item cksum

The TCP checksum.

=item urg

The TCP urgent pointer.

=item options

Any TCP options for this packet in binary form.

=item data

The encapsulated data (payload) for this packet.

=back

=head2 Exports

=over

=item default

FIN SYN RST PSH ACK URG ECE CWR Can be used to set the appropriate flag.

=item exportable

tcp_strip

=item tags

The following tags group together related exportable items.

=over

=item C<:strip>

Import the strip function C<tcp_strip>.

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

The following script is a primitive pop3 sniffer.

  #!/usr/bin/perl -w

  use strict;
  use Net::PcapUtils;
  use NetPacket::Ethernet qw(:strip);
  use NetPacket::IP qw(:strip);
  use NetPacket::TCP;

  sub process_pkt {
      my($arg, $hdr, $pkt) = @_;

      my $tcp_obj = NetPacket::TCP->decode(ip_strip(eth_strip($pkt)));

      if (($tcp_obj->{src_port} == 110) or ($tcp_obj->{dest_port} == 110)) {
	  print($tcp_obj->{data});
      }
  }

  Net::PcapUtils::loop(\&process_pkt, FILTER => 'tcp');

The following uses NetPacket together with Net::Divert to add a syn
flag to all TCP packets passing through:

  #!/usr/bin/perl

  use Net::Divert;
  use NetPacket::IP qw(IP_PROTO_TCP);
  use NetPacket::TCP;


  $divobj = Net::Divert->new('yourhostname',9999);

  $divobj->getPackets(\&alterPacket);

  sub alterPacket {
      my($packet,$fwtag) = @_;

      # decode the IP header
      $ip_obj = NetPacket::IP->decode($packet);

      # check if this is a TCP packet
      if($ip_obj->{proto} == IP_PROTO_TCP) {

          # decode the TCP header
          $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});

          # set the syn flag
          $tcp_obj->{flags} |= SYN;

          # construct the new ip packet
          $ip_obj->{data} = $tcp_obj->encode($ip_obj);
          $packet = $ip_obj->encode;

      }

      # write it back out
      $divobj->putPacket($packet,$fwtag);
   }


=head1 TODO

=over

=item Assembly of TCP fragments into a data stream

=item Option processing

=item Nicer processing of TCP flags

=back

=head1 COPYRIGHT

  Copyright (c) 2001 Tim Potter.

  This package is free software and is provided "as is" without express 
  or implied warranty.  It may be used, redistributed and/or modified 
  under the terms of the Perl Artistic License (see
  http://www.perl.com/perl/misc/Artistic.html)

  Copyright (c) 1995,1996,1997,1998,1999 ANU and CSIRO on behalf of 
  the participants in the CRC for Advanced Computational Systems
  ('ACSys').

  ACSys makes this software and all associated data and documentation
  ('Software') available free of charge.  You may make copies of the 
  Software but you must include all of this notice on any copy.

  The Software was developed for research purposes and ACSys does not
  warrant that it is error free or fit for any purpose.  ACSys
  disclaims any liability for all claims, expenses, losses, damages
  and costs any user may incur as a result of using, copying or
  modifying the Software.

=head1 AUTHOR

Tim Potter E<lt>tpot@samba.orgE<gt>

Stephanie Wehner E<lt>atrak@itsx.comE<gt>

=cut

# any real autoloaded methods go after this line
