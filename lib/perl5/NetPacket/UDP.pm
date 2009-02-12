#
# NetPacket::UDP - Decode and encode UDP (User Datagram Protocol)
# packets. 
#
# Comments/suggestions to tpot@samba.org
# Encode and checksum by Stephanie Wehner <atrak@itsx.com>
#
# $Id: UDP.pm,v 1.13 2001/07/29 23:45:00 tpot Exp $
#

package NetPacket::UDP;

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
BEGIN {
    $myclass = __PACKAGE__;
    $VERSION = "0.04";
}
sub Version () { "$myclass v$VERSION" }

BEGIN {
    @ISA = qw(Exporter NetPacket);

# Items to export into callers namespace by default
# (move infrequently used names to @EXPORT_OK below)

    @EXPORT = qw(
    );

# Other items we are prepared to export if requested

    @EXPORT_OK = qw(udp_strip
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
    strip       => [qw(udp_strip)],
);

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

    # Decode UDP packet

    if (defined($pkt)) {

	($self->{src_port}, $self->{dest_port}, $self->{len}, $self->{cksum},
	 $self->{data}) = unpack("nnnna*", $pkt);
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}

#
# Strip header from packet and return the data contained in it
#

undef &udp_strip;
*udp_strip = \&strip;

sub strip {
    my ($pkt, @rest) = @_;

    my $tcp_obj = decode($pkt);
    return $tcp_obj->data;
}   

#
# Encode a packet
#

sub encode {

    my $self = shift;
    my ($ip) = @_;
    my ($packet);

    # Adjust the length accodingly
    $self->{len} = 8 + length($self->{data});

    # First of all, fix the checksum
    $self->checksum($ip);

    # Put the packet together
    $packet = pack("nnnna*", $self->{src_port},$self->{dest_port},
                $self->{len}, $self->{cksum}, $self->{data});

    return($packet); 
}

# 
# UDP Checksum
#

sub checksum {

    my $self = shift;
    my ($ip) = @_;
    my ($packet,$zero,$udplen);
    my ($src_ip, $dest_ip,$proto);

    $zero = 0;
    $proto = NetPacket::IP::IP_PROTO_UDP;

    # Pack pseudo-header for udp checksum

    $src_ip = gethostbyname($ip->{src_ip});
    $dest_ip = gethostbyname($ip->{dest_ip});

    $packet = pack('a4a4nnnnnna*',
            $src_ip,$dest_ip,$proto,$self->{len},
            $self->{src_port}, $self->{dest_port}, 
            $self->{len},$zero,$self->{data});

    $self->{cksum} = NetPacket::htons(NetPacket::in_cksum($packet)); 

}

#
# Module initialisation
#

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 NAME

C<NetPacket::UDP> - Assemble and disassemble UDP (User Datagram
Protocol) packets.

=head1 SYNOPSIS

  use NetPacket::UDP;

  $udp_obj = NetPacket::UDP->decode($raw_pkt);
  $udp_pkt = NetPacket::UDP->encode($ip_obj);
  $udp_data = NetPacket::UDP::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::UDP> provides a set of routines for assembling and
disassembling packets using UDP (User Datagram Protocol).  

=head2 Methods

=over

=item C<NetPacket::UDP-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::UDP-E<gt>encode(param =E<gt> value)>

Return a UDP packet encoded with the instance data specified. Needs parts 
of the ip header contained in $ip_obj, the IP object, in order to calculate 
the UDP checksum. The length field will also be set automatically.

=back

=head2 Functions

=over

=item C<NetPacket::UDP::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the UDP
packet.  This data is suitable to be used as input for other
C<NetPacket::*> modules.

This function is equivalent to creating an object using the
C<decode()> constructor and returning the C<data> field of that
object.

=back

=head2 Instance data

The instance data for the C<NetPacket::UDP> object consists of
the following fields.

=over

=item src_port

The source UDP port for the datagram.

=item dest_port

The destination UDP port for the datagram.

=item len

The length (including length of header) in bytes for this packet.

=item cksum

The checksum value for this packet.

=item data

The encapsulated data (payload) for this packet.

=back

=head2 Exports

=over

=item default

none

=item exportable

igmp_strip IGMP_VERSION_RFC998 IGMP_VERSION_RFC1112
IGMP_MSG_HOST_MQUERY IGMP_MSG_HOST_MREPORT IGMP_IP_NO_HOSTS
IGMP_IP_ALL_HOSTS IGMP_IP_ALL_ROUTERS

=item tags

The following tags group together related exportable items.

=over

=item C<:strip>

Import the strip function C<igmp_strip>.

=item C<:versions>

IGMP_VERSION_RFC998 IGMP_VERSION_RFC1112

=item C<:msgtypes>

IGMP_HOST_MQUERY IGMP_HOST_MREPORT

=item C<:group_addrs>

IGMP_IP_NO_HOSTS IGMP_IP_ALL_HOSTS IGMP_IP_ALL_ROUTERS

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

The following script dumps IGMP the contents of IGMP frames to
standard output.

  #!/usr/bin/perl -w

  use strict;
  use Net::PcapUtils;
  use NetPacket::Ethernet qw(:strip);
  use NetPacket::IP;
  use NetPacket::UDP;

  sub process_pkt {
      my($arg, $hdr, $pkt) = @_;

      my $ip_obj = NetPacket::IP->decode(eth_strip($pkt));
      my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});

      print("$ip_obj->{src_ip}:$udp_obj->{src_port} -> ",
	    "$ip_obj->{dest_ip}:$udp_obj->{dest_port} ",
	    "$udp_obj->{len}\n");
  }

  Net::PcapUtils::loop(\&process_pkt, FILTER => 'udp');

The following is an example use in combination with Net::Divert 
to alter the payload of packets that pass through. All occurences
of foo will be replaced with bar. This example is easy to test with 
netcat, but otherwise makes little sense. :) Adapt to your needs:

#!/usr/bin/perl 

use Net::Divert;
use NetPacket::IP qw(IP_PROTO_UDP);
use NetPacket::UDP;

$divobj = Net::Divert->new('yourhost',9999);

$divobj->getPackets(\&alterPacket);

sub alterPacket
{
    my ($data, $fwtag) = @_;

    $ip_obj = NetPacket::IP->decode($data);

    if($ip_obj->{proto} == IP_PROTO_UDP) {

        # decode the UDP header
        $udp_obj = NetPacket::UDP->decode($ip_obj->{data});

        # replace foo in the payload with bar
        $udp_obj->{data} =~ s/foo/bar/g;

        # reencode the packet
        $ip_obj->{data} = $udp_obj->encode($ip_obj);
        $data = $ip_obj->encode;

    }

    $divobj->putPacket($data,$fwtag);
}

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
