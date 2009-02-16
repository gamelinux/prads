#
# NetPacket::IGMP - Decode and encode IGMP (Internet Group Management
# Protocol) packets.
#
# Comments/suggestions to tpot@samba.org
#
# $Id: IGMP.pm,v 1.9 2001/07/29 23:45:00 tpot Exp $
#

package NetPacket::IGMP;

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

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

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

    @EXPORT_OK = qw(igmp_strip
		    IGMP_VERSION_RFC998 IGMP_VERSION_RFC1112
		    IGMP_MSG_HOST_MQUERY IGMP_MSG_HOST_MREPORT
		    IGMP_IP_NO_HOSTS IGMP_IP_ALL_HOSTS
		    IGMP_IP_ALL_ROUTERS
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
    strip       => [qw(igmp_strip)],
    versions    => [qw(IGMP_VERSION_RFC998 IGMP_VERSION_RFC1112)],
    msgtypes    => [qw(IGMP_HOST_MQUERY IGMP_HOST_MREPORT)],
    group_addrs => [qw(IGMP_IP_NO_HOSTS IGMP_IP_ALL_HOSTS
		      IGMP_IP_ALL_ROUTERS)]  
);

}

#
# Version numbers
#

use constant IGMP_VERSION_RFC998  => 0;      # Version 0 of IGMP (obsolete)
use constant IGMP_VERSION_RFC1112 => 1;      # Version 1 of IGMP

#
# Message types
#

use constant IGMP_MSG_HOST_MQUERY  => 1;      # Host membership query
use constant IGMP_MSG_HOST_MREPORT => 2;      # Host membership report

#
# IGMP IP addresses
#

use constant IGMP_IP_NO_HOSTS    => '224.0.0.0';     # Not assigned to anyone
use constant IGMP_IP_ALL_HOSTS   => '224.0.0.1';     # All hosts on local net
use constant IGMP_IP_ALL_ROUTERS => '224.0.0.2';     # All routers on local net

# Convert 32-bit IP address to "dotted quad" notation

sub to_dotquad {
    my($net) = @_ ;
    my($na, $nb, $nc, $nd);

    $na = $net >> 24 & 255;
    $nb = $net >> 16 & 255;
    $nc = $net >>  8 & 255;
    $nd = $net & 255;

    return ("$na.$nb.$nc.$nd");
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

    # Decode IGMP packet

    if (defined($pkt)) {
	my $tmp;

	($tmp, $self->{subtype}, $self->{cksum}, $self->{group_addr}, 
	 $self->{data}) = unpack('CCnNa*', $pkt);
    
	# Extract bit fields
	
	$self->{version} = ($tmp & 0xf0) >> 4;
	$self->{type} = $tmp & 0x0f;
	
	# Convert to dq notation
	
	$self->{group_addr} = to_dotquad($self->{group_addr});
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}

#
# Strip header from packet and return the data contained in it.  IGMP 
# packets contain no encapsulated data.
#

undef &igmp_strip;
*igmp_strip = \&strip;

sub strip {
    return undef;
}

#
# Encode a packet
#

sub encode {
    die("Not implemented");
}

# Module return value

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 NAME

C<NetPacket::IGMP> - Assemble and disassemble IGMP (Internet Group
Mangement Protocol) packets. 

=head1 SYNOPSIS

  use NetPacket::IGMP;

  $igmp_obj = NetPacket::IGMP->decode($raw_pkt);
  $igmp_pkt = NetPacket::IGMP->encode(params...);   # Not implemented
  $igmp_data = NetPacket::IGMP::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::IGMP> provides a set of routines for assembling and
disassembling packets using IGMP (Internet Group Mangement Protocol). 

=head2 Methods

=over

=item C<NetPacket::IGMP-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::IGMP-E<gt>encode(param =E<gt> value)>

Return an IGMP packet encoded with the instance data specified.  Not
implemented.

=back

=head2 Functions

=over

=item C<NetPacket::IGMP::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the IGMP
packet.  This function returns undef as there is no encapsulated data
in an IGMP packet.

=back

=head2 Instance data

The instance data for the C<NetPacket::IGMP> object consists of
the following fields.

=over

=item version

The IGMP version of this packet.

=item type

The message type for this packet.

=item len

The length (including length of header) in bytes for this packet.

=item subtype

The message subtype for this packet.

=item cksum

The checksum for this packet.

=item group_addr

The group address specified in this packet.

=item data

The encapsulated data (payload) for this packet.

=back

=head2 Exports

=over

=item default

none

=item exportable

IGMP_VERSION_RFC998 IGMP_VERSION_RFC1112 IGMP_HOST_MQUERY
IGMP_HOST_MREPORT IGMP_IP_NO_HOSTS IGMP_IP_ALL_HOSTS
IGMP_IP_ALL_ROUTERS 

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

The following script dumps UDP frames by IP address and UDP port
to standard output.

  #!/usr/bin/perl -w

  use strict;
  use Net::PcapUtils;
  use NetPacket::Ethernet qw(:strip);
  use NetPacket::IP;
  use NetPacket::IGMP;

  sub process_pkt {
      my($arg, $hdr, $pkt) = @_;

      my $ip_obj = NetPacket::IP->decode(eth_strip($pkt));
      my $igmp_obj = NetPacket::IGMP->decode($ip_obj->{data});

      print("$ip_obj->{src_ip} -> $ip_obj->{dest_ip} ",
	    "$igmp_obj->{type}/$igmp_obj->{subtype} ",
	    "$igmp_obj->{group_addr}\n");
  }

  Net::PcapUtils::loop(\&process_pkt, FILTER => 'igmp');

=head1 TODO

=over

=item Implement encode() function

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

=cut

# any real autoloaded methods go after this line
