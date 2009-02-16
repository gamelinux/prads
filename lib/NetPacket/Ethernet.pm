#
# NetPacket::Ethernet - Decode and encode ethernet packets.
#
# Comments/suggestions to tpot@samba.org
#
# $Id: Ethernet.pm,v 1.12 2001/07/29 23:45:00 tpot Exp $
#

package NetPacket::Ethernet;

#
# Copyright (c) 2001 Tim Potter.
#
# This package is free software and is provided "as is" without express 
# or implied warranty.  It may be used, redistributed and/or modified 
# under the terms of the Perl Artistic License (see
# http://www.perl.com/perl/misc/Artistic.html)
#
# Copyright (c) 1995,1996,1997,1998,1999 ANU and CSIRO on behalf of 
# the  participants in the CRC for Advanced Computational Systems
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

    @EXPORT_OK = qw(eth_strip 
		    ETH_TYPE_IP ETH_TYPE_ARP ETH_TYPE_APPLETALK
		    ETH_TYPE_SNMP ETH_TYPE_IPv6 ETH_TYPE_PPP
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
    strip       => [qw(eth_strip)],
    types       => [qw(ETH_TYPE_IP ETH_TYPE_ARP ETH_TYPE_APPLETALK
		       ETH_TYPE_SNMP ETH_TYPE_IPv6 ETH_TYPE_PPP)],
);

}

#
# Partial list of ethernet protocol types from
# http://www.isi.edu/in-notes/iana/assignments/ethernet-numbers
#

use constant ETH_TYPE_IP        => 0x0800;
use constant ETH_TYPE_ARP       => 0x0806;
use constant ETH_TYPE_APPLETALK => 0x809b;
use constant ETH_TYPE_RARP      => 0x8035;
use constant ETH_TYPE_SNMP      => 0x814c;
use constant ETH_TYPE_IPv6      => 0x86dd;
use constant ETH_TYPE_PPP       => 0x880b;

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

    # Decode ethernet packet

    if (defined($pkt)) {

	my($sm_lo, $sm_hi, $dm_lo, $dm_hi);

	($dm_hi, $dm_lo, $sm_hi, $sm_lo, $self->{type}, $self->{data}) = 
	    unpack('NnNnna*' , $pkt);

	# Convert MAC addresses to hex string to avoid representation
	# problems

	$self->{src_mac} = sprintf("%08x%04x", $sm_hi, $sm_lo);
	$self->{dest_mac} = sprintf("%08x%04x", $dm_hi, $dm_lo);
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}

#
# Strip header from packet and return the data contained in it
#

undef &eth_strip;        # Create eth_strip alias
*eth_strip = \&strip;

sub strip {
    my ($pkt, @rest) = @_;

    my $eth_obj = NetPacket::Ethernet->decode($pkt);
    return $eth_obj->{data};
}   

#
# Encode a packet - not implemented!
#

sub encode {
    die("Not implemented");
}

#
# Module initialisation
#

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 NAME

C<NetPacket::Ethernet> - Assemble and disassemble ethernet packets.

=head1 SYNOPSIS

  use NetPacket::Ethernet;

  $eth_obj = NetPacket::Ethernet->decode($raw_pkt);
  $eth_pkt = NetPacket::Ethernet->encode(params...);   # Not implemented
  $eth_data = NetPacket::Ethernet::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::Ethernet> provides a set of routines for assembling and
disassembling packets using the Ethernet protocol.  

=head2 Methods

=over

=item C<NetPacket::Ethernet-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::Ethernet-E<gt>encode(param =E<gt> value)>

Return an ethernet packet encoded with the instance data specified.
Not implemented.

=back

=head2 Functions

=over

=item C<NetPacket::Ethernet::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the ethernet
packet.  This data is suitable to be used as input for other
C<NetPacket::*> modules.

This function is equivalent to creating an object using the
C<decode()> constructor and returning the C<data> field of that
object.

=back

=head2 Instance data

The instance data for the C<NetPacket::Ethernet> object consists of
the following fields.

=over

=item src_mac

The source MAC address for the ethernet packet as a hex string.

=item dest_mac

The destination MAC address for the ethernet packet as a hex string.

=item type

The protocol type for the ethernet packet.

=item data

The payload for the ethernet packet.

=back

=head2 Exports

=over

=item default

none

=item exportable

ETH_TYPE_IP ETH_TYPE_ARP ETH_TYPE_APPLETALK ETH_TYPE_SNMP
ETH_TYPE_IPv6 ETH_TYPE_PPP 

=item tags

The following tags group together related exportable items.

=over

=item C<:types>

ETH_TYPE_IP ETH_TYPE_ARP ETH_TYPE_APPLETALK ETH_TYPE_SNMP
ETH_TYPE_IPv6 ETH_TYPE_PPP 

=item C<:strip>

Import the strip function C<eth_strip> which is an alias for
C<NetPacket::Ethernet::strip>

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

The following script dumps ethernet frames by mac address and protocol
to standard output.

  #!/usr/bin/perl -w

  use strict;
  use Net::PcapUtils;
  use NetPacket::Ethernet;

  sub process_pkt {
      my($arg, $hdr, $pkt) = @_;

      my $eth_obj = NetPacket::Ethernet->decode($pkt);
      print("$eth_obj->{src_mac}:$eth_obj->{dest_mac} $eth_obj->{type}\n");
  }

  Net::PcapUtils::loop(\&process_pkt);

=head1 TODO

=over

=item Implement C<encode()> function

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
