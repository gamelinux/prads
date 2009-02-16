#
# NetPacket::ARP - Decode and endode ARP (Address Resolution Protocol)
# packets. 
#
# Comments/suggestions to tpot@samba.org
#
# $Id: ARP.pm,v 1.11 2001/07/29 23:45:00 tpot Exp $
#

package NetPacket::ARP;

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

    @EXPORT_OK = qw(arp_strip
		    ARP_OPCODE_REQUEST ARP_OPCODE_REPLY RARP_OPCODE_REQUEST 
		    RARP_OPCODE_REPLY
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
    opcodes     => [qw(ARP_OPCODE_REQUEST ARP_OPCODE_REPLY RARP_OPCODE_REQUEST 
		       RARP_OPCODE_REPLY)],
    strip       => [qw(arp_strip)],
);

}

# 
# List of opcode values
#

use constant ARP_OPCODE_REQUEST  => 1;
use constant ARP_OPCODE_REPLY    => 2;
use constant RARP_OPCODE_REQUEST => 3;
use constant RARP_OPCODE_REPLY   => 4;

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

    # Decode ARP packet

    if (defined($pkt)) {

	($self->{htype}, $self->{proto}, $self->{hlen}, $self->{plen},
	 $self->{opcode}, $self->{sha}, $self->{spa}, $self->{tha},
	 $self->{tpa}) = 
	     unpack('nnCCnH12H8H12H8' , $pkt);

	$self->{data} = undef;
    }

    # Return a blessed object

    bless($self, $class);
    return $self;
}


#
# Strip header from packet and return the data contained in it.  ARP
# packets contain no encapsulated data.
#

undef &arp_strip;
*arp_strip = \&strip;

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

C<NetPacket::ARP> - Assemble and disassemble ARP (Address Resolution
Protocol) packets.

=head1 SYNOPSIS

  use NetPacket::ARP;

  $tcp_obj = NetPacket::ARP->decode($raw_pkt);
  $tcp_pkt = NetPacket::ARP->encode(params...);   # Not implemented

=head1 DESCRIPTION

C<NetPacket::ARP> provides a set of routines for assembling and
disassembling packets using ARP (Address Resolution Protocol).  

=head2 Methods

=over

=item C<NetPacket::ARP-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input.
It is the responsibility of the programmer to ensure valid packet data
is passed to this method.

=item C<NetPacket::ARP-E<gt>encode(param =E<gt> value)>

Return a ARP packet encoded with the instance data specified.  Not
implemented.

=back

=head2 Functions

=over

=item C<NetPacket::ARP::strip([RAW PACKET])>

Return the encapsulated data (or payload) contained in the TCP packet.
Since no payload data is encapulated in an ARP packet (only instance
data), this function returns undef.

=back

=head2 Instance data

The instance data for the C<NetPacket::ARP> object consists of
the following fields.

=over

=item htype

Hardware type.

=item proto

Protocol type.

=item hlen

Header length.

=item plen

Protocol length.

=item opcode

One of the following constants:

=over

=item * ARP_OPCODE_REQUEST

=item * ARP_OPCODE_REPLY

=item * RARP_OPCODE_REQUEST

=item * RARP_OPCODE_REPLY

=back

=item sha

Source hardware address.

=item spa

Source protocol address.

=item tha

Target hardware address.

=item tpa

Target protocol address.

=back

=head2 Exports

=over

=item default

none

=item exportable

none

=item tags

The following tags group together related exportable items.

=over

=item C<:ALL>

All the above exportable items.

=back

=back

=head1 EXAMPLE

Print out arp requests on the local network.

  #!/usr/bin/perl -w

  use Net::PcapUtils;
  use NetPacket::Ethernet qw(:types);
  use NetPacket::ARP;

  sub process_pkt {
    my ($arg, $hdr, $pkt) = @_;

    my $eth_obj = NetPacket::Ethernet->decode($pkt);

    if ($eth_obj->{type} == ETH_TYPE_ARP) {
	my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);
	print("source hw addr=$arp_obj->{sha}, " .
	      "dest hw addr=$arp_obj->{tha}\n");
    }
  }

Net::PcapUtils::loop(\&process_pkt);

=head1 TODO

=over

=item Implement encode() function

=item Does this work for protocols other than IP?  Need to read RFC.

=item Example is a bit silly

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
