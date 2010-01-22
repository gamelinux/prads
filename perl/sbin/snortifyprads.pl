#!/usr/bin/perl -w

# Convert PRADS db to SNORT host-attribute table
#
# Work-in-progress: missing attribute table and services!
#
# Copyright 2010 Kacper Wysocki <kwy@redpill-linpro.com>

use strict;
use warnings;

use DBI;

our $DATABASE = 'dbi:SQLite:dbname=../prads.db';
our $DB_USERNAME;
our $DB_PASSWORD;
our $DB_TABLE = 'asset';

our $SQL_IP = 'ipaddress';
our $SQL_FP = 'os_fingerprint';
our $SQL_MAC = 'mac_address';
our $SQL_DETAILS = 'os_details';
our $SQL_HOSTNAME = 'hostname';
our $SQL_TIME = 'timestamp';

our $SW = 4;
our $IL = 0;

sub tab {
    $IL++;
}
sub bat {
    $IL--;
}
sub out {
    print " " x ($SW * $IL);
    for (@_){
        print;
    }
    print "\n";
}

sub out_tag {
    my ($tag, $value) = @_;
    out ("<$tag>$value</$tag>");
}

sub out_av {
    my ($value) = @_;
    out_tag ('ATTRIBUTE_VALUE', $value);
}

out ('<SNORT_ATTRIBUTES>');
tab;
db_suck($DATABASE,$DB_USERNAME,$DB_PASSWORD,$DB_TABLE);
bat;
out ('</SNORT_ATTRIBUTES>');

sub db_suck {
    my ($db, $user, $pass, $table) = @_;
    my $dbh = DBI->connect($db, $user, $pass);


    if ($db =~ /dbi:sqlite/i) {
        $SQL_IP = 'ip';
        $SQL_FP = 'fingerprint';
        $SQL_MAC = 'mac';
        $SQL_TIME = 'time';
        $SQL_DETAILS = 'details';
        $SQL_HOSTNAME = 'reporting';
    }

    # do attribute map
    out ('<ATTRIBUTE_TABLE>');
    print_hosts($dbh, $table);
    out ('</ATTRIBUTE_TABLE>');
}

sub print_hosts {
    my ($dbh, $table) = @_;
    #todo : should be uniq'ed somehhow!
    my $sql = "SELECT $SQL_IP,$SQL_TIME, service, $SQL_MAC, os, $SQL_DETAILS FROM $table WHERE service = 'SYN' OR service = 'SYNACK'";

    my $sth = $dbh->prepare_cached($sql);
    $sth->execute();
    my ($ip, $time, $service, $mac, $os, $details);
#while ( ($ip, $time, $service, $mac, $os, $details) = $sth->fetchrow_array()) {
#    print "$ip $time $service $mac $os $details\n";
#}

    my $ref;
    while ($ref = $sth->fetchrow_hashref()) {
        out ('<HOST>');
        tab;
        out_tag('IP', $ref->{'ip'});
        tab;
        out ('<OPERATING_SYSTEM>');
        tab;
        print_os($ref);
        bat;
        out ('</OPERATING_SYSTEM>');
        out ('<SERVICES>');
        tab;
        print_services($ref->{'ip'});
        bat;
        out ('</SERVICES>');
        bat;
        out ('</HOST>');
        bat;
    }
}

sub print_os {
    my ($ref) = @_;
    out ('<NAME>');
    tab;
    out_av ('1337');
    bat;
    out ('</NAME>');
    out ('<VENDOR>');
    out_av (gen_vendor($ref->{'os'}));
    out ('</VENDOR>');
    out ('<VERSION>');
    out_av (gen_version($ref->{'os'}, $ref->{$SQL_DETAILS}));
    out ('</VERSION>');
    out ('<FRAG_POLICY>');
    out_av (gen_fragpolicy($ref->{'os'}, $ref->{$SQL_DETAILS}));
    out ('</FRAG_POLICY>');
    out ('<STREAM_POLICY>');
    out_av (gen_streampolicy($ref->{'os'}, $ref->{$SQL_DETAILS}));
    out ('</STREAM_POLICY>');
}

sub gen_vendor {
    my ($os) = @_;
    $_ = $os;
    /windows/i and return "Microsoft" or
    /linux/i and return "Linux" or
    return ucfirst lc $os;
}
sub gen_version {
    my ($os, $details) = @_;
    return $details;
}
sub gen_fragpolicy {
    my ($os, $details) = @_;
    /windows/i and return 'windows' or
    /linux/i and return 'linux' or
    /openbsd/i and return 'linux' or
    /bsd/i and return 'BSD' or
    /jetdirect/i and return 'BSD-right' or
    /hp-ux/i and $details =~ /11/ and return 'First' or
    /hp/i and return 'BSD' or
    /mac/i and return 'First' or
    /irix/i and return 'BSD' or
    /aix/i and return 'BSD' or
    /cisco/i and return 'Last' or
    /vms/i and return 'BSD' or
    /os\/2/i and return 'BSD' or
    /osf/i and return 'BSD' or
    /sun/i and $details =~ /4/ and return 'BSD' or
    /sun/i and return 'First' or
    /tru64/i and return 'BSD' or
    /vms|vax/i and return 'BSD' or
    return 'last';
}

sub gen_streampolicy {
    my ($os, $details) = @_;
    gen_fragpolicy($os, $details);
}

sub print_services {
    # XXX
}

# extract <operating_system>ip, os Vendor, Version, frag_policy, stream_policy,
# & all services: 
# <services><service><port><attribute_value/>
# IPPROTO, PROTOCOL <Confidence>


