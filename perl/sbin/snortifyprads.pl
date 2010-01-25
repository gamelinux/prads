#!/usr/bin/perl -w

# Convert PRADS db to SNORT host-attribute table
#
# Usage: 
# 
# Work-in-progress: services!
#
#
# Copyright 2010 Kacper Wysocki <kwy@redpill-linpro.com>

use strict;
use warnings;

use DBI;

our $DATABASE = 'dbi:SQLite:dbname=../prads.db';
our $DB_USERNAME;
our $DB_PASSWORD;
our $DB_TABLE = 'asset';
our $DBH;

our $SQL_IP = 'ipaddress';
our $SQL_FP = 'os_fingerprint';
our $SQL_MAC = 'mac_address';
our $SQL_DETAILS = 'os_details';
our $SQL_HOSTNAME = 'hostname';
our $SQL_TIME = 'timestamp';

our $SW = 4;
our $IL = 0;

# start attributes at this number
our $ATTR_NUM = 1337;
our %attr;

sub tab {
    $IL++;
}
sub bat {
    $IL--;
}

sub out_hat {
    out ('<SNORT_ATTRIBUTES>');
    tab;
    db_suck($DATABASE,$DB_USERNAME,$DB_PASSWORD,$DB_TABLE);
    bat;
    out ('</SNORT_ATTRIBUTES>');
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

sub out_ai {
    my ($value) = @_;
    out_tag ('ATTRIBUTE_ID', $value);
}
sub out_av {
    my ($value) = @_;
    out_tag ('ATTRIBUTE_VALUE', $value);
}
sub db_suck {
    my ($db, $user, $pass, $table) = @_;
    $DBH = DBI->connect($db, $user, $pass);


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
    out_hosts($table);
    out ('</ATTRIBUTE_TABLE>');
    out_attribute_map();
}

sub out_hosts {
    my ($table) = @_;
    #todo : should be uniq'ed somehhow!
    #my $sql = "SELECT $SQL_IP,$SQL_TIME, service, $SQL_MAC, os, $SQL_DETAILS FROM $table WHERE service = 'SYN' OR service = 'SYNACK'";
    my $sql = "SELECT DISTINCT $SQL_IP,$SQL_TIME, service, $SQL_MAC, os, $SQL_DETAILS FROM $table WHERE service = 'SYN' OR service = 'SYNACK' OR service = 'UDP' OR service = 'ICMP'";

    my $sth = $DBH->prepare_cached($sql);
    $sth->execute();
    my ($ip, $time, $service, $mac, $os, $details);
#meh 
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
        out_os($ref);
        bat;
        out ('</OPERATING_SYSTEM>');
        out ('<SERVICES>');
        tab;
        out_services($ref->{'ip'});
        bat;
        out ('</SERVICES>');
        bat;
        out ('</HOST>');
        bat;
    }
}

sub out_os {
    my ($ref) = @_;
    out ('<NAME>');
    tab;
    out_ai(gen_attribute_id($ref->{'os'}));
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

sub out_attribute_map {
    out('<ATTRIBUTE_MAP>');
    for (keys %attr){
        out('<ENTRY>');
        out_tag('ID', $attr{$_});
        out_tag('VALUE', $_);
        out('</ENTRY>');
    }
    out('</ATTRIBUTE_MAP>');
}


sub gen_attribute_id {
    my ($name) = @_;
    $attr{$name} = $ATTR_NUM++;

    return $attr{$name};
}


sub gen_vendor {
    my ($os) = @_;
    $_ = $os;
    /windows/i and return "Microsoft" or
    /linux/i and return "Linux" or
    return ucfirst $os;
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

# generate PORT IPPROTO PROTOCOL (CONFIDENCE) APPLICATION (VERSION)_
sub out_services {
    my ($ip) = @_;
    my $sql = "SELECT $SQL_IP,$SQL_TIME, service, $SQL_MAC, os, $SQL_DETAILS FROM $DB_TABLE WHERE service LIKE 'SERVICE_%' AND $SQL_IP = ?";

    my $sth = $DBH->prepare($sql);
    $sth->execute($ip);

    my $ref;
    while ($ref = $sth->fetchrow_hashref()) {
        out ("<!-- services for $ref->{'ip'} are forthcoming -->");
    }
}


# extract <operating_system>ip, os Vendor, Version, frag_policy, stream_policy,
# & all services: 
# <services><service><port><attribute_value/>
# IPPROTO, PROTOCOL <Confidence>

out_hat;
