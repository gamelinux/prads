#!/usr/bin/perl -w

# Adjusted to PRADS by Edward Fjellskaal
# Author:William Metcalf <william.metcalf@gmail.com>
# Copyright (C) 2010 Open Information Security Foundation
# http://wiki.wireshark.org/FuzzTesting
#
# Options for getting thre required perl modules:
# Ubuntu 9.10
# sudo apt-get install libdevel-gdb-perl libcapture-tiny-perl
#
# RedHatES/CentOS 5
# yum -y install cpanspec perl-Module-Build
# cpanspec --packager OISF -v -s --follow Capture::Tiny
# cpanspec --packager OISF -v -s --follow Devel::GDB
# rpmbuild --rebuild *.src.rpm
# rpm -ivh /usr/src/redhat/RPMS/noarch/perl-Devel-GDB*.rpm
# rpm -ivh /usr/src/redhat/RPMS/noarch/perl-Capture-Tiny*.rpm
#
# Fedora Core 12
# yum -y install perl-Capture-Tiny perl-Devel-GDB
#
# Other debain based versions, try the Ubunutu instructions if this doesn't work try the following.
# sudo apt-get install dh-make-perl
# mkdir fuzzmodules && cd fuzzmodules
# dh-make-perl --cpan Devel-GDB --build
# dh-make-perl --cpan Capture-Tiny --build
# sudo dpkg -i *.deb

#TODO: Figure out a better way to deal with signal handling.
#TODO: Try to determine flow/stream that caused segv by extracting from the bt and extract it from the pcap.
#TODO: E-mail notification on segv?
#TODO: Parse Valgrind output and alert on errors

use strict;
use warnings;
use Capture::Tiny 'capture';
use List::Util 'shuffle';
use Devel::GDB;
use File::Find;
use Getopt::Long;
use File::Basename;

#globals
my %config;
my @tmpfiles;
my @files;
my $PRADSbin;
my $loopnum;
my $rules;
my $logdir;
my $configfile;
my $editeratio;
my $valgrindopt;
my $shuffle;
my $useltsuri;
my $ltsuribin;
my $core_dump;

Getopt::Long::Configure("prefix_pattern=(-|--)");
GetOptions( \%config, qw(n=s r=s c=s e=s v=s p=s l=s s=s y z h help) );

&parseopts();

#Parse the options
sub parseopts {

    #display help if asked
    if ( $config{h} || $config{help} ) {
        &printhelp();
    }

    #filemask of pcaps to read?
    if ( $config{r} ) {
        @tmpfiles = <$config{r}>;
        if(@tmpfiles eq 0){
            print "parseopts: Pcap filemask was invalid we couldn't find any matching files\n";
            exit;
        }
    }
    else {
        print "parseopts: Pcap filemask not specified or doesn't exist\n";
        &printhelp();
    }

    #filemask do we have a path to PRADS bin?
    if ( $config{p} && -e $config{p} ) {
        $PRADSbin = $config{p};

        #do wrapper script detection lt-PRADS won't be created until first run but .libs/PRADS should exist.
        if ( -T $PRADSbin ) {
            open my $in, '<', $PRADSbin or die "Can't read old file: $!";
            while (<$in>) {
                if ( $_ =~
                        m/PRADS \- temporary wrapper script for \.libs\/PRADS/
                   )
                {
                    print "parseopts: PRADS bin file appears to be a wrapper script going to try to find the real bin for gdb.\n";
                    my $tmpdirname    = dirname $PRADSbin;
                    my $tmpltsuriname = $tmpdirname . "/.libs/PRADS";
                    if ( -e $tmpltsuriname && -B $tmpltsuriname ) {
                        $ltsuribin = $tmpltsuriname;
                        print "parseopts: telling gdb to use " . $ltsuribin . "\n";
                        $useltsuri = "yes";
                    }
                    last;
                }
            }
            close $in;
        }
        elsif ( -B $PRADSbin ) {
            print "parseopts: PRADS bin file checks out\n";
        }
        else {
            print "parseopts: PRADS bin file is not a text or a bin exiting.\n";
            exit;
        }
    }
    else {
        print "parseopts: Path to PRADS bin not provided or doesn't exist\n";
        &printhelp();
    }

    #number of times to loop
    if ( $config{n} ) {
        $loopnum = $config{n};
        print "parseopts: looping through the pcaps " . $loopnum . " times or until we have an error\n";
    }
    else {
        print "parseopts: looping through the pcaps forever or until we have an error\n";
        $loopnum = "infinity";
    }

    #rules file do we have a path and does it exist
    if ( $config{s} && -e $config{s} ) {
        $rules = $config{s};
        print "parseopts: telling PRADS to use rules file " . $rules . "\n";
    }
    else {
        print("parseopts: rules file not specified or doesn't exist\n");
    }

    #log dir does it exist
    if ( $config{l} && -e $config{l} ) {
        $logdir = $config{l};
        print "parseopts: using log dir " . $logdir . "\n";
    }
    else {
        $logdir = "./";
    }

    #config file do we have a path and does it exist
    if ( $config{c} && -e $config{c} ) {
        $configfile = $config{c};
        print "parseopts: telling PRADS to use the config file " . $configfile . "\n";
    }
    else {
        print "parseopts: config file not specified or doesn't exist\n";
        #&printhelp();
    }

    #% chance that a byte will be modified.
    if ( $config{e} ) {

        #valid range?
        my $tmperatio = $config{e} * 100;
        if ( $tmperatio <= 100 && $tmperatio >= 0 ) {
            $editeratio = $config{e};
            print "parseopts: using error ratio " . $editeratio . "\n";
        }
        else {
            print "parseopts: error ratio specified but outside of range. Valid range is 0.00-1.0\n";
            exit;
        }
    }
    else {
        print("parseopts: not going to fuzz pcap(s)\n");
    }

    #parse the valgrind opts
    if ( $config{v} ) {
        if ( $config{v} =~ /^(memcheck|drd|helgrind|callgrind)$/ ) {
            $valgrindopt = $config{v};
            print "parseopts: using valgrind opt " . $valgrindopt . "\n";
        }
        else {
            print "invalid valgrind opt " . $valgrindopt . "\n";
        }
    }

    #shuffle the array if we are starting multiple fuzzers at once.  GO-GO gadget shuffle
    if ( $config{y} ) {
        print "parseopts: going to shuffle the array\n";
        $shuffle = "yes";
    }
    print "******************Initialization Complete**********************\n";
    return;

}

sub printhelp {
    print "
        -h or help <this output>
        -r=<filemask for pcaps to read>
        -n=<(optional) number of iterations or if not specified will run until error>
        -c=<(optional) path to PRADS config file will be passed as -c to PRADS>
        -e=<(optional) editcap error ratio to introduce if not specified will not fuzz. Valid range for this is 0.00 - 1.0>
        -p=<path to the PRADS bin>
        -l=<(optional) log dir for output if not specified will use current directory.>
        -v=<(optional) (memcheck|drd|helgrind|callgrind) will run the command through one of the specified valgrind tools.>
        -y <shuffle the array, this is useful if running multiple instances of this script.>

        Example usage:
        First thing to do is download and build PRADS from git with -O0 so vars don't get optimized out. See the example below:
        git clone git://phalanx.openinfosecfoundation.org/oisf.git PRADSfuzz1 && cd PRADSfuzz1 && make profile

        Second thing to do is to edit prads.conf to fit your environment.

        Third go ahead and run the script.

        In the example below the script will loop forever until an error is encountered will behave in the following way.
        1.-r Process all pcaps in subdirectories of /home/somepath/pcaps/
        2.-c Tell PRADS to use the config file /home/somepath/prads.conf
        3.-y Shuffle the array of pcaps this is useful if running multiple instances of this script.
        5.-e Tell editcap to introduce a 2% error ratio, i.e. there is a 2% chance that a byte will be fuzzed see http://wiki.wireshark.org/FuzzTesting for more info.
        7.-p Use src/PRADS as our PRADS bin file. The script will determin if the argument passed is a bin file or a txt wrapper and will adjust accordingly.

        prads-wirefuzz.pl -r=/home/somepath/pcaps/*/* -c=/home/somepath/prads.conf -y -e=0.02 -p src/PRADS

        If an error is encountered a file named <fuzzedfile>ERR.txt will be created in the log dir (current dir in this example) that will contain output from stderr,stdout, and gdb.

        Take a look at the opts make it work for you environtment and from the PRADS QA team thanks for helping us make our meerkat fuzzier! ;-)\n";
        exit;
}

#escapes for filenames
foreach my $file (@tmpfiles) {
    $file =~ s/\(/\\(/g;
    $file =~ s/\)/\\)/g;
    $file =~ s/\&/\\&/g;
}

my $logfile = $logdir . "prads-wirefuzzlog.txt";
open( LOGFILE, ">>$logfile" )
|| die( print "error: Could not open logfile! $logfile\n" );

my $successcnt = 0;
while ( $successcnt < $loopnum ) {
    if ( defined $shuffle ) {
        @files = shuffle(@tmpfiles);
    }
    else {
        @files = @tmpfiles;
    }

    foreach my $file (@files) {

        #split out the path from the filename
        my $filedir  = dirname $file;
        my $filename = basename $file;
        my ( $fuzzedfile, $editcapcmd, $editcapout, $editcaperr, $editcapexit,
                $editcap_sys_signal, $editcap_sys_coredump );
        my ( $fuzzedfiledir, $fuzzedfilename, $fullcmd, $out, $err, $exit,
                $PRADS_sys_signal, $PRADS_sys_coredump );
        print "Going to work with file: $file\n";
        my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
            localtime(time);
        my $timestamp = sprintf "%4d-%02d-%02d-%02d-%02d-%02d", $year + 1900,
           $mon + 1, $mday, $hour, $min, $sec;

        if ( defined $editeratio ) {
            $fuzzedfile = $logdir . $filename . "-fuzz-" . $timestamp;
            $editcapcmd =
                "editcap -E " . $editeratio . " " . $file . " " . $fuzzedfile;
            print( "editcap: " . $editcapcmd . "\n" );
            ( $editcapout, $editcaperr ) = capture {
                system $editcapcmd;
                $editcapexit          = $? >> 8;
                $editcap_sys_signal   = $? & 127;
                $editcap_sys_coredump = $? & 128;
            };
            if ( $editcapexit ne 0 ) {

                #this could still cause us to loop forever if all pcaps are bad but it's better than nothing.
                if ( @files lt 2 ) {
                    print "editcap: had an error and this was our only pcap:" . $editcaperr . "\n";
                    exit;
                }
                else {
                    print "editcap: had an error going to the next pcap:" . $editcaperr . "\n";
                    next;
                }
            }
            elsif ( $editcap_sys_signal eq 2 ) {
                print "editcap: system() got a ctl+c we are bailing as well\n";
                exit;

            }
            else {
                print("editcap: ran successfully\n");
                print
                    "******************Editcap Complete**********************\n";
            }
        }
        else {
            $fuzzedfile = $file;
        }

        #split out the path from the filename
        $fuzzedfiledir  = dirname $fuzzedfile;
        $fuzzedfilename = basename $fuzzedfile;

        $fullcmd = "ulimit -c unlimited; ";

        if ( defined $valgrindopt ) {
            if ( $valgrindopt eq "memcheck" ) {
                $fullcmd =
                    $fullcmd
                    . "valgrind -v --log-file="
                    . $logdir
                    . $fuzzedfilename
                    . $timestamp
                    . "-memcheck-vg.log ";
            }
            elsif ( $valgrindopt eq "drd" ) {
                $fullcmd =
                    $fullcmd
                    . "valgrind  --tool=drd --var-info=yes -v --log-file="
                    . $logdir
                    . $fuzzedfilename
                    . $timestamp
                    . "-drd-vg.log ";
            }
            elsif ( $valgrindopt eq "helgrind" ) {
                $fullcmd =
                    $fullcmd
                    . "valgrind  --tool=helgrind -v --log-file="
                    . $logdir
                    . $fuzzedfilename
                    . $timestamp
                    . "-helgrind-vg.log ";
            }
            elsif ( $valgrindopt eq "callgrind" ) {
                $fullcmd =
                    $fullcmd
                    . "valgrind  --tool=callgrind -v --callgrind-out-file="
                    . $logdir
                    . $fuzzedfilename
                    . $timestamp
                    . "-callgrind-vg.log ";
            }
        }

        $fullcmd = $fullcmd . "/home/edward/GIT/prads/src/prads -r " . $fuzzedfile;
            #$fullcmd
            #. $PRADSbin . " -c "
            #. $configfile . " -r "
            #. $fuzzedfile . " -l "
            #. $logdir;
        if ( defined $configfile ) {
            $fullcmd = $fullcmd . " -c " . $configfile;
        }
        print "PRADS: $fullcmd \n";
        my $starttime = time();
        ( $out, $err ) = capture {
            system $fullcmd;
            $exit                  = $? >> 8;
            $PRADS_sys_signal   = $? & 127;
            $PRADS_sys_coredump = $? & 128;
        };

        my $stoptime  = time();
        my $timetotal = $stoptime - $starttime;
        print LOGFILE $fullcmd . ","
            . $timetotal . ","
            . $exit . ","
            . $PRADS_sys_signal . ","
            . $PRADS_sys_coredump . "\n";
        print "PRADS: exit value $exit\n";

        if ( $exit ne 0 ) {
            my $knownerr = 0;

            #fuzzer genrated some random link type we can't deal with
            if ( $err =~
                    /datalink type \d+ not \(yet\) supported in module PcapFile\./ )
            {
                print "PRADS: we matched a known error going to the next file\n";
                $knownerr = 1;
            }
            if ( $knownerr eq 1 ) {
                $successcnt++;
                print "PRADS: we have run with success " . $successcnt . " times\n";
                &clean_logs($fuzzedfilename);
            }
            else {
                my $report = $logdir . $fuzzedfilename . "ERR.txt";
                open( REPORT, ">$report" )
                    || ( print "Could not open report file! $report\n" );
                print REPORT "COMMAND:$fullcmd\n";
                print REPORT "STDERR:$err\n";
                print REPORT "EXITVAL:$exit\n";
                print REPORT "STDOUT:$out\n";

                &process_core_dump();
                if ($core_dump) {
                    print REPORT $core_dump;
                    print "core dump \n $core_dump";
                    system( "mv "
                            . $ENV{'PWD'}
                            . "/core* "
                            . $logdir
                            . $fuzzedfilename
                            . ".core" );
                }
                close(REPORT);
                exit;
            }
        }
        elsif ( $PRADS_sys_signal eq 2 ) {
            print "PRADS: system() got a ctl+c we are bailing as well\n";
            exit;
        }
        else {
            $successcnt++;
            print "PRADS: we have run with success " . $successcnt . " times\n";
            print "******************PRADS Complete**********************\n";
            &clean_logs($fuzzedfilename);
            print "******************Next Packet or Exit *******************\n";
        }
    }
}

sub process_core_dump {
    my $gdbbin;
    my $gdb       = new Devel::GDB();
    my $coremask  = $ENV{'PWD'} . "/core*";
    my @coredumps = <${coremask}>;
    if (@coredumps eq 1 ) {
        my $corefile = $coredumps[0];
        print "gdb: core dump found $corefile processesing with";
        if ( $useltsuri eq "yes" ) {
            $gdbbin = $ltsuribin;
        }
        else {
            $gdbbin = $PRADSbin;
        }
        print " the following bin file" . $gdbbin . "\n";
        $core_dump .= join '',
            $gdb->get("file $gdbbin"), $gdb->get("core $corefile"),
            $gdb->get('info threads'), $gdb->get('thread apply all bt full');
        print "gdb: core dump \n $core_dump";

    }
    elsif ( @coredumps gt 1 ) {
        print "gdb: multiple core dumps, please clear all core dumps and try the test again. We found:\n";
        foreach my $corefile (@coredumps) {
            print $corefile . "\n";
        }
    }
    else {
        print "gdb: no coredumps found returning.\n";
        print @coredumps;
        print " $#coredumps" . "\n";
    }
    print "******************GDB Complete**********************\n";
    return;
}

sub clean_logs {
    my $deleteme    = shift;
    my $deletemerge = $logdir . $deleteme;
    my $rmcmd;
    if ( defined $editeratio ) {
        if ( unlink($deletemerge) == 1 ) {
            print "clean_logs: " . $deletemerge . " deleted successfully.\n";
        }
        else {
            print "clean_logs: error " . $deletemerge . " was not deleted. You may have to delete the file manually.\n";
        }
    }

    if ( defined $valgrindopt ) {
        #uncomment the following lines if you want to remove valgrind logs
        #$rmcmd = "rm -f " . $deletemerge . "*vg.log";
        #print( "running " . $rmcmd . "\n" );
        #system("$rmcmd");
    }

    #remove unified logs for next run
    if ( unlink(<$logdir . unified*>) > 0 ) {
        print "clean_logs: deleted unifed logs for next run \n";
    }
    else {
        print "clean_logs: failed to delete unified logs\n:";
    }
    print "******************Log Cleanup Complete**********************\n";
    return;

}
