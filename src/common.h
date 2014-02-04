/* PRADS common includes */
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <pcap.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#ifdef __FreeBSD__
#include <sys/socket.h>
#define s6_addr32   __u6_addr.__u6_addr32
#endif /* __FreeBSD__ */

#endif
