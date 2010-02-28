/*
** This file is a part of PRADS.
**
** Copyright (C) 2009, Redpill Linpro
** Copyright (C) 2009, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

/*  I N C L U D E S  *********************************************************/
#include "../prads.h"
#include "../sys_func.h"
#include "../sig.h"
//#include "../ipfp/ipfp.h"
#include "log_init.h"
#include <stdio.h>

/*  D A T A  S T R U C T U R E S  *********************************************/
typedef struct _log_file_conf
{
    FILE *file;         /* File Reference */
    bstring filename;   /* File's OS name */
}   log_file_conf;

/*  P R O T O T Y P E S  ******************************************************/
int init_output_log_file (bstring filename);
void read_report_file (void);
int parse_raw_report (bstring line);
void file_os(asset *main, os_asset *os);
void file_service(asset *main, serv_asset *service);
void file_arp(asset *main);
int end_output_log_file (void);

