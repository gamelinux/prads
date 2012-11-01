/*
** This file is a part of PRADS.
**
** Copyright (C) 2009, Redpill Linpro
** Copyright (C) 2009, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
** Copyright (C) 2011, Kacper Wysocki <kacper.wysocki@redpill-linpro.com>
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
/*  P R O T O T Y P E S  ******************************************************/

output_plugin *init_log_stdout();
int init_output_stdout(output_plugin *p, const char *f, int flags);
void stdout_init (output_plugin*, const char*, int);
void stdout_arp (output_plugin*, asset *main);
void stdout_os (output_plugin*, asset *main, os_asset *os, connection*);
void stdout_service (output_plugin*, asset *main, serv_asset *service, connection*);
int end_log_stdout(output_plugin *p);
void stdout_connection (output_plugin *plugin, connection *cxt, int outputmode);
