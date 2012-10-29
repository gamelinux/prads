/*
** This file is a part of PRADS.
**
** Copyright (C) 2012, Redpill Linpro
** Copyright (C) 2012, Torgeir Natvig <torgeir.natvig@redpill-linpro.com>
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
#define RINGBUFFER_ITEMS 1024
struct ring_item {
    char text[256];
};

struct log_ringbuffer {
    struct ring_item items[RINGBUFFER_ITEMS];
    unsigned int head;
    size_t element_size;
    size_t buffer_size;
};

#ifdef PRADS_H
output_plugin *init_log_ringbuffer();
int destory_log_ringbuffer (output_plugin *plugin);
void log_ringbuffer_connection (output_plugin *plugin, connection *cxt, int outputmode);
#endif
