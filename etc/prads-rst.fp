#
# prads - stray ACK signatures
# --------------------------
#
# .-------------------------------------------------------------------------.
# | The purpose of this file is to cover signatures for stray ACK packets   |
# | (established session data). This mode of operation is enabled with -XXX |
# | option and is HIGHLY EXPERIMENTAL. Please refer to p0f.fp for more      |
# | information on the metrics used and for a guide on adding new entries   |
# | to this file. This database is looking for a caring maintainer.         |
# `-------------------------------------------------------------------------'
#
# (C) Copyright 1996-2010 by Edward Fjellskål <edward@redpill-linpro.com>
#
# Submit all additions to the authors. Read p0f.fp before adding any
# signatures. Run p0f -O -C after making any modifications. This file is
# NOT compatible with SYN, SYN+ACK or RST+ modes. Use only with -O option.
#
# IMPORTANT INFORMATION ABOUT THE INTERDEPENDENCY OF SYNs AND ACKs
# ----------------------------------------------------------------
#
# Bla bla...
#
# IMPORTANT INFORMATION ABOUT DIFFERENCES IN COMPARISON TO p0f.fp:
# ----------------------------------------------------------------
#
# Bla bla...
#

## Linux
0:64:1:*:E:PZ!:Linux:2.6

## Freebsd

## Windows
0:111:1:*:E:KPA!:Windows:support.microsoft.com



