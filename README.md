# PRADS #

```text
 ______
|  __  |                  __
| _____|.----..------..--|  |.-----. (tm)
|  |    |  |-'|  __  ||  _  |__  --'
|__|    |__|  |____|_||_____|______|

Passive Real-time Asset Detection system!
```

## Baut' ##

PRADS stands for `Passive Real-time Asset Detection System`. PRADS passively
listens to network traffic and gathers information about hosts and services
sending traffic. One potential use of this data is to map out your network
without performing an active scan (no packets are ever sent), allowing you to
enumerate active hosts and services. It can also be used together with your
favorite IDS/IPS setup for "event to application" correlation.

## As is! ##

This program is provided 'as is'. We take no responsibility for anything :)

## Lic ##

GPL v2 or better? See LICENSE

## Install ##

See [doc/INSTALL](doc/INSTALL)

## Usage ##

There are several ways to use PRADS.
PRADS has many commandline options, see the `prads(1)` man page.

## Example ##

`prads -i eth0 -l prads.log`

If you run the prads service, the assets it sees will be dumped into
`/var/log/prads.log` and look like this:

```text
10.43.2.181,0,54354,6,SYN,[65535:64:1:64:M1460,N,W2,N,N,T,S,E,E:P:MacOS:iPhone OS 3.1.3 (UC):link:ethernet/modem:uptime:1574hrs],0,1300882012
10.43.2.181,0,0,0,ARP (Apple),C8:BC:C8:48:65:CA,0,1300882017
```

This information can be further processed, inserted into an SQL database etc.

The general format of this data is:

```text
asset,vlan,port,proto,service,[service-info],distance,discovered

... where ...

asset        = The ip address of the asset.
vlan         = The virtual lan tag of the asset.
port         = The port number of the detected service.
proto        = The protocol number of the matching fingerprint.
service      = The "Service" detected, like: TCP-SERVICE, UDP-SERVICE, SYN, SYNACK,MAC,.....
service-info = The fingerprint that the match was done on, with info.
distance     = Distance based on guessed initial TTL (service = SYN/SYNACK)
discovered   = The timestamp when the data was collected
```

Let it sniff your network for a while and you will be able to do anomaly
detection.

## SNORT (snort.org) ##

The prads2snort script may be used to convert the prads log into a
hosts_attribute.xml file that can be used by snort to decide fragmentation
policies, for better event detection.
http://snort.org/docs/snort_manual/node189.html

## Sguil (sguil.net) ##

You can feed events from PRADS straight into sguil replacing pads by using
the sguil pads agent. PRADS supports the -f fifo argument and the 'fifo:
/path/to/fifo' configuration option to feed events into a FIFO.

## SQL database, WebGUI etc. ##

This is on the agenda. There will be a webgui to the database, for easy
browsing of your network.
