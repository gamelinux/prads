#!/bin/bash
#######################################################################
# prads to dotviz script - Version 1.0
# Copyright © 2015  Andrea Trentini (www.atrent.it)
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#    or browse http://www.gnu.org/licenses/gpl.txt
#######################################################################
#
# this version connects the nodes, it just sorts services to
# group them on a per-node basis, something like this:
#
# (localhost)---(samenet1)---(samenet2)---...---(samenetM)
#  |
# (hop1router[dummy])---(hop1.1)---(hop1.2)---...---(hop1.N)
#  |
# (hop2router[dummy])---(hop2.1)---(hop2.2)---...---(hop2.O)
#  |
# (hop3router[dummy])---(hop3.1)---(hop3.2)---...---(hop3.P)
#  |
#  ...
#  |
# (hopZrouter[dummy])---(hopZ.1)---(hopZ.2)---...---(hopZ.X)
#
# it generates a dot file, then use
# xdot to view it or
# dot to convert to image
#
#######################################################################
# use csvtool?
# only if this gets very complicated
#
# it can be optimized... ;)
#######################################################################
#
#the general format for prads data is:
#asset,vlan,port,proto,service,[service-info],distance,discovered
#
### inside [service info] there is again "," !!!
### standby... temporarily solved by prads author
#
#1 asset       = The ip address of the asset.
#2 vlan        = The virtual lan tag of the asset.
#3 port        = The port number of the detected service.
#4 proto       = The protocol number of the matching fingerprint.
#5 service     = The "Service" detected, like: TCP-SERVICE, UDP-SERVICE, SYN, SYNACK,MAC,.....
#6 service-info= The fingerprint that the match was done on, with info.
#7 distance    = Distance based on guessed initial TTL (service = SYN/SYNACK)
#8 discovered  = The timestamp when the data was collected
#
#######################################################################

if
 test $# -ne 1
then
 echo Usage: $0 '<logfile from prads>'
 exit
fi
PRADSLOG=$1

FILE=$(mktemp)

# convert file to substitute internal "," in "[]" field
cat $PRADSLOG|while
 read LINE
do
 LEFT=$(echo $LINE|cut -f1 -d"[")
 MIDDLE=$(echo $LINE|cut -f2 -d"["|cut -f1 -d"]"|tr "," ";")
 RIGHT=$(echo $LINE|cut -f2 -d"]")
 echo $LEFT"["$MIDDLE"]"$RIGHT
done > $FILE

# sort on distance?
#sort -k7 -b -n -t"," $FILE
#exit

#NODES=$(cut -f1 -d"," $FILE|sort -n|uniq|grep 192.168)  # 192.168 just to test it
NODES=$(grep -v -F "asset,vlan,port,proto,service,[service-info],distance,discovered" $FILE|cut -f1 -d","|sort -n|uniq)
#echo \#Nodes: $NODES

DISTANCES=$(grep -v -F "asset,vlan,port,proto,service,[service-info],distance,discovered" $FILE|cut -f7 -d"," |sort -n|uniq)
#echo \#Distances: $DISTANCES

echo "digraph \"$FILE\" {"
#echo "node [shape=parallelogram]"
echo "graph [root=\"Distance_0\",ratio=\"1\",rankdir = \"LR\"];"

# nodes loop
for node in $NODES
do

 #echo $node \($(host $node)\);
 echo \"Node_$node\" #  |tr "." "_"

 #fields=$(grep $node $FILE|head -n 1|cut -f 2- -d"," | tr -d " "|tr "," "\n")

 echo -n "[ label = "
 echo \"$node \|

 #echo $fields\"|tr -d "[]\n"
 grep -F "$node," $FILE | cut -f 2- -d"," | tr -d " "|tr "\n" "|"|rev|cut -c2-|rev
 echo \"
 echo -n shape = record
 echo "];"

 ##	grep $node $FILE|cut -f 2,3,4,5,6,8 -d","
 #	grep $node $FILE|cut -f 2- -d","
done

# connect the dots
for dist in $DISTANCES
do
 #echo \#  === distance $dist
 if
  test "$prev"
 then
  echo Distance_$prev " ->" Distance_$dist\;
 fi
 
 for node in $(cut -f1,7 -d"," $FILE|sort|uniq|grep ",${dist}$"|cut -f1 -d",")    #repetitive, optimize?
 do
  echo -n Distance_$dist " ->"
  echo \"Node_$node\"\;
 done
 prev=$dist
done

echo "}"

# cleaning...
rm $FILE
