<?php
# --------------------------------------------------------------------------
# Copyright (C) 2010 Edward Fjellskål <edward@redpill-linpro.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# --------------------------------------------------------------------------

// prads Database Settings

$dbhost = "127.0.0.1";
$dbuser = "prads";
$dbpass = "prads";
$dbname = "prads";

// Settings

$maxRows = 20;

// Version Definition
$major = 0;
$minor = 1;
$build = 1;

// Variable Initialization

$op         = sanitize("op");         if (empty($op))         $op = "search";
$ipv        = sanitize("ipv");        if (empty($ipv))        $op = "12";
$srcip      = sanitize("srcip");      if (empty($srcip))      $srcip = "";
$dstip      = sanitize("dstip");      if (empty($dstip))      $dstip = "";
$srcport    = sanitize("srcport");    if (empty($srcport))    $srcport = "";
$dstport    = sanitize("dstport");    if (empty($dstport))    $dstport = "";
$start_date = sanitize("start_date"); if (!valdate($start_date)) $start_date = date("Y-m-d 00:00:00");
$end_date   = sanitize("end_date");   if (!valdate($end_date))   $end_date   = date("Y-m-d H:i:s");
$protocol   = sanitize("protocol");   if (empty($protocol))   $protocol = "any";

// OP Director

switch ($op) {

   case "search":

      $out = mainDisplay();
      //$data = doSessionQuery();
      //pollParse($data);
      break;
      
   default:

      $out = mainDisplay();
      break;
}

echo mainHeading() . $out . mainFooting();

// Operational Functions

function mainDisplay() {
   global $major, $minor, $build, $pollTime, $dbname, $start_date, $end_date;
   global $srcip, $dstip, $srcport, $dstport, $ipv, $protocol;

   $out .= "<div class=titleDisplay><table border=0 width=100% cellpadding=0 cellspacing=0>";
   $out .= "<form METHOD=\"GET\" NAME=\"search\" ACTION=\"\">";
   $out .= "<tr>";

   $out .= "<td width=250 valign=middle align=center><div style=\"font-size: 10px; color: #DEDEDE\">";
   $out .= "SRC <input type=text size=34 maxlength=39 bgcolor=\"#2299bb\" name=\"srcip\" value=\"";
   if (!empty($srcip) && isip4($srcip)) $out .= $srcip;
   $out .= "\">:";
   $out .= "<input type=text size=6 maxlength=5 bgcolor=\"#2299bb\" name=\"srcport\" value=\"";
   if (!empty($srcport) && isport($srcport)) $out .= $srcport;
   $out .= "\">";
   $out .= "</div>";
   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">";
   $out .= "DST <input type=text size=34 maxlength=39 bgcolor=\"#2299bb\" name=\"dstip\" value=\"";
   if (!empty($dstip) && isip4($dstip)) $out .= $dstip;
   $out .= "\">:";
   $out .= "<input type=text size=6 maxlength=5 bgcolor=\"#2299bb\" name=\"dstport\" value=\"";
   if (!empty($dstport) && isport($dstport)) $out .= $dstport;
   $out .= "\">";
   $out .= "</div></td>";

   $out .= "<td width=60 valign=middle align=center><div style=\"font-size: 10px; color: #DEDEDE\">";
   $out .= "<SELECT NAME=\"ipv\"> <OPTION VALUE=\"2\" ";
   if ($ipv == 2) $out .= "SELECTED";
   $out .= ">IPv4</OPTION><OPTION VALUE=\"10\" ";
   if ($ipv == 10) $out .= "SELECTED";
   $out .= ">IPv6</OPTION>";
   $out .= "<OPTION VALUE=\"12\" "; 
   if ($ipv == 12) $out .= "SELECTED";
   $out .= ">IPv4/6</OPTION></SELECT>";
   $out .= "</div>";
   // Select OS
   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">";
   $out .= "<SELECT NAME=\"os\">";
   // Any
   $out .= "<OPTION VALUE=\"any\"";
   if ($os == "any") $out .= "SELECTED";
   $out .= ">Any</OPTION>";
   // Linux
   $out .= "<OPTION VALUE=\"Linux\" ";
   if ($os == "Linux") $out .= "SELECTED";
   $out .= ">Linux</OPTION>";
   // OpenBSD
   $out .= "<OPTION VALUE=\"OpenBSD\" ";
   if ($os == "OpenBSD") $out .= "SELECTED";
   $out .= ">OpenBSD</OPTION>";
   // OSX
   $out .= "<OPTION VALUE=\"OSX\" ";
   if ($os == "OSX") $out .= "SELECTED";
   $out .= ">OSX</OPTION>";
   // FreeBSD
   $out .= "<OPTION VALUE=\"FreeBSD\" ";
   if ($os == "FreeBSD") $out .= "SELECTED";
   $out .= ">FreeBSD</OPTION>";
   // Windows
   $out .= "<OPTION VALUE=\"Windows\" ";
   if ($os == "Windows") $out .= "SELECTED";
   $out .= ">Windows</OPTION>";
   $out .= "</SELECT>";
   $out .= "</div></td>";

   $out .= "<td width=250 valign=middle align=center><div style=\"font-size: 10px; color: #DEDEDE\">";
   $out .= "From date<input type=text size=20 maxlength=21 bgcolor=\"#2299bb\" name=\"start_date\" value=";
   $out .= "\"" . $start_date . "\">";
   $out .= "</div>";
   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">";
   $out .= "To date <input type=text size=20 maxlength=21 bgcolor=\"#2299bb\" name=\"end_date\" value=";
   $out .= "\"" . $end_date . "\">";
   $out .= "</div></td>";

   $out .= "<td width=40 valign=middle align=center><div style=\"font-size: 10px; color: #DEDEDE\">";
   $out .= "<input TYPE=\"submit\" NAME=\"op\" VALUE=\"search\">";
   $out .= "</div></td>";
   
   $out .= "</font></td></tr></table></form></div>";
   
   $out .= "<div class=edwardTest>";
   $out .= "<table border=0 width=100% cellpadding=0 cellspacing=0><tr>";
   $out .= "<td valign=top>";
   $out .= doSearchQuery();
   $out .= "</td>";
   $out .= "</tr></table>";
   $out .= "</div>";

   return $out;
}

function mainHeading() {
   
   $out .= "<html><head><title>Passive Real-time Asset Detection System</title>";
   
   $out .= "
   
      <style type=\"text/css\">
      
      body {
         background-color: #ABABAB;
      }

      a {
         color: #000000;
      }

      .titleDisplay table {
         background: #fff url(./bluegrade.png) repeat-x;
         border: 1px solid #454545;
         padding: 2px; 
         margin: 3px;
         height: 15px;
         font-size: 12px;
      }

      .edwardTest table {
         padding: 1px;
         margin: 1px;
      }

      .eventBox {
         background: #fff url(./bluegrade.png) repeat-x;
         border: 1px solid #454545;
         padding: 2px; 
         margin: 3px;
         height: 32px;
      } 
      
      .eventBox table {
         font-size: 12px;
      }

      .eventDisplay {
         background: #CDCDCD;
         border: 1px solid #454545;
         padding: 2px; 
         margin: 3px;
         font-size: 12px;
      }

      .eventDisplay table {
         font-size: 10px;
      }

      </style>
   ";
   
   $out .= "<script LANGUAGE=\"JavaScript\">";
   
   $out .= "
      function SessionWindow(f,p) {
         window.open('\"?op='+f+'&obj='+p+'\",'Session Search','width=300,height=200,resizable=yes');
      } 
           ";
   
   $out .= "</script>";
   
   $out .= "</head><body>";
   
   return $out;
}

function mainFooting() {

   $out = "</body></html>";
   
   return $out;
}

// Functions

function doSearchQuery() {
   global $maxRows, $srcip, $dstip, $srcport, $dstport, $start_date, $end_date;
   global $protocol, $ipv;

   $siteDB = new siteDB();

   $orderBy = "start_time";

   //if ( preg_match("/^(\d){1,2}$/",$ipv) ) {
   // if ( $ipv != 2 || $ipv != 10 || $ipv !=12 ) $ipv = 12; 
   //}
   if ($protocol == "any") $protocol = "";

   $query = "";
   if ( $ipv == 2 || $ipv == 12 ) {
      $query = "select sid,sessionid,start_time,end_time,inet_ntoa(src_ip) as src_ip,
                src_port,inet_ntoa(dst_ip) as dst_ip,dst_port,ip_proto,ip_version,
                src_pkts,src_bytes,dst_pkts,dst_bytes,src_flags,dst_flags,duration
                from session where 
                start_time > '$start_date' and end_time < '$end_date' and ip_version='2' ";
      if ($ipv == 12) $srcip = $dstip = "";
      if (!empty($srcip) && isip4($srcip)) $query .= "and src_ip = inet_aton('$srcip') ";
      if (!empty($dstip) && isip4($dstip)) $query .= "and dst_ip = inet_aton('$dstip') ";
      if (!empty($srcport) && isport($srcport)) $query .= "and src_port = '$srcport' ";
      if (!empty($dstport) && isport($dstport)) $query .= "and dst_port = '$dstport' ";
      if (!empty($protocol) && isprotocol($protocol)) $query .= "and ip_proto = '$protocol' ";

      if ( $ipv != 12 ) $query .= "ORDER BY $orderBy DESC limit $maxRows;";
   }

   if ( $ipv == 12 ) $query .= " union ";

   if ( $ipv == 10 || $ipv == 12 ) {
      if ($protocol == 1) $protocol = 58;
      $query .= "select sid,sessionid,start_time,end_time,inet_ntoa6(src_ip) as src_ip,
                 src_port,inet_ntoa6(dst_ip) as dst_ip,dst_port,ip_proto,ip_version,
                 src_pkts,src_bytes,dst_pkts,dst_bytes,src_flags,dst_flags,duration
                 from session where
                 start_time > '$start_date' and ip_version='10' ";
      if ($ipv == 12) $srcip = $dstip = "";
      if (!empty($srcip) && isip6($srcip)) $query .= "and src_ip = inet_aton6('$srcip') ";
         if (!empty($dstip) && isip6($dstip)) $query .= "and dst_ip = inet_aton6('$dstip') ";
         if (!empty($srcport))  $query .= "and src_port = '$srcport' ";
         if (!empty($dstport))  $query .= "and dst_port = '$dstport' ";
         if (!empty($protocol)) $query .= "and ip_proto = '$protocol' ";

         $query .= "ORDER BY $orderBy DESC limit $maxRows;";
   }

   $siteQ = $siteDB->query($query);
   for ($i = 0; $row = mysql_fetch_row($siteQ); $i++) {

      for ($p = 0; $p < count($row); $p++) {
         $array[mysql_field_name($siteQ, $p)] = $row[$p];
      }

      $out .= "<div class=eventBox>" . eventRowFormat($array) . "</div>";

      unset($array);
   }

   $siteDB->close();

   return $out;
}

function eventRowFormat($data) {

   //$out .= "<div>";
   $out .= "<table border=0 width=100% cellpadding=0 cellspacing=0>";
   $out .= "<tr onmouseover=\"this.style.cursor=&#39;hand&#39;\" ";
   $out .= "onmouseup=\"javascript:opacity(&#39;object1&#39;, 0, 100, 1000);\" ";
   $out .= "onClick=\"javascript:SessionWindow";
   $out .= "(&#39;?op=SessionQuery&obj=object1&id=" . $data["sessionid"] . "&s=" . $data["ip_version"] . "&#39;)";
   $out .= ";\">";
   
   // Sensor
   $out .= "</td><td width=30 valign=middle align=center>";

   //$out .= "<div style=\"font-size: 10px;\">" . $data["cnt"] . "</div>";
   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">" . "fpc1" . "</div>";
   $out .= "<div style=\"font-size: 10px; text-align: center;\">Sensor</div>";

   $out .= "</td><td width=12 valign=top>";

   $out .= "&nbsp;";

   // Source IP
   $out .= "</td><td width=80 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; text-align: center; color: #DEDEDE\">" . $data["src_ip"] . "</div>";

   $out .= "<div style=\"font-size: 10px; text-align: center;\">Source IP</div>";

   $out .= "</td><td width=1 valign=top>";

   $out .= "&nbsp;";

   // Source PORT
   $out .= "</td><td width=30 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; text-align: center; color: #DEDEDE\">";

   if ($data["src_port"]) {
      $out .= $data["src_port"];
   } else {
      $out .= "0";
   }
      
   $out .= "</div>";

   $out .= "<div style=\"font-size: 10px; text-align: center;\">SrcPort</div>";

   $out .= "</td><td width=12 valign=top>";

   $out .= "&nbsp;";

   // Destination IP
   $out .= "</td><td width=80 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; text-align: center; color: #DEDEDE\">" . $data["dst_ip"] . "</div>";

   $out .= "<div style=\"font-size: 10px; text-align: center;\">Destination IP</div>";

   $out .= "</td><td width=1 valign=top>";

   $out .= "&nbsp;";

   // Destination PORT
   $out .= "</td><td width=30 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; text-align: center; color: #DEDEDE\">";

   if ($data["dst_port"]) {
      $out .= $data["dst_port"];
   } else {
      $out .= "0";
   }

   $out .= "</div>";

   $out .= "<div style=\"font-size: 10px; text-align: center;\">DstPort</div>";

   $out .= "</td><td width=15 valign=top>";

   $out .= "&nbsp;";
   
   // Protocol
   $out .= "</td><td width=20 valign=middle align=center>";
   $out .= "<div style=\"font-size: 10px; text-align: center; color: #DEDEDE\">" . $data["ip_proto"] . "</div>";
   $out .= "<div style=\"font-size: 10px; text-align: center;\">" . "Protocol" . "</div>";

   $out .= "</td><td width=12 valign=top>";

   $out .= "&nbsp;";

   // Duration
   $out .= "</td><td width=20 valign=middle align=center>";
   $out .= "<div style=\"font-size: 10px; text-align: center; color: #DEDEDE\">";
   if ($data["duration"]) {
      $out .= $data["duration"];
   } else {
      $out .= "0";
   }
   $out .= "</div>";

   $out .= "<div style=\"font-size: 10px; text-align: center;\">" . "Duration" . "</div>";

   $out .= "</td><td width=12 valign=top>";

   $out .= "&nbsp;";

   // Src_pkts
   $out .= "</td><td width=30 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">" . $data["src_pkts"] . "</div>";
   $out .= "<div style=\"font-size: 10px; text-align: center;\">src_pkts</div>";

   $out .= "</td><td width=2 valign=top>";

   $out .= "&nbsp;";

   // Dst_pkts
   $out .= "</td><td width=30 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">" . $data["dst_pkts"] . "</div>";
   $out .= "<div style=\"font-size: 10px; text-align: center;\">dst_pkts</div>";

   $out .= "</td><td width=12 valign=top>";

   $out .= "&nbsp;";

   // Src_bytes
   $out .= "</td><td width=30 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">" . $data["src_bytes"] . "</div>";
   $out .= "<div style=\"font-size: 10px; text-align: center;\">src_bytes</div>";

   $out .= "</td><td width=2 valign=top>";

   $out .= "&nbsp;";

   // Dst_bytes
   $out .= "</td><td width=30 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">" . $data["dst_bytes"] . "</div>";
   $out .= "<div style=\"font-size: 10px; text-align: center;\">dst_bytes</div>";

   $out .= "</td><td width=12 valign=top>";

   $out .= "&nbsp;";

   // Src_flags
   $out .= "</td><td width=30 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">" . $data["src_flags"] . "</div>";
   $out .= "<div style=\"font-size: 10px; text-align: center;\">src_flags</div>";

   $out .= "</td><td width=2 valign=top>";

   $out .= "&nbsp;";

   // Dst_flags
   $out .= "</td><td width=30 valign=middle align=center>";

   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">" . $data["dst_flags"] . "</div>";
   $out .= "<div style=\"font-size: 10px; text-align: center;\">dst_flags</div>";

   $out .= "</td><td width=2 valign=top>";

   $out .= "&nbsp;";

   // Time info col
   $out .= "</td><td valign=top align=right>";

   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\">Start " . $data["start_time"] . "</div>";
   $out .= "<div style=\"font-size: 10px; color: #DEDEDE\"> End  " . $data["end_time"] . "</div>";

   $out .= "</td>";
   $out .= "</tr></table>";
   //$out .= "</div>";

   return $out;
   
}

// Support Functions

function backdate($days) {
        $backdate = mktime(0, 0, 0, date("m"), date("d")-$days, date("y"));
        return date("Y-m-d", $backdate);
}

function sanitize($in) {
   return strip_tags(addslashes(getVar($in)));
}

function valdate($sd) {
   // 2009-12-22 18:44:35
   if (preg_match("/^(\d\d\d\d)-(\d\d)-(\d\d)( \d\d:\d\d:\d\d)?$/",$sd,$array)) {
      if(checkdate($array[2],$array[3],$array[1])) {
         return true;
      } else {
         return false;
      }
   } else {
      return false;
   }
}

function isport($port) {
   // 0 - 65535
   if (preg_match("/^([\d]){1,5}$/",$port) && $port >= 0 && $port <= 65535) {
      return true;
   } else {
      return false;
   }
}

function isprotocol($protocol) {
   // 0 - 255
   if (preg_match("/^([\d]){1,3}$/",$protocol) && $protocol >= 0 && $protocol <= 255) {
                return true;
        } else {
                return false;
        }
}

function isip4($ip) {
        // ddd.ddd.ddd.ddd
        if (substr_count($ip,".") == 3) {
                if (preg_match("/^([\d]{1,3}\.){3}[\d]{1,3}$/",$ip)) {
                     return true;
                }
        } else {
                return false;
        }
}

function isip6($ip) {
        // hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh
        if (substr_count($ip,":") > 1 && substr_count($ip,":") < 8 && substr_count($ip,".") == 0){
                $uip = uncompress_ipv6($ip);
                if (!ereg('^:',$uip) && !ereg(':$',$uip) && !ereg('::',$uip) ) {
                        if ( preg_match("/^([a-f\d]{4}:){7}[a-f\d]{4}$/",$uip) ) {
                                return true;
                        }
                }
        } else {
                return false;
        } 
}

function uncompress_ipv6($ip ="") {
   if(strstr($ip,"::" )) {
         $e = explode(":", $ip);
         $s = 8-sizeof($e);
         foreach ($e as $key=>$val) {
            if ($val == "") {
               for($i==0;$i<=$s;$i++) {
                  $newip[] = "0000";
            }
            } else {
               $newip[] = $val;
            }
         }
      $ip = implode(":", $newip);
   }
   return $ip;
} 

function getVar($in) {

    if (isset($_POST[$in])) {
        $out = $_POST[$in];
    } else {
        $out = $_GET[$in];
    }
    
   if (get_magic_quotes_gpc()) {
        if (is_array($out)) {
            foreach ($out as $el) {
            $array[] = stripslashes($el);
            }
            $out = $array;
        } else {
           $out = stripslashes($out);
        }    
   }
        
    return $out;
}

class siteDB {
    function siteDB() {
        global $dbhost, $dbuser, $dbpass, $dbname;

        $this->host = $dbhost;
        $this->db   = $dbname;
        $this->user = $dbuser;
        $this->pass = $dbpass;

   $this->link = mysql_connect($this->host, $this->user, $this->pass, 1);
      
        mysql_select_db($this->db);
    }

    function query($query) {
      
        if ($result = @mysql_query($query, $this->link)) {
         return $result;
        }
    }

    function close() {
      
        @mysql_close($this->link);
    }
}

?>

