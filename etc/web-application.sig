# This file will hold signatures that will be used to
# Identify webapplications hosted on an asset.
# This will be interesting for snort/suricata users,
# so they know what web-application rules they _should_
# have enabled!
# Example:
# If you know you have wordpress on your server, Enable Snort/ET/Suricata rules:
# msg:"BACKDOOR Wordpress backdoor theme.php code execution attempt";
# msg:"BACKDOOR Wordpress backdoor feed.php code execution attempt";
# msg:"WEB-PHP Wordpress cache_lastpostdate code injection attempt";
# msg:"WEB-PHP wordpress cat parameter arbitrary file execution attempt";
# that has wordpress as the secound name in the msg tag!

# WordPress
# <meta name="generator" content="WordPress 2.0.12-alpha" /> <!-- leave this for stats please -->

# Drupal
# <script type="text/javascript" src="/misc/drupal.js?t"></script>
# old
# <style type="text/css" media="all">@import "misc/drupal.css" .... />



