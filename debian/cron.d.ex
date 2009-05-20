#
# Regular cron jobs for the prads package
#
0 4	* * *	root	[ -x /usr/bin/prads_maintenance ] && /usr/bin/prads_maintenance
