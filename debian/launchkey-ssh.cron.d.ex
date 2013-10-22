#
# Regular cron jobs for the launchkey-ssh package
#
0 4	* * *	root	[ -x /usr/bin/launchkey-ssh_maintenance ] && /usr/bin/launchkey-ssh_maintenance
