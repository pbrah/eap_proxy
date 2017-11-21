#!/bin/bash
### BEGIN INIT INFO
# Provides:          eap-proxy
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: EAP Proxy
# Description:       EAP Proxy proxies 802.1X EAPOL frames between interfaces.
### END INIT INFO

# Script author: kangtastic <kangscinate@gmail.com>

PATH="/sbin:/usr/sbin:/bin:/usr/bin"
NAME="eap_proxy"
SNAME="eap-proxy"
SVCNAME="eap-proxy"
DAEMON="/usr/sbin/$NAME"
CONFFILE="/etc/$NAME.conf"
PIDFILE="/var/run/$NAME.pid"
SVCNAME="/etc/init.d/$SVCNAME"

# LOAD_MSG=
OPTIONS=()
PHYS_IFS=()

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Exit if the configuration file is not present
[ -r "/etc/$NAME.conf" ] || exit 2

# Get names of physical network interfaces
for IFACE in /sys/class/net/*; do
   BN=$(basename $IFACE)
   readlink -f $IFACE | grep -qv "virtual" && PHYS_IFS=("${PHYS_IFS[@]}" "$BN")
done

# Parse configuration file
while read LINE; do
   # Ignore blank lines and lines prefixed with #
   TOKEN=$(echo "$LINE" | awk '{print $1}')
   ([ -z "$TOKEN" ] || [ "#" = "${TOKEN:0:1}" ]) && continue

   # Validate first 2 options as physical interface names
   if [ ${#OPTIONS[@]} -lt 2 ]; then
      for ITEM in "${PHYS_IFS[@]}"; do
         [ "$ITEM" = "$TOKEN" ] && OPTIONS=("${OPTIONS[@]}" "$TOKEN") && break
      done
      continue
   fi

   # Assuming --daemon; add it as option 3 right after the interface names
   [ ${#OPTIONS[@]} = 2 ] && OPTIONS=("${OPTIONS[@]}" "--daemon")

   # For all further options, field 1 must look like --some[[-option[-name]]...]
   TOKEN=$(echo "$LINE" |
           awk 'match($1,/^-(-[a-z]+)+$/) {print substr($1,RSTART,RLENGTH)}')
   # Ignore lines that don't look like options, --daemon, and --help
   ([ -z "$TOKEN" ] || [ "$TOKEN" = "--daemon" ] || [ "$TOKEN" = "--help" ]) &&
      continue

   # If field 1 is --pidfile, check if PIDFILE, 'PID FILE' or "PID FILE" follows
   if [ "$TOKEN" = "--pidfile" ]; then
      TOKEN2=$(echo "$LINE" | awk '{print $2}')
      if [ -n "$TOKEN2" ]; then
         if echo "$TOKEN2" | grep -qE "^'"; then  # 'PID FILE'
            TOKEN2=$(echo "$LINE" |
               awk "match(\$0,'.*'/) {print substr(\$0,RSTART+1,RLENGTH-2)}")
         elif echo "$TOKEN2" | grep -qE '^"'; then  # "PID FILE"
            TOKEN2=$(echo "$LINE" |
               awk 'match($0,/".*"/) {print substr($0,RSTART+1,RLENGTH-2)}')
         fi
         PIDFILE="$TOKEN2"  # Update PIDFILE from configuration file
         OPTIONS=("${OPTIONS[@]}" "$TOKEN" "$TOKEN2")
         continue
      fi
   fi

   OPTIONS=("${OPTIONS[@]}" "$TOKEN")
done < "$CONFFILE"

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
   # Return
   #   0 if daemon has been started
   #   1 if daemon was already running
   #   2 if daemon could not be started

   # eap_proxy does its own checks and returns the proper code on its own
   "$DAEMON" "${OPTIONS[@]}"
   return "$?"
}

#
# Function that stops the daemon/service
#
do_stop()
{
   # Return
   #   0 if daemon has been stopped
   #   1 if daemon was already stopped
   #   2 if daemon could not be stopped
   #   other if a failure occurred

   # Stop running programs named python with PID as in $PIDFILE
   start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 \
      --pidfile "$PIDFILE" --name python
   RETVAL="$?"
   [ "$RETVAL" = 2 ] && return 2

   # Send SIGKILL to any remaining python interpreters running eap_proxy
   # But if kill returns nonzero, at least one couldn't be stopped
   for PID in $(ps -ef | grep "[p]ython $DAEMON" | awk '{print $2}'); do
      kill -0 $PID && kill -9 $PID || return 2
   done

   # Many daemons don't delete their pidfiles when they exit.
   rm -f "$PIDFILE"
   return "$RETVAL"
}

case "$1" in
   start)
      [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC " "$SNAME"
      do_start
      case "$?" in
         0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
         2)   [ "$VERBOSE" != no ] && log_end_msg 1 ;;
      esac
      ;;

   stop)
      [ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$SNAME"
      do_stop
      case "$?" in
         0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
         2)   [ "$VERBOSE" != no ] && log_end_msg 1 ;;
      esac
      ;;

   status)
      status_of_proc "$EXEFILE" "$SNAME" && exit 0 || exit "$?"
      ;;

   restart|force-reload)
      log_daemon_msg "Restarting $DESC" "$SNAME"
      do_stop
      case "$?" in
         0|1)
            do_start
            case "$?" in
               0) log_end_msg 0 ;;
               # Old process is still running
               1) log_end_msg 1 ;;
               # Failed to start
               *) log_end_msg 1 ;;
            esac
            ;;
         *)
            # Failed to stop
            log_end_msg 1
            ;;
      esac
      ;;
   *)
      echo "Usage: $SVCNAME {start|stop|status|restart|force-reload}" >&2
      exit 3
      ;;
esac

exit 0
