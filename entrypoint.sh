#!/bin/bash

echo "Launching Caltrops entrypoint"

#launch squid daemon (does not block)
#debug output too
/usr/sbin/squid -YCd 1 -f /etc/squid/squid.conf

echo "=============="

#buy some time for squid to start up
sleep 3

#launch caltrops
/usr/bin/python3 /opt/caltrops/caltrops.py &

#buy some time to start up the webserver
sleep 2

PORT_MIN=13128
PORT_MAX=13148
PORT_CALTROPS=15000

echo "Caltrops is listening on ports $PORT_MIN - $PORT_MAX"
echo "Caltrops UI is accessible via port $PORT_CALTROPS"

#stay running
sleep infinity
