#!/bin/bash

echo "Launching Caltrops entrypoint"

#launch squid daemon (does not block)
/usr/sbin/squid -YCd 1 -f /etc/squid/squid.conf

echo "=============="

#buy some time for squid to start up
sleep 3

#launch caltrops
/usr/bin/python3 /opt/caltrops/caltrops.py &

#buy some time to start up the webserver
sleep 3

PORT_MIN=3128
PORT_MAX=3148

#TODO: port range for proxy connections
echo "Caltrops is listening on ports $PORT_MIN - $PORT_MAX"

sleep infinity
