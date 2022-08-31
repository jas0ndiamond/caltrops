#!/bin/bash

echo "Launching Caltrops entrypoint"

#launch squid (does not block)
/usr/sbin/squid -YCd 1 -f /etc/squid/squid.conf

echo "=============="

#buy some time for squid to start up
sleep 3

#launch caltrops (blocks)
/usr/bin/python3 /opt/caltrops/caltrops.py
