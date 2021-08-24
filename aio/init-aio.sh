#!/bin/bash


/usr/bin/privnet-entrypoint.sh node --config-path /config --privnet &

sleep 5

/bin/neofs-ir --config /config/config-ir.yaml &

sleep 3

/bin/neofs-node --config /config/config-node.yaml 
