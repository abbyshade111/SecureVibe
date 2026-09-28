#!/bin/sh
# Stops the web server, as an error nothing catches stops an app: the shell `sv` started it with
# then has nothing left to wait for, and the container exits.
echo "Content-Type: text/plain"
echo ""
echo "stopping"
killall httpd
