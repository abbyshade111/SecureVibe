#!/bin/sh
# Sends a cookie with none of the attributes that protect it, and echoes back whatever Origin it is
# given. Both are things a careless app really does; neither is anything busybox would do on its own,
# so seeing them in the probe's answers means the request and the response both travelled.
echo "Content-Type: text/html"
echo "Set-Cookie: session=abc; Path=/"
if [ -n "$HTTP_ORIGIN" ]; then
  echo "Access-Control-Allow-Origin: $HTTP_ORIGIN"
  echo "Access-Control-Allow-Credentials: true"
fi
echo ""
echo "<html><body>probe fixture</body></html>"
