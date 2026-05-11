#!/bin/sh
mkdir -p /app/log /app/downloads
chown connector:connector /app/log /app/downloads
exec su -s /bin/sh connector -c "python connector.py"
