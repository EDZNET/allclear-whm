#!/bin/sh
# Removes the AllClear WHM plugin (keeps /var/log/allclear.log).
set -e
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
/usr/local/cpanel/bin/unregister_appconfig allclear || true
rm -f /usr/local/cpanel/whostmgr/docroot/cgi/addon_allclear.cgi /usr/local/cpanel/whostmgr/docroot/addon_plugins/allclear.png
if [ -L /usr/local/sbin/allclear ]; then rm -f /usr/local/sbin/allclear; fi
echo "AllClear uninstalled."
