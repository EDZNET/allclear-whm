#!/bin/sh
# Installs (or upgrades) the AllClear WHM plugin. Run as root from this folder.
set -e
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
[ -x /usr/local/cpanel/bin/register_appconfig ] || { echo "cPanel & WHM not found." >&2; exit 1; }
DIR=$(cd "$(dirname "$0")" && pwd)
CGI=/usr/local/cpanel/whostmgr/docroot/cgi/addon_allclear.cgi
LOG=/var/log/allclear.log

install -o root -g root -m 0755 "$DIR/addon_allclear.cgi" "$CGI"
mkdir -p /usr/local/cpanel/whostmgr/docroot/addon_plugins
install -o root -g root -m 0644 "$DIR/allclear.png" /usr/local/cpanel/whostmgr/docroot/addon_plugins/allclear.png
/usr/local/cpanel/bin/register_appconfig "$DIR/allclear.conf"
ln -sf "$CGI" /usr/local/sbin/allclear
[ -e "$LOG" ] || touch "$LOG"
chmod 0600 "$LOG"

echo "AllClear installed. Open WHM > Plugins > AllClear (IP unblock), or from the shell: allclear search <ip>"
