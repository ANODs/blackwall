#!/bin/sh
# Puts BLACKWALL into the applications menu, for this user only (no root):
#   ./install.sh            copies the files to ~/.local/opt/blackwall
#   ./install.sh --remove   takes them away again
# The network permission is asked for by the app itself, at the first
# Connect, through the system's password dialog.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
dest=$HOME/.local/opt/blackwall
mkdir -p "$dest"
apps=${XDG_DATA_HOME:-$HOME/.local/share}/applications

if [ "${1:-}" = "--remove" ]; then
    [ -x "$dest/blackwall-tun" ] && "$dest/blackwall-tun" release 2>/dev/null || true
    rm -rf "$dest" "$apps/blackwall.desktop"
    echo "BLACKWALL removed"
    exit 0
fi

for f in blackwall blackwall-service blackwall-tun blackwall.png; do
    # an unchanged blackwall-tun keeps its network permission
    if [ "$f" = blackwall-tun ] && [ -f "$dest/$f" ] && cmp -s "$here/$f" "$dest/$f"; then continue; fi
    cp "$here/$f" "$dest/$f.new" && mv -f "$dest/$f.new" "$dest/$f"
done
chmod 755 "$dest/blackwall" "$dest/blackwall-service" "$dest/blackwall-tun"
mkdir -p "$apps"
sed "s|@BIN@|$dest|g" "$here/blackwall.desktop" > "$apps/blackwall.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$apps" 2>/dev/null || true
# blackwall:// links (a provider's "add to app" button) open in the app
command -v xdg-mime >/dev/null 2>&1 && xdg-mime default blackwall.desktop x-scheme-handler/blackwall 2>/dev/null || true
echo "BLACKWALL installed in $dest; it is in the applications menu"
