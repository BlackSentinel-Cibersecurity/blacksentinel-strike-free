#!/bin/bash
# BlackSentinel Strike - Docker Entrypoint
# Starts Xvfb + VNC + the application.
#
# SECURITY: VNC used to run with -nopw on a published port, so anyone who could
# reach port 5900 controlled the desktop of an offensive-security tool. It now
# needs a password: VNC_PASSWORD from .env, or a random one printed once below.
# docker compose also binds the port to 127.0.0.1; to use it from another
# machine, tunnel it:  ssh -L 5900:127.0.0.1:5900 you@your-host
# (The VNC protocol only checks the first 8 characters of the password.)
set -e

Xvfb :0 -screen 0 1920x1080x24 &
sleep 1

if [ "${#VNC_PASSWORD}" -lt 8 ]; then
  VNC_PASSWORD="$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 8)"
  echo "VNC password (shown only this once): $VNC_PASSWORD"
fi
mkdir -p "$HOME/.vnc" && chmod 700 "$HOME/.vnc"
x11vnc -storepasswd "$VNC_PASSWORD" "$HOME/.vnc/passwd" >/dev/null 2>&1
unset VNC_PASSWORD
x11vnc -display :0 -forever -shared -rfbauth "$HOME/.vnc/passwd" &
sleep 1

cd /app
exec python3 app.py
