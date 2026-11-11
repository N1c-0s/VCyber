#!/usr/bin/env bash
# Mise à jour de VCyber sur le VPS. À lancer en tant que `nicolas` depuis /opt/vcyber.
# Ne touche qu'au service "vcyber" : jamais à Caddy, Mosquitto ni PartyScan.
set -euo pipefail
cd "$(dirname "$0")/.."
git pull --ff-only
npm ci
npm run build:vps
npm prune --omit=dev
sudo systemctl restart vcyber
sleep 2
systemctl is-active vcyber
curl -fsS http://127.0.0.1:8790/healthz && echo " : VCyber répond"
