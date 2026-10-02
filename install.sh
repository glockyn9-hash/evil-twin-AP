#!/bin/bash
# Installation EVIL-TWIN-PRO — Ubuntu/WSL (root requis)
set -e
echo "[*] Installation des dépendances système..."
sudo apt-get update -qq
sudo apt-get install -y hostapd dnsmasq aircrack-ng iw python3-venv
echo "[*] Venv Python..."
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
echo "[+] Terminé. Lance : sudo ./venv/bin/python EVIL_TWIN_PRO.py"
