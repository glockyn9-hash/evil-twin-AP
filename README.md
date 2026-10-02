# EVIL-TWIN-PRO v1.0

Rogue AP (evil twin) avec portail captif de capture d'identifiants.
Usage exclusif : pentests autorisés (écrit) et labo. Le clonage de SSID
d'un réseau tiers sans autorisation est illégal.

## Install
    sudo ./install.sh

## Run (root + WiFi physique, pas d'adaptateur USB dans WSL2 par défaut)
    sudo ./venv/bin/python EVIL_TWIN_PRO.py

## Contraintes matérielles
- WSL2 ne donne pas d'accès direct aux cartes WiFi → utiliser une carte
  USB avec passthrough USB/IPD (usbipd-win) ou tester sur Linux natif/VM
  avec carte dédiée.
- La carte doit supporter AP + monitor (ex : Atheros AR9271, Ralink
  MT7612U). Vérifier : `iw list | grep -A10 "Supported interface modes"`

## Flux
1. Interface → moniteur (airmon-ng)
2. Scan airodump-ng → choix cible
3. hostapd clone le SSID, dnsmasq DNS captif (tout → portail)
4. Déauth aireplay-ng des clients du vrai AP
5. Les clients tombent sur le portail captif → creds en SQLite (/tmp/evil_twin_pro/credentials.db)
