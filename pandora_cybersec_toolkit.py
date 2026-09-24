#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pandora® CyberSec Toolkit — AKI_SystemDown® ©2026
==================================================
Benutzerfreundliche PyQt6-Oberfläche für gängige, auf Kali Linux bereits
installierte Analyse-Tools (nmap, nikto, whois, dig, gobuster, sqlmap, hydra).

WICHTIG: Dieses Tool startet lediglich vorhandene Kali-Bordmittel per
Subprozess. Es enthält keinerlei Exploit-Code. Die Nutzung ist ausschließlich
für eigene Systeme oder Systeme mit ausdrücklicher Erlaubnis des Eigentümers
gestattet.

Zielplattform: Raspberry Pi 4B (8GB), Kali Linux, Xfce
Abhängigkeiten: python3-pyqt6  (sudo apt install python3-pyqt6)
Optional benötigte Kali-Tools: nmap, nikto, whois, dnsutils, gobuster,
                                sqlmap, hydra
"""

import sys
import os
import re
import json
import shlex
import shutil
import signal
import base64
import tempfile
import datetime
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import Counter

from PyQt6.QtCore import Qt, QProcess, QTimer, QElapsedTimer, QThread, pyqtSignal
from PyQt6.QtGui import (
    QFont, QTextCursor, QColor, QIcon, QSyntaxHighlighter,
    QTextCharFormat, QKeySequence, QShortcut
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QLabel, QLineEdit, QPushButton,
    QTextEdit, QFormLayout, QComboBox, QFileDialog, QMessageBox,
    QStatusBar, QSplitter, QFrame, QCheckBox, QTabWidget, QPlainTextEdit
)

# matplotlib ist optional — das Tool läuft auch ohne Dashboard-Diagramme,
# falls die Bibliothek auf dem Pi (noch) nicht installiert ist.
try:
    import matplotlib
    matplotlib.use("QtAgg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    MATPLOTLIB_OK = True
except Exception:
    MATPLOTLIB_OK = False

CONFIG_DIR = Path.home() / ".config" / "pandora_cybersec"
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_FILE = CONFIG_DIR / "history.json"
LOG_DIR = CONFIG_DIR / "logs"

# Gemini-API (Google AI Studio) — nur aktiv, wenn der Nutzer einen eigenen
# API-Key hinterlegt. Es werden ausschließlich bereits erzeugte Scan-Logs
# (Text) zur Zusammenfassung/Einordnung an die API geschickt.
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_URL_TMPL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "{model}:generateContent?key={key}"
)

# --- Thermal-Guard (Raspberry Pi 4B) ---------------------------------------
# Der Pi 4B drosselt ab ~80°C automatisch den Takt und kann bei Dauerlast
# (z.B. Hydra, John, Masscan) im Sommer/ohne Kühlkörper thermisch throtteln
# oder einfrieren. Der Guard pausiert den laufenden Scan-Prozess rechtzeitig.
THERMAL_ZONE_PATH = Path("/sys/class/thermal/thermal_zone0/temp")
THERMAL_PAUSE_C = 75.0
THERMAL_RESUME_C = 68.0

# --- Log-Rotation (schont die SD-Karte des Pi) -----------------------------
MAX_LOG_FILES = 200

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
HOST_RE = re.compile(r"^(https?://)?[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(/.*)?$")

# ---------------------------------------------------------------------------
# Farbschema (Pandora-Branding)
# ---------------------------------------------------------------------------
BG_DARK      = "#1A0B28"
BG_PANEL     = "#241236"
GOLD         = "#D4AF37"
GOLD_DIM     = "#8a742a"
TERM_GREEN   = "#39FF14"
TEXT_LIGHT   = "#EDE6F5"
RED_WARN     = "#FF4C4C"

STYLE_SHEET = f"""
QMainWindow {{ background-color: {BG_DARK}; }}
QWidget {{ background-color: {BG_DARK}; color: {TEXT_LIGHT}; font-family: 'Consolas','DejaVu Sans Mono'; }}
QListWidget {{
    background-color: {BG_PANEL};
    border: 1px solid {GOLD_DIM};
    border-radius: 6px;
    padding: 4px;
}}
QListWidget::item {{ padding: 8px; border-radius: 4px; }}
QListWidget::item:selected {{ background-color: {GOLD}; color: {BG_DARK}; font-weight: bold; }}
QLineEdit, QComboBox {{
    background-color: {BG_PANEL};
    border: 1px solid {GOLD_DIM};
    border-radius: 4px;
    padding: 6px;
    color: {TEXT_LIGHT};
}}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {GOLD}; }}
QPushButton {{
    background-color: {GOLD};
    color: {BG_DARK};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
}}
QPushButton:hover {{ background-color: #e8c25a; }}
QPushButton:disabled {{ background-color: {GOLD_DIM}; color: #444; }}
QPushButton#stopBtn {{ background-color: {RED_WARN}; color: #1a0b28; }}
QPushButton#stopBtn:hover {{ background-color: #ff7a7a; }}
QTextEdit {{
    background-color: #05070a;
    color: {TERM_GREEN};
    border: 1px solid {GOLD_DIM};
    border-radius: 6px;
    font-family: 'Consolas','DejaVu Sans Mono';
    font-size: 12px;
}}
QLabel#header {{ color: {GOLD}; font-size: 20px; font-weight: bold; }}
QLabel#sub {{ color: {GOLD_DIM}; font-size: 11px; }}
QLabel {{ color: {TEXT_LIGHT}; }}
QStatusBar {{ background-color: {BG_PANEL}; color: {GOLD}; }}
QCheckBox {{ color: {TEXT_LIGHT}; }}
"""

# ---------------------------------------------------------------------------
# Tool-Definitionen: Name -> (Binary, Parameterliste, Kommando-Builder)
# Jede Parameterdefinition: (Label, Key, Typ, Default/Optionen)
# ---------------------------------------------------------------------------
TOOLS = {
    "Nmap – Portscan": {
        "bin": "nmap",
        "fields": [
            ("Ziel (IP/Host/Bereich)", "target", "text", ""),
            ("Scan-Typ", "scantype", "combo",
             ["Schnellscan (-F)", "Standard (Standardports)",
              "Alle Ports (-p-)", "Service-/Versionserkennung (-sV)",
              "OS-Erkennung (-O)", "Aggressiv (-A)"]),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["nmap"]
            + {
                "Schnellscan (-F)": ["-F"],
                "Standard (Standardports)": [],
                "Alle Ports (-p-)": ["-p-"],
                "Service-/Versionserkennung (-sV)": ["-sV"],
                "OS-Erkennung (-O)": ["-O"],
                "Aggressiv (-A)": ["-A"],
            }.get(v["scantype"], [])
            + (v["extra"].split() if v["extra"] else [])
            + [v["target"]]
        ),
    },
    "Nikto – Webserver-Scan": {
        "bin": "nikto",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["nikto", "-h", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "WHOIS – Domain-/IP-Info": {
        "bin": "whois",
        "fields": [
            ("Domain / IP", "target", "text", ""),
        ],
        "build": lambda v: ["whois", v["target"]],
    },
    "DNS-Lookup (dig)": {
        "bin": "dig",
        "fields": [
            ("Domain", "target", "text", ""),
            ("Record-Typ", "rtype", "combo",
             ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "ANY"]),
        ],
        "build": lambda v: ["dig", v["target"], v["rtype"]],
    },
    "Gobuster – Verzeichnis-/DNS-Suche": {
        "bin": "gobuster",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Wortliste (Pfad)", "wordlist", "file",
             "/usr/share/wordlists/dirb/common.txt"),
            ("Modus", "mode", "combo", ["dir", "dns", "vhost"]),
        ],
        "build": lambda v: ["gobuster", v["mode"], "-u", v["target"],
                             "-w", v["wordlist"]],
    },
    "SQLMap – SQL-Injection-Test": {
        "bin": "sqlmap",
        "fields": [
            ("Ziel-URL (mit Parameter)", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", "--batch"),
        ],
        "build": lambda v: (
            ["sqlmap", "-u", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Hydra – Login-Bruteforce (autorisiert)": {
        "bin": "hydra",
        "fields": [
            ("Ziel (IP/Host)", "target", "text", ""),
            ("Service", "service", "combo",
             ["ssh", "ftp", "http-get", "http-post-form", "rdp", "smb"]),
            ("Benutzername", "user", "text", ""),
            ("Passwortliste (Pfad)", "wordlist", "file",
             "/usr/share/wordlists/rockyou.txt"),
        ],
        "build": lambda v: ["hydra", "-l", v["user"], "-P", v["wordlist"],
                             v["target"], v["service"]],
    },
    "TheHarvester – OSINT-Sammlung": {
        "bin": "theHarvester",
        "fields": [
            ("Domain", "target", "text", ""),
            ("Quelle", "source", "combo",
             ["all", "google", "bing", "duckduckgo", "crtsh"]),
        ],
        "build": lambda v: ["theHarvester", "-d", v["target"], "-b", v["source"]],
    },
    "Netdiscover – Netzwerk-Erkennung": {
        "bin": "netdiscover",
        "needs_root": True,
        "fields": [
            ("Netzwerkbereich (z.B. 192.168.1.0/24)", "range", "text", ""),
            ("Interface", "iface", "text", "eth0"),
        ],
        "build": lambda v: ["netdiscover", "-r", v["range"], "-i", v["iface"]],
    },
    "Aircrack-ng – Handshake-Cracking": {
        "bin": "aircrack-ng",
        "fields": [
            ("Capture-Datei (.cap/.pcap)", "capfile", "file", ""),
            ("Wortliste (Pfad)", "wordlist", "file",
             "/usr/share/wordlists/rockyou.txt"),
        ],
        "build": lambda v: ["aircrack-ng", "-w", v["wordlist"], v["capfile"]],
    },
    "John the Ripper – Hash-Cracking": {
        "bin": "john",
        "fields": [
            ("Hash-Datei (Pfad)", "hashfile", "file", ""),
            ("Wortliste (Pfad)", "wordlist", "file",
             "/usr/share/wordlists/rockyou.txt"),
            ("Format (leer = auto)", "format", "text", ""),
        ],
        "build": lambda v: (
            ["john", f"--wordlist={v['wordlist']}"]
            + ([f"--format={v['format']}"] if v["format"] else [])
            + [v["hashfile"]]
        ),
    },
    "WPScan – WordPress-Scan": {
        "bin": "wpscan",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Enumerieren", "enum", "combo",
             ["vp (verwundbare Plugins)", "vt (verwundbare Themes)",
              "u (Benutzer)", "ap (alle Plugins)", "at (alle Themes)"]),
            ("Zusätzliche Flags", "extra", "text", "--random-user-agent"),
        ],
        "build": lambda v: (
            ["wpscan", "--url", v["target"], "--enumerate",
             v["enum"].split(" ")[0]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Enum4linux – SMB-/Windows-Enumeration": {
        "bin": "enum4linux",
        "fields": [
            ("Ziel (IP/Host)", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", "-a"),
        ],
        "build": lambda v: (
            ["enum4linux"]
            + (v["extra"].split() if v["extra"] else ["-a"])
            + [v["target"]]
        ),
    },
    "SMBmap – SMB-Freigaben auflisten": {
        "bin": "smbmap",
        "fields": [
            ("Ziel (IP/Host)", "target", "text", ""),
            ("Benutzername (optional)", "user", "text", ""),
            ("Passwort (optional)", "pass", "text", ""),
        ],
        "build": lambda v: (
            ["smbmap", "-H", v["target"]]
            + (["-u", v["user"]] if v["user"] else [])
            + (["-p", v["pass"]] if v["pass"] else [])
        ),
    },
    "DNSrecon – DNS-Enumeration": {
        "bin": "dnsrecon",
        "fields": [
            ("Domain", "target", "text", ""),
            ("Modus", "mode", "combo", ["std", "brt", "axfr", "goo", "zonewalk"]),
        ],
        "build": lambda v: ["dnsrecon", "-d", v["target"], "-t", v["mode"]],
    },
    "Fierce – DNS-Recon (leichtgewichtig)": {
        "bin": "fierce",
        "fields": [
            ("Domain", "target", "text", ""),
        ],
        "build": lambda v: ["fierce", "--domain", v["target"]],
    },
    "Masscan – Schneller Portscan": {
        "bin": "masscan",
        "needs_root": True,
        "fields": [
            ("Ziel (IP/Bereich)", "target", "text", ""),
            ("Ports (z.B. 1-65535)", "ports", "text", "1-1000"),
            ("Rate (Pakete/Sek.)", "rate", "text", "1000"),
        ],
        "build": lambda v: ["masscan", v["target"], "-p", v["ports"],
                             "--rate", v["rate"]],
    },
    "FFUF – Web-Fuzzing": {
        "bin": "ffuf",
        "fields": [
            ("Ziel-URL (FUZZ als Platzhalter)", "target", "text",
             "http://TARGET/FUZZ"),
            ("Wortliste (Pfad)", "wordlist", "file",
             "/usr/share/wordlists/dirb/common.txt"),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["ffuf", "-u", v["target"], "-w", v["wordlist"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "WafW00f – WAF-Erkennung": {
        "bin": "wafw00f",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
        ],
        "build": lambda v: ["wafw00f", v["target"]],
    },
    "SSLScan – TLS/SSL-Konfiguration prüfen": {
        "bin": "sslscan",
        "fields": [
            ("Ziel (Host[:Port])", "target", "text", ""),
        ],
        "build": lambda v: ["sslscan", v["target"]],
    },
    "ARP-scan – Lokales Netzwerk erkennen": {
        "bin": "arp-scan",
        "needs_root": True,
        "fields": [
            ("Interface", "iface", "text", "eth0"),
            ("Modus", "mode", "combo", ["--localnet", "Bereich angeben"]),
            ("Netzwerkbereich (falls oben gewählt)", "range", "text", ""),
        ],
        "build": lambda v: (
            ["arp-scan", "-I", v["iface"]]
            + (["--localnet"] if v["mode"] == "--localnet" else [v["range"]])
        ),
    },
    "Searchsploit – Exploit-Datenbank durchsuchen": {
        "bin": "searchsploit",
        "fields": [
            ("Suchbegriff (Software/Version)", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["searchsploit"]
            + (v["extra"].split() if v["extra"] else [])
            + v["target"].split()
        ),
    },
    "CrackMapExec – SMB/AD-Enumeration (autorisiert)": {
        "bin": "crackmapexec",
        "fields": [
            ("Ziel (IP/Bereich)", "target", "text", ""),
            ("Protokoll", "proto", "combo", ["smb", "winrm", "ssh", "ldap", "mssql"]),
            ("Benutzername (optional)", "user", "text", ""),
            ("Passwort (optional)", "pass", "text", ""),
        ],
        "build": lambda v: (
            ["crackmapexec", v["proto"], v["target"]]
            + (["-u", v["user"]] if v["user"] else [])
            + (["-p", v["pass"]] if v["pass"] else [])
        ),
    },
    "Nbtscan – NetBIOS-Namensscan": {
        "bin": "nbtscan",
        "fields": [
            ("Netzwerkbereich (z.B. 192.168.1.0/24)", "target", "text", ""),
        ],
        "build": lambda v: ["nbtscan", v["target"]],
    },
    "Tcpdump – Paketmitschnitt": {
        "bin": "tcpdump",
        "needs_root": True,
        "fields": [
            ("Interface", "iface", "text", "eth0"),
            ("Filter (BPF, optional)", "filter", "text", ""),
            ("Anzahl Pakete (0 = unbegrenzt)", "count", "text", "100"),
        ],
        "build": lambda v: (
            ["tcpdump", "-i", v["iface"], "-nn"]
            + (["-c", v["count"]] if v["count"] and v["count"] != "0" else [])
            + (shlex.split(v["filter"]) if v["filter"] else [])
        ),
    },
    "Whatweb – Technologie-Fingerprinting": {
        "bin": "whatweb",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Aggressivität (-a)", "aggro", "combo", ["1", "2", "3", "4"]),
        ],
        "build": lambda v: ["whatweb", "-a", v["aggro"], v["target"]],
    },
    "Subfinder – Subdomain-Enumeration": {
        "bin": "subfinder",
        "fields": [
            ("Domain", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", "-silent"),
        ],
        "build": lambda v: (
            ["subfinder", "-d", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Amass – Subdomain-/Asset-Enumeration": {
        "bin": "amass",
        "fields": [
            ("Domain", "target", "text", ""),
            ("Modus", "mode", "combo", ["enum", "enum -passive", "intel"]),
        ],
        "build": lambda v: (
            ["amass"] + v["mode"].split() + ["-d", v["target"]]
        ),
    },
    "Httpx – HTTP-Probe / Live-Hosts": {
        "bin": "httpx",
        "fields": [
            ("Ziel (Host/URL)", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", "-status-code -title"),
        ],
        "build": lambda v: (
            ["httpx", "-u", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Nuclei – Vulnerability-Templates-Scan": {
        "bin": "nuclei",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Templates/Tags (leer = Standard)", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["nuclei", "-u", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Dirsearch – Verzeichnis-Bruteforce": {
        "bin": "dirsearch",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Wortliste (Pfad)", "wordlist", "file",
             "/usr/share/wordlists/dirb/common.txt"),
        ],
        "build": lambda v: ["dirsearch", "-u", v["target"], "-w", v["wordlist"]],
    },
    "Feroxbuster – Rekursive Verzeichnissuche": {
        "bin": "feroxbuster",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Wortliste (Pfad)", "wordlist", "file",
             "/usr/share/wordlists/dirb/common.txt"),
        ],
        "build": lambda v: ["feroxbuster", "-u", v["target"], "-w", v["wordlist"]],
    },
    "Testssl.sh – Tiefenprüfung TLS/SSL": {
        "bin": "testssl.sh",
        "fields": [
            ("Ziel (Host[:Port])", "target", "text", ""),
        ],
        "build": lambda v: ["testssl.sh", v["target"]],
    },
    "Dnsenum – DNS-Enumeration": {
        "bin": "dnsenum",
        "fields": [
            ("Domain", "target", "text", ""),
        ],
        "build": lambda v: ["dnsenum", v["target"]],
    },

    # --- Wireless-Tools (WLAN-Adapter im Monitor-Mode erforderlich) --------
    "Airmon-ng – Monitor-Mode aktivieren": {
        "bin": "airmon-ng",
        "needs_root": True,
        "fields": [
            ("WLAN-Interface", "target", "text", "wlan0"),
        ],
        "build": lambda v: ["airmon-ng", "start", v["target"]],
    },
    "Airodump-ng – WLAN-Scan/Capture": {
        "bin": "airodump-ng",
        "needs_root": True,
        "fields": [
            ("Interface (Monitor-Mode)", "target", "text", "wlan0mon"),
            ("BSSID (optional)", "bssid", "text", ""),
            ("Kanal (optional)", "channel", "text", ""),
            ("Ausgabe-Prefix", "prefix", "text", "capture"),
        ],
        "build": lambda v: (
            ["airodump-ng"]
            + (["--bssid", v["bssid"]] if v["bssid"] else [])
            + (["--channel", v["channel"]] if v["channel"] else [])
            + ["--write", v["prefix"], v["target"]]
        ),
    },
    "Aireplay-ng – Deauth-Test (autorisiert)": {
        "bin": "aireplay-ng",
        "needs_root": True,
        "fields": [
            ("Interface (Monitor-Mode)", "target", "text", "wlan0mon"),
            ("BSSID (Access Point)", "bssid", "text", ""),
            ("Anzahl Deauth-Pakete", "count", "text", "10"),
        ],
        "build": lambda v: (
            ["aireplay-ng", "--deauth", v["count"], "-a", v["bssid"], v["target"]]
        ),
    },
    "Wifite – Automatisierter WLAN-Audit (autorisiert)": {
        "bin": "wifite",
        "needs_root": True,
        "fields": [
            ("Interface", "target", "text", "wlan0"),
            ("Ziel-BSSID (optional)", "bssid", "text", ""),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["wifite", "-i", v["target"]]
            + (["--bssid", v["bssid"]] if v["bssid"] else [])
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Reaver – WPS-PIN-Audit (autorisiert)": {
        "bin": "reaver",
        "needs_root": True,
        "fields": [
            ("Interface (Monitor-Mode)", "target", "text", "wlan0mon"),
            ("BSSID (Access Point)", "bssid", "text", ""),
            ("Zusätzliche Flags", "extra", "text", "-vv"),
        ],
        "build": lambda v: (
            ["reaver", "-i", v["target"], "-b", v["bssid"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Bully – WPS-Audit (autorisiert)": {
        "bin": "bully",
        "needs_root": True,
        "fields": [
            ("Interface (Monitor-Mode)", "target", "text", "wlan0mon"),
            ("BSSID (Access Point)", "bssid", "text", ""),
        ],
        "build": lambda v: ["bully", v["target"], "-b", v["bssid"]],
    },
    "Hcxdumptool – PMKID-/Handshake-Erfassung": {
        "bin": "hcxdumptool",
        "needs_root": True,
        "fields": [
            ("Interface (Monitor-Mode)", "target", "text", "wlan0mon"),
            ("Ausgabedatei (.pcapng)", "outfile", "text", "capture.pcapng"),
        ],
        "build": lambda v: ["hcxdumptool", "-i", v["target"], "-o", v["outfile"]],
    },
    "Kismet – Wireless-IDS/Scan": {
        "bin": "kismet",
        "needs_root": True,
        "fields": [
            ("Interface (optional)", "target", "text", ""),
        ],
        "build": lambda v: (["kismet", "-c", v["target"]] if v["target"] else ["kismet"]),
    },

    # --- Cloud-Recon-Tools --------------------------------------------------
    "Cloud_enum – Multi-Cloud Public Asset Enum": {
        "bin": "cloud_enum",
        "fields": [
            ("Schlüsselwort (Firma/Projekt)", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["cloud_enum", "-k", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "S3Scanner – AWS-S3-Bucket-Scan": {
        "bin": "s3scanner",
        "fields": [
            ("Bucket-Name/Keyword", "target", "text", ""),
        ],
        "build": lambda v: ["s3scanner", "scan", "--bucket", v["target"]],
    },
    "ScoutSuite – Cloud-Security-Audit (AWS/Azure/GCP)": {
        "bin": "scout",
        "fields": [
            ("Cloud-Provider", "provider", "combo", ["aws", "azure", "gcp"]),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["scout", v["provider"]] + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Prowler – AWS-Security-Best-Practice-Check": {
        "bin": "prowler",
        "fields": [
            ("Cloud-Provider", "provider", "combo", ["aws", "azure", "gcp", "kubernetes"]),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["prowler", v["provider"]] + (v["extra"].split() if v["extra"] else [])
        ),
    },

    # --- Mobile-/IoT-/Bluetooth-Recon --------------------------------------
    "Bettercap – Netzwerk-/BLE-Recon-Framework": {
        "bin": "bettercap",
        "needs_root": True,
        "fields": [
            ("Interface", "target", "text", "wlan0"),
            ("Modul/Eval-Befehl (optional)", "module", "text", "ble.recon on"),
        ],
        "build": lambda v: (
            ["bettercap", "-iface", v["target"]]
            + (["-eval", v["module"]] if v["module"] else [])
        ),
    },
    "Bluetoothctl – Classic-Bluetooth-Scan": {
        "bin": "bluetoothctl",
        "fields": [
            ("Scan-Dauer (Sekunden)", "target", "text", "10"),
        ],
        "build": lambda v: ["bluetoothctl", "--timeout", v["target"], "scan", "on"],
    },
    "Hcitool – Bluetooth-Scan (Classic/BLE)": {
        "bin": "hcitool",
        "needs_root": True,
        "fields": [
            ("Interface", "target", "text", "hci0"),
            ("Modus", "mode", "combo", ["scan", "lescan"]),
        ],
        "build": lambda v: ["hcitool", "-i", v["target"], v["mode"]],
    },
    "Gatttool – BLE-GATT-Enumeration": {
        "bin": "gatttool",
        "fields": [
            ("BLE-MAC-Adresse", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", "--primary"),
        ],
        "build": lambda v: (
            ["gatttool", "-b", v["target"]]
            + (v["extra"].split() if v["extra"] else ["--primary"])
        ),
    },
    "BtleJack – BLE-Sniffing/Hijacking (autorisiert)": {
        "bin": "btlejack",
        "needs_root": True,
        "fields": [
            ("BLE-Kanal/Interface", "target", "text", "0"),
        ],
        "build": lambda v: ["btlejack", "-f", v["target"]],
    },
    "Shodan CLI – IoT-/Internet-Geräte-Suche": {
        "bin": "shodan",
        "fields": [
            ("Suchbegriff/IP", "target", "text", ""),
            ("Modus", "mode", "combo", ["search", "host"]),
        ],
        "build": lambda v: ["shodan", v["mode"], v["target"]],
    },

    # --- RFID-/NFC-Recon (libnfc / Proxmark3) ------------------------------
    "Nfc-list – NFC-Tag erkennen (libnfc)": {
        "bin": "nfc-list",
        "fields": [],
        "build": lambda v: ["nfc-list"],
    },
    "Nfc-poll – NFC-Polling/Info (libnfc)": {
        "bin": "nfc-poll",
        "fields": [],
        "build": lambda v: ["nfc-poll"],
    },
    "Mfoc – Mifare-Classic Offline-Cracking (autorisiert)": {
        "bin": "mfoc",
        "fields": [
            ("Ausgabedatei (.mfd)", "outfile", "text", "dump.mfd"),
        ],
        "build": lambda v: ["mfoc", "-O", v["outfile"]],
    },
    "Mfcuk – Mifare-Classic Keyrecovery (autorisiert)": {
        "bin": "mfcuk",
        "fields": [
            ("Zusätzliche Flags", "extra", "text", "-C -R 0:60 -s 500"),
        ],
        "build": lambda v: ["mfcuk"] + (v["extra"].split() if v["extra"] else []),
    },
    "Proxmark3 – RFID/NFC-Client (autorisiert)": {
        "bin": "pm3",
        "fields": [
            ("Client-Kommando", "cmd", "text", "hf search"),
        ],
        "build": lambda v: ["pm3", "-c", v["cmd"]],
    },

    # --- Active-Directory / Kerberos (autorisiert) -------------------------
    "Kerbrute – AD-User-/Passwort-Enumeration (autorisiert)": {
        "bin": "kerbrute",
        "fields": [
            ("Domain", "domain", "text", ""),
            ("DC-IP", "target", "text", ""),
            ("Benutzerliste (Pfad)", "userlist", "file",
             "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt"),
        ],
        "build": lambda v: (
            ["kerbrute", "userenum", "-d", v["domain"], "--dc", v["target"],
             v["userlist"]]
        ),
    },
    "GetUserSPNs – Kerberoasting (Impacket, autorisiert)": {
        "bin": "GetUserSPNs.py",
        "fields": [
            ("Domain/Benutzer (DOMAIN/user:pass)", "target", "text", ""),
            ("DC-IP", "dcip", "text", ""),
            ("Zusätzliche Flags", "extra", "text", "-request"),
        ],
        "build": lambda v: (
            ["GetUserSPNs.py", v["target"]]
            + (["-dc-ip", v["dcip"]] if v["dcip"] else [])
            + (v["extra"].split() if v["extra"] else ["-request"])
        ),
    },
    "GetNPUsers – AS-REP-Roasting (Impacket, autorisiert)": {
        "bin": "GetNPUsers.py",
        "fields": [
            ("Domain", "domain", "text", ""),
            ("Benutzerliste (Pfad)", "userlist", "file", ""),
            ("DC-IP (optional)", "target", "text", ""),
        ],
        "build": lambda v: (
            ["GetNPUsers.py", f"{v['domain']}/", "-usersfile", v["userlist"],
             "-no-pass"]
            + (["-dc-ip", v["target"]] if v["target"] else [])
        ),
    },
    "Secretsdump – Credential-Dump (Impacket, autorisiert)": {
        "bin": "secretsdump.py",
        "fields": [
            ("Ziel (DOMAIN/user:pass@ip)", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["secretsdump.py", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "BloodHound-python – AD-Angriffspfad-Mapping (autorisiert)": {
        "bin": "bloodhound-python",
        "fields": [
            ("Domain", "domain", "text", ""),
            ("Benutzer:Passwort", "cred", "text", ""),
            ("DC-IP", "target", "text", ""),
        ],
        "build": lambda v: (
            ["bloodhound-python", "-d", v["domain"], "-u",
             v["cred"].split(":")[0] if ":" in v["cred"] else v["cred"],
             "-p", v["cred"].split(":", 1)[1] if ":" in v["cred"] else "",
             "-ns", v["target"], "-c", "All"]
        ),
    },

    # --- Web-API-Fuzzing -----------------------------------------------------
    "Kiterunner – API-Endpoint-Discovery": {
        "bin": "kr",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Routen-Wortliste (Pfad)", "wordlist", "file",
             "/usr/share/wordlists/kiterunner/routes-large.kite"),
        ],
        "build": lambda v: ["kr", "scan", v["target"], "-w", v["wordlist"]],
    },
    "Arjun – HTTP-Parameter-Discovery": {
        "bin": "arjun",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["arjun", "-u", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "X8 – Hidden-Parameter-Fuzzing": {
        "bin": "x8",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Wortliste (Pfad)", "wordlist", "file",
             "/usr/share/wordlists/dirb/common.txt"),
        ],
        "build": lambda v: ["x8", "-u", v["target"], "-w", v["wordlist"]],
    },
    "Schemathesis – OpenAPI/Swagger-Fuzzing": {
        "bin": "schemathesis",
        "fields": [
            ("OpenAPI-Schema (URL oder Pfad)", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", "--checks all"),
        ],
        "build": lambda v: (
            ["schemathesis", "run", v["target"]]
            + (v["extra"].split() if v["extra"] else ["--checks", "all"])
        ),
    },

    # --- Forensik & Incident Response ---------------------------------------
    "Volatility3 – Memory-Forensik": {
        "bin": "vol",
        "fields": [
            ("Speicherabbild (Pfad)", "target", "file", ""),
            ("Plugin", "plugin", "combo",
             ["windows.pslist", "windows.pstree", "windows.netscan",
              "windows.cmdline", "windows.filescan", "linux.pslist",
              "linux.bash"]),
        ],
        "build": lambda v: ["vol", "-f", v["target"], v["plugin"]],
    },
    "Binwalk – Firmware-/Datei-Signaturanalyse": {
        "bin": "binwalk",
        "fields": [
            ("Datei (Pfad)", "target", "file", ""),
            ("Modus", "mode", "combo",
             ["Signaturanalyse", "Extrahieren (-e)", "Entropie-Analyse (-E)"]),
        ],
        "build": lambda v: (
            ["binwalk"]
            + {
                "Signaturanalyse": [],
                "Extrahieren (-e)": ["-e"],
                "Entropie-Analyse (-E)": ["-E"],
            }.get(v["mode"], [])
            + [v["target"]]
        ),
    },
    "Foremost – Datei-Carving aus Images": {
        "bin": "foremost",
        "fields": [
            ("Quell-Image (Pfad)", "target", "file", ""),
            ("Ausgabeverzeichnis", "outdir", "text", "output_foremost"),
        ],
        "build": lambda v: ["foremost", "-i", v["target"], "-o", v["outdir"]],
    },
    "ExifTool – Metadaten-Extraktion": {
        "bin": "exiftool",
        "fields": [
            ("Datei (Pfad)", "target", "file", ""),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["exiftool"]
            + (v["extra"].split() if v["extra"] else [])
            + [v["target"]]
        ),
    },
    "Bulk_extractor – Artefakt-Extraktion aus Images": {
        "bin": "bulk_extractor",
        "fields": [
            ("Quell-Image (Pfad)", "target", "file", ""),
            ("Ausgabeverzeichnis", "outdir", "text", "bulk_output"),
        ],
        "build": lambda v: ["bulk_extractor", "-o", v["outdir"], v["target"]],
    },
    "Chkrootkit – Rootkit-Erkennung": {
        "bin": "chkrootkit",
        "needs_root": True,
        "fields": [
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: ["chkrootkit"] + (v["extra"].split() if v["extra"] else []),
    },
    "Rkhunter – Rootkit Hunter": {
        "bin": "rkhunter",
        "needs_root": True,
        "fields": [
            ("Modus", "mode", "combo", ["--check", "--update", "--propupd"]),
        ],
        "build": lambda v: ["rkhunter", v["mode"]],
    },
    "Dc3dd – Forensisches Imaging mit Hashing (autorisiert)": {
        "bin": "dc3dd",
        "needs_root": True,
        "fields": [
            ("Quelle (Gerät/Datei)", "target", "text", "/dev/sdX"),
            ("Ausgabedatei", "outfile", "text", "image.dd"),
            ("Hash-Algorithmus", "hashalgo", "combo", ["sha256", "md5", "sha1"]),
        ],
        "build": lambda v: (
            ["dc3dd", f"if={v['target']}", f"of={v['outfile']}",
             f"hash={v['hashalgo']}"]
        ),
    },

    # --- Malware-Analyse / Reverse Engineering -------------------------------
    "YARA – Malware-Signatur-Scan": {
        "bin": "yara",
        "fields": [
            ("YARA-Regel(n) (Pfad)", "rulesfile", "file",
             "/usr/share/yara-rules/index.yar"),
            ("Ziel (Datei/Verzeichnis)", "target", "file", ""),
            ("Zusätzliche Flags", "extra", "text", "-r"),
        ],
        "build": lambda v: (
            ["yara"]
            + (v["extra"].split() if v["extra"] else ["-r"])
            + [v["rulesfile"], v["target"]]
        ),
    },
    "Radare2 – Statische Binäranalyse": {
        "bin": "r2",
        "fields": [
            ("Binärdatei (Pfad)", "target", "file", ""),
            ("Befehle (r2 -c, ';'-getrennt)", "cmds", "text", "aaa;afl"),
        ],
        "build": lambda v: ["r2", "-q", "-c", v["cmds"], v["target"]],
    },
    "Objdump – Disassembly": {
        "bin": "objdump",
        "fields": [
            ("Binärdatei (Pfad)", "target", "file", ""),
            ("Modus", "mode", "combo",
             ["Disassemblieren (-d)", "Alle Header (-x)", "Symboltabelle (-t)"]),
        ],
        "build": lambda v: (
            ["objdump"]
            + {
                "Disassemblieren (-d)": ["-d"],
                "Alle Header (-x)": ["-x"],
                "Symboltabelle (-t)": ["-t"],
            }.get(v["mode"], ["-d"])
            + [v["target"]]
        ),
    },
    "Strings – Zeichenketten aus Binärdatei extrahieren": {
        "bin": "strings",
        "fields": [
            ("Datei (Pfad)", "target", "file", ""),
            ("Mindestlänge", "minlen", "text", "4"),
        ],
        "build": lambda v: ["strings", "-n", v["minlen"], v["target"]],
    },
    "Capa – Capability-Detection in Binaries": {
        "bin": "capa",
        "fields": [
            ("Binärdatei (Pfad)", "target", "file", ""),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["capa"] + (v["extra"].split() if v["extra"] else []) + [v["target"]]
        ),
    },
    "Ssdeep – Fuzzy-Hashing / Ähnlichkeitsvergleich": {
        "bin": "ssdeep",
        "fields": [
            ("Datei/Verzeichnis (Pfad)", "target", "file", ""),
            ("Modus", "mode", "combo",
             ["Hash berechnen", "Rekursiv vergleichen (-r)"]),
        ],
        "build": lambda v: (
            ["ssdeep"]
            + (["-r"] if v["mode"].startswith("Rekursiv") else [])
            + [v["target"]]
        ),
    },
    "UPX – Unpacking gepackter Binärdateien": {
        "bin": "upx",
        "fields": [
            ("Gepackte Datei (Pfad)", "target", "file", ""),
            ("Modus", "mode", "combo", ["Entpacken (-d)", "Info (-l)"]),
        ],
        "build": lambda v: (
            ["upx", "-d" if v["mode"].startswith("Entpacken") else "-l", v["target"]]
        ),
    },

    # --- Passwort-/Hash-/Krypto-Tools ---------------------------------------
    "Hashcat – GPU-beschleunigtes Hash-Cracking": {
        "bin": "hashcat",
        "fields": [
            ("Hash-Datei (Pfad)", "hashfile", "file", ""),
            ("Hash-Modus (-m)", "mode", "text", "0"),
            ("Angriffsart (-a)", "attack", "combo",
             ["0 – Wörterbuch", "3 – Bruteforce-Maske"]),
            ("Wortliste / Maske", "wordlist", "file",
             "/usr/share/wordlists/rockyou.txt"),
        ],
        "build": lambda v: (
            ["hashcat", "-m", v["mode"], "-a", v["attack"].split(" ")[0],
             v["hashfile"], v["wordlist"]]
        ),
    },
    "Hashid – Hash-Typ-Erkennung": {
        "bin": "hashid",
        "fields": [
            ("Hash-Wert", "target", "text", ""),
        ],
        "build": lambda v: ["hashid", v["target"]],
    },
    "CeWL – Wortlisten-Generator aus Webseite": {
        "bin": "cewl",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Mindestlänge", "minlen", "text", "5"),
            ("Ausgabedatei", "outfile", "text", "wordlist.txt"),
        ],
        "build": lambda v: (
            ["cewl", v["target"], "-m", v["minlen"], "-w", v["outfile"]]
        ),
    },
    "Crunch – Wortlisten-Generator": {
        "bin": "crunch",
        "fields": [
            ("Min-Länge", "minlen", "text", "8"),
            ("Max-Länge", "maxlen", "text", "8"),
            ("Zeichensatz", "charset", "text",
             "abcdefghijklmnopqrstuvwxyz0123456789"),
            ("Ausgabedatei", "outfile", "text", "wordlist.txt"),
        ],
        "build": lambda v: (
            ["crunch", v["minlen"], v["maxlen"], v["charset"], "-o", v["outfile"]]
        ),
    },
    "Medusa – Login-Bruteforce (autorisiert)": {
        "bin": "medusa",
        "fields": [
            ("Ziel (IP/Host)", "target", "text", ""),
            ("Service (-M)", "service", "combo",
             ["ssh", "ftp", "http", "smbnt", "telnet"]),
            ("Benutzername (-u)", "user", "text", ""),
            ("Passwortliste (-P)", "wordlist", "file",
             "/usr/share/wordlists/rockyou.txt"),
        ],
        "build": lambda v: (
            ["medusa", "-h", v["target"], "-u", v["user"], "-P", v["wordlist"],
             "-M", v["service"]]
        ),
    },
    "OpenSSL – Hash-/Digest-Berechnung": {
        "bin": "openssl",
        "fields": [
            ("Datei (Pfad)", "target", "file", ""),
            ("Algorithmus", "algo", "combo", ["sha256", "sha1", "md5", "sha512"]),
        ],
        "build": lambda v: ["openssl", v["algo"], v["target"]],
    },

    # --- Container-/Kubernetes-Security --------------------------------------
    "Trivy – Container-/IaC-Vulnerability-Scanner": {
        "bin": "trivy",
        "fields": [
            ("Ziel (Image/Verzeichnis)", "target", "text", ""),
            ("Scan-Typ", "scantype", "combo", ["image", "fs", "config", "repo"]),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["trivy", v["scantype"], v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Grype – Vulnerability-Scanner für Container-Images": {
        "bin": "grype",
        "fields": [
            ("Image/Verzeichnis", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["grype", v["target"]] + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Kube-hunter – Kubernetes-Penetrationstest": {
        "bin": "kube-hunter",
        "fields": [
            ("Ziel (IP/Host, --remote)", "target", "text", ""),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["kube-hunter", "--remote", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Kube-bench – CIS-Benchmark-Check für Kubernetes": {
        "bin": "kube-bench",
        "needs_root": True,
        "fields": [
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: ["kube-bench", "run"] + (v["extra"].split() if v["extra"] else []),
    },
    "Kubeaudit – Kubernetes-Sicherheitsaudit": {
        "bin": "kubeaudit",
        "fields": [
            ("Prüfmodus", "mode", "combo",
             ["all", "privileged", "capabilities", "non-root", "image-tag"]),
        ],
        "build": lambda v: ["kubeaudit", v["mode"]],
    },
    "Checkov – IaC-Security-Scan": {
        "bin": "checkov",
        "fields": [
            ("Verzeichnis/Datei", "target", "text", "."),
        ],
        "build": lambda v: ["checkov", "-d", v["target"]],
    },
    "Docker Bench Security – Docker-CIS-Benchmark": {
        "bin": "docker-bench-security.sh",
        "needs_root": True,
        "fields": [],
        "build": lambda v: ["docker-bench-security.sh"],
    },

    # --- Ergänzungen: Web-/Netzwerk-Recon -------------------------------------
    "OWASP ZAP (Baseline) – Automatisierter Web-App-Scan": {
        "bin": "zap-baseline.py",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["zap-baseline.py", "-t", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },
    "Commix – Command-Injection-Test": {
        "bin": "commix",
        "fields": [
            ("Ziel-URL", "target", "text", "http://"),
            ("Zusätzliche Flags", "extra", "text", "--batch"),
        ],
        "build": lambda v: (
            ["commix", "--url", v["target"]]
            + (v["extra"].split() if v["extra"] else ["--batch"])
        ),
    },

    # --- Ergänzungen: Wireless ------------------------------------------------
    "Wifiphisher – Rogue-AP-/Phishing-Framework (autorisiert)": {
        "bin": "wifiphisher",
        "needs_root": True,
        "fields": [
            ("Interface", "target", "text", "wlan0"),
            ("Zusätzliche Flags", "extra", "text", ""),
        ],
        "build": lambda v: (
            ["wifiphisher", "-i", v["target"]]
            + (v["extra"].split() if v["extra"] else [])
        ),
    },

    # --- Ergänzungen: Cloud ----------------------------------------------------
    "CloudFox – Cloud-Pentest-Enumeration": {
        "bin": "cloudfox",
        "fields": [
            ("Provider/Kommando", "cmd", "text", "aws all-checks"),
        ],
        "build": lambda v: ["cloudfox"] + v["cmd"].split(),
    },

    # --- Ergänzungen: Mobile-/IoT-/Bluetooth ------------------------------------
    "Spooftooph – Bluetooth-Spoofing (autorisiert)": {
        "bin": "spooftooph",
        "needs_root": True,
        "fields": [
            ("Interface", "target", "text", "hci0"),
        ],
        "build": lambda v: ["spooftooph", "-i", v["target"], "-R"],
    },

    # --- Ergänzungen: Active-Directory -------------------------------------------
    "Responder – LLMNR-/NBT-NS-/mDNS-Poisoning (autorisiert)": {
        "bin": "responder",
        "needs_root": True,
        "fields": [
            ("Interface", "target", "text", "eth0"),
        ],
        "build": lambda v: ["responder", "-I", v["target"]],
    },
}


# ---------------------------------------------------------------------------
# Automationen: Scan-Ketten, die mehrere Tools nacheinander mit demselben
# Ziel ausführen. Jeder Eintrag verweist auf Tool-Namen aus TOOLS, die ein
# "target"-Feld besitzen.
# ---------------------------------------------------------------------------
WORKFLOWS = {
    "Web-Rezon: Nmap → Nikto → Gobuster": [
        "Nmap – Portscan",
        "Nikto – Webserver-Scan",
        "Gobuster – Verzeichnis-/DNS-Suche",
    ],
    "Web-Vollcheck: Nmap → Nikto → WafW00f → SSLScan → WPScan": [
        "Nmap – Portscan",
        "Nikto – Webserver-Scan",
        "WafW00f – WAF-Erkennung",
        "SSLScan – TLS/SSL-Konfiguration prüfen",
        "WPScan – WordPress-Scan",
    ],
    "DNS-Rezon: WHOIS → dig → DNSrecon → Fierce": [
        "WHOIS – Domain-/IP-Info",
        "DNS-Lookup (dig)",
        "DNSrecon – DNS-Enumeration",
        "Fierce – DNS-Recon (leichtgewichtig)",
    ],
    "SMB-Rezon: Nmap → Enum4linux → SMBmap → Nbtscan": [
        "Nmap – Portscan",
        "Enum4linux – SMB-/Windows-Enumeration",
        "SMBmap – SMB-Freigaben auflisten",
        "Nbtscan – NetBIOS-Namensscan",
    ],
    "Netzwerk-Discovery: ARP-scan → Netdiscover → Nmap": [
        "ARP-scan – Lokales Netzwerk erkennen",
        "Netdiscover – Netzwerk-Erkennung",
        "Nmap – Portscan",
    ],
    "TLS/WAF-Audit: Nmap → SSLScan → WafW00f": [
        "Nmap – Portscan",
        "SSLScan – TLS/SSL-Konfiguration prüfen",
        "WafW00f – WAF-Erkennung",
    ],
    "AD/SMB-Tiefenscan: Nmap → CrackMapExec → Enum4linux → SMBmap": [
        "Nmap – Portscan",
        "CrackMapExec – SMB/AD-Enumeration (autorisiert)",
        "Enum4linux – SMB-/Windows-Enumeration",
        "SMBmap – SMB-Freigaben auflisten",
    ],
    "Subdomain-Rezon: Subfinder → Amass → Httpx → Nmap": [
        "Subfinder – Subdomain-Enumeration",
        "Amass – Subdomain-/Asset-Enumeration",
        "Httpx – HTTP-Probe / Live-Hosts",
        "Nmap – Portscan",
    ],
    "Web-Tiefenscan: Httpx → Whatweb → Nuclei → Nikto": [
        "Httpx – HTTP-Probe / Live-Hosts",
        "Whatweb – Technologie-Fingerprinting",
        "Nuclei – Vulnerability-Templates-Scan",
        "Nikto – Webserver-Scan",
    ],
    "Verzeichnis-Vollscan: Gobuster → Dirsearch → Feroxbuster → FFUF": [
        "Gobuster – Verzeichnis-/DNS-Suche",
        "Dirsearch – Verzeichnis-Bruteforce",
        "Feroxbuster – Rekursive Verzeichnissuche",
        "FFUF – Web-Fuzzing",
    ],
    "TLS-Tiefenaudit: SSLScan → Testssl.sh → WafW00f": [
        "SSLScan – TLS/SSL-Konfiguration prüfen",
        "Testssl.sh – Tiefenprüfung TLS/SSL",
        "WafW00f – WAF-Erkennung",
    ],
    "OSINT-Vollscan: TheHarvester → Subfinder → Amass → WHOIS": [
        "TheHarvester – OSINT-Sammlung",
        "Subfinder – Subdomain-Enumeration",
        "Amass – Subdomain-/Asset-Enumeration",
        "WHOIS – Domain-/IP-Info",
    ],
    "Vuln-Kette: Nmap → Nuclei → Searchsploit": [
        "Nmap – Portscan",
        "Nuclei – Vulnerability-Templates-Scan",
        "Searchsploit – Exploit-Datenbank durchsuchen",
    ],
    "DNS-Tiefenscan: WHOIS → dig → DNSrecon → Dnsenum → Fierce": [
        "WHOIS – Domain-/IP-Info",
        "DNS-Lookup (dig)",
        "DNSrecon – DNS-Enumeration",
        "Dnsenum – DNS-Enumeration",
        "Fierce – DNS-Recon (leichtgewichtig)",
    ],
    "Rezon-Gesamtkette: Subfinder → Httpx → Nmap → Nikto → Nuclei": [
        "Subfinder – Subdomain-Enumeration",
        "Httpx – HTTP-Probe / Live-Hosts",
        "Nmap – Portscan",
        "Nikto – Webserver-Scan",
        "Nuclei – Vulnerability-Templates-Scan",
    ],
    "Netzwerk-Vollcheck: ARP-scan → Netdiscover → Nmap → Masscan": [
        "ARP-scan – Lokales Netzwerk erkennen",
        "Netdiscover – Netzwerk-Erkennung",
        "Nmap – Portscan",
        "Masscan – Schneller Portscan",
    ],
    "Wordpress-Tiefenscan: Whatweb → WPScan → Nuclei → Nikto": [
        "Whatweb – Technologie-Fingerprinting",
        "WPScan – WordPress-Scan",
        "Nuclei – Vulnerability-Templates-Scan",
        "Nikto – Webserver-Scan",
    ],
    "Wireless-Rezon: Airmon-ng → Airodump-ng → Kismet": [
        "Airmon-ng – Monitor-Mode aktivieren",
        "Airodump-ng – WLAN-Scan/Capture",
        "Kismet – Wireless-IDS/Scan",
    ],
    "WLAN-Sicherheitsaudit (autorisiert): Airmon-ng → Wifite → Aircrack-ng": [
        "Airmon-ng – Monitor-Mode aktivieren",
        "Wifite – Automatisierter WLAN-Audit (autorisiert)",
        "Aircrack-ng – Handshake-Cracking",
    ],
    "WPS-Audit (autorisiert): Airmon-ng → Reaver → Bully": [
        "Airmon-ng – Monitor-Mode aktivieren",
        "Reaver – WPS-PIN-Audit (autorisiert)",
        "Bully – WPS-Audit (autorisiert)",
    ],
    "PMKID-Erfassung: Airmon-ng → Hcxdumptool → Aircrack-ng": [
        "Airmon-ng – Monitor-Mode aktivieren",
        "Hcxdumptool – PMKID-/Handshake-Erfassung",
        "Aircrack-ng – Handshake-Cracking",
    ],
    "Cloud-Rezon: Cloud_enum → S3Scanner": [
        "Cloud_enum – Multi-Cloud Public Asset Enum",
        "S3Scanner – AWS-S3-Bucket-Scan",
    ],
    "Cloud-Sicherheitsaudit: ScoutSuite → Prowler": [
        "ScoutSuite – Cloud-Security-Audit (AWS/Azure/GCP)",
        "Prowler – AWS-Security-Best-Practice-Check",
    ],
    "Cloud-Gesamtcheck: Cloud_enum → S3Scanner → ScoutSuite → Prowler": [
        "Cloud_enum – Multi-Cloud Public Asset Enum",
        "S3Scanner – AWS-S3-Bucket-Scan",
        "ScoutSuite – Cloud-Security-Audit (AWS/Azure/GCP)",
        "Prowler – AWS-Security-Best-Practice-Check",
    ],
    "Bluetooth-Rezon: Hcitool → Bluetoothctl → Gatttool": [
        "Hcitool – Bluetooth-Scan (Classic/BLE)",
        "Bluetoothctl – Classic-Bluetooth-Scan",
        "Gatttool – BLE-GATT-Enumeration",
    ],
    "BLE-Sicherheitsaudit (autorisiert): Bettercap → Hcitool → BtleJack": [
        "Bettercap – Netzwerk-/BLE-Recon-Framework",
        "Hcitool – Bluetooth-Scan (Classic/BLE)",
        "BtleJack – BLE-Sniffing/Hijacking (autorisiert)",
    ],
    "IoT-Netzwerkscan: Nmap → Shodan CLI → Bettercap": [
        "Nmap – Portscan",
        "Shodan CLI – IoT-/Internet-Geräte-Suche",
        "Bettercap – Netzwerk-/BLE-Recon-Framework",
    ],
    "RFID/NFC-Rezon: Nfc-list → Nfc-poll": [
        "Nfc-list – NFC-Tag erkennen (libnfc)",
        "Nfc-poll – NFC-Polling/Info (libnfc)",
    ],
    "Mifare-Sicherheitsaudit (autorisiert): Nfc-list → Mfcuk → Mfoc": [
        "Nfc-list – NFC-Tag erkennen (libnfc)",
        "Mfcuk – Mifare-Classic Keyrecovery (autorisiert)",
        "Mfoc – Mifare-Classic Offline-Cracking (autorisiert)",
    ],
    "Kerberoasting-Kette (autorisiert): Kerbrute → GetUserSPNs → John the Ripper": [
        "Kerbrute – AD-User-/Passwort-Enumeration (autorisiert)",
        "GetUserSPNs – Kerberoasting (Impacket, autorisiert)",
        "John the Ripper – Hash-Cracking",
    ],
    "AS-REP-Roasting-Kette (autorisiert): Kerbrute → GetNPUsers → John the Ripper": [
        "Kerbrute – AD-User-/Passwort-Enumeration (autorisiert)",
        "GetNPUsers – AS-REP-Roasting (Impacket, autorisiert)",
        "John the Ripper – Hash-Cracking",
    ],
    "AD-Tiefenrezon (autorisiert): BloodHound-python → CrackMapExec → Enum4linux": [
        "BloodHound-python – AD-Angriffspfad-Mapping (autorisiert)",
        "CrackMapExec – SMB/AD-Enumeration (autorisiert)",
        "Enum4linux – SMB-/Windows-Enumeration",
    ],
    "AD-Credential-Kette (autorisiert): Nmap → CrackMapExec → Secretsdump": [
        "Nmap – Portscan",
        "CrackMapExec – SMB/AD-Enumeration (autorisiert)",
        "Secretsdump – Credential-Dump (Impacket, autorisiert)",
    ],
    "API-Rezon: Httpx → Kiterunner → Arjun": [
        "Httpx – HTTP-Probe / Live-Hosts",
        "Kiterunner – API-Endpoint-Discovery",
        "Arjun – HTTP-Parameter-Discovery",
    ],
    "API-Fuzzing-Vollkette: Kiterunner → Arjun → X8 → Nuclei": [
        "Kiterunner – API-Endpoint-Discovery",
        "Arjun – HTTP-Parameter-Discovery",
        "X8 – Hidden-Parameter-Fuzzing",
        "Nuclei – Vulnerability-Templates-Scan",
    ],
    "API-Schema-Audit: Schemathesis → Nuclei": [
        "Schemathesis – OpenAPI/Swagger-Fuzzing",
        "Nuclei – Vulnerability-Templates-Scan",
    ],
    "Datei-Forensik: Binwalk → ExifTool → YARA": [
        "Binwalk – Firmware-/Datei-Signaturanalyse",
        "ExifTool – Metadaten-Extraktion",
        "YARA – Malware-Signatur-Scan",
    ],
    "Statische Malware-Analyse: Strings → Objdump → Capa → YARA": [
        "Strings – Zeichenketten aus Binärdatei extrahieren",
        "Objdump – Disassembly",
        "Capa – Capability-Detection in Binaries",
        "YARA – Malware-Signatur-Scan",
    ],
    "Container-Image-Audit: Trivy → Grype": [
        "Trivy – Container-/IaC-Vulnerability-Scanner",
        "Grype – Vulnerability-Scanner für Container-Images",
    ],
    "Kubernetes-Sicherheitsaudit: Kube-hunter → Kubeaudit → Kube-bench": [
        "Kube-hunter – Kubernetes-Penetrationstest",
        "Kubeaudit – Kubernetes-Sicherheitsaudit",
        "Kube-bench – CIS-Benchmark-Check für Kubernetes",
    ],
    "Web-Angriffsflächen-Erweiterung: Nikto → Commix → OWASP ZAP Baseline": [
        "Nikto – Webserver-Scan",
        "Commix – Command-Injection-Test",
        "OWASP ZAP (Baseline) – Automatisierter Web-App-Scan",
    ],
    "Cloud-Enumeration-Erweiterung: Cloud_enum → CloudFox": [
        "Cloud_enum – Multi-Cloud Public Asset Enum",
        "CloudFox – Cloud-Pentest-Enumeration",
    ],
}

# Legt fest, ob das gemeinsame Automations-Ziel als reiner Host/IP
# ("host") oder als URL ("url") an das jeweilige Tool übergeben wird.
TOOL_TARGET_KIND = {
    "Nmap – Portscan": "host",
    "WHOIS – Domain-/IP-Info": "host",
    "DNS-Lookup (dig)": "host",
    "DNSrecon – DNS-Enumeration": "host",
    "Fierce – DNS-Recon (leichtgewichtig)": "host",
    "Enum4linux – SMB-/Windows-Enumeration": "host",
    "SMBmap – SMB-Freigaben auflisten": "host",
    "Nbtscan – NetBIOS-Namensscan": "host",
    "SSLScan – TLS/SSL-Konfiguration prüfen": "host",
    "Nikto – Webserver-Scan": "url",
    "Gobuster – Verzeichnis-/DNS-Suche": "url",
    "WPScan – WordPress-Scan": "url",
    "WafW00f – WAF-Erkennung": "url",
    "Whatweb – Technologie-Fingerprinting": "url",
    "Subfinder – Subdomain-Enumeration": "host",
    "Amass – Subdomain-/Asset-Enumeration": "host",
    "Httpx – HTTP-Probe / Live-Hosts": "host",
    "Nuclei – Vulnerability-Templates-Scan": "url",
    "Dirsearch – Verzeichnis-Bruteforce": "url",
    "Feroxbuster – Rekursive Verzeichnissuche": "url",
    "Testssl.sh – Tiefenprüfung TLS/SSL": "host",
    "Dnsenum – DNS-Enumeration": "host",
    "Kiterunner – API-Endpoint-Discovery": "url",
    "Arjun – HTTP-Parameter-Discovery": "url",
    "X8 – Hidden-Parameter-Fuzzing": "url",
    "Schemathesis – OpenAPI/Swagger-Fuzzing": "url",
    "OWASP ZAP (Baseline) – Automatisierter Web-App-Scan": "url",
    "Commix – Command-Injection-Test": "url",
}


from core.language_service import LanguageService
from ui.settings_dialog import SettingsDialog


# Tool-Beschreibungsteil (nach 'Marke – ') -> Uebersetzungsschluessel
TOOL_DESC_KEYS = {
    'AD-Angriffspfad-Mapping (autorisiert)': 'tooldesc.ad_angriffspfad_mapping_autorisiert',
    'AD-User-/Passwort-Enumeration (autorisiert)': 'tooldesc.ad_user_passwort_enumeration_autorisiert',
    'API-Endpoint-Discovery': 'tooldesc.api_endpoint_discovery',
    'AS-REP-Roasting (Impacket, autorisiert)': 'tooldesc.as_rep_roasting_impacket_autorisiert',
    'AWS-S3-Bucket-Scan': 'tooldesc.aws_s3_bucket_scan',
    'AWS-Security-Best-Practice-Check': 'tooldesc.aws_security_best_practice_check',
    'Artefakt-Extraktion aus Images': 'tooldesc.artefakt_extraktion_aus_images',
    'Automatisierter WLAN-Audit (autorisiert)': 'tooldesc.automatisierter_wlan_audit_autorisiert',
    'Automatisierter Web-App-Scan': 'tooldesc.automatisierter_web_app_scan',
    'BLE-GATT-Enumeration': 'tooldesc.ble_gatt_enumeration',
    'BLE-Sniffing/Hijacking (autorisiert)': 'tooldesc.ble_sniffing_hijacking_autorisiert',
    'Bluetooth-Scan (Classic/BLE)': 'tooldesc.bluetooth_scan_classic_ble',
    'Bluetooth-Spoofing (autorisiert)': 'tooldesc.bluetooth_spoofing_autorisiert',
    'CIS-Benchmark-Check für Kubernetes': 'tooldesc.cis_benchmark_check_fur_kubernetes',
    'Capability-Detection in Binaries': 'tooldesc.capability_detection_in_binaries',
    'Classic-Bluetooth-Scan': 'tooldesc.classic_bluetooth_scan',
    'Cloud-Pentest-Enumeration': 'tooldesc.cloud_pentest_enumeration',
    'Cloud-Security-Audit (AWS/Azure/GCP)': 'tooldesc.cloud_security_audit_aws_azure_gcp',
    'Command-Injection-Test': 'tooldesc.command_injection_test',
    'Container-/IaC-Vulnerability-Scanner': 'tooldesc.container_iac_vulnerability_scanner',
    'Credential-Dump (Impacket, autorisiert)': 'tooldesc.credential_dump_impacket_autorisiert',
    'DNS-Enumeration': 'tooldesc.dns_enumeration',
    'DNS-Recon (leichtgewichtig)': 'tooldesc.dns_recon_leichtgewichtig',
    'Datei-Carving aus Images': 'tooldesc.datei_carving_aus_images',
    'Deauth-Test (autorisiert)': 'tooldesc.deauth_test_autorisiert',
    'Disassembly': 'tooldesc.disassembly',
    'Docker-CIS-Benchmark': 'tooldesc.docker_cis_benchmark',
    'Domain-/IP-Info': 'tooldesc.domain_ip_info',
    'Exploit-Datenbank durchsuchen': 'tooldesc.exploit_datenbank_durchsuchen',
    'Firmware-/Datei-Signaturanalyse': 'tooldesc.firmware_datei_signaturanalyse',
    'Forensisches Imaging mit Hashing (autorisiert)': 'tooldesc.forensisches_imaging_mit_hashing_autorisiert',
    'Fuzzy-Hashing / Ähnlichkeitsvergleich': 'tooldesc.fuzzy_hashing_ahnlichkeitsvergleich',
    'GPU-beschleunigtes Hash-Cracking': 'tooldesc.gpu_beschleunigtes_hash_cracking',
    'HTTP-Parameter-Discovery': 'tooldesc.http_parameter_discovery',
    'HTTP-Probe / Live-Hosts': 'tooldesc.http_probe_live_hosts',
    'Handshake-Cracking': 'tooldesc.handshake_cracking',
    'Hash-/Digest-Berechnung': 'tooldesc.hash_digest_berechnung',
    'Hash-Cracking': 'tooldesc.hash_cracking',
    'Hash-Typ-Erkennung': 'tooldesc.hash_typ_erkennung',
    'Hidden-Parameter-Fuzzing': 'tooldesc.hidden_parameter_fuzzing',
    'IaC-Security-Scan': 'tooldesc.iac_security_scan',
    'IoT-/Internet-Geräte-Suche': 'tooldesc.iot_internet_gerate_suche',
    'Kerberoasting (Impacket, autorisiert)': 'tooldesc.kerberoasting_impacket_autorisiert',
    'Kubernetes-Penetrationstest': 'tooldesc.kubernetes_penetrationstest',
    'Kubernetes-Sicherheitsaudit': 'tooldesc.kubernetes_sicherheitsaudit',
    'LLMNR-/NBT-NS-/mDNS-Poisoning (autorisiert)': 'tooldesc.llmnr_nbt_ns_mdns_poisoning_autorisiert',
    'Login-Bruteforce (autorisiert)': 'tooldesc.login_bruteforce_autorisiert',
    'Lokales Netzwerk erkennen': 'tooldesc.lokales_netzwerk_erkennen',
    'Malware-Signatur-Scan': 'tooldesc.malware_signatur_scan',
    'Memory-Forensik': 'tooldesc.memory_forensik',
    'Metadaten-Extraktion': 'tooldesc.metadaten_extraktion',
    'Mifare-Classic Keyrecovery (autorisiert)': 'tooldesc.mifare_classic_keyrecovery_autorisiert',
    'Mifare-Classic Offline-Cracking (autorisiert)': 'tooldesc.mifare_classic_offline_cracking_autorisiert',
    'Monitor-Mode aktivieren': 'tooldesc.monitor_mode_aktivieren',
    'Multi-Cloud Public Asset Enum': 'tooldesc.multi_cloud_public_asset_enum',
    'NFC-Polling/Info (libnfc)': 'tooldesc.nfc_polling_info_libnfc',
    'NFC-Tag erkennen (libnfc)': 'tooldesc.nfc_tag_erkennen_libnfc',
    'NetBIOS-Namensscan': 'tooldesc.netbios_namensscan',
    'Netzwerk-/BLE-Recon-Framework': 'tooldesc.netzwerk_ble_recon_framework',
    'Netzwerk-Erkennung': 'tooldesc.netzwerk_erkennung',
    'OSINT-Sammlung': 'tooldesc.osint_sammlung',
    'OpenAPI/Swagger-Fuzzing': 'tooldesc.openapi_swagger_fuzzing',
    'PMKID-/Handshake-Erfassung': 'tooldesc.pmkid_handshake_erfassung',
    'Paketmitschnitt': 'tooldesc.paketmitschnitt',
    'Portscan': 'tooldesc.portscan',
    'RFID/NFC-Client (autorisiert)': 'tooldesc.rfid_nfc_client_autorisiert',
    'Rekursive Verzeichnissuche': 'tooldesc.rekursive_verzeichnissuche',
    'Rogue-AP-/Phishing-Framework (autorisiert)': 'tooldesc.rogue_ap_phishing_framework_autorisiert',
    'Rootkit Hunter': 'tooldesc.rootkit_hunter',
    'Rootkit-Erkennung': 'tooldesc.rootkit_erkennung',
    'SMB-/Windows-Enumeration': 'tooldesc.smb_windows_enumeration',
    'SMB-Freigaben auflisten': 'tooldesc.smb_freigaben_auflisten',
    'SMB/AD-Enumeration (autorisiert)': 'tooldesc.smb_ad_enumeration_autorisiert',
    'SQL-Injection-Test': 'tooldesc.sql_injection_test',
    'Schneller Portscan': 'tooldesc.schneller_portscan',
    'Statische Binäranalyse': 'tooldesc.statische_binaranalyse',
    'Subdomain-/Asset-Enumeration': 'tooldesc.subdomain_asset_enumeration',
    'Subdomain-Enumeration': 'tooldesc.subdomain_enumeration',
    'TLS/SSL-Konfiguration prüfen': 'tooldesc.tls_ssl_konfiguration_prufen',
    'Technologie-Fingerprinting': 'tooldesc.technologie_fingerprinting',
    'Tiefenprüfung TLS/SSL': 'tooldesc.tiefenprufung_tls_ssl',
    'Unpacking gepackter Binärdateien': 'tooldesc.unpacking_gepackter_binardateien',
    'Verzeichnis-/DNS-Suche': 'tooldesc.verzeichnis_dns_suche',
    'Verzeichnis-Bruteforce': 'tooldesc.verzeichnis_bruteforce',
    'Vulnerability-Scanner für Container-Images': 'tooldesc.vulnerability_scanner_fur_container_images',
    'Vulnerability-Templates-Scan': 'tooldesc.vulnerability_templates_scan',
    'WAF-Erkennung': 'tooldesc.waf_erkennung',
    'WLAN-Scan/Capture': 'tooldesc.wlan_scan_capture',
    'WPS-Audit (autorisiert)': 'tooldesc.wps_audit_autorisiert',
    'WPS-PIN-Audit (autorisiert)': 'tooldesc.wps_pin_audit_autorisiert',
    'Web-Fuzzing': 'tooldesc.web_fuzzing',
    'Webserver-Scan': 'tooldesc.webserver_scan',
    'Wireless-IDS/Scan': 'tooldesc.wireless_ids_scan',
    'WordPress-Scan': 'tooldesc.wordpress_scan',
    'Wortlisten-Generator': 'tooldesc.wortlisten_generator',
    'Wortlisten-Generator aus Webseite': 'tooldesc.wortlisten_generator_aus_webseite',
    'Zeichenketten aus Binärdatei extrahieren': 'tooldesc.zeichenketten_aus_binardatei_extrahieren',
}

# Workflow-Namenspraefix (vor ': ') -> Uebersetzungsschluessel
WORKFLOW_PREFIX_KEYS = {
    'AD-Credential-Kette (autorisiert)': 'wfdesc.ad_credential_kette_autorisiert',
    'AD-Tiefenrezon (autorisiert)': 'wfdesc.ad_tiefenrezon_autorisiert',
    'AD/SMB-Tiefenscan': 'wfdesc.ad_smb_tiefenscan',
    'API-Fuzzing-Vollkette': 'wfdesc.api_fuzzing_vollkette',
    'API-Rezon': 'wfdesc.api_rezon',
    'API-Schema-Audit': 'wfdesc.api_schema_audit',
    'AS-REP-Roasting-Kette (autorisiert)': 'wfdesc.as_rep_roasting_kette_autorisiert',
    'BLE-Sicherheitsaudit (autorisiert)': 'wfdesc.ble_sicherheitsaudit_autorisiert',
    'Bluetooth-Rezon': 'wfdesc.bluetooth_rezon',
    'Cloud-Enumeration-Erweiterung': 'wfdesc.cloud_enumeration_erweiterung',
    'Cloud-Gesamtcheck': 'wfdesc.cloud_gesamtcheck',
    'Cloud-Rezon': 'wfdesc.cloud_rezon',
    'Cloud-Sicherheitsaudit': 'wfdesc.cloud_sicherheitsaudit',
    'Container-Image-Audit': 'wfdesc.container_image_audit',
    'DNS-Rezon': 'wfdesc.dns_rezon',
    'DNS-Tiefenscan': 'wfdesc.dns_tiefenscan',
    'Datei-Forensik': 'wfdesc.datei_forensik',
    'IoT-Netzwerkscan': 'wfdesc.iot_netzwerkscan',
    'Kerberoasting-Kette (autorisiert)': 'wfdesc.kerberoasting_kette_autorisiert',
    'Kubernetes-Sicherheitsaudit': 'wfdesc.kubernetes_sicherheitsaudit',
    'Mifare-Sicherheitsaudit (autorisiert)': 'wfdesc.mifare_sicherheitsaudit_autorisiert',
    'Netzwerk-Discovery': 'wfdesc.netzwerk_discovery',
    'Netzwerk-Vollcheck': 'wfdesc.netzwerk_vollcheck',
    'OSINT-Vollscan': 'wfdesc.osint_vollscan',
    'PMKID-Erfassung': 'wfdesc.pmkid_erfassung',
    'RFID/NFC-Rezon': 'wfdesc.rfid_nfc_rezon',
    'Rezon-Gesamtkette': 'wfdesc.rezon_gesamtkette',
    'SMB-Rezon': 'wfdesc.smb_rezon',
    'Statische Malware-Analyse': 'wfdesc.statische_malware_analyse',
    'Subdomain-Rezon': 'wfdesc.subdomain_rezon',
    'TLS-Tiefenaudit': 'wfdesc.tls_tiefenaudit',
    'TLS/WAF-Audit': 'wfdesc.tls_waf_audit',
    'Verzeichnis-Vollscan': 'wfdesc.verzeichnis_vollscan',
    'Vuln-Kette': 'wfdesc.vuln_kette',
    'WLAN-Sicherheitsaudit (autorisiert)': 'wfdesc.wlan_sicherheitsaudit_autorisiert',
    'WPS-Audit (autorisiert)': 'wfdesc.wps_audit_autorisiert',
    'Web-Angriffsflächen-Erweiterung': 'wfdesc.web_angriffsflachen_erweiterung',
    'Web-Rezon': 'wfdesc.web_rezon',
    'Web-Tiefenscan': 'wfdesc.web_tiefenscan',
    'Web-Vollcheck': 'wfdesc.web_vollcheck',
    'Wireless-Rezon': 'wfdesc.wireless_rezon',
    'Wordpress-Tiefenscan': 'wfdesc.wordpress_tiefenscan',
}

# Parameter-Feld-Label (Originaltext) -> Uebersetzungsschluessel
FIELD_LABEL_KEYS = {
    'Aggressivität (-a)': 'field.aggressivitat_a',
    'Algorithmus': 'field.algorithmus',
    'Angriffsart (-a)': 'field.angriffsart_a',
    'Anzahl Deauth-Pakete': 'field.anzahl_deauth_pakete',
    'Anzahl Pakete (0 = unbegrenzt)': 'field.anzahl_pakete_0_unbegrenzt',
    'Ausgabe-Prefix': 'field.ausgabe_prefix',
    'Ausgabedatei': 'field.ausgabedatei',
    'Ausgabedatei (.mfd)': 'field.ausgabedatei_mfd',
    'Ausgabedatei (.pcapng)': 'field.ausgabedatei_pcapng',
    'Ausgabeverzeichnis': 'field.ausgabeverzeichnis',
    'BLE-Kanal/Interface': 'field.ble_kanal_interface',
    'BLE-MAC-Adresse': 'field.ble_mac_adresse',
    'BSSID (Access Point)': 'field.bssid_access_point',
    'BSSID (optional)': 'field.bssid_optional',
    "Befehle (r2 -c, ';'-getrennt)": 'field.befehle_r2_c_getrennt',
    'Benutzer:Passwort': 'field.benutzer_passwort',
    'Benutzerliste (Pfad)': 'field.benutzerliste_pfad',
    'Benutzername': 'field.benutzername',
    'Benutzername (-u)': 'field.benutzername_u',
    'Benutzername (optional)': 'field.benutzername_optional',
    'Binärdatei (Pfad)': 'field.binardatei_pfad',
    'Bucket-Name/Keyword': 'field.bucket_name_keyword',
    'Capture-Datei (.cap/.pcap)': 'field.capture_datei_cap_pcap',
    'Client-Kommando': 'field.client_kommando',
    'Cloud-Provider': 'field.cloud_provider',
    'DC-IP': 'field.dc_ip',
    'DC-IP (optional)': 'field.dc_ip_optional',
    'Datei (Pfad)': 'field.datei_pfad',
    'Datei/Verzeichnis (Pfad)': 'field.datei_verzeichnis_pfad',
    'Domain': 'field.domain',
    'Domain / IP': 'field.domain_ip',
    'Domain/Benutzer (DOMAIN/user:pass)': 'field.domain_benutzer_domain_user_pass',
    'Enumerieren': 'field.enumerieren',
    'Filter (BPF, optional)': 'field.filter_bpf_optional',
    'Format (leer = auto)': 'field.format_leer_auto',
    'Gepackte Datei (Pfad)': 'field.gepackte_datei_pfad',
    'Hash-Algorithmus': 'field.hash_algorithmus',
    'Hash-Datei (Pfad)': 'field.hash_datei_pfad',
    'Hash-Modus (-m)': 'field.hash_modus_m',
    'Hash-Wert': 'field.hash_wert',
    'Image/Verzeichnis': 'field.image_verzeichnis',
    'Interface': 'field.interface',
    'Interface (Monitor-Mode)': 'field.interface_monitor_mode',
    'Interface (optional)': 'field.interface_optional',
    'Kanal (optional)': 'field.kanal_optional',
    'Max-Länge': 'field.max_lange',
    'Min-Länge': 'field.min_lange',
    'Mindestlänge': 'field.mindestlange',
    'Modul/Eval-Befehl (optional)': 'field.modul_eval_befehl_optional',
    'Modus': 'field.modus',
    'Netzwerkbereich (falls oben gewählt)': 'field.netzwerkbereich_falls_oben_gewahlt',
    'Netzwerkbereich (z.B. 192.168.1.0/24)': 'field.netzwerkbereich_z_b_192_168_1_0_24',
    'OpenAPI-Schema (URL oder Pfad)': 'field.openapi_schema_url_oder_pfad',
    'Passwort (optional)': 'field.passwort_optional',
    'Passwortliste (-P)': 'field.passwortliste_p',
    'Passwortliste (Pfad)': 'field.passwortliste_pfad',
    'Plugin': 'field.plugin',
    'Ports (z.B. 1-65535)': 'field.ports_z_b_1_65535',
    'Protokoll': 'field.protokoll',
    'Provider/Kommando': 'field.provider_kommando',
    'Prüfmodus': 'field.prufmodus',
    'Quell-Image (Pfad)': 'field.quell_image_pfad',
    'Quelle': 'field.quelle',
    'Quelle (Gerät/Datei)': 'field.quelle_gerat_datei',
    'Rate (Pakete/Sek.)': 'field.rate_pakete_sek',
    'Record-Typ': 'field.record_typ',
    'Routen-Wortliste (Pfad)': 'field.routen_wortliste_pfad',
    'Scan-Dauer (Sekunden)': 'field.scan_dauer_sekunden',
    'Scan-Typ': 'field.scan_typ',
    'Schlüsselwort (Firma/Projekt)': 'field.schlusselwort_firma_projekt',
    'Service': 'field.service',
    'Service (-M)': 'field.service_m',
    'Speicherabbild (Pfad)': 'field.speicherabbild_pfad',
    'Suchbegriff (Software/Version)': 'field.suchbegriff_software_version',
    'Suchbegriff/IP': 'field.suchbegriff_ip',
    'Templates/Tags (leer = Standard)': 'field.templates_tags_leer_standard',
    'Verzeichnis/Datei': 'field.verzeichnis_datei',
    'WLAN-Interface': 'field.wlan_interface',
    'Wortliste (Pfad)': 'field.wortliste_pfad',
    'Wortliste / Maske': 'field.wortliste_maske',
    'YARA-Regel(n) (Pfad)': 'field.yara_regel_n_pfad',
    'Zeichensatz': 'field.zeichensatz',
    'Ziel (DOMAIN/user:pass@ip)': 'field.ziel_domain_user_pass_ip',
    'Ziel (Datei/Verzeichnis)': 'field.ziel_datei_verzeichnis',
    'Ziel (Host/URL)': 'field.ziel_host_url',
    'Ziel (Host[:Port])': 'field.ziel_host_port',
    'Ziel (IP/Bereich)': 'field.ziel_ip_bereich',
    'Ziel (IP/Host)': 'field.ziel_ip_host',
    'Ziel (IP/Host, --remote)': 'field.ziel_ip_host_remote',
    'Ziel (IP/Host/Bereich)': 'field.ziel_ip_host_bereich',
    'Ziel (Image/Verzeichnis)': 'field.ziel_image_verzeichnis',
    'Ziel-BSSID (optional)': 'field.ziel_bssid_optional',
    'Ziel-URL': 'field.ziel_url',
    'Ziel-URL (FUZZ als Platzhalter)': 'field.ziel_url_fuzz_als_platzhalter',
    'Ziel-URL (mit Parameter)': 'field.ziel_url_mit_parameter',
    'Zusätzliche Flags': 'field.zusatzliche_flags',
}


def tr_tool_name(tr, name: str) -> str:
    """Uebersetzt einen internen Tool-Namen (TOOLS-Key, bleibt als stabile
    ID fuer Profile/Verlauf unveraendert) fuer die Anzeige. Format meist
    'Marke – Beschreibung'; nur die Beschreibung wird uebersetzt, die
    Marke (z.B. 'Nmap', 'YARA') bleibt unveraendert. Sonderfaelle ohne
    dieses Format (z.B. 'DNS-Lookup (dig)') werden direkt uebersetzt."""
    if name == "DNS-Lookup (dig)":
        return tr("tool.dns_lookup_dig")
    if " – " in name:
        brand, desc = name.split(" – ", 1)
        key = TOOL_DESC_KEYS.get(desc)
        if key:
            return f"{brand} – {tr(key)}"
    return name


def tr_workflow_name(tr, name: str) -> str:
    """Uebersetzt den Namenspraefix eines Workflows (vor ': '); die
    '→'-Toolkette danach besteht bereits nur aus sprachneutralen Marken-
    namen und bleibt unveraendert."""
    if ": " in name:
        prefix, chain = name.split(": ", 1)
        key = WORKFLOW_PREFIX_KEYS.get(prefix)
        if key:
            return f"{tr(key)}: {chain}"
    return name


def tr_field_label(tr, label: str) -> str:
    """Uebersetzt ein Parameter-Feld-Label aus TOOLS[...]['fields']."""
    key = FIELD_LABEL_KEYS.get(label)
    return tr(key) if key else label


class TerminalHighlighter(QSyntaxHighlighter):
    """Hebt Ports, IPs und Fehlermeldungen in der Ausgabebox farblich hervor."""

    def __init__(self, document):
        super().__init__(document)
        self.rules = []

        def fmt(color, bold=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Weight.Bold)
            return f

        self.rules.append((re.compile(r"\bopen\b", re.I), fmt("#39FF14", True)))
        self.rules.append((re.compile(r"\b(closed|filtered)\b", re.I), fmt("#6b6b6b")))
        self.rules.append((re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b"), fmt("#D4AF37")))
        self.rules.append((re.compile(r"\b(error|failed|denied|timeout|refused)\b", re.I),
                            fmt("#FF4C4C", True)))
        self.rules.append((re.compile(r"\b(found|success|vulnerable|200 OK)\b", re.I),
                            fmt("#39FF14")))
        self.rules.append((re.compile(r"==+"), fmt(GOLD)))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class GeminiWorker(QThread):
    """Schickt einen Scan-Log-Ausschnitt an die Gemini-API und liefert die
    Antwort asynchron zurück, damit die GUI währenddessen NICHT einfriert.
    Läuft komplett in einem eigenen Thread — wichtig auf dem Pi, da der
    Netzwerk-Roundtrip mehrere Sekunden dauern kann."""

    finished_ok = pyqtSignal(str)
    finished_err = pyqtSignal(str)

    def __init__(self, api_key, tool_name, target, log_text, parent=None):
        super().__init__(parent)
        self.api_key = api_key
        self.tool_name = tool_name
        self.target = target
        # Log auf ein vernünftiges Maß kürzen (Token-/Kosten-Schutz)
        self.log_text = log_text[-12000:]

    def run(self):
        prompt = (
            "Du bist ein erfahrener Security-Analyst. Analysiere folgenden "
            "Scan-Log-Ausschnitt eines autorisierten Penetrationstests.\n"
            f"Werkzeug: {self.tool_name}\nZiel: {self.target}\n\n"
            "Fasse zusammen (auf Deutsch, kompakt, in Stichpunkten):\n"
            "1) Wichtigste Befunde (offene Ports/Dienste, Versionen, Fehler)\n"
            "2) Mögliche Risiken/Schwachstellen und deren grobe Einstufung "
            "(niedrig/mittel/hoch)\n"
            "3) Konkrete nächste Schritte für den Pentest\n\n"
            "Gib KEINE Anleitung zum Ausnutzen (Exploit-Code); nur "
            "Einordnung und empfohlene defensive/weiterführende Prüfschritte.\n\n"
            f"--- LOG ---\n{self.log_text}\n--- ENDE LOG ---"
        )
        body = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}]
        }).encode("utf-8")
        url = GEMINI_URL_TMPL.format(model=GEMINI_MODEL, key=self.api_key)
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = (
                data.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            )
            self.finished_ok.emit(text or "[Leere Antwort von Gemini erhalten]")
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            self.finished_err.emit(f"HTTP-Fehler {e.code}: {detail}")
        except urllib.error.URLError as e:
            self.finished_err.emit(
                f"Netzwerkfehler: {e.reason}\n"
                "(Prüfe Internetverbindung — der Pi braucht dafür WLAN/LAN.)"
            )
        except Exception as e:
            self.finished_err.emit(f"Unerwarteter Fehler: {e}")


class VTWorker(QThread):
    """Fragt die VirusTotal-API v3 zu Hash/IP/Domain/URL ab und liefert die
    Antwort asynchron zurück (eigener Thread — GUI bleibt responsiv)."""

    finished_ok = pyqtSignal(str)
    finished_err = pyqtSignal(str)

    def __init__(self, api_key, qtype, query, parent=None):
        super().__init__(parent)
        self.api_key = api_key
        self.qtype = qtype
        self.query = query.strip()

    def run(self):
        try:
            if self.qtype == "hash":
                url = f"https://www.virustotal.com/api/v3/files/{self.query}"
            elif self.qtype == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.query}"
            elif self.qtype == "domain":
                url = f"https://www.virustotal.com/api/v3/domains/{self.query}"
            else:  # url
                url_id = base64.urlsafe_b64encode(
                    self.query.encode()
                ).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            req = urllib.request.Request(
                url, method="GET", headers={"x-apikey": self.api_key}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            rep = attrs.get("reputation", "—")
            summary = (
                f"Malicious: {stats.get('malicious', 0)}  ·  "
                f"Suspicious: {stats.get('suspicious', 0)}  ·  "
                f"Harmless: {stats.get('harmless', 0)}  ·  "
                f"Undetected: {stats.get('undetected', 0)}\n"
                f"Reputation-Score: {rep}\n\n"
                f"--- Rohdaten (Auszug) ---\n"
                + json.dumps(attrs, indent=2, ensure_ascii=False)[:3000]
            )
            self.finished_ok.emit(summary)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            if e.code == 404:
                self.finished_err.emit(
                    "Nicht gefunden (404) — VirusTotal kennt diesen Wert "
                    "(noch) nicht."
                )
            elif e.code == 401:
                self.finished_err.emit("API-Key ungültig oder abgelaufen (401).")
            else:
                self.finished_err.emit(f"HTTP-Fehler {e.code}: {detail}")
        except urllib.error.URLError as e:
            self.finished_err.emit(
                f"Netzwerkfehler: {e.reason}\n"
                "(Prüfe Internetverbindung — der Pi braucht dafür WLAN/LAN.)"
            )
        except Exception as e:
            self.finished_err.emit(f"Unerwarteter Fehler: {e}")


class CyberToolkit(QMainWindow):
    def __init__(self, language_service: "LanguageService | None" = None):
        super().__init__()
        self.lang = language_service or LanguageService()
        self.setWindowTitle("Pandora® CyberSec Toolkit — AKI_SystemDown® ©2026")
        self.resize(1200, 900)
        self.setStyleSheet(STYLE_SHEET)

        self.process = None
        self.field_widgets = {}
        self.profiles = self._load_profiles()
        self.history = self._load_history()

        self.elapsed_timer = QElapsedTimer()
        self.status_timer = QTimer(self)
        self.status_timer.setInterval(1000)
        self.status_timer.timeout.connect(self._tick_elapsed)
        self._current_tool_name = None

        # --- Automation (Scan-Ketten) State ---
        self._workflow_running = False
        self._wf_name = None
        self._wf_target = None
        self._wf_steps = []
        self._wf_index = 0
        self._wf_report_lines = []
        self._wf_step_output = []

        # --- Performance: gepufferte Ausgabe (schont GUI/CPU auf dem Pi) ---
        # Statt jede kleine Prozess-Ausgabe sofort ins QTextEdit zu schreiben
        # (viele kleine Repaints belasten die GPU/CPU des Pi spürbar),
        # werden Daten gesammelt und alle ~200ms in einem Rutsch geflusht.
        self._out_buffer = []
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(200)
        self._flush_timer.timeout.connect(self._flush_output_buffer)
        self._flush_timer.start()
        self._MAX_OUTPUT_LINES = 4000  # älteste Zeilen werden verworfen

        # --- Gemini-KI-Analyse State ---
        self.gemini_worker = None
        self.vt_worker = None
        self._last_log_text = ""
        self._last_target = ""

        # --- Thermal-Guard (schützt den Pi vor Überhitzung/Einfrieren) ---
        self._thermal_paused = False
        self._health_timer = QTimer(self)
        self._health_timer.setInterval(4000)
        self._health_timer.timeout.connect(self._check_system_health)
        self._health_timer.start()

        # --- Nmap-XML (für präziseres Dashboard/Reporting) ---
        self._last_nmap_xml = None  # Path zur zuletzt erzeugten Nmap-XML
        self._current_nmap_xml = None  # während des laufenden Scans
        self._last_host_lines = []

        # Alte Logs aufräumen, damit die SD-Karte des Pi nicht vollläuft
        self._rotate_old_logs()

        self._build_ui()
        self.retranslate_ui()
        self.lang.language_changed.connect(self.retranslate_ui)
        self._check_authorization()
        self._setup_shortcuts()

    # ---------------------------------------------------------------
    def _load_history(self):
        try:
            if HISTORY_FILE.exists():
                return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return []

    def _save_history(self):
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            HISTORY_FILE.write_text(
                json.dumps(self.history[-200:], ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
        except Exception:
            pass

    # ---------------------------------------------------------------
    # Log-Rotation (schont die SD-Karte des Pi vor unbegrenztem Wachstum)
    # ---------------------------------------------------------------
    @staticmethod
    def _rotate_old_logs():
        try:
            if not LOG_DIR.exists():
                return
            files = sorted(
                LOG_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True
            )
            for old in files[MAX_LOG_FILES:]:
                try:
                    old.unlink()
                except Exception:
                    pass
        except Exception:
            pass

    # ---------------------------------------------------------------
    # Thermal-Guard / System-Gesundheit (Pi 4B: CPU-Temperatur & Last)
    # ---------------------------------------------------------------
    @staticmethod
    def _read_cpu_temp():
        """Liest die CPU-Temperatur (°C). Funktioniert auf dem Pi/Linux
        über /sys/class/thermal; auf anderen Systemen -> None (Feature
        deaktiviert sich dann automatisch, kein Fehler)."""
        try:
            raw = THERMAL_ZONE_PATH.read_text().strip()
            return int(raw) / 1000.0
        except Exception:
            return None

    def _check_system_health(self):
        temp = self._read_cpu_temp()
        try:
            load1, _, _ = os.getloadavg()
        except (OSError, AttributeError):
            load1 = None

        parts = []
        if temp is not None:
            parts.append(f"🌡 {temp:.0f}°C")
        if load1 is not None:
            parts.append(f"{self.lang.tr('health.load')} {load1:.1f}")
        if hasattr(self, "health_lbl"):
            self.health_lbl.setText("  ·  ".join(parts) if parts else "")
            if temp is not None and temp >= THERMAL_PAUSE_C:
                self.health_lbl.setStyleSheet(f"color: {RED_WARN}; font-weight: bold;")
            elif temp is not None and temp >= THERMAL_PAUSE_C - 8:
                self.health_lbl.setStyleSheet(f"color: {GOLD};")
            else:
                self.health_lbl.setStyleSheet(f"color: {TEXT_LIGHT};")

        if temp is None or not getattr(self, "thermal_guard_chk", None):
            return
        if not self.thermal_guard_chk.isChecked():
            return
        if not hasattr(signal, "SIGSTOP") or not hasattr(signal, "SIGCONT"):
            return  # Signale nur auf POSIX (Linux/Pi) verfügbar

        proc = self.process
        if proc is None or proc.state() == QProcess.ProcessState.NotRunning:
            self._thermal_paused = False
            return

        pid = int(proc.processId())
        if not pid:
            return

        if not self._thermal_paused and temp >= THERMAL_PAUSE_C:
            try:
                os.kill(pid, signal.SIGSTOP)
                self._thermal_paused = True
                msg = (
                    f"\n[🌡 Thermal-Guard: CPU bei {temp:.0f}°C — Scan pausiert, "
                    f"um den Pi zu schützen …]\n"
                )
                self.output_box.append(msg)
                self.status.showMessage(
                    self.lang.tr("status.thermal_paused", temp=f"{temp:.0f}"), 6000
                )
            except ProcessLookupError:
                pass
        elif self._thermal_paused and temp <= THERMAL_RESUME_C:
            try:
                os.kill(pid, signal.SIGCONT)
                self._thermal_paused = False
                self.output_box.append(
                    f"\n[🌡 Thermal-Guard: abgekühlt auf {temp:.0f}°C — Scan wird fortgesetzt]\n"
                )
                self.status.showMessage(self.lang.tr("status.scan_resumed"), 4000)
            except ProcessLookupError:
                pass

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+Return"), self, activated=self._run_tool)
        QShortcut(QKeySequence("Ctrl+Enter"), self, activated=self._run_tool)
        QShortcut(QKeySequence("Escape"), self, activated=self._stop_any)

    # ---------------------------------------------------------------
    def _load_profiles(self):
        try:
            if CONFIG_FILE.exists():
                return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def _save_profiles(self):
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            CONFIG_FILE.write_text(
                json.dumps(self.profiles, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
        except Exception as e:
            self.status.showMessage(self.lang.tr("status.profile_save_failed", error=e), 5000)

    # ---------------------------------------------------------------
    def _check_authorization(self):
        tr = self.lang.tr
        box = QMessageBox(self)
        box.setWindowTitle(tr("dialog.auth_title"))
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(tr("dialog.auth_text"))
        box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        box.button(QMessageBox.StandardButton.Yes).setText(tr("button.auth_continue"))
        box.button(QMessageBox.StandardButton.No).setText(tr("button.auth_cancel"))
        if box.exec() != QMessageBox.StandardButton.Yes:
            sys.exit(0)

    # ---------------------------------------------------------------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        header_row = QHBoxLayout()
        header_col = QVBoxLayout()
        header = QLabel("PANDORA® CYBERSEC TOOLKIT")
        header.setObjectName("header")
        self._header_sub_lbl = QLabel("")
        self._header_sub_lbl.setObjectName("sub")
        header_col.addWidget(header)
        header_col.addWidget(self._header_sub_lbl)
        header_row.addLayout(header_col)
        header_row.addStretch(1)
        self.settings_button = QPushButton("⚙")
        self.settings_button.setFixedWidth(44)
        self.settings_button.clicked.connect(self._on_open_settings)
        header_row.addWidget(self.settings_button, 0, Qt.AlignmentFlag.AlignTop)
        root.addLayout(header_row)

        outer_splitter = QSplitter(Qt.Orientation.Vertical)
        root.addWidget(outer_splitter, stretch=1)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        outer_splitter.addWidget(splitter)

        # --- Linke Spalte: Tool-Liste -------------------------------
        left = QFrame()
        left_l = QVBoxLayout(left)
        self._tools_lbl = QLabel()
        left_l.addWidget(self._tools_lbl)
        self.search_box = QLineEdit()
        self.search_box.textChanged.connect(self._filter_tools)
        left_l.addWidget(self.search_box)
        self.tool_list = QListWidget()
        for name in TOOLS:
            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, name)
            self.tool_list.addItem(item)
        self.tool_list.currentItemChanged.connect(self._on_tool_item_changed)
        left_l.addWidget(self.tool_list, stretch=1)

        # --- Automationen (Scan-Ketten) ---
        self._wf_panel_lbl = QLabel()
        self._wf_panel_lbl.setObjectName("sub")
        left_l.addWidget(self._wf_panel_lbl)

        self.workflow_list = QListWidget()
        for wf_name in WORKFLOWS:
            wf_item = QListWidgetItem(wf_name)
            wf_item.setData(Qt.ItemDataRole.UserRole, wf_name)
            self.workflow_list.addItem(wf_item)
        self.workflow_list.setMaximumHeight(100)
        left_l.addWidget(self.workflow_list)

        self.workflow_target = QLineEdit()
        left_l.addWidget(self.workflow_target)

        wf_btn_row = QHBoxLayout()
        self.workflow_run_btn = QPushButton()
        self.workflow_run_btn.clicked.connect(self._run_workflow)
        self.workflow_stop_btn = QPushButton()
        self.workflow_stop_btn.setObjectName("stopBtn")
        self.workflow_stop_btn.setEnabled(False)
        self.workflow_stop_btn.clicked.connect(self._stop_workflow)
        wf_btn_row.addWidget(self.workflow_run_btn)
        wf_btn_row.addWidget(self.workflow_stop_btn)
        left_l.addLayout(wf_btn_row)

        self.workflow_progress = QLabel("")
        self.workflow_progress.setObjectName("sub")
        left_l.addWidget(self.workflow_progress)

        splitter.addWidget(left)

        # --- Mitte: Parameter --------------------------------------
        mid = QFrame()
        mid_l = QVBoxLayout(mid)
        self._params_lbl = QLabel()
        mid_l.addWidget(self._params_lbl)
        self.form_container = QWidget()
        self.form_layout = QFormLayout(self.form_container)
        mid_l.addWidget(self.form_container)
        mid_l.addStretch()

        self.root_chk = QCheckBox()
        mid_l.addWidget(self.root_chk)

        self.nice_chk = QCheckBox()
        self.nice_chk.setChecked(shutil.which("nice") is not None)
        self.nice_chk.setEnabled(shutil.which("nice") is not None)
        mid_l.addWidget(self.nice_chk)

        self._thermal_available = (
            THERMAL_ZONE_PATH.exists()
            and hasattr(signal, "SIGSTOP")
        )
        self.thermal_guard_chk = QCheckBox()
        self.thermal_guard_chk.setChecked(self._thermal_available)
        self.thermal_guard_chk.setEnabled(self._thermal_available)
        mid_l.addWidget(self.thermal_guard_chk)

        self.nmap_xml_chk = QCheckBox()
        self.nmap_xml_chk.setChecked(True)
        mid_l.addWidget(self.nmap_xml_chk)

        self._cmd_preview_lbl = QLabel()
        mid_l.addWidget(self._cmd_preview_lbl)
        self.cmd_preview = QLineEdit()
        mid_l.addWidget(self.cmd_preview)
        refresh_row = QHBoxLayout()
        self._refresh_preview_btn = QPushButton()
        self._refresh_preview_btn.clicked.connect(self._update_preview)
        refresh_row.addWidget(self._refresh_preview_btn)
        mid_l.addLayout(refresh_row)

        btn_row = QHBoxLayout()
        self.run_btn = QPushButton()
        self.run_btn.clicked.connect(self._run_tool)
        self.stop_btn = QPushButton()
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_tool)
        btn_row.addWidget(self.run_btn)
        btn_row.addWidget(self.stop_btn)
        mid_l.addLayout(btn_row)
        splitter.addWidget(mid)

        # --- Rechts: Tabs (Ausgabe / Dashboard / KI-Analyse) ----------
        self.right_tabs = QTabWidget()

        # -- Tab 1: Ausgabe --
        out_tab = QFrame()
        right_l = QVBoxLayout(out_tab)
        out_header = QHBoxLayout()
        self._output_lbl = QLabel()
        out_header.addWidget(self._output_lbl)
        out_header.addStretch()
        self.autoscroll_chk = QCheckBox()
        self.autoscroll_chk.setChecked(True)
        out_header.addWidget(self.autoscroll_chk)
        right_l.addLayout(out_header)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setFont(QFont("Consolas", 11))
        self.highlighter = TerminalHighlighter(self.output_box.document())
        right_l.addWidget(self.output_box, stretch=1)

        save_row = QHBoxLayout()
        self._save_log_btn = QPushButton()
        self._save_log_btn.clicked.connect(self._save_log)
        self._clear_btn = QPushButton()
        self._clear_btn.clicked.connect(self.output_box.clear)
        save_row.addWidget(self._save_log_btn)
        save_row.addWidget(self._clear_btn)
        right_l.addLayout(save_row)

        self._history_lbl = QLabel()
        right_l.addWidget(self._history_lbl)
        self.history_list = QListWidget()
        self.history_list.setMaximumHeight(120)
        self.history_list.itemDoubleClicked.connect(self._load_history_entry)
        self._refresh_history_list()
        right_l.addWidget(self.history_list)

        self.right_tabs.addTab(out_tab, "")

        # -- Tab 2: Dashboard (Reporting/Visualisierung) --
        dash_tab = QFrame()
        dash_l = QVBoxLayout(dash_tab)
        dash_header = QHBoxLayout()
        self._dash_intro_lbl = QLabel()
        dash_header.addWidget(self._dash_intro_lbl)
        dash_header.addStretch()
        self._dash_refresh_btn = QPushButton()
        self._dash_refresh_btn.clicked.connect(
            lambda: self._update_dashboard(
                getattr(self, "_last_log_text", ""), getattr(self, "_last_nmap_xml", None)
            )
        )
        dash_header.addWidget(self._dash_refresh_btn)
        self._export_html_btn = QPushButton()
        self._export_html_btn.clicked.connect(self._export_html_report)
        dash_header.addWidget(self._export_html_btn)
        dash_l.addLayout(dash_header)

        self._dashboard_placeholder = QLabel("")
        self._dashboard_placeholder.setWordWrap(True)
        dash_l.addWidget(self._dashboard_placeholder)

        self._dash_canvas = None
        self._dash_container = QVBoxLayout()
        dash_l.addLayout(self._dash_container, stretch=1)

        self.dash_summary_lbl = QLabel("")
        self.dash_summary_lbl.setObjectName("sub")
        self.dash_summary_lbl.setWordWrap(True)
        dash_l.addWidget(self.dash_summary_lbl)

        self.right_tabs.addTab(dash_tab, "")

        # -- Tab 3: KI-Analyse (optional, Gemini API) --
        ki_tab = QFrame()
        ki_l = QVBoxLayout(ki_tab)
        self._ki_intro_lbl = QLabel()
        ki_l.addWidget(self._ki_intro_lbl)
        key_row = QHBoxLayout()
        self._gemini_key_lbl = QLabel()
        key_row.addWidget(self._gemini_key_lbl)
        self.gemini_key_edit = QLineEdit()
        self.gemini_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.gemini_key_edit.setText(self._load_gemini_key())
        key_row.addWidget(self.gemini_key_edit, stretch=1)
        save_key_btn = QPushButton("💾")
        save_key_btn.setMaximumWidth(40)
        save_key_btn.clicked.connect(
            lambda: self._save_gemini_key(self.gemini_key_edit.text().strip())
        )
        key_row.addWidget(save_key_btn)
        ki_l.addLayout(key_row)

        self.ki_analyze_btn = QPushButton()
        self.ki_analyze_btn.clicked.connect(self._run_gemini_analysis)
        ki_l.addWidget(self.ki_analyze_btn)

        self.ki_result_box = QPlainTextEdit()
        self.ki_result_box.setReadOnly(True)
        ki_l.addWidget(self.ki_result_box, stretch=1)

        self.right_tabs.addTab(ki_tab, "")

        # -- Tab 4: Zentrales API-Key-Profil + VirusTotal-Lookup --
        keys_tab = QFrame()
        keys_l = QVBoxLayout(keys_tab)
        self._apikeys_intro_lbl = QLabel()
        keys_l.addWidget(self._apikeys_intro_lbl)

        def _make_key_row(label_widget_attr, load_fn, save_fn):
            row = QHBoxLayout()
            label = QLabel()
            setattr(self, label_widget_attr, label)
            row.addWidget(label)
            edit = QLineEdit()
            edit.setEchoMode(QLineEdit.EchoMode.Password)
            edit.setText(load_fn())
            row.addWidget(edit, stretch=1)
            btn = QPushButton("💾")
            btn.setMaximumWidth(40)
            btn.clicked.connect(lambda: save_fn(edit.text().strip()))
            row.addWidget(btn)
            keys_l.addLayout(row)
            return edit

        self.gemini_key_edit2 = _make_key_row(
            "_gemini_key2_lbl", self._load_gemini_key, self._save_gemini_key
        )
        self.shodan_key_edit = _make_key_row(
            "_shodan_key_lbl", lambda: self._load_api_key("shodan"), self._save_shodan_key
        )
        self.vt_key_edit = _make_key_row(
            "_vt_key_lbl", lambda: self._load_api_key("virustotal"),
            lambda k: self._save_api_key("virustotal", k, "VirusTotal")
        )

        keys_l.addWidget(QFrame())  # kleiner visueller Abstand

        self._vt_section_lbl = QLabel()
        keys_l.addWidget(self._vt_section_lbl)
        vt_row = QHBoxLayout()
        self.vt_type_combo = QComboBox()
        vt_row.addWidget(self.vt_type_combo)
        self.vt_query_edit = QLineEdit()
        vt_row.addWidget(self.vt_query_edit, stretch=1)
        keys_l.addLayout(vt_row)

        self.vt_lookup_btn = QPushButton()
        self.vt_lookup_btn.clicked.connect(self._run_vt_lookup)
        keys_l.addWidget(self.vt_lookup_btn)

        self.vt_result_box = QPlainTextEdit()
        self.vt_result_box.setReadOnly(True)
        keys_l.addWidget(self.vt_result_box, stretch=1)

        self.right_tabs.addTab(keys_tab, "")

        splitter.setSizes([260, 340])

        outer_splitter.addWidget(self.right_tabs)
        outer_splitter.setSizes([320, 480])

        self.status = QStatusBar()
        self.setStatusBar(self.status)

        self.health_lbl = QLabel("")
        self.health_lbl.setStyleSheet(f"color: {TEXT_LIGHT}; padding-right: 8px;")
        self.status.addPermanentWidget(self.health_lbl)
        self._check_system_health()

        self.tool_list.setCurrentRow(0)

    # ---------------------------------------------------------------
    def retranslate_ui(self) -> None:
        """Setzt alle statischen UI-Texte in der aktuell aktiven Sprache
        neu. Wird initial nach _build_ui() sowie bei jedem Sprachwechsel
        (live, inkl. Hot-Reload der Sprachpakete) aufgerufen."""
        tr = self.lang.tr

        self._header_sub_lbl.setText(
            f"{tr('header.subtitle')} · Raspberry Pi 4B · AKI_SystemDown® ©2026"
        )
        self.settings_button.setToolTip(tr("button.settings"))

        self._tools_lbl.setText(tr("panel.tools"))
        self.search_box.setPlaceholderText(tr("placeholder.filter_tools"))
        self._wf_panel_lbl.setText(tr("panel.automations"))
        self.workflow_target.setPlaceholderText(tr("placeholder.workflow_target"))
        self.workflow_run_btn.setText(tr("button.workflow_start"))
        self.workflow_stop_btn.setText(tr("button.stop"))

        self._params_lbl.setText(tr("panel.parameters"))
        self.root_chk.setText(tr("checkbox.root"))
        self.nice_chk.setText(tr("checkbox.nice"))
        self.thermal_guard_chk.setText(
            tr("checkbox.thermal_guard", temp=f"{THERMAL_PAUSE_C:.0f}")
        )
        if not self._thermal_available:
            self.thermal_guard_chk.setToolTip(tr("tooltip.thermal_guard_unavailable"))
        else:
            self.thermal_guard_chk.setToolTip("")
        self.nmap_xml_chk.setText(tr("checkbox.nmap_xml"))
        self._cmd_preview_lbl.setText(tr("label.cmd_preview"))
        self.cmd_preview.setPlaceholderText(tr("placeholder.cmd_preview"))
        self._refresh_preview_btn.setText(tr("button.refresh_preview"))
        self.run_btn.setText(tr("button.run"))
        self.stop_btn.setText(tr("button.stop"))

        self.right_tabs.setTabText(0, tr("tab.output"))
        self.right_tabs.setTabText(1, tr("tab.dashboard"))
        self.right_tabs.setTabText(2, tr("tab.ki_analysis"))
        self.right_tabs.setTabText(3, tr("tab.api_keys"))

        self._output_lbl.setText(tr("label.output"))
        self.autoscroll_chk.setText(tr("checkbox.autoscroll"))
        self._save_log_btn.setText(tr("button.save_log"))
        self._clear_btn.setText(tr("button.clear"))
        self._history_lbl.setText(tr("label.history"))

        self._dash_intro_lbl.setText(tr("label.dashboard_intro"))
        self._dash_refresh_btn.setText(tr("button.dashboard_refresh"))
        self._export_html_btn.setText(tr("button.export_html"))
        self._dashboard_placeholder.setText(
            tr("dashboard.placeholder_no_data") if MATPLOTLIB_OK
            else tr("dashboard.placeholder_no_matplotlib")
        )

        self._ki_intro_lbl.setText(tr("label.ki_intro"))
        self._gemini_key_lbl.setText(tr("label.gemini_key"))
        self.gemini_key_edit.setPlaceholderText(tr("placeholder.gemini_key"))
        self.ki_analyze_btn.setText(tr("button.ki_analyze"))
        self.ki_result_box.setPlaceholderText(tr("placeholder.ki_result"))

        self._apikeys_intro_lbl.setText(tr("label.apikeys_intro"))
        self._gemini_key2_lbl.setText(tr("label.gemini_key"))
        self.gemini_key_edit2.setPlaceholderText(tr("placeholder.gemini_key"))
        self._shodan_key_lbl.setText(tr("label.shodan_key"))
        self.shodan_key_edit.setPlaceholderText(tr("placeholder.shodan_key"))
        self._vt_key_lbl.setText(tr("label.vt_key"))
        self.vt_key_edit.setPlaceholderText(tr("placeholder.vt_key"))
        self._vt_section_lbl.setText(tr("label.vt_section"))

        vt_current = self.vt_type_combo.currentIndex()
        self.vt_type_combo.blockSignals(True)
        self.vt_type_combo.clear()
        self.vt_type_combo.addItems([
            tr("vt.type_hash"), tr("vt.type_ip"), tr("vt.type_domain"), tr("vt.type_url")
        ])
        self.vt_type_combo.setCurrentIndex(max(vt_current, 0))
        self.vt_type_combo.blockSignals(False)

        self.vt_query_edit.setPlaceholderText(tr("placeholder.vt_query"))
        self.vt_lookup_btn.setText(tr("button.vt_lookup"))
        self.vt_result_box.setPlaceholderText(tr("placeholder.vt_result"))

        # Tool-/Workflow-Liste neu aufbauen (uebersetzte Anzeige, stabile
        # interne ID via itemData), Auswahl und Suchfilter erhalten.
        current_tool = None
        if self.tool_list.currentItem():
            current_tool = self.tool_list.currentItem().data(Qt.ItemDataRole.UserRole)
        self.tool_list.blockSignals(True)
        self.tool_list.clear()
        for internal_name in TOOLS:
            item = QListWidgetItem(tr_tool_name(tr, internal_name))
            item.setData(Qt.ItemDataRole.UserRole, internal_name)
            self.tool_list.addItem(item)
        self.tool_list.blockSignals(False)
        if current_tool:
            for i in range(self.tool_list.count()):
                if self.tool_list.item(i).data(Qt.ItemDataRole.UserRole) == current_tool:
                    self.tool_list.setCurrentRow(i)
                    break
        self._filter_tools(self.search_box.text())
        # Formular-Labels der aktuell offenen Parameteransicht neu uebersetzen
        self._on_tool_selected(current_tool)

        current_wf = None
        if self.workflow_list.currentItem():
            current_wf = self.workflow_list.currentItem().data(Qt.ItemDataRole.UserRole)
        self.workflow_list.blockSignals(True)
        self.workflow_list.clear()
        for wf_internal_name in WORKFLOWS:
            wf_item = QListWidgetItem(tr_workflow_name(tr, wf_internal_name))
            wf_item.setData(Qt.ItemDataRole.UserRole, wf_internal_name)
            self.workflow_list.addItem(wf_item)
        self.workflow_list.blockSignals(False)
        if current_wf:
            for i in range(self.workflow_list.count()):
                if self.workflow_list.item(i).data(Qt.ItemDataRole.UserRole) == current_wf:
                    self.workflow_list.setCurrentRow(i)
                    break

        self.status.showMessage(tr("status.ready"))

    # ---------------------------------------------------------------
    def _on_open_settings(self):
        dialog = SettingsDialog(self.lang, parent=self)
        dialog.exec()

    # ---------------------------------------------------------------
    def _clear_form(self):
        while self.form_layout.rowCount():
            self.form_layout.removeRow(0)
        self.field_widgets = {}

    def _filter_tools(self, text):
        text = text.lower().strip()
        for i in range(self.tool_list.count()):
            item = self.tool_list.item(i)
            item.setHidden(text not in item.text().lower())

    def _on_tool_item_changed(self, current, _previous):
        """Bridge fuer currentItemChanged: liefert die stabile interne
        Tool-ID (itemData) statt des uebersetzten Anzeigetexts an
        _on_tool_selected weiter."""
        name = current.data(Qt.ItemDataRole.UserRole) if current else None
        self._on_tool_selected(name)

    def _on_tool_selected(self, name):
        if not name:
            return
        tr = self.lang.tr
        self._clear_form()
        tool = TOOLS[name]
        saved = self.profiles.get(name, {})

        if not shutil.which(tool["bin"]):
            self.status.showMessage(
                self.lang.tr("status.binary_not_found", bin=tool["bin"]), 6000
            )

        self.root_chk.setChecked(bool(tool.get("needs_root", False)))

        for label, key, ftype, default in tool["fields"]:
            saved_val = saved.get(key)
            if ftype == "text":
                w = QLineEdit()
                w.setText(saved_val if saved_val is not None else default)
                w.textChanged.connect(self._update_preview)
            elif ftype == "combo":
                w = QComboBox()
                w.addItems(default)
                if saved_val in default:
                    w.setCurrentText(saved_val)
                w.currentTextChanged.connect(self._update_preview)
            elif ftype == "file":
                w = QHBoxLayout()
                line = QLineEdit(saved_val if saved_val is not None else default)
                line.textChanged.connect(self._update_preview)
                btn = QPushButton("…")
                btn.setMaximumWidth(36)
                btn.clicked.connect(lambda _, l=line: self._pick_file(l))
                wrap = QWidget()
                wrap.setLayout(w)
                w.addWidget(line)
                w.addWidget(btn)
                self.field_widgets[key] = line
                self.form_layout.addRow(tr_field_label(tr, label), wrap)
                continue
            self.field_widgets[key] = w
            self.form_layout.addRow(tr_field_label(tr, label), w)

        self._update_preview()

    def _pick_file(self, line_edit):
        path, _ = QFileDialog.getOpenFileName(self, self.lang.tr("dialog.pick_file_title"))
        if path:
            line_edit.setText(path)

    def _apply_nice(self, cmd):
        """Setzt den Subprozess auf niedrigere CPU-Priorität (falls gewählt
        und verfügbar). Wichtig auf dem Pi 4B: verhindert, dass ein
        CPU-hungriges Tool (z.B. Hydra/John/Masscan) die GUI komplett
        blockiert. pkexec bleibt immer außen vor (nice davor eingefügt)."""
        if not getattr(self, "nice_chk", None) or not self.nice_chk.isChecked():
            return cmd
        if not shutil.which("nice"):
            return cmd
        if cmd and cmd[0] == "pkexec":
            return [cmd[0], "nice", "-n", "10"] + cmd[1:]
        return ["nice", "-n", "10"] + cmd

    def _maybe_add_nmap_xml(self, tool_name, cmd):
        """Hängt bei Nmap-Läufen '-oX <tempdatei>' an, damit das Dashboard
        exakte, strukturierte Daten (Host/Port/Dienst/Version) statt nur
        grober Regex-Treffer bekommt. Die normale Konsolenausgabe bleibt
        davon unberührt — Nmap schreibt bei -oX zusätzlich, nicht anstelle
        des Terminal-Reports. Gibt (cmd, xml_path_oder_None) zurück."""
        if not tool_name or not tool_name.startswith("Nmap"):
            return cmd, None
        if not getattr(self, "nmap_xml_chk", None) or not self.nmap_xml_chk.isChecked():
            return cmd, None
        if "-oX" in cmd:
            return cmd, None  # Nutzer hat es in "Zusätzliche Flags" bereits gesetzt
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            fd, path = tempfile.mkstemp(
                suffix=".xml", prefix="nmap_", dir=str(LOG_DIR)
            )
            os.close(fd)
        except Exception:
            return cmd, None
        return cmd + ["-oX", path], Path(path)

    @staticmethod
    def _parse_nmap_xml(xml_path):
        """Parst eine Nmap-XML-Datei zu (status_counter, service_counter,
        host_lines) für ein präzises Dashboard/Reporting. Fällt bei
        fehlerhaftem/leerem XML sauber auf (None, None, []) zurück."""
        try:
            tree = ET.parse(str(xml_path))
        except Exception:
            return None, None, []
        status_counter = Counter()
        service_counter = Counter()
        host_lines = []
        for host in tree.getroot().findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else "?"
            hostname_el = host.find("hostnames/hostname")
            hostname = hostname_el.get("name") if hostname_el is not None else ""
            open_services = []
            for port in host.findall("ports/port"):
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                status_counter[state] += 1
                if state == "open":
                    svc_el = port.find("service")
                    svc_name = svc_el.get("name") if svc_el is not None else "?"
                    svc_product = svc_el.get("product") if svc_el is not None else ""
                    service_counter[svc_name] += 1
                    portid = port.get("portid")
                    label = f"{portid}/{svc_name}"
                    if svc_product:
                        label += f" ({svc_product})"
                    open_services.append(label)
            label = f"{addr}" + (f" ({hostname})" if hostname else "")
            host_lines.append(
                f"{label}: " + (", ".join(open_services) if open_services else "keine offenen Ports")
            )
        return status_counter, service_counter, host_lines

    def _collect_values(self):
        values = {}
        for key, widget in self.field_widgets.items():
            if isinstance(widget, QLineEdit):
                values[key] = widget.text().strip()
            elif isinstance(widget, QComboBox):
                values[key] = widget.currentText()
        return values

    def _update_preview(self, *_):
        name = self.tool_list.currentItem().data(Qt.ItemDataRole.UserRole) if self.tool_list.currentItem() else None
        if not name:
            return
        tool = TOOLS[name]
        values = self._collect_values()
        try:
            cmd = tool["build"](values)
        except Exception:
            return
        if self.root_chk.isChecked():
            cmd = ["pkexec"] + cmd
        self.cmd_preview.setText(" ".join(shlex.quote(c) for c in cmd))

    def _missing_files(self, values):
        """Prüft Datei-Felder (Wordlist, Capture, Hash-Datei) auf Existenz."""
        missing = []
        for key, widget in self.field_widgets.items():
            if key in ("wordlist", "capfile", "hashfile", "rulesfile", "userlist"):
                path = widget.text().strip()
                if path and not os.path.isfile(path):
                    missing.append(path)
        return missing

    # ---------------------------------------------------------------
    def _run_tool(self):
        tr = self.lang.tr
        if self._workflow_running:
            QMessageBox.warning(
                self, tr("msg.workflow_running_title"), tr("msg.workflow_running_text")
            )
            return
        name = self.tool_list.currentItem().data(Qt.ItemDataRole.UserRole) if self.tool_list.currentItem() else None
        if not name:
            return
        tool = TOOLS[name]

        if not shutil.which(tool["bin"]):
            QMessageBox.critical(
                self, tr("msg.tool_not_found_title"),
                tr("msg.tool_not_found_text", bin=tool["bin"])
            )
            return

        values = self._collect_values()
        if "target" in values and not values["target"]:
            QMessageBox.warning(self, tr("msg.input_missing_title"), tr("msg.input_missing_target_text"))
            return

        if "target" in values and values["target"]:
            t = values["target"]
            if not (IP_RE.match(t) or HOST_RE.match(t)):
                reply = QMessageBox.question(
                    self, tr("msg.target_check_title"),
                    tr("msg.target_check_text", target=t),
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return

        missing = self._missing_files(values)
        if missing:
            reply = QMessageBox.question(
                self, tr("msg.file_missing_title"),
                tr("msg.file_missing_text", files="\n".join(missing)),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        # Editierte Kommando-Vorschau hat Vorrang, falls vom Nutzer angepasst
        preview_text = self.cmd_preview.text().strip()
        if preview_text:
            try:
                cmd = shlex.split(preview_text)
            except ValueError as e:
                QMessageBox.critical(self, tr("msg.invalid_command_title"), str(e))
                return
        else:
            try:
                cmd = tool["build"](values)
            except Exception as e:
                QMessageBox.critical(self, tr("msg.build_command_failed_title"), str(e))
                return
            if self.root_chk.isChecked():
                cmd = ["pkexec"] + cmd

        if self.root_chk.isChecked() and cmd[0] != "pkexec" and not shutil.which("pkexec"):
            QMessageBox.warning(
                self, tr("msg.pkexec_missing_title"), tr("msg.pkexec_missing_text")
            )
            return

        cmd, self._current_nmap_xml = self._maybe_add_nmap_xml(name, cmd)
        cmd = self._apply_nice(cmd)

        # Profil speichern (für nächste Sitzung)
        self.profiles[name] = values
        self._save_profiles()
        self._current_tool_name = name
        self._current_cmd_str = " ".join(cmd)
        self._current_target_value = values.get("target", "")

        self.output_box.append(
            f"\n{'='*70}\n[{datetime.datetime.now():%H:%M:%S}] $ {' '.join(cmd)}\n{'='*70}\n"
        )

        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._read_output)
        self.process.finished.connect(self._process_finished)
        self.process.errorOccurred.connect(self._process_error)

        self.process.start(cmd[0], cmd[1:])
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.workflow_run_btn.setEnabled(False)
        self.elapsed_timer.start()
        self.status_timer.start()
        self.status.showMessage(tr("status.running_tool", name=name))

    def _read_output(self):
        if not self.process:
            return
        data = self.process.readAllStandardOutput().data().decode(errors="replace")
        self._out_buffer.append(data)

    def _flush_output_buffer(self):
        """Schreibt gepufferte Prozess-Ausgabe gesammelt ins QTextEdit.
        Läuft alle 200ms statt bei jedem einzelnen Datenhäppchen — spart
        auf dem Pi spürbar CPU/GPU (weniger Layout-/Repaint-Zyklen)."""
        if not self._out_buffer:
            return
        chunk = "".join(self._out_buffer)
        self._out_buffer = []
        self.output_box.moveCursor(QTextCursor.MoveOperation.End)
        self.output_box.insertPlainText(chunk)
        self._trim_output_if_needed()
        if self.autoscroll_chk.isChecked():
            self.output_box.moveCursor(QTextCursor.MoveOperation.End)

    def _trim_output_if_needed(self):
        """Kappt sehr lange Logs im Fenster (Datei-Log bleibt vollständig),
        damit QTextEdit/Highlighter auf dem Pi nicht ins Stocken geraten."""
        doc = self.output_box.document()
        if doc.blockCount() > self._MAX_OUTPUT_LINES:
            cursor = QTextCursor(doc)
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(
                QTextCursor.MoveOperation.Down,
                QTextCursor.MoveMode.KeepAnchor,
                doc.blockCount() - self._MAX_OUTPUT_LINES
            )
            cursor.removeSelectedText()

    def _tick_elapsed(self):
        secs = self.elapsed_timer.elapsed() // 1000
        mins, s = divmod(secs, 60)
        self.status.showMessage(self.lang.tr(
            "status.running_tool_elapsed", name=self._current_tool_name,
            mm=f"{mins:02d}", ss=f"{s:02d}"
        ))

    def _process_finished(self, code, status):
        self.status_timer.stop()
        self._flush_output_buffer()
        self.output_box.append(f"\n[Prozess beendet — Exit-Code {code}]\n")
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.workflow_run_btn.setEnabled(True)
        self.status.showMessage(self.lang.tr("status.done"), 4000)

        self._last_log_text = self.output_box.toPlainText()
        self._last_target = getattr(self, "_current_target_value", "")
        self._last_nmap_xml = self._current_nmap_xml
        self._current_nmap_xml = None
        self._update_dashboard(self._last_log_text, self._last_nmap_xml)

        # Automatisch archivieren + im Verlauf vermerken
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.datetime.now()
            fname = f"{ts:%Y%m%d_%H%M%S}_{self._current_tool_name.split(' ')[0]}.log"
            log_path = LOG_DIR / fname
            log_path.write_text(self.output_box.toPlainText(), encoding="utf-8")
            self.history.append({
                "timestamp": ts.isoformat(timespec="seconds"),
                "tool": self._current_tool_name,
                "command": getattr(self, "_current_cmd_str", ""),
                "log_path": str(log_path),
                "exit_code": code,
            })
            self._save_history()
            self._refresh_history_list()
        except Exception as e:
            self.status.showMessage(
                self.lang.tr("status.history_save_failed", error=e), 5000
            )

        self.process = None

    def _refresh_history_list(self):
        self.history_list.clear()
        for entry in reversed(self.history[-50:]):
            label = f"{entry['timestamp']}  ·  {entry['tool']}  ·  Exit {entry.get('exit_code','?')}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, entry.get("log_path"))
            self.history_list.addItem(item)

    def _load_history_entry(self, item):
        log_path = item.data(Qt.ItemDataRole.UserRole)
        if log_path and os.path.isfile(log_path):
            try:
                content = Path(log_path).read_text(encoding="utf-8")
                self.output_box.setPlainText(content)
                self.status.showMessage(
                    self.lang.tr("status.history_loaded", path=log_path), 4000
                )
            except Exception as e:
                QMessageBox.warning(
                    self, self.lang.tr("msg.error_title"),
                    self.lang.tr("msg.history_load_failed_text", error=e)
                )

    def _process_error(self, error):
        self.output_box.append(f"\n[Fehler beim Ausführen: {error}]\n")
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _stop_tool(self):
        if self.process:
            self.process.kill()
            self.status_timer.stop()
            self.status.showMessage(self.lang.tr("status.cancelled"), 3000)

    def _stop_any(self):
        """Escape-Taste: stoppt je nachdem was gerade läuft."""
        if self._workflow_running:
            self._stop_workflow()
        else:
            self._stop_tool()

    # ---------------------------------------------------------------
    # Automationen (Scan-Ketten)
    # ---------------------------------------------------------------
    @staticmethod
    def _normalize_target(raw, kind):
        t = raw.strip()
        if kind == "url":
            if not re.match(r"^https?://", t, re.I):
                t = "http://" + t
        else:
            t = re.sub(r"^https?://", "", t, flags=re.I).rstrip("/")
        return t

    @staticmethod
    def _default_values_for_tool(tool_name, target):
        """Erzeugt einen values-dict für ein Tool, wobei 'target' übernommen
        und alle übrigen Felder auf ihren Standardwert gesetzt werden."""
        values = {}
        for label, key, ftype, default in TOOLS[tool_name]["fields"]:
            if key == "target":
                values[key] = target
            elif ftype == "combo":
                values[key] = default[0]
            else:
                values[key] = default
        return values

    def _run_workflow(self):
        tr = self.lang.tr
        if self._workflow_running or self.process is not None:
            QMessageBox.warning(
                self, tr("msg.already_running_title"), tr("msg.already_running_text")
            )
            return

        item = self.workflow_list.currentItem()
        if not item:
            QMessageBox.information(
                self, tr("msg.choose_automation_title"), tr("msg.choose_automation_text")
            )
            return

        target = self.workflow_target.text().strip()
        if not target:
            QMessageBox.warning(self, tr("msg.input_missing_title"), tr("msg.target_missing_wf_text"))
            return

        bare = re.sub(r"^https?://", "", target, flags=re.I)
        if not (IP_RE.match(target) or HOST_RE.match(target) or IP_RE.match(bare)):
            reply = QMessageBox.question(
                self, tr("msg.target_check_title"),
                tr("msg.target_check_text", target=target),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        wf_name = item.data(Qt.ItemDataRole.UserRole)
        all_steps = WORKFLOWS[wf_name]
        available_steps = [s for s in all_steps if shutil.which(TOOLS[s]["bin"])]
        missing_bins = [TOOLS[s]["bin"] for s in all_steps if s not in available_steps]

        if missing_bins:
            reply = QMessageBox.question(
                self, tr("msg.tools_missing_title"),
                tr("msg.tools_missing_text", bins="\n".join(missing_bins)),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        if not available_steps:
            QMessageBox.critical(
                self, tr("msg.no_tools_available_title"), tr("msg.no_tools_available_text")
            )
            return

        self._wf_name = wf_name
        self._wf_target = target
        self._wf_steps = available_steps
        self._wf_index = 0
        self._wf_report_lines = [
            f"Automation: {wf_name}\nZiel: {target}\n"
            f"Gestartet: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n{'='*70}\n"
        ]

        self.output_box.append(
            f"\n{'#'*70}\n⚡ AUTOMATION GESTARTET: {wf_name}\nZiel: {target}\n{'#'*70}\n"
        )

        self._workflow_running = True
        self.run_btn.setEnabled(False)
        self.workflow_run_btn.setEnabled(False)
        self.workflow_stop_btn.setEnabled(True)
        self._wf_start_next_step()

    def _wf_start_next_step(self):
        if self._wf_index >= len(self._wf_steps):
            self._wf_finish()
            return

        tool_name = self._wf_steps[self._wf_index]
        tool = TOOLS[tool_name]
        kind = TOOL_TARGET_KIND.get(tool_name, "host")
        target = self._normalize_target(self._wf_target, kind)
        values = self._default_values_for_tool(tool_name, target)

        try:
            cmd = tool["build"](values)
        except Exception as e:
            self.output_box.append(
                f"\n[Schritt übersprungen — Fehler beim Erstellen des Befehls "
                f"für {tool_name}: {e}]\n"
            )
            self._wf_index += 1
            self._wf_start_next_step()
            return

        cmd, self._current_nmap_xml = self._maybe_add_nmap_xml(tool_name, cmd)
        cmd = self._apply_nice(cmd)

        step_no = self._wf_index + 1
        total = len(self._wf_steps)
        self.workflow_progress.setText(f"Schritt {step_no}/{total}: {tool_name}")
        header = (
            f"\n{'='*70}\n[Schritt {step_no}/{total}] {tool_name}\n"
            f"$ {' '.join(cmd)}\n{'='*70}\n"
        )
        self.output_box.append(header)
        self._wf_report_lines.append(header)
        self._wf_step_output = []

        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._wf_read_output)
        self.process.finished.connect(self._wf_step_finished)
        self.process.errorOccurred.connect(self._wf_step_error)
        self.process.start(cmd[0], cmd[1:])
        self.status.showMessage(
            self.lang.tr(
                "status.workflow_running_step", name=self._wf_name,
                step=step_no, total=total, tool=tool_name
            )
        )

    def _wf_read_output(self):
        if not self.process:
            return
        data = self.process.readAllStandardOutput().data().decode(errors="replace")
        self._out_buffer.append(data)
        self._wf_step_output.append(data)

    def _wf_step_finished(self, code, status):
        self._flush_output_buffer()
        self._wf_report_lines.append("".join(self._wf_step_output))
        self._wf_report_lines.append(f"\n[Exit-Code: {code}]\n")
        self.process = None
        # Dashboard nach jedem Schritt aktualisieren (z.B. direkt nach Nmap
        # bereits Port-Statistik sehen, ohne auf die ganze Kette zu warten)
        self._last_nmap_xml = self._current_nmap_xml
        self._current_nmap_xml = None
        self._update_dashboard("".join(self._wf_step_output), self._last_nmap_xml)
        if not self._workflow_running:
            return  # wurde zwischenzeitlich abgebrochen
        self._wf_index += 1
        self._wf_start_next_step()

    def _wf_step_error(self, error):
        self.output_box.append(f"\n[Fehler in Schritt {self._wf_index + 1}: {error}]\n")
        self._wf_report_lines.append(f"\n[Fehler: {error}]\n")
        self.process = None
        if not self._workflow_running:
            return
        self._wf_index += 1
        self._wf_start_next_step()

    def _wf_finish(self):
        self._workflow_running = False
        self.workflow_progress.setText(f"{self.lang.tr('status.workflow_done')} ✓")
        self.output_box.append(
            f"\n{'#'*70}\n✓ AUTOMATION ABGESCHLOSSEN: {self._wf_name}\n{'#'*70}\n"
        )
        self.run_btn.setEnabled(True)
        self.workflow_run_btn.setEnabled(True)
        self.workflow_stop_btn.setEnabled(False)
        self.status.showMessage(self.lang.tr("status.workflow_done"), 5000)

        self._last_log_text = "\n".join(self._wf_report_lines)
        self._last_target = self._wf_target
        self._update_dashboard(self._last_log_text)

        # Als einfache Textdatei archivieren + im Verlauf vermerken
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.datetime.now()
            safe_name = re.sub(r"[^A-Za-z0-9]+", "_", self._wf_name)[:40].strip("_")
            fname = f"{ts:%Y%m%d_%H%M%S}_AUTOMATION_{safe_name}.txt"
            report_path = LOG_DIR / fname
            report_path.write_text("\n".join(self._wf_report_lines), encoding="utf-8")

            self.history.append({
                "timestamp": ts.isoformat(timespec="seconds"),
                "tool": f"⚡ {self._wf_name}",
                "command": f"Automation ({len(self._wf_steps)} Schritte) — Ziel: {self._wf_target}",
                "log_path": str(report_path),
                "exit_code": "—",
            })
            self._save_history()
            self._refresh_history_list()
        except Exception as e:
            self.status.showMessage(
                self.lang.tr("status.workflow_report_failed", error=e), 5000
            )

    def _stop_workflow(self):
        if not self._workflow_running:
            return
        self._workflow_running = False
        self._wf_index = len(self._wf_steps)  # verhindert weitere Schritte
        if self.process:
            self.process.kill()
            self.process = None
        self._wf_report_lines.append("\n[Automation durch Benutzer abgebrochen]\n")
        self.output_box.append("\n[⚡ Automation abgebrochen durch Benutzer]\n")
        self.workflow_progress.setText(self.lang.tr("status.cancelled"))
        self.run_btn.setEnabled(True)
        self.workflow_run_btn.setEnabled(True)
        self.workflow_stop_btn.setEnabled(False)
        self.status.showMessage(self.lang.tr("status.workflow_cancelled"), 4000)

        # Auch abgebrochene Läufe archivieren
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.datetime.now()
            safe_name = re.sub(r"[^A-Za-z0-9]+", "_", self._wf_name or "automation")[:40].strip("_")
            fname = f"{ts:%Y%m%d_%H%M%S}_AUTOMATION_{safe_name}_ABBRUCH.txt"
            report_path = LOG_DIR / fname
            report_path.write_text("\n".join(self._wf_report_lines), encoding="utf-8")
            self.history.append({
                "timestamp": ts.isoformat(timespec="seconds"),
                "tool": f"⚡ {self._wf_name} (abgebrochen)",
                "command": f"Automation abgebrochen — Ziel: {self._wf_target}",
                "log_path": str(report_path),
                "exit_code": "—",
            })
            self._save_history()
            self._refresh_history_list()
        except Exception:
            pass

    # ---------------------------------------------------------------
    def _save_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self, self.lang.tr("button.save_log"), "pandora_cybersec_log.txt",
            "Textdatei (*.txt)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.output_box.toPlainText())
            self.status.showMessage(self.lang.tr("status.log_saved", path=path), 4000)

    # ---------------------------------------------------------------
    # Dashboard / Reporting (Visualisierung der Ergebnisse)
    # ---------------------------------------------------------------
    @staticmethod
    def _parse_port_stats(log_text):
        """Leichte, robuste Regex-Auswertung von Nmap-/allgemeinem Scan-Text
        (funktioniert auch ohne -oX, da die meisten Kali-Tools Klartext auf
        stdout schreiben). Gibt (status_counter, top_services) zurück."""
        status_counter = Counter()
        service_counter = Counter()
        # Nmap-Zeilenformat: "22/tcp   open  ssh   OpenSSH 8.9"
        line_re = re.compile(
            r"^\s*(\d{1,5})/(tcp|udp)\s+(open|closed|filtered)\S*\s*(\S+)?", re.M
        )
        for m in line_re.finditer(log_text):
            status_counter[m.group(3)] += 1
            if m.group(4) and m.group(4) not in ("open|filtered",):
                service_counter[m.group(4)] += 1
        return status_counter, service_counter

    def _update_dashboard(self, log_text, xml_path=None):
        """Baut/aktualisiert das Balkendiagramm im Dashboard-Tab. Wird nach
        jedem einzelnen Tool-Lauf und nach jedem Automations-Schritt
        aufgerufen. Wenn eine Nmap-XML-Datei vorliegt, werden die exakten,
        strukturierten Daten daraus genutzt (Host/Port/Dienst/Version);
        sonst dient eine schnelle Regex-Auswertung des Klartexts als
        Fallback — beides ist auf dem Pi vernachlässigbar günstig."""
        if not log_text and not xml_path:
            return

        tr = self.lang.tr
        host_lines = []
        source_note = tr("dashboard.source_text")
        status_counter = service_counter = None
        if xml_path is not None:
            try:
                if xml_path.exists() and xml_path.stat().st_size > 0:
                    status_counter, service_counter, host_lines = self._parse_nmap_xml(xml_path)
                    if status_counter:
                        source_note = tr("dashboard.source_xml")
            except Exception:
                status_counter = None

        if not status_counter:
            status_counter, service_counter = self._parse_port_stats(log_text)

        if host_lines:
            self._last_host_lines = host_lines  # für HTML-Report

        total_ports = sum(status_counter.values())
        if total_ports == 0:
            self.dash_summary_lbl.setText(tr("dashboard.no_port_lines"))
        else:
            top_services = ", ".join(
                f"{name} ({n}x)" for name, n in service_counter.most_common(5)
            ) or "—"
            self.dash_summary_lbl.setText(
                tr("dashboard.summary", source=source_note, total=total_ports,
                   services=top_services)
                + (tr("dashboard.summary_hosts_suffix", n=len(host_lines)) if host_lines else "")
            )

        if not MATPLOTLIB_OK:
            return

        # Alten Canvas entfernen, um Speicherlecks auf dem Pi zu vermeiden
        if self._dash_canvas is not None:
            self._dash_container.removeWidget(self._dash_canvas)
            self._dash_canvas.setParent(None)
            self._dash_canvas.deleteLater()
            self._dash_canvas = None

        if total_ports == 0:
            self._dashboard_placeholder.setText(tr("dashboard.no_chart_data"))
            self._dashboard_placeholder.show()
            return
        self._dashboard_placeholder.hide()

        # kleine, feste Figure-Größe + niedriges DPI: hält Render-Kosten
        # auf dem Pi gering (kein interaktives/animiertes Redraw nötig)
        fig = plt.Figure(figsize=(5.5, 3.2), dpi=90)
        fig.patch.set_facecolor(BG_DARK)
        ax = fig.add_subplot(111)
        ax.set_facecolor(BG_PANEL)

        order = ["open", "filtered", "closed"]
        colors = {"open": TERM_GREEN, "filtered": GOLD, "closed": "#6b6b6b"}
        labels = [s for s in order if s in status_counter]
        values = [status_counter[s] for s in labels]
        bars = ax.bar(labels, values, color=[colors[s] for s in labels])
        ax.set_ylabel(tr("dashboard.chart_ylabel"), color=TEXT_LIGHT)
        ax.set_title(tr("dashboard.chart_title"), color=GOLD)
        ax.tick_params(colors=TEXT_LIGHT)
        for spine in ax.spines.values():
            spine.set_color(GOLD_DIM)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, val, str(val),
                    ha="center", va="bottom", color=TEXT_LIGHT, fontsize=9)
        fig.tight_layout()

        self._dash_canvas = FigureCanvas(fig)
        self._dash_container.addWidget(self._dash_canvas)

    def _export_html_report(self):
        """Exportiert einen eigenständigen HTML-Report (Diagramm als
        eingebettetes PNG + Host-/Port-Tabelle + Log-Auszug + ggf.
        KI-Analyse) — ohne zusätzliche Abhängigkeiten, ein Browser reicht."""
        tr = self.lang.tr
        if not getattr(self, "_last_log_text", ""):
            QMessageBox.information(
                self, tr("msg.no_run_yet_title"), tr("msg.no_run_yet_text")
            )
            return
        path, _ = QFileDialog.getSaveFileName(
            self, tr("button.export_html"), "pandora_report.html", "HTML (*.html)"
        )
        if not path:
            return

        img_tag = ""
        if MATPLOTLIB_OK and self._dash_canvas is not None:
            try:
                buf_path = Path(tempfile.gettempdir()) / "pandora_dash_export.png"
                self._dash_canvas.figure.savefig(
                    buf_path, facecolor=BG_DARK, dpi=110
                )
                b64 = base64.b64encode(buf_path.read_bytes()).decode("ascii")
                img_tag = f'<img src="data:image/png;base64,{b64}" style="max-width:600px;">'
            except Exception:
                img_tag = ""

        hosts_html = "".join(
            f"<li>{h}</li>" for h in getattr(self, "_last_host_lines", [])
        ) or "<li>(keine strukturierten Host-Daten — Nmap-XML aktivieren für Details)</li>"

        ki_text = self.ki_result_box.toPlainText().strip() if hasattr(self, "ki_result_box") else ""
        ki_html = (
            f"<h2>KI-Analyse</h2><pre>{self._html_escape(ki_text)}</pre>"
            if ki_text else ""
        )

        html = f"""<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<title>Pandora CyberSec Report</title>
<style>
body {{ background:{BG_DARK}; color:{TEXT_LIGHT}; font-family: sans-serif; padding: 24px; }}
h1 {{ color:{GOLD}; }} h2 {{ color:{GOLD}; border-bottom:1px solid {GOLD_DIM}; }}
pre {{ background:#05070a; color:{TERM_GREEN}; padding:12px; border-radius:6px;
       overflow-x:auto; white-space:pre-wrap; }}
li {{ margin: 4px 0; }}
</style></head><body>
<h1>Pandora® CyberSec Toolkit — Report</h1>
<p>Ziel: {self._html_escape(self._last_target or "—")}<br>
Erstellt: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}</p>
<h2>Port-/Statusdiagramm</h2>
{img_tag or "<p><em>(kein Diagramm — matplotlib nicht installiert oder keine Portdaten)</em></p>"}
<h2>Hosts</h2>
<ul>{hosts_html}</ul>
{ki_html}
<h2>Log (Auszug, letzte 10.000 Zeichen)</h2>
<pre>{self._html_escape(self._last_log_text[-10000:])}</pre>
</body></html>"""

        try:
            Path(path).write_text(html, encoding="utf-8")
            self.status.showMessage(tr("status.report_saved", path=path), 5000)
        except Exception as e:
            QMessageBox.critical(
                self, tr("msg.error_title"), tr("msg.report_save_failed_text", error=e)
            )

    @staticmethod
    def _html_escape(text):
        return (
            text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )

    # ---------------------------------------------------------------
    # Zentrales API-Key-Profil (Gemini / Shodan / VirusTotal — jeweils
    # optional, alle Keys liegen lokal in derselben config.json wie die
    # übrigen Tool-Profile).
    # ---------------------------------------------------------------
    def _load_api_key(self, name):
        return self.profiles.get(f"__{name}_api_key__", "")

    def _save_api_key(self, name, key, label=None):
        self.profiles[f"__{name}_api_key__"] = key
        self._save_profiles()
        self.status.showMessage(
            self.lang.tr("status.apikey_saved", label=label or name.capitalize()), 3000
        )

    def _save_shodan_key(self, key):
        """Speichert den Shodan-Key im zentralen Profil UND initialisiert
        gleichzeitig die shodan-CLI (shodan init <key>), damit das
        'Shodan CLI'-Tool direkt ohne weiteren Schritt funktioniert."""
        self._save_api_key("shodan", key, "Shodan")
        if key and shutil.which("shodan"):
            try:
                import subprocess
                subprocess.run(
                    ["shodan", "init", key],
                    capture_output=True, timeout=15, check=False
                )
            except Exception:
                pass  # Init-Fehler sind nicht kritisch — Key ist trotzdem gespeichert

    # -- Rückwärtskompatible Gemini-Wrapper (bestehender Code nutzt diese) --
    def _load_gemini_key(self):
        return self._load_api_key("gemini")

    def _save_gemini_key(self, key):
        self._save_api_key("gemini", key, "Gemini")

    def _run_gemini_analysis(self):
        tr = self.lang.tr
        api_key = self.gemini_key_edit.text().strip()
        if not api_key:
            QMessageBox.information(
                self, tr("msg.apikey_missing_title"), tr("msg.gemini_key_missing_text")
            )
            return
        if not self._last_log_text:
            QMessageBox.information(
                self, tr("msg.no_log_title"), tr("msg.no_log_text")
            )
            return
        if self.gemini_worker is not None and self.gemini_worker.isRunning():
            self.status.showMessage(tr("status.ki_already_running"), 3000)
            return

        self.ki_analyze_btn.setEnabled(False)
        self.ki_result_box.setPlainText(tr("status.ki_running"))
        self.status.showMessage(tr("status.ki_sending"))

        self.gemini_worker = GeminiWorker(
            api_key,
            self._current_tool_name or self._wf_name or "Unbekanntes Werkzeug",
            self._last_target,
            self._last_log_text,
        )
        self.gemini_worker.finished_ok.connect(self._on_gemini_ok)
        self.gemini_worker.finished_err.connect(self._on_gemini_err)
        self.gemini_worker.start()

    def _on_gemini_ok(self, text):
        self.ki_result_box.setPlainText(text)
        self.ki_analyze_btn.setEnabled(True)
        self.status.showMessage(self.lang.tr("status.ki_done"), 4000)

    def _on_gemini_err(self, text):
        self.ki_result_box.setPlainText(self.lang.tr("ki.error_prefix", error=text))
        self.ki_analyze_btn.setEnabled(True)
        self.status.showMessage(self.lang.tr("status.ki_failed"), 5000)

    # ---------------------------------------------------------------
    # VirusTotal-Reputationsabfrage (optional, erfordert eigenen Key)
    # ---------------------------------------------------------------
    def _run_vt_lookup(self):
        tr = self.lang.tr
        api_key = self.vt_key_edit.text().strip()
        if not api_key:
            QMessageBox.information(
                self, tr("msg.apikey_missing_title"), tr("msg.vt_key_missing_text")
            )
            return
        query = self.vt_query_edit.text().strip()
        if not query:
            QMessageBox.information(
                self, tr("msg.input_missing_title"), tr("msg.vt_query_missing_text")
            )
            return
        if self.vt_worker is not None and self.vt_worker.isRunning():
            self.status.showMessage(tr("status.vt_already_running"), 3000)
            return

        qtype = ["hash", "ip", "domain", "url"][self.vt_type_combo.currentIndex()]

        self.vt_lookup_btn.setEnabled(False)
        self.vt_result_box.setPlainText(tr("status.vt_querying"))
        self.status.showMessage(tr("status.vt_sending"))

        self.vt_worker = VTWorker(api_key, qtype, query)
        self.vt_worker.finished_ok.connect(self._on_vt_ok)
        self.vt_worker.finished_err.connect(self._on_vt_err)
        self.vt_worker.start()

    def _on_vt_ok(self, text):
        self.vt_result_box.setPlainText(text)
        self.vt_lookup_btn.setEnabled(True)
        self.status.showMessage(self.lang.tr("status.vt_done"), 4000)

    def _on_vt_err(self, text):
        self.vt_result_box.setPlainText(self.lang.tr("vt.error_prefix", error=text))
        self.vt_lookup_btn.setEnabled(True)
        self.status.showMessage(self.lang.tr("status.vt_failed"), 5000)


def main():
    app = QApplication(sys.argv)

    # PyInstaller sys.frozen Pfad-Fix (Icon liegt im Bundle statt im Skriptordner)
    if getattr(sys, "frozen", False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).resolve().parent
    icon_path = base_path / "pandora_cybersec_icon.svg"

    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))
    # Sprachdienst zuerst erzeugen: lädt alle 10 Sprachpakete, stellt die
    # zuletzt gewählte Sprache wieder her und überwacht language_packs/
    # per Hot-Reload auf neue/geänderte Sprachdateien.
    language_service = LanguageService(default_language="de")
    win = CyberToolkit(language_service=language_service)
    if icon_path.exists():
        win.setWindowIcon(QIcon(str(icon_path)))
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
