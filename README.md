# Pandora® CyberSec Toolkit

**A unified PyQt6 GUI front-end for ~100 well-known Kali Linux security tools — with built-in authorization gate, AI-assisted log analysis, and a live findings dashboard.**

> Brand: AKI_SystemDown® / Pandora® · Platform: Kali Linux (Raspberry Pi 4B, 8GB, Xfce) · Language: Python 3 / PyQt6

![Pandora CyberSec Toolkit](pandora_cybersec_toolkit_icon.png)

---

## ⚠️ Legal & Ethical Notice

**This project does not contain any exploit code.** It is a graphical launcher/wrapper around security tools that are already installed on Kali Linux — it builds the correct command line for you, runs it as a subprocess, and helps you read the output.

- Use is permitted **only** against systems you own, or systems for which you have the **explicit, written permission** of the owner.
- Unauthorized scanning, brute-forcing, wireless attacks, or exploitation is **illegal in most jurisdictions**.
- On startup, the application shows a **mandatory authorization dialog** that the user must actively confirm before any tool can be executed.
- The authors/maintainers assume no liability for misuse. You are solely responsible for how you use this software.

By using this toolkit you confirm you are acting within an authorized engagement (e.g. your own lab, a CTF, or a signed penetration test / bug bounty scope).

---

## What is this?

Pandora® CyberSec Toolkit turns dozens of separate command-line security utilities into one consistent, form-based interface: pick a tool, fill in a few fields (target, wordlist, flags, …), hit run, and watch live output in a terminal-style pane — complete with process control (start/stop), automatic Nmap XML capture, a results dashboard, and optional AI-assisted analysis of the scan log.

It is aimed at people who already know how to use these tools on the command line but want:
- one consistent place to launch them,
- saved target/parameter profiles instead of retyping commands,
- an at-a-glance dashboard of open ports/services after a scan,
- and an authorization gate to reduce the risk of running a tool against the wrong target by mistake.

---

## Who is this for? (Team / Role Mapping)

The toolkit bundles offensive, defensive, and investigative tooling in one place. The table below maps the included categories to the security team / role that typically owns that kind of work, so you know which parts are relevant to you:

| Category in the app | Example tools | Relevant team / role |
|---|---|---|
| Network & Service Recon | Nmap, Masscan, ARP-scan, Netdiscover, Nbtscan | **Red Team** / Pentesters — initial reconnaissance |
| Web Application Testing | Nikto, SQLMap, Gobuster, FFUF, WPScan, Dirsearch, Feroxbuster, Nuclei, OWASP ZAP, Commix, WafW00f | **Red Team** / AppSec / Bug Bounty Hunters |
| DNS & OSINT | WHOIS, dig, DNSrecon, Fierce, Dnsenum, TheHarvester, Subfinder, Amass, Httpx | **Red Team** / OSINT Analysts |
| Credential Attacks & Hash Cracking | Hydra, Medusa, John the Ripper, Hashcat, Hashid, CeWL, Crunch | **Red Team** — *authorized* credential auditing |
| Active Directory | Kerbrute, Impacket (GetUserSPNs, GetNPUsers, secretsdump), BloodHound-python, CrackMapExec | **Red Team** — AD attack-path assessment |
| Wireless (Wi-Fi / BLE / RFID / NFC) | Aircrack-ng, Airmon-ng, Airodump-ng, Aireplay-ng, Wifite, Reaver, Bully, Hcxdumptool, Kismet, Bettercap, Bluetoothctl, Proxmark3, Mfoc/Mfcuk | **Red Team** — *authorized* wireless / RF assessments |
| Cloud & Container Security | ScoutSuite, Prowler, S3Scanner, Cloud_enum, CloudFox, Trivy, Grype, Kube-hunter, Kube-bench, Kubeaudit, Checkov, Docker Bench Security | **Cloud Security / DevSecOps** teams |
| Forensics & Malware Analysis | Volatility3, Binwalk, Foremost, ExifTool, Bulk_extractor, YARA, Radare2, Objdump, Strings, Capa, Ssdeep, UPX | **Blue Team / DFIR / Malware Analysts** |
| Host Integrity | Chkrootkit, Rkhunter, Dc3dd | **Blue Team / SysAdmins** — integrity & incident response |
| API Security | Kiterunner, Arjun, X8, Schemathesis | **AppSec / API Security** teams |
| Exploit Research | Searchsploit | **Red Team / Vulnerability Research** |
| Threat Enrichment | VirusTotal lookup (IP/domain/hash/URL), Shodan CLI | **Blue Team / SOC / Threat Intel** |
| AI Log Triage | Gemini-powered scan-log summarization | All roles — faster first-pass triage of raw tool output |

> **Purple Team** use is implicit throughout: the recon/attack tooling (Red) paired with the forensics, integrity, and threat-intel tooling (Blue) in the same interface supports collaborative exercises where offense and defense validate each other's findings.

All tools call out to binaries that must already be installed on the host system (mostly present by default on Kali Linux, or installable via `apt`/`pip`/`go install`). This project does **not** ship or bundle any of those binaries.

---

## Features

- 🧩 **~100 integrated tools** across recon, web, credentials, AD, wireless, cloud, forensics, and RE/malware analysis
- 🛡️ **Mandatory authorization dialog** on startup — no tool runs without explicit user confirmation
- 🖥️ **Live terminal pane** with syntax highlighting, start/stop control, and process management (`QProcess`)
- 📊 **Automatic results dashboard** — parses Nmap XML output into host/port/service summaries and charts (via `matplotlib`, if installed)
- 🤖 **Optional AI-assisted analysis** — send a scan log excerpt to the Gemini API for a plain-language summary (bring your own API key)
- 🔍 **VirusTotal lookup tab** — query hash/IP/domain/URL reputation (bring your own API key)
- 🔑 **Central API key profile** — Gemini / VirusTotal / Shodan keys stored locally in one place
- 💾 **Saved target/parameter profiles** so you don't retype the same scan configuration
- 🌍 **10-language UI** (see below) with hot-reloadable language packs
- 🖼️ Custom Pandora® dark-red cyberpunk theme, desktop launcher (`.desktop`) install script for Kali/Xfce

---

## Supported Languages

The UI ships with language packs for:

`en_US` (English) · `de_DE` (German) · `es_ES` (Spanish) · `fr_FR` (French) · `it_IT` (Italian) · `ru_RU` (Russian) · `tr_TR` (Turkish) · `sq_AL` (Albanian) · `mk_MK` (Macedonian) · `bs_BA` (Bosnian)

Language can be switched at runtime via **Settings** — no restart required.

---

## Requirements

- **OS:** Kali Linux (developed/tested on Raspberry Pi 4B, 8GB RAM, Xfce). Should run on any Linux with the tools below installed.
- **Python:** 3.10+
- **GUI framework:**
  ```bash
  sudo apt install python3-pyqt6
  ```
- **Optional (for charts on the dashboard tab):**
  ```bash
  pip install matplotlib
  ```
- **Security tools invoked by the app** (install only what you plan to use — most are pre-installed on Kali or available via `apt`):
  ```
  nmap nikto whois dnsutils gobuster sqlmap hydra theharvester netdiscover
  aircrack-ng john wpscan enum4linux smbmap dnsrecon fierce masscan ffuf
  wafw00f sslscan arp-scan exploitdb crackmapexec nbtscan tcpdump whatweb
  subfinder amass httpx nuclei dirsearch feroxbuster testssl.sh dnsenum
  aircrack-ng-suite wifite reaver bully hcxtools kismet cloud-enum s3scanner
  scoutsuite prowler bettercap bluez impacket-scripts bloodhound.py
  volatility3 binwalk foremost exiftool bulk-extractor chkrootkit rkhunter
  yara radare2 binutils ssdeep upx-ucl hashcat hash-identifier cewl crunch
  medusa openssl trivy grype kube-hunter kube-bench kubeaudit checkov
  docker-bench-security zaproxy commix wifiphisher cloudfox spooftooph
  responder proxmark3
  ```
  Each tool tab clearly names its required binary; the app will report an error if a binary is missing rather than failing silently.
- **API keys (all optional, bring-your-own):**
  - Google Gemini API key — for AI-assisted log analysis
  - VirusTotal API key — for reputation lookups
  - Shodan API key — for the Shodan CLI tab

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/bosancero85/pandora-cybersec-toolkit.git
cd pandora-cybersec-toolkit

# 2. Install the GUI dependency
sudo apt install python3-pyqt6

# 3. (Optional) install charting support
pip install matplotlib

# 4. Install whichever security tools you intend to use (see Requirements above)
sudo apt install nmap nikto whois dnsutils gobuster sqlmap hydra ...

# 5. Run
python3 pandora_cybersec_toolkit.py
```

### Desktop launcher (Kali / Xfce)

To add the toolkit to your application menu with its icon:

```bash
./install_pandora_cybersec_toolkit_desktop.sh
```

Run without arguments to auto-detect the script location (checks the current folder, `~/Pandora`, `~`, and `~/Desktop`), or pass an explicit path:

```bash
./install_pandora_cybersec_toolkit_desktop.sh /path/to/pandora_cybersec_toolkit.py
```

---

## Usage

1. Launch the app: `python3 pandora_cybersec_toolkit.py`
2. **Confirm the authorization dialog** — you must acknowledge that you are only targeting systems you're authorized to test.
3. Pick a tool from the list, fill in the required fields (target, wordlist path, flags, etc.).
4. Press **Run** (or `Ctrl+Enter`) to execute; press `Esc` to stop a running process.
5. Review output in the live terminal pane; Nmap scans are automatically captured as XML for the **Dashboard** tab.
6. Optionally send the scan log to the **AI Analysis** tab (requires a Gemini API key, configured under the **API Keys** tab) for a plain-language summary.
7. Use the **VirusTotal** tab to enrich a hash, IP, domain, or URL (requires a VirusTotal API key).
8. Save frequently used target/parameter combinations as a **profile** for quick re-use.

---

## Project Structure

```
pandora_cybersec_toolkit/
├── pandora_cybersec_toolkit.py       # Main application (GUI, tool definitions, process handling)
├── core/
│   └── language_service.py           # Language loading/translation service
├── ui/
│   └── settings_dialog.py            # Settings dialog (language, API keys, preferences)
├── language_plugin/
│   ├── language_manager.py           # Language pack manager / hot-reload
│   └── language_packs/               # en_US, de_DE, es_ES, fr_FR, it_IT, ru_RU, tr_TR, sq_AL, mk_MK, bs_BA
├── install_pandora_cybersec_toolkit_desktop.sh   # .desktop launcher installer for Kali/Xfce
└── pandora_cybersec_toolkit_icon.png
```

---

## Disclaimer

This software is provided "as is", without warranty of any kind. It is intended for authorized security testing, security research, CTFs, and educational purposes only. The developer(s) are not responsible for any misuse or damage caused by this software. Always obtain proper written authorization before testing any system you do not own.

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for the full text. Note the additional usage notice included there regarding the third-party security tools this GUI invokes, and the authorization requirement for using this software at all.

---

## Credits

Developed by **AKI_SystemDown® / Pandora®**.
