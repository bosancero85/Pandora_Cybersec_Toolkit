#!/usr/bin/env bash
# ---------------------------------------------------------------------
# Pandora® Cybersec Toolkit - Installer für Anwendungsstarter (.desktop)
# ---------------------------------------------------------------------
# Installiert Icon + .desktop-Datei, sodass der Editor im Kali-
# Anwendungsmenü (und optional auf dem Desktop) auftaucht.
#
# Verwendung:
#   ./install_pandora_cybersec_toolkit_desktop.sh [Pfad/zu/pandora_cybersec_toolkit.py]
#
# Ohne Argument wird das Skript automatisch in diesem Ordner sowie in
# ~/Pandora, ~/ und ~/Desktop gesucht.
# ---------------------------------------------------------------------

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICON_SRC="$SCRIPT_DIR/pandora_cybersec_toolkit_icon.png"

# ---- 1. pandora_cybersec_toolkit.py finden ----
TARGET_PY="$1"
if [ -z "$TARGET_PY" ]; then
    CANDIDATES=(
        "$SCRIPT_DIR/pandora_cybersec_toolkit.py"
        "$HOME/Pandora/pandora_cybersec_toolkit.py"
        "$HOME/pandora_cybersec_toolkit.py"
        "$HOME/Desktop/pandora_cybersec_toolkit.py"
    )
    for c in "${CANDIDATES[@]}"; do
        if [ -f "$c" ]; then
            TARGET_PY="$c"
            break
        fi
    done
fi

if [ -z "$TARGET_PY" ] || [ ! -f "$TARGET_PY" ]; then
    echo "❌ pandora_cybersec_toolkit.py wurde nicht gefunden."
    echo "   Bitte Pfad als Argument übergeben:"
    echo "   ./install_pandora_cybersec_toolkit_desktop.sh /pfad/zu/pandora_cybersec_toolkit.py"
    exit 1
fi
TARGET_PY="$(cd "$(dirname "$TARGET_PY")" && pwd)/$(basename "$TARGET_PY")"
echo "✅ Skript gefunden: $TARGET_PY"

# ---- 2. Icon installieren ----
ICON_DIR="$HOME/.local/share/icons/pandora"
mkdir -p "$ICON_DIR"
if [ -f "$ICON_SRC" ]; then
    cp -f "$ICON_SRC" "$ICON_DIR/pandora_cybersec_toolkit_icon.png"
    ICON_PATH="$ICON_DIR/pandora_cybersec_toolkit_icon.png"
    echo "✅ Icon installiert: $ICON_PATH"
else
    ICON_PATH="utilities-terminal"
    echo "⚠️  Icon-Datei nicht gefunden, verwende Fallback-Icon."
fi

# ---- 3. .desktop-Datei erzeugen ----
APP_DIR="$HOME/.local/share/applications"
mkdir -p "$APP_DIR"
DESKTOP_FILE="$APP_DIR/pandora-cybersec-toolkit.desktop"

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Type=Application
Name=Pandora® CyberSec Toolkit
GenericName=Pandora® Kali CyberSec Toolkit
Comment=100+ Kali-Security-Tools per GUI, Scan-Ketten, Gemini-KI-Analyse und Dashboard
Exec=python3 "$TARGET_PY"
Icon=$ICON_PATH
Terminal=false
Categories=Development;IDE;TextEditor;
Keywords=Pandora;Python;Editor;IDE;CTF;Kali;
StartupNotify=true
StartupWMClass=pandora_cybersec_toolkit.py
EOF

chmod +x "$DESKTOP_FILE"
chmod +x "$TARGET_PY"
echo "✅ Starter installiert: $DESKTOP_FILE"

# ---- 4. Desktop-Datenbank aktualisieren ----
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR" 2>/dev/null || true
    echo "✅ Anwendungsmenü aktualisiert."
fi

# ---- 5. Optional: Verknüpfung auf dem Desktop ----
if [ -d "$HOME/Desktop" ]; then
    read -p "Zusätzlich eine Verknüpfung auf dem Desktop anlegen? [j/N] " ans
    if [[ "$ans" =~ ^[jJ]$ ]]; then
        cp -f "$DESKTOP_FILE" "$HOME/Desktop/pandora-cybersec-toolkit.desktop"
        chmod +x "$HOME/Desktop/pandora-cybersec-toolkit.desktop"
        # Kali/GNOME/XFCE verlangen oft "als vertrauenswürdig markieren"
        gio set "$HOME/Desktop/pandora-cybersec-toolkit.desktop" metadata::trusted true 2>/dev/null || true
        echo "✅ Desktop-Verknüpfung angelegt."
    fi
fi

echo ""
echo "🎉 Fertig! Pandora® CyberSec Toolkit sollte jetzt im Anwendungsmenü"
echo "   (Kategorie 'Entwicklung/Development') auffindbar sein."
echo "   Falls PyQt6 fehlt: pip install PyQt6 --break-system-packages"
