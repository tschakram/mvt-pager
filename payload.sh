#!/bin/bash
# Title: MVT on Pager
# Description: Android spyware detection via ADB (packages, processes, IOCs)
# Author: tschakram
# Category: reconnaissance
# Version: 1.1

# OpenWrt: mmc-Pakete nicht im Standard-PATH (Pager Framework = non-login shell)
export PATH="/mmc/usr/bin:/mmc/usr/sbin:/mmc/bin:/mmc/sbin:$PATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:/mmc/lib:${LD_LIBRARY_PATH:-}"

# ============================================================
# CONFIGURATION
# ============================================================
LOOT_DIR="/root/loot/mvt_pager"
REPORT_DIR="$LOOT_DIR/reports"
PYTHON_DIR="/root/payloads/user/reconnaissance/mvt-pager/python"
ADB_WAIT_TIMEOUT=90

# ============================================================
# SETUP
# ============================================================
mkdir -p "$LOOT_DIR" "$REPORT_DIR"

LOG "=============================="
LOG "    MVT on Pager  v1.1"
LOG "=============================="
LOG ""
LOG "Android Spyware Detection"
LOG "via ADB + IOC Matching"
LOG ""
sleep 2

# ============================================================
# DEPENDENCY CHECK
# ============================================================
SPINNER_ID=$(START_SPINNER "Prüfe Abhängigkeiten...")

# Systemzeit prüfen
CURRENT_YEAR=$(date +%Y)
if [ "$CURRENT_YEAR" -lt 2026 ]; then
    hwclock -s 2>/dev/null
fi

STOP_SPINNER "$SPINNER_ID"

# Python3
if ! command -v python3 >/dev/null 2>&1; then
    LOG red "✗ Python3 nicht gefunden!"
    LOG yellow "  Installiere python3..."
    opkg update -d mmc 2>/dev/null
    opkg install -d mmc python3 2>/dev/null
    if ! command -v python3 >/dev/null 2>&1; then
        LOG red "✗ Python3 Installation fehlgeschlagen"
        WAIT_FOR_BUTTON_PRESS "red"
        exit 1
    fi
fi
LOG green "✓ Python3 OK"

# ADB
if ! command -v adb >/dev/null 2>&1; then
    LOG yellow "⚠ ADB nicht gefunden"
    LOG "  Installiere via opkg..."
    opkg update -d mmc 2>/dev/null
    opkg install -d mmc adb 2>/dev/null
    if ! command -v adb >/dev/null 2>&1; then
        LOG red "✗ ADB nicht installiert"
        LOG yellow "  Bitte manuell:"
        LOG "  opkg install -d mmc adb"
        WAIT_FOR_BUTTON_PRESS "red"
        exit 1
    fi
    LOG green "✓ ADB installiert"
fi
LOG green "✓ ADB OK"
sleep 1

# ============================================================
# SCAN-MODUS WÄHLEN
# ============================================================
LOG ""
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG blue "       Scan-Modus"
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG ""
LOG "1 = Quick-Scan  (~2-3 min)"
LOG "    Pakete, Prozesse,"
LOG "    Settings, Properties"
LOG ""
LOG "2 = Full-Scan   (~10-15 min)"
LOG "    Alle Module + IOC-Check"
LOG ""
sleep 3

SCAN_MODE=$(NUMBER_PICKER "1=Quick 2=Full:" 1)
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        SCAN_MODE=1 ;;
esac

# IOC-Datenbank Option (nur Full-Scan)
USE_IOC=false
if [ "$SCAN_MODE" -eq 2 ]; then
    LOG ""
    CONFIRMATION_DIALOG "IOC-Datenbank von MVT laden? (Internet)"
    [ $? -eq 0 ] && USE_IOC=true
fi

LOG ""
if [ "$SCAN_MODE" -eq 1 ]; then
    LOG blue "  Modus: Quick-Scan"
else
    LOG blue "  Modus: Full-Scan"
    [ "$USE_IOC" = true ] && LOG blue "  IOCs: aktiv" || LOG "  IOCs: deaktiviert"
fi
sleep 2

# ============================================================
# ANDROID-GERÄT VERBINDEN
# ============================================================
LOG ""
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG blue "  Android-Gerät verbinden"
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG ""
LOG "1. USB-OTG Adapter anstecken"
LOG "2. Android-Gerät anschließen"
LOG "3. USB-Debugging aktivieren"
LOG "4. 'Immer von diesem PC'"
LOG "   auf dem Gerät erlauben"
LOG ""
LOG "ROT = Abbrechen"
LOG ""
sleep 4

LED yellow blink
DEVICE_FOUND=false
ELAPSED=0

while [ "$DEVICE_FOUND" = false ] && [ "$ELAPSED" -lt "$ADB_WAIT_TIMEOUT" ]; do
    DEVICE_RESULT=$(python3 "$PYTHON_DIR/adb_check.py" 2>/dev/null)
    case "$DEVICE_RESULT" in
        DEVICE:*)
            DEVICE_SERIAL=$(echo "$DEVICE_RESULT" | cut -d: -f2)
            DEVICE_MODEL=$(echo "$DEVICE_RESULT" | cut -d: -f3)
            DEVICE_FOUND=true
            ;;
        UNAUTHORIZED)
            LOG yellow "⚠ Gerät verbunden — nicht autorisiert"
            LOG yellow "  Verbindung am Gerät erlauben!"
            LED yellow solid
            sleep 5
            ELAPSED=$((ELAPSED + 5))
            LED yellow blink
            ;;
        NO_DEVICE)
            REMAINING=$((ADB_WAIT_TIMEOUT - ELAPSED))
            LOG "  Warte... (${REMAINING}s)"
            sleep 5
            ELAPSED=$((ELAPSED + 5))
            ;;
        ERROR:*)
            ERR_MSG=$(echo "$DEVICE_RESULT" | cut -d: -f2-)
            LOG red "ADB Fehler: $ERR_MSG"
            sleep 5
            ELAPSED=$((ELAPSED + 5))
            ;;
    esac
done

if [ "$DEVICE_FOUND" = false ]; then
    LED red solid
    LOG red ""
    LOG red "✗ Kein Gerät gefunden"
    LOG red "  Timeout nach ${ADB_WAIT_TIMEOUT}s"
    LOG ""
    LOG "USB-Debugging aktiviert?"
    WAIT_FOR_BUTTON_PRESS "red"
    exit 1
fi

LED cyan solid
LOG ""
LOG green "✓ Gerät verbunden!"
LOG ""
LOG "  Serial: $DEVICE_SERIAL"
[ -n "$DEVICE_MODEL" ] && LOG "  Modell: $DEVICE_MODEL"
LOG ""
sleep 2

CONFIRMATION_DIALOG "Scan starten: ${DEVICE_MODEL:-$DEVICE_SERIAL}?"
if [ $? -ne 0 ]; then
    LOG yellow "Abgebrochen."
    LED off
    WAIT_FOR_BUTTON_PRESS "red"
    exit 0
fi

# ============================================================
# SCAN STARTEN
# ============================================================
TS=$(date +%Y%m%d_%H%M%S)
SCAN_DIR="$REPORT_DIR/scan_${TS}"
mkdir -p "$SCAN_DIR"

LOG ""
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG blue "       Scan läuft"
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG ""

if [ "$SCAN_MODE" -eq 1 ]; then
    LOG "📱 Quick-Scan gestartet..."
    LOG "   Dauer: ~2-3 Minuten"
else
    LOG "📱 Full-Scan gestartet..."
    LOG "   Dauer: ~10-15 Minuten"
    [ "$USE_IOC" = true ] && LOG "   IOC-Check: aktiv"
fi
LOG ""

LED blue blink
SPINNER_ID=$(START_SPINNER "MVT Scan läuft...")

SCAN_OUTPUT=$(python3 "$PYTHON_DIR/adb_scan.py" \
    --serial "$DEVICE_SERIAL" \
    --output "$SCAN_DIR" \
    --mode "$SCAN_MODE" \
    $([ "$USE_IOC" = true ] && echo "--iocs") 2>&1)
SCAN_EXIT=$?

STOP_SPINNER "$SPINNER_ID"

# Ergebniswerte parsen
DETECTIONS=$(echo "$SCAN_OUTPUT" | grep "^DETECTIONS:" | cut -d: -f2)
PACKAGES=$(echo "$SCAN_OUTPUT" | grep "^PACKAGES:" | cut -d: -f2)
PROCESSES=$(echo "$SCAN_OUTPUT" | grep "^PROCESSES:" | cut -d: -f2)
IOC_HITS=$(echo "$SCAN_OUTPUT" | grep "^IOC_HITS:" | cut -d: -f2)
SCAN_ERROR=$(echo "$SCAN_OUTPUT" | grep "^ERROR:" | cut -d: -f2-)

# ============================================================
# ERGEBNIS ANZEIGEN
# ============================================================
LOG ""
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG blue "        ERGEBNIS"
LOG blue "━━━━━━━━━━━━━━━━━━━━━━━━━━"
LOG ""

if [ $SCAN_EXIT -ne 0 ] && [ -n "$SCAN_ERROR" ]; then
    LED red solid
    LOG red "✗ Scan fehlgeschlagen:"
    LOG red "  $SCAN_ERROR"
    LOG ""
    LOG "Report-Pfad: $SCAN_DIR"
    WAIT_FOR_BUTTON_PRESS "red"
    exit 1
fi

LOG "📦 Pakete:       ${PACKAGES:-?}"
LOG "⚙  Prozesse:     ${PROCESSES:-?}"
LOG "🔍 Detektionen:  ${DETECTIONS:-0}"
[ "$USE_IOC" = true ] && LOG "☣  IOC Treffer:  ${IOC_HITS:-0}"
LOG ""

if [ "${DETECTIONS:-0}" -gt 0 ] || [ "${IOC_HITS:-0}" -gt 0 ]; then
    LED red blink
    LOG red "🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨"
    LOG red "   SPYWARE-HINWEIS!"
    LOG red "   Indikatoren gefunden!"
    LOG red "🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨"
    LOG ""
    # Detektierte Indikatoren einzeln anzeigen
    echo "$SCAN_OUTPUT" | grep "^INDICATOR:" | cut -d: -f2- | while IFS= read -r line; do
        LOG red "  ⚠ $line"
    done
    LOG ""
    VIBRATE 5
else
    LED green solid
    LOG green "✅ Keine Spyware erkannt"
    LOG green "   Gerät unauffällig"
fi

LOG ""
LOG "Report: $SCAN_DIR"
LOG ""

# ============================================================
# CYT EXPORT
# ============================================================
SPINNER_ID=$(START_SPINNER "CYT Export...")
CYT_OUTPUT=$(python3 "$PYTHON_DIR/cyt_export.py" \
    --scan-dir "$SCAN_DIR" \
    --device "${DEVICE_MODEL:-Unbekannt}" \
    --serial "$DEVICE_SERIAL" \
    --detections "${DETECTIONS:-0}" \
    --ioc-hits "${IOC_HITS:-0}" \
    --loot-dir "$LOOT_DIR" 2>/dev/null)
STOP_SPINNER "$SPINNER_ID"

CYT_PATH=$(echo "$CYT_OUTPUT" | grep "^CYT_REPORT:" | cut -d: -f2-)
if [ -n "$CYT_PATH" ]; then
    LOG green "✓ CYT Export: $CYT_PATH"
else
    LOG yellow "⚠ CYT Export fehlgeschlagen"
fi

# ============================================================
# BEENDEN
# ============================================================
LOG ""
LOG "=============================="
LOG "  Drücke ROT zum Beenden"
LOG "=============================="
LED off
WAIT_FOR_BUTTON_PRESS "red"
exit 0
