# MVT on Pager

A [WiFi Pineapple Pager](https://docs.hak5.org/wifi-pineapple-pager) payload for Android spyware detection via USB-OTG/ADB. Detects stalkerware, Pegasus indicators and suspicious apps — directly from the field, no laptop required.

Part of the [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager) counter-surveillance ecosystem.

---

## Why not MVT?

[MVT (Mobile Verification Toolkit)](https://github.com/mvt-project/mvt) requires Rust-compiled Python packages (`cryptography`, `pydantic-core`) that cannot be built on the Pager's `mipsel_24kc` architecture — `pip install mvt` hangs and crashes the device (OOM).

**Solution:** A custom ADB-based scanner (`adb_scan.py`) that replicates the most important MVT checks using only Python stdlib + the native `adb` binary.

---

## What it does

- Connects to an Android device via **USB-OTG + ADB**
- Scans installed packages, running processes and system properties for **spyware/stalkerware indicators**
- Checks APK hashes against **VirusTotal** (optional, free API key)
- Displays scan status and results on the **Pager display** via DuckyScript UI
- Optionally **wipes the Downloads folder** on the scanned device
- Exports findings as a **CYT-compatible JSON report** for cross-reference with WiFi/BT surveillance data

---

## Checks performed

| Module | What is checked |
|---|---|
| `check_packages` | All installed APKs vs. IOC package name list |
| `check_processes` | Running processes vs. known spyware process names |
| `check_properties` | `ro.debuggable`, `ro.secure`, `service.adb.root` |
| `check_settings` | Global + secure Android settings (Full mode only) |
| `check_sideloaded` | APKs installed from `/data/local/tmp`, `/sdcard` |
| `check_vt_hashes` | SHA-256 of 3rd-party APKs → VirusTotal API v3 |

IOC data sources: Amnesty Tech, Security Without Borders, public stalkerware research.

---

## Requirements

### Hardware
- WiFi Pineapple Pager (OpenWrt 24.10.1, `mipsel_24kc`)
- USB-OTG adapter
- Android device with **USB debugging enabled**

### Software (auto-installed by payload if missing)
- Python 3.11+ (`opkg install -d mmc python3`)
- ADB binary (`opkg install -d mmc adb`)

---

## Installation

```bash
# On the Pager
cd /root/payloads/user/reconnaissance/
git clone https://github.com/tschakram/mvt-pager
```

No pip, no compilation, no external Python dependencies.

### VirusTotal (optional)

Get a free API key at [virustotal.com](https://www.virustotal.com/gui/my-apikey) (500 lookups/day).

```bash
# Create config.json on the Pager (gitignored — OPSEC safe)
cat > /root/payloads/user/reconnaissance/mvt-pager/config.json << 'EOF'
{
  "virustotal": {
    "api_key": "YOUR_KEY_HERE"
  }
}
EOF
```

---

## Usage

1. Connect Android device via USB-OTG
2. Enable USB debugging on Android device (`Settings → Developer options`)
3. Run payload from Pager menu
4. Select scan mode: **Quick** (~3 min) or **Full** (~15 min)
5. Confirm USB authorization on the Android device when prompted
6. Results appear on Pager display — optionally wipe Downloads folder
7. Report saved to `/root/loot/mvt_pager/`

---

## DuckyScript Interface

```
┌──────────────────────────────┐
│   MVT on Pager  v1.2         │
│   Android Spyware Detection  │
│                              │
│ 1 = Quick-Scan  (~3 min)     │
│ 2 = Full-Scan   (~15 min)    │
│ ☁  VirusTotal: aktiv         │
│                              │
│ [Connect Android via OTG...] │
│                              │
│ 📦 Pakete:       330         │
│ ⚙  Prozesse:     669         │
│ 🔍 Detektionen:  0           │
│ ☁  VT Treffer:   0           │
│                              │
│ ✅ Keine Spyware erkannt     │
└──────────────────────────────┘
```

Pager commands used: `LOG`, `LED`, `VIBRATE`, `START_SPINNER`, `STOP_SPINNER`, `NUMBER_PICKER`, `CONFIRMATION_DIALOG`, `WAIT_FOR_BUTTON_PRESS`

---

## File structure

```
mvt-pager/
├── payload.sh              # DuckyScript UI + scan orchestration
├── python/
│   ├── adb_check.py        # ADB device detection
│   ├── adb_scan.py         # Custom scanner (replaces MVT)
│   └── cyt_export.py       # CYT JSON report export
├── config.example.json     # Config template (copy to config.json on Pager)
└── .gitignore              # config.json, loot/, *.key gitignored
```

---

## OPSEC

- `config.json` (API keys) is **gitignored** — never leaves the Pager
- Scan results in `/root/loot/` are **gitignored**
- `config.example.json` contains only empty placeholder values

---

## Project Status

| Component | Status |
|---|---|
| ADB connectivity (USB-OTG) | ✅ Working |
| Custom ADB scanner | ✅ v1.2 |
| IOC matching (packages, processes, props) | ✅ Working |
| VirusTotal APK hash check | ✅ v1.2 |
| DuckyScript UI | ✅ Working |
| Downloads cleanup | ✅ v1.2 |
| CYT export module | ✅ Working |
| SMS / call log scan | ⚠️ Android 11+ blocked without root |

---

## CYT Integration

Scan results are written as a CYT-compatible JSON entry to `/root/loot/mvt_pager/cyt_mvt_reports.json` and can be cross-referenced with WiFi/Bluetooth surveillance data from [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager).

---

## Disclaimer

This tool is intended for **authorized security research, forensic analysis of your own devices, and counter-surveillance** purposes only. Always obtain proper authorization before scanning any device. The authors are not responsible for misuse.

---

## Related Projects

- [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager)
- [MVT - Mobile Verification Toolkit](https://github.com/mvt-project/mvt)
- [WiFi Pineapple Pager Payloads](https://github.com/hak5/wifipineapplepager-payloads)
