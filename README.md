# MVT on Pager

A [WiFi Pineapple Pager](https://docs.hak5.org/wifi-pineapple-pager) payload that runs [MVT (Mobile Verification Toolkit)](https://github.com/mvt-project/mvt) Android scans via USB-OTG/ADB. Detects spyware indicators (Pegasus, stalkerware, IOCs) on connected Android devices — directly from the field.

Part of the [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager) counter-surveillance ecosystem.

---

## What it does

- Connects to an Android device via **USB-OTG + ADB**
- Runs MVT Android scan modules (SMS, calls, installed apps, network activity, IOCs)
- Displays scan status and results on the **Pager display** via DuckyScript
- Exports findings as a **CYT-compatible JSON report** for cross-reference with WiFi/BT surveillance data

---

## Requirements

### Hardware
- WiFi Pineapple Pager
- USB-OTG adapter
- Android device with **USB debugging enabled**

### Software (on Pager)
- Python 3.11+
- ADB (`adb` binary for mipsel_24kc)
- MVT (installed on Pager via pip or bundled)

---

## Installation

```bash
# On the Pager
cd /root/payloads/user/reconnaissance/
git clone https://github.com/tschakram/mvt-pager
cd mvt-pager
pip install mvt
```

---

## Usage

1. Connect Android device via USB-OTG
2. Enable USB debugging on Android device
3. Run payload from Pager menu
4. Follow on-screen prompts (DuckyScript UI)
5. Report is saved to `/root/loot/mvt_pager/` and exported to CYT

---

## DuckyScript Interface

The payload uses the Pager's built-in DuckyScript commands:
- `LED` — scan status indicators
- `VIBRATE` — alert on IOC detection
- `START_SPINNER` — scan progress
- `CONFIRMATION_DIALOG` — user prompts
- `WAIT_FOR_BUTTON_PRESS` — step-through UI

---

## CYT Integration

Scan results are written as a CYT-compatible JSON entry and can be imported into [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager) reports for combined analysis with WiFi/Bluetooth surveillance data.

---

## Project Status

> ⚠️ Work in Progress — initial research and payload scaffolding phase.

| Component | Status |
|---|---|
| ADB connectivity (USB-OTG) | 🔬 Research |
| MVT install on mipsel_24kc | 🔬 Research |
| DuckyScript UI | 📋 Planned |
| CYT export module | 📋 Planned |

---

## Disclaimer

This tool is intended for **authorized security research, forensic analysis of your own devices, and counter-surveillance** purposes only. Always obtain proper authorization before scanning any device. The authors are not responsible for misuse.

---

## Related Projects

- [Chasing Your Tail NG](https://github.com/tschakram/chasing-your-tail-pager)
- [MVT - Mobile Verification Toolkit](https://github.com/mvt-project/mvt)
- [WiFi Pineapple Pager Payloads](https://github.com/hak5/wifipineapplepager-payloads)
