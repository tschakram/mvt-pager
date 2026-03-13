#!/usr/bin/env python3
"""
ADB Scanner for MVT on Pager.

Replicates the most important mvt-android check-adb checks using only
the native 'adb' binary. No Rust/C dependencies required.

Checks performed:
  - Installed packages (pm list packages)
  - Running processes (ps -A)
  - System properties (getprop)
  - Global/secure settings
  - IOC matching against known spyware package names

Output protocol (stdout):
  PACKAGES:<count>
  PROCESSES:<count>
  DETECTIONS:<count>
  IOC_HITS:<count>
  INDICATOR:<desc>
  ERROR:<msg>
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ── Known spyware / stalkerware package names (public IOC data) ──────────────
# Sources: Amnesty Tech / Security Without Borders / public research
SPYWARE_PACKAGES = {
    # Pegasus / NSO Group indicators
    "com.apple.jetsamproperties": "Pegasus indicator",
    "com.android.systemupdate": "Pegasus indicator",

    # Commercial stalkerware
    "com.flexispy.android": "FlexiSpy",
    "com.mspy.android": "mSpy",
    "com.cerberus.app": "Cerberus stalkerware",
    "com.hoverwatch": "Hoverwatch",
    "com.spyera": "Spyera",
    "com.ispyoo": "iSpyoo",
    "com.android.spyware": "Generic spyware",
    "com.kidsguard": "KidsGuard Pro",
    "com.clevguard": "ClevGuard",
    "com.spapp": "SPY Phone",
    "com.mobilespy": "MobileSpy",
    "com.highster.mobile": "Highster Mobile",
    "com.cocospy.android": "Cocospy",
    "com.spyier": "Spyier",
    "com.minspy": "Minspy",
    "com.xnspy": "XNSPY",
    "com.spyic": "Spyic",
    "com.neatspy": "NeatSpy",
    "com.ino.android.safephone": "SafePhone",

    # Remote access / RAT
    "com.androrat": "AndroRAT",
    "org.placid.app": "Remote access tool",
    "org.omnitelecom.client": "Omni surveillance",

    # Dual-space / cloner apps used to hide spyware
    "com.lbe.parallel.intl": "Parallel Space (dual)",
    "com.excelliance.dualaid": "Dual Aid",
    "com.ludashi.dualspace": "Dual Space",

    # Fake system/utility apps (common spyware disguise)
    "com.android.providers.telephony.data": "Fake system app",
    "com.google.services": "Fake Google Services",
    "com.android.system.service": "Fake system service",
    "com.android.update": "Fake system update",
    "com.system.update.manager": "Fake update manager",
}

# Suspicious process names
SPYWARE_PROCESSES = {
    "gsm0710muxd.bak": "Pegasus indicator",
    "launchctl.bak": "Pegasus indicator",
    "sshd.bak": "SSH daemon (hidden)",
    "frida-server": "Frida instrumentation",
    "frida-agent": "Frida instrumentation",
    "gdbserver": "Remote debugger",
}

# Suspicious system properties (value patterns)
SUSPICIOUS_PROPS = {
    "ro.debuggable": ("1", "Debug mode enabled on production device"),
    "ro.secure": ("0", "Insecure boot mode"),
    "service.adb.root": ("1", "ADB running as root"),
}


def adb(serial, *args, timeout=30):
    """Run an adb command and return stdout. Returns None on error."""
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def check_packages(serial, output_dir):
    """Check installed packages against spyware IOC list."""
    detections = []
    packages = []

    raw = adb(serial, "shell", "pm", "list", "packages", "-f", timeout=60)
    if not raw:
        return packages, detections

    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        # Format: package:/path/to/apk=com.package.name
        parts = line[len("package:"):].rsplit("=", 1)
        if len(parts) == 2:
            apk_path, pkg_name = parts
        else:
            pkg_name = parts[0]
            apk_path = ""

        packages.append({"name": pkg_name, "apk": apk_path})

        # IOC match: exact
        if pkg_name in SPYWARE_PACKAGES:
            label = SPYWARE_PACKAGES[pkg_name]
            detections.append({
                "type": "package",
                "value": pkg_name,
                "label": label,
                "indicator": f"[Paket] {pkg_name} — {label}",
            })
            continue

        # IOC match: partial substring match on known fragments
        for ioc, label in SPYWARE_PACKAGES.items():
            if ioc in pkg_name and ioc != pkg_name:
                detections.append({
                    "type": "package",
                    "value": pkg_name,
                    "label": label,
                    "indicator": f"[Paket ähnlich] {pkg_name} ~ {ioc} ({label})",
                })
                break

    _save_json(output_dir, "packages.json", packages)
    return packages, detections


def check_processes(serial, output_dir):
    """Check running processes against spyware IOC list."""
    detections = []
    processes = []

    raw = adb(serial, "shell", "ps", "-A", timeout=30)
    if not raw:
        # Fallback: ps without -A (older Android)
        raw = adb(serial, "shell", "ps", timeout=30)
    if not raw:
        return processes, detections

    for line in raw.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue
        proc_name = parts[-1]
        pid = parts[1] if len(parts) > 1 else "?"
        user = parts[0]

        processes.append({"name": proc_name, "pid": pid, "user": user})

        for ioc, label in SPYWARE_PROCESSES.items():
            if ioc in proc_name:
                detections.append({
                    "type": "process",
                    "value": proc_name,
                    "label": label,
                    "indicator": f"[Prozess] {proc_name} (PID {pid}) — {label}",
                })

    _save_json(output_dir, "processes.json", processes)
    return processes, detections


def check_properties(serial, output_dir):
    """Check system properties for suspicious values."""
    detections = []
    props = {}

    raw = adb(serial, "shell", "getprop", timeout=30)
    if not raw:
        return props, detections

    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            key = line[1:line.index("]")]
            val = line[line.index(": [") + 3:-1]
            props[key] = val
        except (ValueError, IndexError):
            continue

    for prop, (bad_val, label) in SUSPICIOUS_PROPS.items():
        actual = props.get(prop, "")
        if actual == bad_val:
            detections.append({
                "type": "property",
                "value": f"{prop}={actual}",
                "label": label,
                "indicator": f"[Eigenschaft] {prop}={actual} — {label}",
            })

    _save_json(output_dir, "properties.json", props)
    return props, detections


def check_settings(serial, output_dir):
    """Extract system settings for the report."""
    settings = {}
    for namespace in ("global", "secure"):
        raw = adb(serial, "shell", "settings", "list", namespace, timeout=30)
        if raw:
            ns_settings = {}
            for line in raw.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    ns_settings[k.strip()] = v.strip()
            settings[namespace] = ns_settings

    _save_json(output_dir, "settings.json", settings)
    return settings


def check_sideloaded(packages):
    """Flag packages not from Play Store (unknown sources)."""
    detections = []
    # Packages from /data/local/tmp or /sdcard are suspicious
    for pkg in packages:
        apk = pkg.get("apk", "")
        if any(p in apk for p in ("/data/local/tmp", "/sdcard", "/storage/emulated")):
            name = pkg.get("name", "")
            detections.append({
                "type": "sideloaded",
                "value": name,
                "label": f"Sideloaded from {apk}",
                "indicator": f"[Sideload] {name} von {apk}",
            })
    return detections


def check_vt_hashes(serial, packages, output_dir, api_key, max_checks=20):
    """Check APK SHA-256 hashes against VirusTotal API v3.

    Free tier limit: 4 requests/min → 16 s sleep between calls.
    Only 3rd-party APKs are checked (skips /system/ and /vendor/).
    """
    if not api_key:
        return []

    detections = []
    vt_results = []

    # Filter: only non-system packages with a known APK path
    third_party = [
        p for p in packages
        if p.get("apk") and not p["apk"].startswith(("/system/", "/vendor/", "/apex/"))
    ]

    for pkg in third_party[:max_checks]:
        apk_path = pkg["apk"]
        pkg_name = pkg.get("name", apk_path)

        # Get SHA-256 hash via adb shell (Android has sha256sum or sha256)
        raw = adb(serial, "shell", f"sha256sum '{apk_path}' 2>/dev/null || sha256 '{apk_path}' 2>/dev/null", timeout=30)
        if not raw:
            continue
        parts = raw.split()
        sha256 = parts[0].strip().lower() if parts else ""
        if len(sha256) != 64:
            continue

        # Query VirusTotal
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        req = urllib.request.Request(url, headers={"x-apikey": api_key, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = int(stats.get("malicious",  0))
            suspicious = int(stats.get("suspicious", 0))
            total      = sum(stats.values()) if stats else 0

            vt_results.append({
                "package":    pkg_name,
                "sha256":     sha256,
                "malicious":  malicious,
                "suspicious": suspicious,
                "total_engines": total,
            })

            if malicious > 0 or suspicious > 2:
                detections.append({
                    "type":      "virustotal",
                    "value":     pkg_name,
                    "label":     f"VT {malicious}/{total} malicious",
                    "indicator": (
                        f"[VirusTotal] {pkg_name} — "
                        f"{malicious} AV-Engines positiv, {suspicious} verdächtig"
                    ),
                })

        except urllib.error.HTTPError as e:
            if e.code == 404:
                pass   # Hash not yet in VT — not necessarily malicious
            elif e.code == 429:
                # Rate-limit hit: wait a full minute and retry once
                time.sleep(61)
                try:
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        data = json.loads(resp.read())
                except Exception:
                    pass
        except Exception:
            pass

        # Respect free-tier rate limit (4 req / 60 s)
        time.sleep(16)

    _save_json(output_dir, "vt_results.json", vt_results)
    return detections


def _save_json(output_dir, filename, data):
    """Save data as JSON to output directory."""
    if not output_dir:
        return
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(description="ADB Scanner (MVT replacement)")
    parser.add_argument("--serial",  default=None)
    parser.add_argument("--output",  required=True)
    parser.add_argument("--mode",    type=int, default=1, choices=[1, 2])
    parser.add_argument("--iocs",    action="store_true")
    parser.add_argument("--vt-key",  default="", dest="vt_key",
                        help="VirusTotal API key (free tier)")
    parser.add_argument("--vt-max",  type=int, default=15, dest="vt_max",
                        help="Max APKs to check against VT (default 15 quick, 40 full)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    all_detections = []

    # Run checks
    packages, pkg_det = check_packages(args.serial, args.output)
    all_detections += pkg_det

    processes, proc_det = check_processes(args.serial, args.output)
    all_detections += proc_det

    props, prop_det = check_properties(args.serial, args.output)
    all_detections += prop_det

    if args.mode == 2:
        check_settings(args.serial, args.output)

    # Sideloaded apps check
    side_det = check_sideloaded(packages)
    all_detections += side_det

    # VirusTotal hash check (optional, requires API key)
    vt_det = []
    if args.vt_key:
        vt_max = args.vt_max if args.vt_max else (15 if args.mode == 1 else 40)
        vt_det = check_vt_hashes(args.serial, packages, args.output, args.vt_key, vt_max)
        all_detections += vt_det

    # Save summary
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "serial": args.serial,
        "packages_total": len(packages),
        "processes_total": len(processes),
        "detections": len(all_detections),
        "indicators": all_detections,
    }
    _save_json(args.output, "summary.json", summary)

    # Output protocol
    print(f"PACKAGES:{len(packages)}")
    print(f"PROCESSES:{len(processes)}")
    print(f"DETECTIONS:{len(all_detections)}")
    print(f"IOC_HITS:{len(all_detections) - len(vt_det)}")
    print(f"VT_HITS:{len(vt_det)}")
    for det in all_detections:
        print(f"INDICATOR:{det['indicator']}")


if __name__ == "__main__":
    main()
