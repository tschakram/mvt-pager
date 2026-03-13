#!/usr/bin/env python3
"""
CYT Export for MVT on Pager.

Creates a CYT-compatible JSON report entry from an MVT scan result.
Appends to /root/loot/mvt_pager/cyt_mvt_reports.json.

Output protocol (stdout):
  CYT_REPORT:<path>    — path to the written CYT JSON file
  ERROR:<msg>          — on failure
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone


def load_mvt_summary(scan_dir):
    """Extract summary data from MVT output directory."""
    summary = {
        "packages": [],
        "processes": [],
        "detections": [],
        "settings": {},
        "properties": {},
    }

    if not os.path.isdir(scan_dir):
        return summary

    for filename in os.listdir(scan_dir):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(scan_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        name_lower = filename.lower()

        if "packages" in name_lower and isinstance(data, list):
            summary["packages"] = [
                {
                    "name": e.get("package_name", e.get("name", "")),
                    "version": e.get("version_name", ""),
                    "installer": e.get("installer", ""),
                    "detected": bool(e.get("detected") or e.get("matched_indicators")),
                }
                for e in data if isinstance(e, dict)
            ]

        elif "processes" in name_lower and isinstance(data, list):
            summary["processes"] = [
                {
                    "name": e.get("process_name", e.get("name", "")),
                    "pid": e.get("pid", ""),
                    "detected": bool(e.get("detected") or e.get("matched_indicators")),
                }
                for e in data if isinstance(e, dict)
            ]

        elif "detected_indicators" in name_lower and isinstance(data, list):
            summary["detections"] = data

    return summary


def build_cyt_entry(device, serial, detections, ioc_hits, scan_dir, summary):
    """Build a CYT-compatible JSON entry."""
    now = datetime.now(timezone.utc)
    suspicious_packages = [p for p in summary["packages"] if p.get("detected")]
    suspicious_processes = [p for p in summary["processes"] if p.get("detected")]

    threat_level = "clear"
    if int(ioc_hits) > 0:
        threat_level = "critical"
    elif int(detections) > 0:
        threat_level = "suspicious"

    return {
        "source": "mvt_pager",
        "version": "1.0",
        "timestamp": now.isoformat(),
        "device": {
            "model": device,
            "serial": serial,
        },
        "scan": {
            "directory": scan_dir,
            "packages_total": len(summary["packages"]),
            "processes_total": len(summary["processes"]),
            "detections": int(detections),
            "ioc_hits": int(ioc_hits),
            "threat_level": threat_level,
        },
        "suspicious_packages": suspicious_packages[:20],  # cap for readability
        "suspicious_processes": suspicious_processes[:20],
        "ioc_detections": summary["detections"][:10],
    }


def main():
    parser = argparse.ArgumentParser(description="CYT Export")
    parser.add_argument("--scan-dir", required=True, help="MVT output directory")
    parser.add_argument("--device", required=True, help="Device model name")
    parser.add_argument("--serial", required=True, help="Device ADB serial")
    parser.add_argument("--detections", default="0", help="Detection count")
    parser.add_argument("--ioc-hits", default="0", help="IOC hit count")
    parser.add_argument("--loot-dir", required=True, help="Loot base directory")
    args = parser.parse_args()

    os.makedirs(args.loot_dir, exist_ok=True)

    summary = load_mvt_summary(args.scan_dir)
    entry = build_cyt_entry(
        device=args.device,
        serial=args.serial,
        detections=args.detections,
        ioc_hits=args.ioc_hits,
        scan_dir=args.scan_dir,
        summary=summary,
    )

    # Append to rolling report log
    report_path = os.path.join(args.loot_dir, "cyt_mvt_reports.json")
    existing = []
    if os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                existing = []
        except (json.JSONDecodeError, OSError):
            existing = []

    existing.append(entry)

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
        print(f"CYT_REPORT:{report_path}")
    except OSError as e:
        print(f"ERROR:{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
