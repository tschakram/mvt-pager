#!/usr/bin/env python3
"""
ADB Device Checker for MVT on Pager.

Checks for connected Android devices via ADB and returns device info.
Output protocol (stdout):
  DEVICE:<serial>:<model>   — device found and authorized
  UNAUTHORIZED              — device connected but not authorized
  NO_DEVICE                 — no device connected
  ERROR:<msg>               — adb command failed
"""
import subprocess
import sys


def get_adb_devices():
    """Run 'adb devices' and return parsed list of (serial, state)."""
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().splitlines()
        devices = []
        for line in lines[1:]:  # skip "List of devices attached"
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                devices.append((parts[0].strip(), parts[1].strip()))
        return devices
    except FileNotFoundError:
        print("ERROR:adb nicht gefunden")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR:adb Timeout")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR:{e}")
        sys.exit(1)


def get_device_model(serial):
    """Get device model name via adb shell getprop."""
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", "getprop", "ro.product.model"],
            capture_output=True, text=True, timeout=10
        )
        model = result.stdout.strip().replace(":", "-")
        return model if model else ""
    except Exception:
        return ""


def main():
    devices = get_adb_devices()

    if not devices:
        print("NO_DEVICE")
        return

    # Prefer authorized device
    for serial, state in devices:
        if state == "device":
            model = get_device_model(serial)
            print(f"DEVICE:{serial}:{model}")
            return

    # Check for unauthorized
    for serial, state in devices:
        if state == "unauthorized":
            print("UNAUTHORIZED")
            return

    # Other states (offline, etc.)
    serial, state = devices[0]
    print(f"ERROR:Gerät im Zustand '{state}' ({serial})")


if __name__ == "__main__":
    main()
