import subprocess
import time
import os
import signal
import csv


def _ensure_str(x):
    """Если пришёл ('wlan0mon',) → вернуть 'wlan0mon'"""
    if isinstance(x, tuple):
        return x[0]
    return x


def find_channel_by_bssid(interface, bssid, timeout=8):
    interface = _ensure_str(interface)
    bssid = _ensure_str(bssid)

    prefix = "/tmp/channel_scan"

    proc = subprocess.Popen(
        [
            "airodump-ng",
            "--band", "bg",
            "--output-format", "csv",
            "--write", prefix,
            interface
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )

    time.sleep(timeout)
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    proc.wait()

    csv_file = f"{prefix}-01.csv"
    if not os.path.exists(csv_file):
        return None

    channels = []

    with open(csv_file, encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) > 13 and row[0].strip().lower() == bssid.lower():
                try:
                    channels.append(int(row[3]))
                except ValueError:
                    pass

    if not channels:
        return None

    return max(set(channels), key=channels.count)


def capture_handshake(interface, bssid, ssid, channel, prefix, duration=120):
    interface = _ensure_str(interface)
    bssid = _ensure_str(bssid)

    cmd = [
        "airodump-ng",
        "--bssid", bssid,
        "--essid", ssid,
        "-c", str(channel),
        "-w", prefix,
        interface
    ]

    print(f"[+] Starting capture for {duration} seconds")
    print(f"[+] Command: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )

        time.sleep(duration)

        print("[+] Time elapsed, stopping capture")

        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)

        print("[+] Capture stopped cleanly")
        print(f"[+] Output file: {prefix}-01.cap")

        return True

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        return False

    except Exception as e:
        print(f"[-] Error: {e}")
        return False
