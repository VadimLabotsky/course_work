from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt
from collections import defaultdict
import tempfile
import os
import subprocess


def get_encryption(beacon):
    encryption = set()
    elt = beacon[Dot11Elt]
    
    while isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            encryption.add("WPA2/WPA3")
        elif elt.ID == 221 and b"WPA" in elt.info:
            encryption.add("WPA")
        elt = elt.payload
    
    if not encryption:
        encryption.add("OPEN")
    return ", ".join(encryption)


def analyze_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"File {pcap_file} not found!")
        return None
    
    networks = {}
    clients = defaultdict(set)
    
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
            
            if bssid not in networks:
                networks[bssid] = {
                    "ssid": ssid,
                    "encryption": get_encryption(pkt),
                }
        
        if pkt.haslayer(Dot11):
            if pkt.addr1 and pkt.addr2:
                clients[pkt.addr2].add(pkt.addr1)
    
    for bssid, data in networks.items():
        device_count = sum(1 for c in clients.values() if bssid in c)
        print(f"SSID: {data['ssid']}")
        print(f"BSSID: {bssid}")
        print(f"Security: {data['encryption']}")
        print(f"Connected devices (approx): {device_count}")
       
    return networks


def check_password_subprocess(pcap_file, bssid_target, password):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(password + "\n")
        wordlist_file = f.name
    
    try:
        cmd = [
            "aircrack-ng",
            "-b", bssid_target,
            "-w", wordlist_file,
            pcap_file
        ]
        
        print(f"Executing command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        if "KEY FOUND!" in result.stdout:
            print("Password is correct!")
            return True
        elif "Passphrase not in dictionary" in result.stdout:
            print("Password is incorrect!")
            return False
        else:
            print("Could not determine result")
            return False
            
    except subprocess.TimeoutExpired:
        print("Password check took too long")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        try:
            os.unlink(wordlist_file)
        except:
            pass


