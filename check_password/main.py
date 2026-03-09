from analyze_pcap import analyze_pcap
from analyze_pcap import check_password_subprocess
from capture_traffic import find_channel_by_bssid
from capture_traffic import capture_handshake
interface="wlan0mon",
bssid = "54:22:F8:1B:E3:F6"
ssid = "MyWiFi"
prefix = "handshake"
password = "12356789"

channel = find_channel_by_bssid(interface, bssid)
print()
print("Starting WPA Handshake Capture")
print()
capture_handshake(interface, bssid, ssid, channel, prefix)
cap_file = "handshake-01.cap"
analyze_pcap(cap_file)
check_password_subprocess(cap_file, bssid, password)
