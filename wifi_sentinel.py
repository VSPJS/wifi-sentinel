# wifi_sentinel.py

from scapy.all import ARP, Ether, srp
from prettytable import PrettyTable
import time
import os

WHITELIST_FILE = "whitelist.txt"
SCAN_RANGE = "192.168.157.0/24"  # Change to match your network (e.g., 192.168.0.0/24)

def scan(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def display(devices, title="Devices Found"):
    table = PrettyTable(["IP Address", "MAC Address"])
    for device in devices:
        table.add_row([device["ip"], device["mac"]])
    print(f"\n🔍 {title}")
    print(table)

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            pass  # create empty file
        return []
    with open(WHITELIST_FILE, "r") as f:
        return [line.strip().lower() for line in f.readlines()]

def check_unknown(devices, whitelist):
    return [d for d in devices if d['mac'].lower() not in whitelist]

def save_log(devices):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open("log.csv", "a") as log:
        for d in devices:
            log.write(f"{timestamp},{d['ip']},{d['mac']}\n")

def main():
    print("📡 Starting WiFi Sentinel - Monitoring Local Network")
    whitelist = load_whitelist()

    devices = scan(SCAN_RANGE)
    display(devices)

    unknown = check_unknown(devices, whitelist)
    if unknown:
        display(unknown, title="⚠️ Unknown Devices Detected")
        save_log(unknown)
    else:
        print("\n✅ All devices are trusted. No threats detected.")

if __name__ == "__main__":
    main()
