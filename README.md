# 🔒 WiFi Sentinel

WiFi Sentinel is a simple Python script that monitors your Wi-Fi network for unauthorized or unknown devices using ARP scanning

Install scapy and prettytable
-->sudo apt install python3-scapy
-->sudo apt install python3-prettytable

🖥️ How to Use
Clone or download the repo
Make sure you’re connected to your Wi-Fi network
Edit the IP range in the script:

#In wifi_sentinel.py:
SCAN_RANGE = "192.168.157.0/24"  # Change this to match your local network

Add known MAC addresses to whitelist.txt:
Example:
a0:b1:c2:d3:e4:f5
12:34:56:78:9a:bc

Run the tool

sudo python3 wifi_sentinel.py
