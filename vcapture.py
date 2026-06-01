#!/usr/bin/env python3

import argparse
import sys
from scapy.all import sniff, IP, TCP, UDP

def print_banner():
    banner = """
    _    _  ___  ___ ___ _____ _   _ ___ ___ 
    \ \  / / __|/ _ \ _ \_   _| | | | _ \ __|
     \ \/ / (__|  __/  _/ | | | |_| |   / _| 
      \__/ \___|\___|_|   |_|  \___/|_|_\___|
      
       Network Packet Sniffer | v1.0
    """
    print(banner)

def packet_handler(packet):
    """Parses and displays relevant packet information."""
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol = "UNKNOWN"
        
        # Identify the Transport Layer Protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
            port_info = f"Port: {packet[TCP].sport} -> {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            protocol = "UDP"
            port_info = f"Port: {packet[UDP].sport} -> {packet[UDP].dport}"
        else:
            port_info = "N/A"

        # Print the dissected packet data
        print(f"[+] [{protocol}] {ip_layer.src} -> {ip_layer.dst} | {port_info}")

def main():
    print_banner()
    
    # Set up command-line arguments
    parser = argparse.ArgumentParser(description="vcapture - Custom Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., eth0, wlan0)", required=False)
    parser.add_argument("-c", "--count", help="Number of packets to capture (default: infinite)", type=int, default=0)
    
    args = parser.parse_args()

    try:
        print(f"[*] Starting vcapture...")
        if args.interface:
            print(f"[*] Listening on interface: {args.interface}")
            sniff(iface=args.interface, prn=packet_handler, count=args.count, store=False)
        else:
            print(f"[*] Listening on default interface...")
            sniff(prn=packet_handler, count=args.count, store=False)
            
    except KeyboardInterrupt:
        print("\n[*] Stopping vcapture. Goodbye!")
        sys.exit(0)
    except PermissionError:
        print("\n[!] Error: vcapture requires root privileges. Try running with 'sudo'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
