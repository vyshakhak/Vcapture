# vcapture 🕸️

> A lightweight, custom network packet sniffer built in Python for rapid triage and real-time network traffic analysis.

**vcapture** is a command-line utility designed to capture and dissect network packets directly from the terminal. Built with Scapy, it strips away the heavy GUI of traditional network analyzers to provide fast, readable output of Layer 3 and Layer 4 traffic, making it ideal for penetration testing, CTF environments, and network troubleshooting.

---

### 🚀 Features

* **Live Traffic Sniffing:** Captures network packets in real-time.
* **Protocol Dissection:** Automatically identifies and parses IP, TCP, and UDP headers.
* **Targeted Capture:** Allows specifying network interfaces (e.g., `eth0`, `wlan0`).
* **Packet Limiting:** Option to capture a specific number of packets or run indefinitely.
* **Terminal Native:** Clean, color-coded (optional) terminal output designed for fast reading.

---

### 📋 Prerequisites

To run vcapture, you need Python 3 and the Scapy library installed on your system. It is designed to run on Linux environments (like Kali Linux or Ubuntu) and requires root privileges to interact with raw network sockets.

```bash
sudo apt update
sudo apt install python3-scapy
