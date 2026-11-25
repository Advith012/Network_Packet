# Network Packet Analyzer and Traffic Monitoring System

## Features
- Start/stop packet capture from a selected interface
- Extract timestamp, source/destination IP, protocol, ports, and packet size
- Filter by protocol or source/destination IP
- Live dashboard statistics and charts
- Packet detail panel and CSV export
- Stores packet metadata in memory only; does not save raw packet payloads

## Requirements
- Python 3.10+
- A supported network interface
- Packet-capture permissions appropriate for your operating system
- Internet access only for loading the Chart.js CDN (or host Chart.js locally)

## Run
1. Open a terminal in this folder.
2. Create and activate a virtual environment (recommended).
3. Install dependencies:
   `python -m pip install -r requirements.txt`
4. Start the app:
   `python app.py`
5. Open `http://127.0.0.1:5000` in your browser.
6. Choose an interface and press **Start capture**.

## Permission notes
- On Windows, install Npcap from https://npcap.com/ and ensure Scapy can access it. This is required for layer-2 sniffing; without it, Scapy shows `winpcap is not installed`.
- On Linux, packet capture may require root or appropriate capabilities.
- On macOS, capture permissions and BPF access may need configuration.
- If the default interface does not work, choose a listed interface explicitly.

## Safety
Use only on devices and networks you own or have explicit permission to monitor.
This educational tool captures metadata visible to the selected interface. It does not decrypt HTTPS or guarantee visibility into other devices' traffic.

## Limitations
- Recent packet records are kept in memory (up to 2,000).
- The charts use Chart.js from a CDN by default.
- This is a student mini-project, not a production-grade network monitoring or security product.
