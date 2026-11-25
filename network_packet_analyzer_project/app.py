from collections import Counter, deque
from datetime import datetime
import threading
import time

from flask import Flask, jsonify, render_template, request, Response
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP

app = Flask(__name__)

# In-memory storage for this demo. The limit prevents unbounded growth.
MAX_PACKETS = 2000
packets = deque(maxlen=MAX_PACKETS)
packet_lock = threading.Lock()
capture_thread = None
capture_stop = threading.Event()
capture_state = {"running": False, "interface": None, "error": None}
next_id = 1
start_time = None


def friendly_capture_error(exc):
    """Translate low-level Scapy capture errors into actionable guidance."""
    message = str(exc)
    lower = message.lower()

    if "winpcap" in lower or "libpcap provider" in lower or "layer 2" in lower:
        return (
            "Windows packet capture is unavailable because the Npcap/WinPcap driver is not installed. "
            "Install Npcap from https://npcap.com/ and restart the app, then try again."
        )
    if "permission" in lower or "access denied" in lower or "admin" in lower:
        return (
            "Packet capture permission was denied. Run the app with administrator privileges or allow "
            "Npcap to access the selected network adapter."
        )
    return message


def get_protocol(pkt):
    """Return a readable protocol label for a captured packet."""
    if ARP in pkt:
        return "ARP"
    if IPv6 in pkt:
        if TCP in pkt:
            return "TCP/IPv6"
        if UDP in pkt:
            return "UDP/IPv6"
        return "IPv6"
    if IP in pkt:
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "IPv4"
    return "Other"


def packet_to_record(pkt):
    """Extract metadata only; do not save raw packet payloads."""
    global next_id

    source_ip = "-"
    destination_ip = "-"
    source_port = None
    destination_port = None

    if IP in pkt:
        source_ip = pkt[IP].src
        destination_ip = pkt[IP].dst
    elif IPv6 in pkt:
        source_ip = pkt[IPv6].src
        destination_ip = pkt[IPv6].dst
    elif ARP in pkt:
        source_ip = pkt[ARP].psrc or "-"
        destination_ip = pkt[ARP].pdst or "-"

    if TCP in pkt:
        source_port = int(pkt[TCP].sport)
        destination_port = int(pkt[TCP].dport)
    elif UDP in pkt:
        source_port = int(pkt[UDP].sport)
        destination_port = int(pkt[UDP].dport)

    record = {
        "id": None,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": get_protocol(pkt),
        "source_port": source_port,
        "destination_port": destination_port,
        "size": int(len(pkt)),
    }
    with packet_lock:
        record["id"] = next_id
        next_id += 1
        packets.append(record)


def capture_worker(interface):
    global start_time
    try:
        # timeout lets Scapy periodically return so we can check stop state.
        while not capture_stop.is_set():
            sniff(
                iface=interface or None,
                prn=packet_to_record,
                store=False,
                timeout=1,
                stop_filter=lambda _pkt: capture_stop.is_set(),
            )
    except Exception as exc:
        with packet_lock:
            capture_state["error"] = friendly_capture_error(exc)
    finally:
        with packet_lock:
            capture_state["running"] = False


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/interfaces")
def interfaces():
    try:
        from scapy.all import get_if_list
        return jsonify({"interfaces": get_if_list()})
    except Exception as exc:
        return jsonify({"interfaces": [], "error": str(exc)}), 500


@app.post("/api/capture/start")
def start_capture():
    global capture_thread, start_time
    body = request.get_json(silent=True) or {}
    interface = (body.get("interface") or "").strip() or None

    with packet_lock:
        if capture_state["running"]:
            return jsonify({"ok": False, "message": "Capture is already running."}), 409
        capture_state.update({"running": True, "interface": interface, "error": None})
        capture_stop.clear()
        start_time = time.time()
        capture_thread = threading.Thread(
            target=capture_worker, args=(interface,), daemon=True
        )
        capture_thread.start()

    return jsonify({"ok": True, "message": "Capture started."})


@app.post("/api/capture/stop")
def stop_capture():
    capture_stop.set()
    return jsonify({"ok": True, "message": "Stop requested."})


@app.get("/api/capture/status")
def capture_status():
    with packet_lock:
        return jsonify({
            **capture_state,
            "packet_count": len(packets),
        })


@app.get("/api/packets")
def get_packets():
    protocol = request.args.get("protocol", "All")
    ip_filter = request.args.get("ip", "").strip().lower()
    limit = min(max(int(request.args.get("limit", "300")), 1), MAX_PACKETS)

    with packet_lock:
        data = list(packets)

    if protocol != "All":
        data = [p for p in data if p["protocol"] == protocol or p["protocol"].startswith(protocol + "/")]
    if ip_filter:
        data = [
            p for p in data
            if ip_filter in p["source_ip"].lower()
            or ip_filter in p["destination_ip"].lower()
        ]
    return jsonify({"packets": data[-limit:][::-1]})


@app.get("/api/statistics")
def statistics():
    with packet_lock:
        data = list(packets)

    counts = Counter(p["protocol"].split("/")[0] for p in data)
    sizes = [p["size"] for p in data]
    return jsonify({
        "total_packets": len(data),
        "tcp": counts.get("TCP", 0),
        "udp": counts.get("UDP", 0),
        "icmp": counts.get("ICMP", 0),
        "arp": counts.get("ARP", 0),
        "other": sum(v for k, v in counts.items() if k not in {"TCP", "UDP", "ICMP", "ARP"}),
        "total_bytes": sum(sizes),
        "average_size": round(sum(sizes) / len(sizes), 1) if sizes else 0,
        "max_size": max(sizes, default=0),
    })


@app.get("/api/packets/<int:packet_id>")
def packet_detail(packet_id):
    with packet_lock:
        for record in packets:
            if record["id"] == packet_id:
                return jsonify(record)
    return jsonify({"error": "Packet not found."}), 404


@app.get("/api/export")
def export_csv():
    import csv
    import io

    with packet_lock:
        data = list(packets)

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id", "timestamp", "source_ip", "destination_ip",
            "protocol", "source_port", "destination_port", "size"
        ],
    )
    writer.writeheader()
    writer.writerows(data)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=packets.csv"},
    )


@app.post("/api/clear")
def clear_packets():
    global next_id
    with packet_lock:
        packets.clear()
    return jsonify({"ok": True, "message": "Displayed packet history cleared."})


if __name__ == "__main__":
    # Keep the web dashboard local to this computer.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
