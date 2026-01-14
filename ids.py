#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether
from collections import defaultdict
from datetime import datetime, timedelta
from config import INTERFACE, PORT_SCAN_THRESHOLD, BRUTE_FORCE_THRESHOLD, KNOWN_DEVICES, SLACK_WEBHOOK
from database import init_db, log_alert, log_device, log_traffic, flush_traffic_buffer
from ml_detector import record_and_check, train_model, detector
import requests
import threading
import time
import atexit



# Track connection attempts
port_scan_tracker = defaultdict(lambda: {"ports": set(), "first_seen": None})
brute_force_tracker = defaultdict(lambda: {"attempts": 0, "first_seen": None})
anomaly_alerted = defaultdict(lambda: None)  # Track when we last alerted for each IP

# Stats counters
packet_count = 0
ml_enabled = False

# Flush traffic buffer on exit
atexit.register(flush_traffic_buffer)

def send_slack_alert(message):
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": f"🚨 IDS Alert: {message}"})
        except:
            pass

def check_port_scan(src_ip, dst_port):
    now = datetime.now()
    tracker = port_scan_tracker[src_ip]
    
    if tracker["first_seen"] is None or now - tracker["first_seen"] > timedelta(seconds=60):
        tracker["ports"] = set()
        tracker["first_seen"] = now
    
    tracker["ports"].add(dst_port)
    
    if len(tracker["ports"]) >= PORT_SCAN_THRESHOLD:
        alert = f"Port scan detected from {src_ip} - {len(tracker['ports'])} ports in 60s"
        print(f"[ALERT] {alert}")
        log_alert("port_scan", src_ip, "", alert, "high")
        send_slack_alert(alert)
        tracker["ports"] = set()

alerted_devices = set()

def check_ml_anomaly(src_ip, dst_ip, port, size, protocol):
    """Check for ML-detected anomalies."""
    global ml_enabled
    if not ml_enabled:
        return

    is_anomaly, score, description = record_and_check(src_ip, dst_ip, port, size, protocol)

    if is_anomaly:
        now = datetime.now()
        last_alert = anomaly_alerted[src_ip]

        # Only alert once per 5 minutes per IP
        if last_alert is None or (now - last_alert).seconds >= 300:
            anomaly_alerted[src_ip] = now
            alert = f"ML Anomaly from {src_ip}: {description} (score: {score:.2f})"
            print(f"[ML ALERT] {alert}")
            log_alert("ml_anomaly", src_ip, dst_ip, alert, "medium")
            send_slack_alert(alert)

def check_rogue_device(mac, ip):
    mac_lower = mac.lower()
    
    # Skip if already alerted or known
    if mac_lower in alerted_devices:
        return
    if mac_lower in [m.lower() for m in KNOWN_DEVICES.keys()]:
        log_device(mac, ip)
        return
    
    # New unknown device - alert once
    alerted_devices.add(mac_lower)
    alert = f"New device detected: MAC={mac}, IP={ip}"
    print(f"[ALERT] {alert}")
    log_alert("rogue_device", ip, "", alert, "medium")
    send_slack_alert(alert)
    log_device(mac, ip)

def packet_callback(packet):
    global packet_count
    try:
        packet_count += 1

        # Check for new devices via ARP
        if ARP in packet and packet[ARP].op == 2:  # ARP reply
            check_rogue_device(packet[ARP].hwsrc, packet[ARP].psrc)

        # Check Ethernet source
        if Ether in packet:
            src_mac = packet[Ether].src
            if IP in packet:
                check_rogue_device(src_mac, packet[IP].src)

        # Analyze IP traffic
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_size = len(packet)

            # Check TCP
            if TCP in packet:
                dst_port = packet[TCP].dport
                protocol = "TCP"

                # Log traffic for ML
                log_traffic(src_ip, dst_ip, protocol, dst_port, pkt_size)

                # ML anomaly detection
                check_ml_anomaly(src_ip, dst_ip, dst_port, pkt_size, protocol)

                check_port_scan(src_ip, dst_port)

                # Detect SSH brute force
                if dst_port == 22:
                    flags = packet[TCP].flags
                    if flags & 0x02:  # SYN flag
                        now = datetime.now()
                        tracker = brute_force_tracker[src_ip]
                        if tracker["first_seen"] is None or now - tracker["first_seen"] > timedelta(seconds=60):
                            tracker["attempts"] = 0
                            tracker["first_seen"] = now
                        tracker["attempts"] += 1

                        if tracker["attempts"] >= BRUTE_FORCE_THRESHOLD:
                            alert = f"Possible SSH brute force from {src_ip}"
                            print(f"[ALERT] {alert}")
                            log_alert("brute_force", src_ip, dst_ip, alert, "high")
                            send_slack_alert(alert)
                            tracker["attempts"] = 0

            # Check UDP
            elif UDP in packet:
                dst_port = packet[UDP].dport
                protocol = "UDP"
                log_traffic(src_ip, dst_ip, protocol, dst_port, pkt_size)
                check_ml_anomaly(src_ip, dst_ip, dst_port, pkt_size, protocol)

    except Exception as e:
        print(f"Error processing packet: {e}")

def main():
    global ml_enabled

    print(f"🛡️  Tandoori IDS Starting...")
    print(f"📡 Monitoring interface: {INTERFACE}")
    print(f"⚙️  Port scan threshold: {PORT_SCAN_THRESHOLD} ports/60s")
    print(f"⚙️  Brute force threshold: {BRUTE_FORCE_THRESHOLD} attempts/60s")
    print("-" * 50)

    init_db()

    # Initialize ML
    print("[ML] Initializing anomaly detection...")
    if detector.model is not None:
        ml_enabled = True
        print("[ML] Model loaded - anomaly detection ACTIVE")
    else:
        print("[ML] No trained model found. Collecting baseline data...")
        print("[ML] Run 'python ml_detector.py' after collecting traffic to train")

    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=0)
    except PermissionError:
        print("Need root privileges. Run with sudo.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
