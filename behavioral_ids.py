import scapy.all as scapy
import numpy as np
import pandas as pd
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(filename='anomaly_alerts.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Traffic tracking
traffic_data = {}
VOLUME_THRESHOLD = 500  # packets per minute
TIME_WINDOW = 60  # seconds

def update_traffic_stats(packet):
    """Update traffic statistics for each IP."""
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        current_time = datetime.now().timestamp()
        
        if ip_src not in traffic_data:
            traffic_data[ip_src] = []
        
        traffic_data[ip_src].append(current_time)
        traffic_data[ip_src] = [t for t in traffic_data[ip_src] if current_time - t < TIME_WINDOW]
        
        packet_count = len(traffic_data[ip_src])
        if packet_count > VOLUME_THRESHOLD:
            alert = f"ALERT: Anomaly detected! IP {ip_src} exceeds traffic volume threshold ({packet_count} packets/min)."
            print(alert)
            logging.info(alert)

def save_stats():
    """Save traffic statistics to CSV."""
    df = pd.DataFrame([(ip, len(times)) for ip, times in traffic_data.items()], columns=['IP', 'PacketCount'])
    df.to_csv('traffic_stats.csv', index=False)

def packet_callback(packet):
    """Process each captured packet."""
    if packet.haslayer(scapy.IP):
        update_traffic_stats(packet)
        save_stats()

def main():
    print("Starting IDS... Press Ctrl+C to stop.")
    try:
        scapy.sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("IDS stopped.")
        save_stats()

if __name__ == "__main__":
    main()