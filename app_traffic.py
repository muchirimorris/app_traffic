import psutil
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from rich.live import Live
from rich.table import Table
import threading
import time

# Dictionary to store traffic: Key is (PID, Destination IP), Value is App Name and Bytes
traffic_stats = defaultdict(lambda: {"name": "Unknown", "bytes": 0})
port_to_pid = {}

def update_connections():
    """Background thread: Maps local network ports to Process IDs (PIDs)"""
    while True:
        try:
            conns = psutil.net_connections(kind='inet')
            new_mapping = {}
            for conn in conns:
                # We only map ports that have an assigned process
                if conn.pid is not None and conn.laddr:
                    new_mapping[conn.laddr.port] = conn.pid
            
            global port_to_pid
            port_to_pid = new_mapping
        except Exception:
            pass
        time.sleep(2) # Refresh mapping every 2 seconds

def process_packet(packet):
    """Callback triggered for every single packet captured"""
    if IP in packet:
        dst_ip = packet[IP].dst
        src_port = None

        # Extract the source port depending on the protocol
        if TCP in packet:
            src_port = packet[TCP].sport
        elif UDP in packet:
            src_port = packet[UDP].sport

        if src_port:
            # Check if this source port belongs to a local application
            pid = port_to_pid.get(src_port)
            if pid:
                key = (pid, dst_ip)
                
                # Fetch the application's name if we haven't already
                if traffic_stats[key]["name"] == "Unknown":
                    try:
                        traffic_stats[key]["name"] = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        traffic_stats[key]["name"] = "Terminated"
                
                # Add the payload size of this packet to the app's total
                traffic_stats[key]["bytes"] += len(packet)

def generate_table():
    """Generates the Rich TUI Table for the dashboard"""
    table = Table(title="🎯 Live Per-App Outbound Traffic", expand=True)
    table.add_column("PID", style="cyan", justify="right")
    table.add_column("Application", style="magenta")
    table.add_column("Destination IP", style="yellow")
    table.add_column("Data Sent", justify="right", style="green")

    # Sort apps by whoever is sending the most data
    sorted_traffic = sorted(traffic_stats.items(), key=lambda item: item[1]["bytes"], reverse=True)

    # Display the top 15 active connections to avoid terminal overflow
    for (pid, dst_ip), data in sorted_traffic[:15]:
        b = data["bytes"]
        if b < 1024:
            size_str = f"{b} B"
        elif b < 1024 * 1024:
            size_str = f"{b / 1024:.2f} KB"
        else:
            size_str = f"{b / (1024 * 1024):.2f} MB"

        table.add_row(str(pid), data["name"], dst_ip, size_str)

    return table

print("Starting Scapy Sniffer & Process Monitor...")
print("Please wait a few seconds to capture traffic...")

# 1. Start mapping ports to PIDs in the background
threading.Thread(target=update_connections, daemon=True).start()

# 2. Start sniffing packets in the background
threading.Thread(target=lambda: sniff(prn=process_packet, store=False), daemon=True).start()

# 3. Draw and update the dashboard in the main thread
try:
    with Live(generate_table(), refresh_per_second=2) as live:
        while True:
            time.sleep(1)
            live.update(generate_table())
except KeyboardInterrupt:
    print("\nDashboard stopped.")