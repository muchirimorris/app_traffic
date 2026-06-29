import psutil
import time
from rich.live import Live
from rich.table import Table

# Store previous stats to calculate per-second speeds
last_io = psutil.net_io_counters(pernic=True)
last_time = time.time()

def generate_table():
    global last_io, last_time
    
    current_io = psutil.net_io_counters(pernic=True)
    current_time = time.time()
    time_elapsed = current_time - last_time

    # Build the UI Table
    table = Table(title="🚀 Live Outbound Network Traffic", expand=True)
    table.add_column("Interface", style="cyan", no_wrap=True)
    table.add_column("Total Pkts Sent", justify="right", style="magenta")
    table.add_column("Pkts Sent/sec", justify="right", style="red")
    table.add_column("Total Data Sent", justify="right", style="yellow")
    table.add_column("Upload Speed", justify="right", style="red")

    for iface, io in current_io.items():
        # Optional: Skip loopback (localhost) to only see external traffic
        if iface == 'lo': 
            continue 
        
        prev_io = last_io.get(iface)
        if prev_io:
            # Calculate the speed based on the time elapsed
            pkts_sent_sec = (io.packets_sent - prev_io.packets_sent) / time_elapsed
            bytes_sent_sec = (io.bytes_sent - prev_io.bytes_sent) / time_elapsed
        else:
            pkts_sent_sec = 0
            bytes_sent_sec = 0

        table.add_row(
            iface,
            f"{io.packets_sent:,}",
            f"{pkts_sent_sec:.1f} pkt/s",
            f"{io.bytes_sent / 1024 / 1024:.2f} MB",
            f"{bytes_sent_sec / 1024:.2f} KB/s"
        )

    # Update states for the next tick
    last_io = current_io
    last_time = current_time
    
    return table

print("Starting dashboard... Press Ctrl+C to stop.")

try:
    # Live block updates the terminal in place
    with Live(generate_table(), refresh_per_second=2) as live:
        while True:
            time.sleep(1)
            live.update(generate_table())
except KeyboardInterrupt:
    print("\nDashboard stopped.")