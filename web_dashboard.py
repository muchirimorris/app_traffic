import psutil
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import threading
import time
from flask import Flask, jsonify, render_template_string
import logging

# Disable default Flask logging so it doesn't clutter the terminal
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

# Dictionary to store traffic
traffic_stats = defaultdict(lambda: {"name": "Unknown", "bytes": 0})
port_to_pid = {}

def update_connections():
    """Background thread: Maps local network ports to Process IDs"""
    while True:
        try:
            conns = psutil.net_connections(kind='inet')
            new_mapping = {}
            for conn in conns:
                if conn.pid is not None and conn.laddr:
                    new_mapping[conn.laddr.port] = conn.pid
            
            global port_to_pid
            port_to_pid = new_mapping
        except Exception:
            pass
        time.sleep(2)

def process_packet(packet):
    """Callback triggered for every single packet captured"""
    if IP in packet:
        dst_ip = packet[IP].dst
        src_port = None

        if TCP in packet:
            src_port = packet[TCP].sport
        elif UDP in packet:
            src_port = packet[UDP].sport

        if src_port:
            pid = port_to_pid.get(src_port)
            if pid:
                key = (pid, dst_ip)
                
                if traffic_stats[key]["name"] == "Unknown":
                    try:
                        traffic_stats[key]["name"] = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        traffic_stats[key]["name"] = "Terminated"
                
                traffic_stats[key]["bytes"] += len(packet)

# --- WEB UI HTML & CSS ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Traffic Dashboard</title>
    <style>
        body { 
            background-color: #121212; color: #e0e0e0; 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; padding: 20px; 
        }
        .container { max-width: 1000px; margin: auto; }
        h1 { color: #00e676; text-align: center; margin-bottom: 30px; font-weight: 400;}
        table { width: 100%; border-collapse: collapse; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #333; }
        th { background-color: #1f1f1f; color: #b39ddb; text-transform: uppercase; font-size: 14px;}
        tr:hover { background-color: #2c2c2c; }
        .data-sent { color: #64b5f6; font-weight: bold; text-align: right;}
        th:last-child { text-align: right; }
        .pid-badge { background-color: #37474f; padding: 3px 8px; border-radius: 4px; font-size: 12px;}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Live Outbound Traffic</h1>
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Application</th>
                    <th>Destination IP</th>
                    <th>Data Sent</th>
                </tr>
            </thead>
            <tbody id="table-body">
                <tr><td colspan="4" style="text-align:center;">Listening for packets...</td></tr>
            </tbody>
        </table>
    </div>

    <script>
        // Convert raw bytes to KB/MB for the UI
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Fetch data from Python backend and update table
        async function fetchData() {
            try {
                const response = await fetch('/data');
                const data = await response.json();
                
                let tbody = document.getElementById('table-body');
                if (data.length === 0) return; // Keep loading message if no data yet

                tbody.innerHTML = '';
                
                data.forEach(row => {
                    let tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><span class="pid-badge">${row.pid}</span></td>
                        <td>${row.name}</td>
                        <td>${row.ip}</td>
                        <td class="data-sent">${formatBytes(row.bytes)}</td>
                    `;
                    tbody.appendChild(tr);
                });
            } catch (error) {
                console.error("Error fetching data:", error);
            }
        }
        
        // Refresh the table every 1 second
        setInterval(fetchData, 1000);
        fetchData();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/data')
def data():
    """API Endpoint: Returns the current traffic stats as JSON"""
    sorted_traffic = sorted(traffic_stats.items(), key=lambda item: item[1]["bytes"], reverse=True)
    result = []
    
    # Send the top 20 connections to the UI
    for (pid, dst_ip), data in sorted_traffic[:20]:
        result.append({
            "pid": pid,
            "name": data["name"],
            "ip": dst_ip,
            "bytes": data["bytes"]
        })
    return jsonify(result)

if __name__ == '__main__':
    print("Starting packet sniffer...")
    threading.Thread(target=update_connections, daemon=True).start()
    threading.Thread(target=lambda: sniff(prn=process_packet, store=False), daemon=True).start()
    
    print("\n" + "="*50)
    print("🚀 DASHBOARD LIVE: Open http://127.0.0.1:5000 in your browser")
    print("="*50 + "\n")
    
    # Run the web server
    app.run(host='127.0.0.1', port=5000)