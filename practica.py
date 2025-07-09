import pexpect
import re
import subprocess
import json
from datetime import datetime

def get_wifi_data_tshark(interface="wlx60a4b721c80d", timeout=10):
    """
    Captează date WiFi folosind tshark în loc de airodump-ng
    """
    try:
        # Comanda tshark pentru a capta cadre WiFi
        cmd = [
            'sudo', 'tshark', '-i', interface,
            '-a', f'duration:{timeout}',
            '-Y', 'wlan.fc.type_subtype == 0x08',  # Beacon frames
            '-T', 'fields',
            '-e', 'wlan.bssid',
            '-e', 'wlan.ssid',
            '-e', 'radiotap.dbm_antsignal',
            '-e', 'wlan.fixed.beacon',
            '-e', 'wlan.ds.current_channel',
            '-e', 'wlan.fixed.capabilities.privacy',
            '-e', 'wlan.tag.number',
            '-E', 'header=n',
            '-E', 'separator=|',
            '-E', 'quote=n'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        print(f"Eroare tshark: {e}")
        return None

def get_wifi_clients_tshark(interface="wlx60a4b721c80d", timeout=10):
    """
    Captează informații despre clienții WiFi
    """
    try:
        cmd = [
            'sudo', 'tshark', '-i', interface,
            '-a', f'duration:{timeout}',
            '-Y', 'wlan.fc.type in {0 2}',  # management+control+data
            '-T', 'fields',
            '-e', 'wlan.sa',  # Source address
            '-e', 'wlan.da',  # Destination address
            '-e', 'wlan.bssid',
            '-e', 'radiotap.dbm_antsignal',
            '-e', 'frame.len',
            '-E', 'header=n',
            '-E', 'separator=|',
            '-E', 'quote=n'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        print(f"Eroare tshark clienți: {e}")
        return None

def parse_wifi_beacons(output):
    """
    Parsează output-ul de la tshark pentru beacon frames
    """
    if not output:
        return []
    
    aps = {}
    lines = output.strip().split('\n')
    
    for line in lines:
        if not line.strip():
            continue
            
        parts = line.split('|')
        if len(parts) < 4:
            continue
            
        bssid = parts[0] if parts[0] else "Unknown"
        raw_ssid = parts[1]
        if not raw_ssid:
             ssid = "Hidden"
        elif all(c in '0123456789abcdefABCDEF' for c in raw_ssid) and len(raw_ssid) % 2 == 0:
            try:
              ssid = bytes.fromhex(raw_ssid).decode('utf-8', errors='replace')
            except:
               ssid = f"(hex) {raw_ssid}"
        else:
            ssid = raw_ssid
        signal = parts[2] if parts[2] else "0"
        channel = parts[4] if len(parts) > 4 and parts[4] else "Unknown"
        privacy = parts[5] if len(parts) > 5 and parts[5] else "0"
        
        if bssid not in aps:
            aps[bssid] = {
                'bssid': bssid,
                'ssid': ssid,
                'signal': signal,
                'channel': channel,
                'privacy': "WEP/WPA" if privacy == "1" else "Open",
                'beacons': 0,
                'last_seen': datetime.now().strftime("%H:%M:%S")
            }
        
        aps[bssid]['beacons'] += 1
    
    return list(aps.values())

def parse_wifi_clients(output):
    """
    Parsează output-ul de la tshark pentru clienți WiFi
    """
    if not output:
        return []
    
    clients = {}
    lines = output.strip().split('\n')
    
    for line in lines:
        if not line.strip():
            continue
            
        parts = line.split('|')
        if len(parts) < 3:
            continue
            
        src_mac = parts[0] if parts[0] else "Unknown"
        dst_mac = parts[1] if parts[1] else "Unknown"
        bssid = parts[2] if parts[2] else "Unknown"
        signal = parts[3] if len(parts) > 3 and parts[3] else "0"
        frame_len = parts[4] if len(parts) > 4 and parts[4] else "0"
        
        # Identificăm clientul (nu este BSSID)
        if src_mac != bssid and src_mac not in clients:
            clients[src_mac] = {
                'mac': src_mac,
                'bssid': bssid,
                'signal': signal,
                'packets': 0,
                'bytes': 0,
                'last_seen': datetime.now().strftime("%H:%M:%S")
            }
        
        if src_mac in clients:
            clients[src_mac]['packets'] += 1
            clients[src_mac]['bytes'] += int(frame_len) if frame_len.isdigit() else 0
    
    return list(clients.values())

# Restul codului rămâne la fel până la partea de GUI pentru WiFi

from scapy.all import AsyncSniffer, IP, TCP, UDP, DNS, DNSQR
import tkinter as tk
from tkinter import ttk
import threading
import time
from collections import defaultdict

known_ports = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
    25: "SMTP", 110: "POP3", 143: "IMAP", 3389: "RDP"
}

packet_log = []
traffic_per_ip = defaultdict(lambda: {"packets": 0, "bytes": 0})
traffic_per_connection = defaultdict(lambda: {"packets": 0, "bytes": 0})
ports_accessed = defaultdict(set)
alerts = set()
ip_to_domain = {}
wifi_aps = []
wifi_clients = []

stop_event = threading.Event()
sniffer = None

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)

        sport = dport = "?"
        proto = "?"

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            proto = "TCP"
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto = "UDP"

        proto_name = known_ports.get(dport, proto)

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            queried_domain = packet[DNSQR].qname.decode().strip(".")
            if packet[DNS].qr == 0:
                ip_to_domain[dst] = queried_domain

        traffic_per_ip[src]["packets"] += 1
        traffic_per_ip[src]["bytes"] += size
        traffic_per_connection[(src, dport)]["packets"] += 1
        traffic_per_connection[(src, dport)]["bytes"] += size

        if proto == "TCP":
            ports_accessed[src].add(dport)
            if len(ports_accessed[src]) > 10 and src not in alerts:
                packet_log.append({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "type": "ALERT",
                    "src": src,
                    "dst": "",
                    "desc": f"Port scanning detectat de la {src} ({len(ports_accessed[src])} porturi)"
                })
                alerts.add(src)

        domain_str = ip_to_domain.get(dst) or ip_to_domain.get(src) or ""
        if domain_str:
            domain_str = f" ({domain_str})"

        packet_log.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "type": "PACKET",
            "src": f"{src}:{sport}",
            "dst": f"{dst}:{dport}{domain_str}",
            "proto": proto_name,
            "bytes": size
        })

def get_color_by_volume(packets):
    if packets > 100:
        return "#ffcccc"
    elif packets > 10:
        return "#fff0b3"
    else:
        return "#ccffcc"

def get_signal_color(signal):
    """Returnează culoarea pe baza puterii semnalului"""
    try:
        signal_val = int(signal)
        if signal_val > -30:
            return "#00ff00"  # Verde - semnal excelent
        elif signal_val > -50:
            return "#ffff00"  # Galben - semnal bun
        elif signal_val > -70:
            return "#ff8000"  # Portocaliu - semnal mediu
        else:
            return "#ff0000"  # Roșu - semnal slab
    except:
        return "#cccccc"  # Gri - necunoscut

def update_gui():
    global wifi_aps, wifi_clients
    
    while not stop_event.is_set():
        new_packets = list(packet_log)
        packet_log.clear()

        for pkt in new_packets:
            if pkt["type"] == "PACKET":
                try:
                    src_ip = pkt["src"].split(':')[0]
                    dst_port = int(pkt["dst"].split(':')[1].split()[0])
                    packets = traffic_per_connection[(src_ip, dst_port)]["packets"]
                    color = get_color_by_volume(packets)
                    tree_packets.insert("", "end", values=(
                        pkt["timestamp"], pkt["src"], pkt["dst"],
                        pkt["proto"], pkt["bytes"]
                    ), tags=('colored',))
                    tree_packets.tag_configure('colored', background=color)
                except:
                    pass
            elif pkt["type"] == "ALERT":
                tree_alerts.insert("", "end", values=(pkt["timestamp"], pkt["src"], pkt["desc"]))

        # Actualizează statistici IP
        for item in tree_ip.get_children():
            tree_ip.delete(item)
        for ip, data in traffic_per_ip.items():
            tree_ip.insert("", "end", values=(ip, data["packets"], data["bytes"]))

        # Actualizează statistici conexiuni
        for item in tree_conn.get_children():
            tree_conn.delete(item)
        for (ip, port), data in traffic_per_connection.items():
            tree_conn.insert("", "end", values=(f"{ip}:{port}", data["packets"], data["bytes"]))

        # Actualizează datele WiFi AP
        for item in tree_wifi_ap.get_children():
            tree_wifi_ap.delete(item)

        # Calculează nr. clienți per AP
        clients_per_ap = defaultdict(int)
        for client in wifi_clients:
            clients_per_ap[client['bssid']] += 1

        for ap in wifi_aps:
            color = get_signal_color(ap['signal'])
            nr_clients = clients_per_ap.get(ap['bssid'], 0)
            item = tree_wifi_ap.insert("", "end", values=(
                ap['bssid'], ap['ssid'], ap['signal'], ap['channel'],
                ap['privacy'], ap['beacons'], ap['last_seen'], nr_clients
            ), tags=('signal',))
            tree_wifi_ap.tag_configure('signal', background=color)

        for ap in wifi_aps:
            color = get_signal_color(ap['signal'])
            item = tree_wifi_ap.insert("", "end", values=(
                ap['bssid'], ap['ssid'], ap['signal'], ap['channel'],
                ap['privacy'], ap['beacons'], ap['last_seen']
            ), tags=('signal',))
            tree_wifi_ap.tag_configure('signal', background=color)

        # Actualizează datele WiFi Clienți
        for item in tree_wifi_clients.get_children():
            tree_wifi_clients.delete(item)
        for client in wifi_clients:
            color = get_signal_color(client['signal'])
            item = tree_wifi_clients.insert("", "end", values=(
                client['mac'], client['bssid'], client['signal'],
                client['packets'], client['bytes'], client['last_seen']
            ), tags=('signal',))
            tree_wifi_clients.tag_configure('signal', background=color)

        time.sleep(10)

def update_wifi_data():
    """Funcție actualizată pentru a folosi tshark"""
    global wifi_aps, wifi_clients
    
    while not stop_event.is_set():
        # Captează date despre AP-uri
        beacon_output = get_wifi_data_tshark()
        if beacon_output:
            wifi_aps = parse_wifi_beacons(beacon_output)
        
        # Captează date despre clienți
        client_output = get_wifi_clients_tshark()
        if client_output:
            wifi_clients = parse_wifi_clients(client_output)
        
        time.sleep(15)

def start_sniffing():
    global sniffer
    sniffer = AsyncSniffer(prn=process_packet, store=False)
    sniffer.start()

def stop_monitoring():
    stop_event.set()
    if sniffer:
        sniffer.stop()
    btn_stop.config(state="disabled")

# === GUI ===
root = tk.Tk()
root.title("Monitorizare trafic rețea")
root.geometry("1400x800")

frame_top = tk.Frame(root)
frame_top.pack(fill="x", padx=10, pady=5)

btn_stop = tk.Button(frame_top, text="⛔ Stop monitorizare", bg="#ff6666", fg="white", font=("Arial", 12, "bold"), command=stop_monitoring)
btn_stop.pack(side="right")

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

frame_packets = ttk.Frame(notebook)
frame_ip = ttk.Frame(notebook)
frame_conn = ttk.Frame(notebook)
frame_alerts = ttk.Frame(notebook)
frame_wifi_ap = ttk.Frame(notebook)
frame_wifi_clients = ttk.Frame(notebook)

notebook.add(frame_packets, text="Pachete cronologic")
notebook.add(frame_ip, text="Statistici per IP")
notebook.add(frame_conn, text="Statistici IP:Port")
notebook.add(frame_alerts, text="Alerte port scanning")
notebook.add(frame_wifi_ap, text="WiFi Access Points")
notebook.add(frame_wifi_clients, text="WiFi Clienți")

def setup_tree(parent, columns, widths):
    frame = tk.Frame(parent)
    frame.pack(fill="both", expand=True)
    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    tree = ttk.Treeview(frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)
    scrollbar.config(command=tree.yview)
    for i, col in enumerate(columns):
        tree.heading(col, text=col)
        tree.column(col, anchor=tk.CENTER, width=widths[i])
    tree.pack(fill="both", expand=True)
    return tree

tree_packets = setup_tree(frame_packets, ["Timp", "Sursă", "Destinație", "Protocol", "Bytes"], [100, 250, 250, 100, 100])
tree_ip = setup_tree(frame_ip, ["IP", "Nr. Pachete", "Total Bytes"], [300, 150, 150])
tree_conn = setup_tree(frame_conn, ["IP:Port", "Nr. Pachete", "Total Bytes"], [300, 150, 150])
tree_alerts = setup_tree(frame_alerts, ["Timp", "Sursă", "Descriere"], [100, 250, 600])
tree_wifi_ap = setup_tree(
    frame_wifi_ap,
    ["BSSID", "SSID", "Signal (dBm)", "Canal", "Securitate", "Beacons", "Ultima detecție", "Nr. Clienți"],
    [180, 200, 100, 80, 100, 80, 120, 100]
)
tree_wifi_clients = setup_tree(
    frame_wifi_clients,
    ["MAC Client", "BSSID AP", "Signal (dBm)", "Pachete", "Bytes", "Ultima detecție"],
    [180, 180, 100, 80, 100, 120]
)

# Start threads
threading.Thread(target=start_sniffing, daemon=True).start()
threading.Thread(target=update_gui, daemon=True).start()
threading.Thread(target=update_wifi_data, daemon=True).start()

root.mainloop()
