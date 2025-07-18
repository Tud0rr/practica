import pexpect
import re
import subprocess
import json
from datetime import datetime

def get_wifi_data_tshark(interface="wlx60a4b721c80d", timeout=10):
    """
    Captează date WiFi folosind tshark
    """
    try:
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

def get_wifi_clients_tshark_improved(interface="wlx60a4b721c80d", timeout=10):
    """
    Capturarea clienților WiFi
    """
    try:
        cmd = [
            'sudo', 'tshark', '-i', interface,
            '-a', f'duration:{timeout}',
            '-Y', 'wlan and not wlan.fc.type_subtype == 0x08',  # Toate exceptând beacon frames
            '-T', 'fields',
            '-e', 'wlan.ta',
            '-e', 'wlan.ra',
            '-e', 'wlan.sa',
            '-e', 'wlan.da',
            '-e', 'wlan.bssid',
            '-e', 'radiotap.dbm_antsignal',
            '-e', 'frame.len',
            '-e', 'wlan.fc.type_subtype',
            '-e', 'wlan.fc.type',
            '-e', 'wlan.fc.subtype',
            '-E', 'header=n',
            '-E', 'separator=|',
            '-E', 'quote=n',
            '-E', 'occurrence=f'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+10)
        
        if result.returncode != 0:
            print(f"Eroare tshark: {result.stderr}")
            return None
            
        return result.stdout if result.stdout.strip() else None
        
    except subprocess.TimeoutExpired:
        print("Timeout la capturarea clienților")
        return None
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
             ssid = "Hidden Network"
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
                'privacy': "Securizat" if privacy == "1" else "Deschis",
                'beacons': 0,
                'last_seen': datetime.now().strftime("%H:%M:%S")
            }
        
        aps[bssid]['beacons'] += 1
    
    return list(aps.values())

def parse_wifi_clients_improved(output, wifi_aps):
    """
    Parser îmbunătățit pentru clienți WiFi cu informații despre AP
    """
    if not output:
        return []
    
    clients = {}
    lines = output.strip().split('\n')
    
    # Creează un dicționar pentru căutarea rapidă a AP-urilor
    ap_dict = {ap['bssid']: ap for ap in wifi_aps}
    
    for line_num, line in enumerate(lines):
        if not line.strip():
            continue
            
        parts = line.split('|')
        if len(parts) < 8:
            continue
            
        ta = parts[0].strip() if parts[0] else None
        ra = parts[1].strip() if parts[1] else None  
        sa = parts[2].strip() if parts[2] else None
        da = parts[3].strip() if parts[3] else None
        bssid = parts[4].strip() if parts[4] else None
        signal = parts[5].strip() if parts[5] else "0"
        frame_len = parts[6].strip() if parts[6] else "0"
        frame_type = parts[7].strip() if parts[7] else "0"
        
        # Identificăm potențialii clienți
        potential_clients = []
        
        for addr in [ta, ra, sa, da]:
            if addr and addr != "00:00:00:00:00:00" and not addr.startswith("ff:ff:ff"):
                # Verifică dacă adresa nu este un AP cunoscut
                if addr not in ap_dict:
                    potential_clients.append(addr)
        
        # Procesăm fiecare potențial client
        for client_mac in potential_clients:
            if client_mac not in clients:
                # Obține informații despre AP
                ap_info = ap_dict.get(bssid, {})
                ap_name = ap_info.get('ssid', 'Unknown AP')
                
                clients[client_mac] = {
                    'mac': client_mac,
                    'bssid': bssid or "Unknown",
                    'signal': signal,
                    'packets': 0,
                    'bytes': 0,
                    'last_seen': datetime.now().strftime("%H:%M:%S"),
                    'frame_types': set(),
                    'ap_name': ap_name
                }
            
            # Actualizăm statisticile
            clients[client_mac]['packets'] += 1
            if frame_len.isdigit():
                clients[client_mac]['bytes'] += int(frame_len)
            clients[client_mac]['last_seen'] = datetime.now().strftime("%H:%M:%S")
            clients[client_mac]['frame_types'].add(frame_type)
            
            # Actualizăm semnalul dacă este mai bun
            try:
                if signal and signal != "0":
                    current_signal = int(clients[client_mac]['signal']) if clients[client_mac]['signal'] != "0" else -100
                    new_signal = int(signal)
                    if new_signal > current_signal:
                        clients[client_mac]['signal'] = signal
            except:
                pass
    
    return list(clients.values())

def test_wifi_capture(interface="wlx60a4b721c80d"):
    """
    Funcție de test pentru a verifica capturarea
    """
    print("=== Test capturare WiFi ===")
    
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        if "Mode:Monitor" not in result.stdout:
            print("AVERTISMENT: Interfața nu pare să fie în modul monitor!")
    except:
        print("Nu se poate verifica statusul interfeței")
    
    cmd = ['sudo', 'tshark', '-i', interface, '-a', 'duration:3', '-Y', 'wlan']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        if result.stdout:
            print("✓ Trafic WiFi detectat!")
        else:
            print("✗ Niciun trafic WiFi detectat")
    except Exception as e:
        print(f"Eroare test WiFi: {e}")

# Importuri pentru partea de rețea
from scapy.all import AsyncSniffer, IP, TCP, UDP, DNS, DNSQR
import tkinter as tk
from tkinter import ttk, font
import threading
import time
from collections import defaultdict

known_ports = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
    25: "SMTP", 110: "POP3", 143: "IMAP", 3389: "RDP", 23: "Telnet",
    993: "IMAPS", 995: "POP3S", 465: "SMTPS", 587: "SMTP", 8080: "HTTP-Alt",
    3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 6379: "Redis"
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

        proto_name = known_ports.get(dport, f"{proto}:{dport}")

        # DEBUG: Print pentru a verifica capturarea
        print(f"DEBUG: Packet captat - {src}:{sport} -> {dst}:{dport} ({proto})")

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
            print(f"DEBUG: {src} a accesat portul {dport} (total porturi: {len(ports_accessed[src])})")
            
            # Reducem pragul pentru testare
            if len(ports_accessed[src]) > 3 and src not in alerts:
                print(f"ALERT GENERAT: Port scanning de la {src} - {len(ports_accessed[src])} porturi")
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
        return "#ffcccc"  # Roșu deschis - mult trafic
    elif packets > 50:
        return "#ffe6cc"  # Portocaliu deschis
    elif packets > 10:
        return "#fff0b3"  # Galben deschis
    else:
        return "#e6ffe6"  # Verde deschis - puțin trafic

def get_signal_color(signal):
    """Returnează culoarea pe baza puterii semnalului"""
    try:
        signal_val = int(signal)
        if signal_val > -30:
            return "#00ff00"  # Verde - semnal excelent
        elif signal_val > -50:
            return "#7fff00"  # Verde-galben - semnal foarte bun
        elif signal_val > -70:
            return "#ffff00"  # Galben - semnal bun
        elif signal_val > -80:
            return "#ff8000"  # Portocaliu - semnal mediu
        else:
            return "#ff4444"  # Roșu - semnal slab
    except:
        return "#e0e0e0"  # Gri - necunoscut

def format_bytes(bytes_val):
    """Formatează bytes în unități mai ușor de citit"""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024**2:
        return f"{bytes_val/1024:.1f} KB"
    elif bytes_val < 1024**3:
        return f"{bytes_val/1024**2:.1f} MB"
    else:
        return f"{bytes_val/1024**3:.1f} GB"

def update_gui():
    global wifi_aps, wifi_clients
    
    while not stop_event.is_set():
        new_packets = list(packet_log)
        packet_log.clear()

        for pkt in new_packets:
            if pkt["type"] == "PACKET":
                try:
                    src_ip = pkt["src"].split(':')[0]
                    dst_info = pkt["dst"].split(':')
                    dst_port = int(dst_info[1].split()[0])
                    packets = traffic_per_connection[(src_ip, dst_port)]["packets"]
                    color = get_color_by_volume(packets)
                    
                    # Limitează numărul de rânduri afișate
                    if len(tree_packets.get_children()) > 1000:
                        tree_packets.delete(tree_packets.get_children()[0])
                    
                    tree_packets.insert("", "end", values=(
                        pkt["timestamp"], pkt["src"], pkt["dst"],
                        pkt["proto"], format_bytes(pkt["bytes"])
                    ), tags=('colored',))
                    tree_packets.tag_configure('colored', background=color)
                except:
                    pass
            elif pkt["type"] == "ALERT":
                tree_alerts.insert("", "end", values=(pkt["timestamp"], pkt["src"], pkt["desc"]))

        # Actualizează statistici IP
        for item in tree_ip.get_children():
            tree_ip.delete(item)
        for ip, data in sorted(traffic_per_ip.items(), key=lambda x: x[1]["packets"], reverse=True)[:100]:
            tree_ip.insert("", "end", values=(
                ip, data["packets"], format_bytes(data["bytes"])
            ))

        # Actualizează statistici conexiuni
        for item in tree_conn.get_children():
            tree_conn.delete(item)
        for (ip, port), data in sorted(traffic_per_connection.items(), key=lambda x: x[1]["packets"], reverse=True)[:100]:
            port_name = known_ports.get(port, str(port))
            tree_conn.insert("", "end", values=(
                f"{ip}:{port_name}", data["packets"], format_bytes(data["bytes"])
            ))

        # Actualizează datele WiFi AP
        for item in tree_wifi_ap.get_children():
            tree_wifi_ap.delete(item)

        clients_per_ap = defaultdict(int)
        for client in wifi_clients:
            clients_per_ap[client['bssid']] += 1

        for ap in sorted(wifi_aps, key=lambda x: int(x['signal']) if x['signal'].lstrip('-').isdigit() else -100, reverse=True):
            color = get_signal_color(ap['signal'])
            nr_clients = clients_per_ap.get(ap['bssid'], 0)
            
            item = tree_wifi_ap.insert("", "end", values=(
                ap['bssid'], ap['ssid'], f"{ap['signal']} dBm", 
                ap['channel'], ap['privacy'], ap['beacons'], 
                ap['last_seen'], nr_clients
            ), tags=('signal',))
            tree_wifi_ap.tag_configure('signal', background=color)

        # Actualizează datele WiFi Clienți
        for item in tree_wifi_clients.get_children():
            tree_wifi_clients.delete(item)
        for client in sorted(wifi_clients, key=lambda x: int(x['signal']) if x['signal'].lstrip('-').isdigit() else -100, reverse=True):
            color = get_signal_color(client['signal'])
            
            # Formatează afișarea cu numele AP în paranteză
            bssid_display = f"{client['bssid']} ({client['ap_name']})" if client['ap_name'] != 'Unknown AP' else client['bssid']
            
            item = tree_wifi_clients.insert("", "end", values=(
                client['mac'], bssid_display, f"{client['signal']} dBm",
                client['packets'], format_bytes(client['bytes']), client['last_seen']
            ), tags=('signal',))
            tree_wifi_clients.tag_configure('signal', background=color)

        time.sleep(5)

def update_wifi_data_improved():
    """
    Funcție actualizată pentru a folosi versiunea îmbunătățită
    """
    global wifi_aps, wifi_clients
    
    test_wifi_capture()
    
    while not stop_event.is_set():
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Captez date WiFi...")
        
        # Captează date despre AP-uri
        beacon_output = get_wifi_data_tshark()
        if beacon_output:
            wifi_aps = parse_wifi_beacons(beacon_output)
            print(f"✓ Găsite {len(wifi_aps)} AP-uri")
        else:
            print("✗ Niciun AP găsit")
        
        # Captează date despre clienți
        client_output = get_wifi_clients_tshark_improved()
        if client_output:
            wifi_clients = parse_wifi_clients_improved(client_output, wifi_aps)
            print(f"✓ Găsiți {len(wifi_clients)} clienți")
        else:
            print("✗ Niciun client găsit")
        
        time.sleep(15)

def start_sniffing():
    global sniffer
    print("Pornesc sniffing...")
    
    # Detectează interfața automată
    import netifaces
    try:
        # Încearcă să găsească interfața default
        default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        print(f"Folosesc interfața: {default_interface}")
    except:
        default_interface = None
        print("Folosesc toate interfețele (any)")
    
    try:
        if default_interface:
            sniffer = AsyncSniffer(iface=default_interface, prn=process_packet, store=False)
        else:
            sniffer = AsyncSniffer(prn=process_packet, store=False)
        
        sniffer.start()
        print("Sniffer pornit cu succes!")
    except Exception as e:
        print(f"Eroare la pornirea sniffer: {e}")
        # Fallback - încearcă fără interfață specifică
        try:
            sniffer = AsyncSniffer(prn=process_packet, store=False)
            sniffer.start()
            print("Sniffer pornit cu interfața default!")
        except Exception as e2:
            print(f"Eroare critică: {e2}")

def stop_monitoring():
    stop_event.set()
    if sniffer:
        sniffer.stop()
    btn_stop.config(state="disabled")

# === GUI cu Design îmbunătățit ===
root = tk.Tk()
root.title("Monitorizare Trafic Rețea")
root.geometry("1500x850")
root.configure(bg="#f5f5f5")

# Frame pentru titlu
title_frame = tk.Frame(root, bg="#2c3e50", height=60)
title_frame.pack(fill="x")
title_frame.pack_propagate(False)

title_label = tk.Label(title_frame, text="Monitorizare Trafic Rețea & WiFi", 
                      font=('Arial', 18, 'bold'), bg="#2c3e50", fg="white")
title_label.pack(pady=15)

# Frame pentru butoane
button_frame = tk.Frame(root, bg="#ecf0f1", height=50)
button_frame.pack(fill="x")
button_frame.pack_propagate(False)

btn_stop = tk.Button(button_frame, text="Stop Monitorizare", bg="#e74c3c", fg="white", 
                    font=("Arial", 11, "bold"), command=stop_monitoring)
btn_stop.pack(side="right", padx=10, pady=10)

# Notebook
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=10)

# Crearea frame-urilor
frame_packets = ttk.Frame(notebook)
frame_ip = ttk.Frame(notebook)
frame_conn = ttk.Frame(notebook)
frame_alerts = ttk.Frame(notebook)
frame_wifi_ap = ttk.Frame(notebook)
frame_wifi_clients = ttk.Frame(notebook)

notebook.add(frame_packets, text="Pachete Cronologic")
notebook.add(frame_ip, text="Statistici IP")
notebook.add(frame_conn, text="Conexiuni IP:Port")
notebook.add(frame_alerts, text="Alerte Port Scanning")
notebook.add(frame_wifi_ap, text="WiFi Access Points")
notebook.add(frame_wifi_clients, text="WiFi Clienți")

def setup_tree_with_header(parent, title, columns, widths):
    """Configurează un TreeView cu header personalizat"""
    # Frame principal
    main_frame = tk.Frame(parent, bg="#f5f5f5")
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Header
    header_frame = tk.Frame(main_frame, bg="#34495e", height=35)
    header_frame.pack(fill="x", pady=(0, 5))
    header_frame.pack_propagate(False)
    
    header_label = tk.Label(header_frame, text=title, 
                           font=('Arial', 12, 'bold'), bg="#34495e", fg="white")
    header_label.pack(side="left", padx=15, pady=8)
    
    # TreeView cu scrollbar
    tree_frame = tk.Frame(main_frame)
    tree_frame.pack(fill="both", expand=True)
    
    scrollbar = tk.Scrollbar(tree_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    tree = ttk.Treeview(tree_frame, columns=columns, show="headings", 
                       yscrollcommand=scrollbar.set)
    scrollbar.config(command=tree.yview)
    
    # Configurare coloane
    for i, col in enumerate(columns):
        tree.heading(col, text=col)
        tree.column(col, anchor=tk.CENTER, width=widths[i])
    
    tree.pack(fill="both", expand=True)
    return tree

# Configurarea TreeView-urilor
tree_packets = setup_tree_with_header(
    frame_packets, "Pachete de Rețea în Timp Real",
    ["Timp", "Sursă", "Destinație", "Protocol", "Dimensiune"],
    [100, 200, 300, 120, 120]
)

tree_ip = setup_tree_with_header(
    frame_ip, "Statistici Trafic per Adresă IP",
    ["Adresă IP", "Nr. Pachete", "Total Bytes"],
    [250, 120, 150]
)

tree_conn = setup_tree_with_header(
    frame_conn, "Statistici Conexiuni IP:Port",
    ["Conexiune", "Nr. Pachete", "Total Bytes"],
    [300, 120, 150]
)

tree_alerts = setup_tree_with_header(
    frame_alerts, "Alerte de Securitate",
    ["Timp", "Adresă IP", "Descriere"],
    [100, 200, 500]
)

tree_wifi_ap = setup_tree_with_header(
    frame_wifi_ap, "Access Points WiFi Detectate",
    ["BSSID", "SSID", "Putere Semnal", "Canal", "Securitate", "Beacons", "Ultima Detecție", "Nr. Clienți"],
    [180, 200, 120, 80, 100, 80, 120, 100]
)

tree_wifi_clients = setup_tree_with_header(
    frame_wifi_clients, "Clienți WiFi Detectați",
    ["MAC Client", "BSSID (Access Point)", "Putere Semnal", "Pachete", "Bytes", "Ultima Detecție"],
    [180, 250, 120, 80, 100, 120]
)

# Start threads
threading.Thread(target=start_sniffing, daemon=True).start()
threading.Thread(target=update_gui, daemon=True).start()
threading.Thread(target=update_wifi_data_improved, daemon=True).start()

root.mainloop()