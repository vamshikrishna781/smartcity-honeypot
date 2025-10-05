# scripts/network_fingerprint.py
from scapy.all import sniff, TCP, IP
import json, time, os
import sqlite3

EVIDENCE_DIR = os.path.join('..', 'data', 'realtime_evidence')
DB_PATH = os.path.join(EVIDENCE_DIR, 'network_fingerprints.db')

def init_fingerprint_db():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_port INTEGER,
            ttl INTEGER,
            window_size INTEGER,
            tcp_options TEXT,
            estimated_hops INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def estimate_hops(ttl):
    """Estimate network hops based on TTL"""
    common_initial_ttls = [64, 128, 255]
    min_hops = float('inf')
    
    for initial_ttl in common_initial_ttls:
        if ttl <= initial_ttl:
            hops = initial_ttl - ttl
            min_hops = min(min_hops, hops)
    
    return min_hops if min_hops != float('inf') else ttl

def packet_handler(packet):
    """Handle captured TCP SYN packets"""
    if IP in packet and TCP in packet and packet[TCP].flags & 0x02:  # SYN flag
        timestamp = time.time()
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        ttl = packet[IP].ttl
        window_size = packet[TCP].window
        tcp_options = str(packet[TCP].options)
        estimated_hops = estimate_hops(ttl)
        
        fingerprint_data = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_port': dst_port,
            'ttl': ttl,
            'window_size': window_size,
            'tcp_options': tcp_options,
            'estimated_hops': estimated_hops
        }
        
        # Save to database
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute('''
                INSERT INTO fingerprints (timestamp, src_ip, dst_port, ttl, window_size, tcp_options, estimated_hops)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, dst_port, ttl, window_size, tcp_options, estimated_hops))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database error: {e}")
        
        # Save to file
        filename = os.path.join(EVIDENCE_DIR, f"fingerprint_{int(timestamp)}_{src_ip.replace('.', '_')}.json")
        try:
            with open(filename, 'w') as f:
                json.dump(fingerprint_data, f, indent=2)
        except Exception as e:
            print(f"File write error: {e}")
        
        print(f"📡 Fingerprint: {src_ip} -> port {dst_port} (TTL: {ttl}, Hops: ~{estimated_hops})")

if __name__ == '__main__':
    print("🔍 Starting passive network fingerprinting...")
    init_fingerprint_db()
    
    # Requires root privileges
    try:
        print("Capturing TCP SYN packets... (Press Ctrl+C to stop)")
        sniff(filter='tcp and tcp[tcpflags] & tcp-syn != 0', prn=packet_handler, store=0)
    except PermissionError:
        print("❌ Root privileges required for packet capture")
        print("Run with: sudo python3 network_fingerprint.py")
    except KeyboardInterrupt:
        print("\n👋 Network fingerprinting stopped")
    except Exception as e:
        print(f"❌ Error: {e}")