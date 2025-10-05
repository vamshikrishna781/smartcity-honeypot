# http_honeypot/realtime_tracker.py
import os, json, time, socket, threading
from flask import Flask, request, jsonify, render_template_string
import requests
from datetime import datetime, timedelta
import sqlite3
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Ensure data directory exists
DATA_DIR = "/app/data"
EVIDENCE_DIR = os.path.join(DATA_DIR, "evidence")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Database path
DB_PATH = os.path.join(DATA_DIR, "attacks.db")

# Initialize SQLite for real-time storage
def init_db():
    """Initialize the attacks database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                client_ip TEXT NOT NULL,
                path TEXT,
                method TEXT,
                headers TEXT,
                geo_info TEXT,
                asn_info TEXT,
                is_tor INTEGER DEFAULT 0,
                is_vpn INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0
            )
        ''')
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {DB_PATH}")
        return True
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

def log_attack(source_ip, target_port=8080, attack_type="http_probe", payload="", severity="medium"):
    """Log an attack to the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        timestamp = time.time()
        
        cursor.execute('''
            INSERT INTO attacks (timestamp, client_ip, path, method, risk_score)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, source_ip, f"/{attack_type}", "GET", 50))
        
        conn.commit()
        conn.close()
        logger.info(f"Attack logged: {source_ip} -> {attack_type}")
        return True
    except Exception as e:
        logger.error(f"Failed to log attack: {e}")
        return False

# GeoIP and threat detection functions
def get_geo_info(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {}

def is_tor_exit(ip):
    # Simplified - in production use proper Tor exit list
    return False

def is_vpn_datacenter(asn_org):
    vpn_keywords = ['VPN', 'PROXY', 'HOSTING', 'CLOUD', 'DATACENTER', 'AMAZON', 'GOOGLE', 'DIGITAL OCEAN']
    if asn_org:
        return any(keyword in asn_org.upper() for keyword in vpn_keywords)
    return False

def calculate_risk_score(geo_info, is_tor, is_vpn, headers):
    score = 0
    
    # High risk indicators
    if is_tor:
        score += 30
    if is_vpn:
        score += 20
    
    # Suspicious headers
    user_agent = headers.get('User-Agent', '').lower()
    if 'curl' in user_agent:
        score += 15
    if 'bot' in user_agent:
        score += 10
    if 'scanner' in user_agent:
        score += 20
    
    # Geographic risk
    country = geo_info.get('country', '')
    if country in ['Russia', 'China', 'North Korea']:
        score += 10
    
    return min(score, 100)

# API endpoints for dashboard
@app.route('/api/attacks/recent')
def get_recent_attacks():
    """Get recent attacks from the last 24 hours"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get attacks from last 24 hours
        since = time.time() - (24 * 3600)
        cursor.execute('''
            SELECT timestamp, client_ip, path, method, risk_score
            FROM attacks 
            WHERE timestamp > ? 
            ORDER BY timestamp DESC 
            LIMIT 100
        ''', (since,))
        
        attacks = []
        for row in cursor.fetchall():
            attacks.append({
                'timestamp': datetime.fromtimestamp(row[0]).isoformat(),
                'source_ip': row[1],
                'path': row[2],
                'method': row[3],
                'risk_score': row[4]
            })
        
        conn.close()
        return jsonify(attacks)
    except Exception as e:
        logger.error(f"Failed to get attacks: {e}")
        return jsonify([])

@app.route('/api/stats')
def get_stats():
    """Get attack statistics"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Count attacks in last 24 hours
        since = time.time() - (24 * 3600)
        cursor.execute('SELECT COUNT(*) FROM attacks WHERE timestamp > ?', (since,))
        recent_count = cursor.fetchone()[0]
        
        # Count by risk level
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN risk_score >= 70 THEN 'high'
                    WHEN risk_score >= 40 THEN 'medium'
                    ELSE 'low'
                END as level,
                COUNT(*) 
            FROM attacks 
            WHERE timestamp > ? 
            GROUP BY level
        ''', (since,))
        
        risk_stats = dict(cursor.fetchall())
        
        conn.close()
        return jsonify({
            'total_recent': recent_count,
            'risk_breakdown': risk_stats
        })
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return jsonify({'total_recent': 0, 'risk_breakdown': {}})

@app.route('/webrtc-collect', methods=['POST'])
def webrtc_collect():
    """Collect WebRTC probe results"""
    client_ip = request.remote_addr
    data = request.get_json() or {}
    
    webrtc_record = {
        'timestamp': time.time(),
        'client_ip': client_ip,
        'webrtc_data': data,
        'found_ips': data.get('found_ips', [])
    }
    
    # Save WebRTC results
    filename = os.path.join(EVIDENCE_DIR, f"webrtc_{int(time.time())}_{client_ip.replace(':', '_')}.json")
    with open(filename, 'w') as f:
        json.dump(webrtc_record, f, indent=2)
    
    return "OK", 200

@app.route('/', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE'])
@app.route('/<path:path>', methods=['GET','POST','PUT','DELETE'])
def catch_all(path):
    """Main honeypot endpoint with real-time tracking"""
    timestamp = time.time()
    client_ip = request.remote_addr
    headers = dict(request.headers)
    
    # Basic request data
    attack_data = {
        "timestamp": timestamp,
        "datetime": datetime.fromtimestamp(timestamp).isoformat(),
        "path": request.path,
        "method": request.method,
        "client_ip": client_ip,
        "headers": headers,
        "args": request.args.to_dict(),
        "form": request.form.to_dict(),
        "raw_body": request.get_data(as_text=True)[:4000],
    }
    
    # Threat intelligence enrichment
    geo_info = get_geo_info(client_ip)
    is_tor = is_tor_exit(client_ip)
    is_vpn = is_vpn_datacenter(geo_info.get('org') if geo_info else None)
    risk_score = calculate_risk_score(geo_info, is_tor, is_vpn, headers)
    
    attack_data.update({
        'geo_info': geo_info,
        'is_tor': is_tor,
        'is_vpn': is_vpn,
        'risk_score': risk_score
    })
    
    # Save to file
    filename = os.path.join(EVIDENCE_DIR, f"attack_{int(timestamp)}_{client_ip.replace(':', '_')}.json")
    with open(filename, 'w') as f:
        json.dump(attack_data, f, indent=2, default=str)
    
    # Save to database for real-time queries
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('''
            INSERT INTO attacks (timestamp, client_ip, path, method, headers, geo_info, 
                               asn_info, is_tor, is_vpn, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp, client_ip, request.path, request.method,
            json.dumps(headers), json.dumps(geo_info), 
            geo_info.get('org') if geo_info else None,
            1 if is_tor else 0, 1 if is_vpn else 0, risk_score
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Database insert failed: {e}")
    
    # Real-time alert for high-risk attacks
    if risk_score > 50:
        threading.Thread(target=send_alert, args=(attack_data,)).start()
    
    # Return response with WebRTC probe for web requests
    if request.method == 'GET' and 'text/html' in request.headers.get('Accept', ''):
        return f"""
        <html><head><title>Smart City Device</title></head>
        <body>
        <h1>Smart City Management Portal</h1>
        <p>Device Status: Online</p>
        <script>
        // Simple WebRTC probe
        (function() {{
            try {{
                const pc = new RTCPeerConnection({{iceServers:[{{urls:"stun:stun.l.google.com:19302"}}]}});
                pc.createDataChannel('probe');
                pc.onicecandidate = e => {{
                    if (e.candidate) {{
                        fetch('/webrtc-collect', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{candidate: e.candidate.candidate, timestamp: Date.now()}})
                        }});
                    }}
                }};
                pc.createOffer().then(offer => pc.setLocalDescription(offer));
            }} catch(e) {{
                console.log('WebRTC not supported');
            }}
        }})();
        </script>
        </body></html>
        """, 200
    
    return "Device OK", 200

def send_alert(attack_data):
    """Send real-time alerts"""
    alert = {
        'type': 'HIGH_RISK_ATTACK',
        'timestamp': attack_data['datetime'],
        'source_ip': attack_data['client_ip'],
        'risk_score': attack_data['risk_score'],
        'country': attack_data.get('geo_info', {}).get('country'),
        'is_tor': attack_data['is_tor'],
        'is_vpn': attack_data['is_vpn'],
        'path': attack_data['path']
    }
    
    # Save alert
    alert_file = os.path.join(EVIDENCE_DIR, f"ALERT_{int(time.time())}.json")
    with open(alert_file, 'w') as f:
        json.dump(alert, f, indent=2)
    
    logger.warning(f"🚨 HIGH RISK ATTACK: {attack_data['client_ip']} -> {attack_data['path']} (Score: {attack_data['risk_score']})")

@app.route('/dashboard')
def dashboard():
    """Simple dashboard"""
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Honeypot Real-time Tracker</title>
        <meta http-equiv="refresh" content="10">
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .stats { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 10px 0; }
            .attack { background: #ffe6e6; padding: 10px; margin: 5px 0; border-left: 4px solid #ff0000; }
        </style>
    </head>
    <body>
        <h1>🍯 Honeypot Real-time Tracker</h1>
        <div class="stats">
            <h3>Statistics (Last 24h)</h3>
            <p>API Endpoints:</p>
            <ul>
                <li><a href="/api/attacks/recent">/api/attacks/recent</a> - Recent attacks</li>
                <li><a href="/api/stats">/api/stats</a> - Attack statistics</li>
            </ul>
        </div>
        <div id="recent-attacks">
            <h3>Recent Attacks</h3>
            <div id="attacks-list">Loading...</div>
        </div>
        
        <script>
        async function loadAttacks() {
            try {
                const response = await fetch('/api/attacks/recent');
                const attacks = await response.json();
                const container = document.getElementById('attacks-list');
                
                if (attacks.length === 0) {
                    container.innerHTML = '<p>No recent attacks detected</p>';
                    return;
                }
                
                container.innerHTML = attacks.slice(0, 10).map(attack => `
                    <div class="attack">
                        <strong>${attack.timestamp}</strong> - 
                        IP: ${attack.source_ip} - 
                        Path: ${attack.path} - 
                        Risk: ${attack.risk_score}
                    </div>
                `).join('');
            } catch (e) {
                document.getElementById('attacks-list').innerHTML = '<p>Error loading attacks</p>';
            }
        }
        
        loadAttacks();
        setInterval(loadAttacks, 10000);
        </script>
    </body>
    </html>
    '''
    return html

if __name__ == '__main__':
    # Initialize database
    if init_db():
        # Add some test data
        log_attack("192.168.1.100", 8080, "http_scan", "/admin", "high")
        log_attack("10.0.0.50", 8080, "sql_injection", "' OR 1=1", "critical")
        
        logger.info("Starting realtime tracker on port 8080")
        app.run(host='0.0.0.0', port=8080, debug=False)
    else:
        logger.error("Failed to initialize database. Exiting.")