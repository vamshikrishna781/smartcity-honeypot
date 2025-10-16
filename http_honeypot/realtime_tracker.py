# http_honeypot/realtime_tracker.py
import os, json, time, socket, threading
from flask import Flask, request, jsonify, render_template_string, abort
import requests
from datetime import datetime, timedelta
import sqlite3
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# configure DATA_DIR via env var with fallback to local writable dir
# Default to project-local data/http_honeypot if DATA_DIR not set
DEFAULT_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'http_honeypot'))
DATA_DIR = os.environ.get('DATA_DIR', DEFAULT_DATA_DIR)

# Try creating requested dir, fall back to a local dir if permission denied
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except PermissionError:
    FALLBACK_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'data'))
    os.makedirs(FALLBACK_DIR, exist_ok=True)
    DATA_DIR = FALLBACK_DIR

EVIDENCE_DIR = os.path.join(DATA_DIR, "evidence")
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

def log_attack(db_conn, client_ip, path, method, headers, payload, risk_score):
    """Insert a new attack row with UNIX epoch seconds."""
    ts = int(time.time())  # ensure seconds since epoch (not milliseconds / not zero)
    cur = db_conn.cursor()
    cur.execute(
        "INSERT INTO attacks(timestamp, client_ip, path, method, headers, payload, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, client_ip, path, method, json.dumps(dict(headers)), payload, risk_score)
    )
    db_conn.commit()

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

# --- NEW: admin protection (allow only localhost or valid ADMIN_TOKEN) ---
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN')

def require_admin_request():
    # allow local requests (127.0.0.1 or ::1)
    if request.remote_addr in ('127.0.0.1', '::1'):
        return True
    # allow requests with correct token header or ?token=...
    token = request.headers.get('X-Admin-Token') or request.args.get('token')
    if ADMIN_TOKEN and token and token == ADMIN_TOKEN:
        return True
    return False

def admin_only_response():
    # used in routes to block external access
    if not require_admin_request():
        abort(401)

# API endpoints for dashboard
# protect recent attacks API
@app.route('/api/attacks/recent')
def get_recent_attacks():
    admin_only_response()   # blocks external access
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, client_ip, path, method, risk_score
            FROM attacks ORDER BY timestamp DESC LIMIT 100
        ''')
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
    except Exception:
        return jsonify([])

# protect stats API
@app.route('/api/stats')
def get_stats():
    admin_only_response()   # blocks external access
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        since = time.time() - (24 * 3600)
        cursor.execute('SELECT COUNT(*) FROM attacks WHERE timestamp > ?', (since,))
        recent_count = cursor.fetchone()[0]
        # simple risk breakdown
        cursor.execute('SELECT risk_score FROM attacks WHERE timestamp > ?', (since,))
        rows = [r[0] for r in cursor.fetchall()]
        high = sum(1 for r in rows if r >= 70)
        medium = sum(1 for r in rows if 40 <= r < 70)
        low = sum(1 for r in rows if r < 40)
        conn.close()
        return jsonify({'total_recent': recent_count, 'risk_breakdown': {'high': high, 'medium': medium, 'low': low}})
    except Exception:
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

# protect dashboard page (return 401 to remote clients)
@app.route('/dashboard')
def dashboard():
    admin_only_response()
    # existing dashboard HTML or redirect to admin_app if desired
    return render_template_string("""
    <html><head><title>Honeypot Dashboard</title></head>
    <body><h1>Admin Dashboard (local only)</h1>
    <p>Use the local admin app: http://127.0.0.1:5000/admin</p>
    </body></html>
    """)

# === New: human-friendly pages for the API endpoints ===
@app.route('/page/attacks')
def attacks_page():
    html = """
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>Recent Attacks - Honeypot</title>
      <style>
        body{font-family:Arial,Helvetica,sans-serif;margin:20px;background:#f7f8fb}
        table{width:100%;border-collapse:collapse;background:#fff}
        th,td{padding:8px;border-bottom:1px solid #eee;text-align:left}
        th{background:#f0f4f8}
        .container{max-width:1000px;margin:0 auto}
        .header{display:flex;justify-content:space-between;align-items:center}
        .muted{color:#666;font-size:0.9rem}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Recent Attacks (Last 24h)</h1>
          <div class="muted">Auto-refreshes every 10s</div>
        </div>
        <table id="attacks-table" aria-live="polite">
          <thead><tr><th>Time</th><th>IP</th><th>Path</th><th>Method</th><th>Risk</th></tr></thead>
          <tbody><tr><td colspan="5">Loading…</td></tr></tbody>
        </table>
      </div>

      <script>
        async function render() {
          try {
            const res = await fetch('/api/attacks/recent');
            const attacks = await res.json();
            const tbody = document.querySelector('#attacks-table tbody');
            if (!attacks || attacks.length === 0) {
              tbody.innerHTML = '<tr><td colspan="5">No recent attacks</td></tr>';
              return;
            }
            tbody.innerHTML = attacks.slice(0,200).map(a => {
              const time = new Date(a.timestamp).toLocaleString();
              return `<tr>
                <td>${time}</td>
                <td>${a.source_ip}</td>
                <td>${a.path}</td>
                <td>${a.method}</td>
                <td>${a.risk_score}</td>
              </tr>`;
            }).join('');
          } catch(e) {
            document.querySelector('#attacks-table tbody').innerHTML = '<tr><td colspan="5">Error loading data</td></tr>';
            console.error(e);
          }
        }
        render(); setInterval(render, 10000);
      </script>
    </body>
    </html>
    """
    return html

@app.route('/page/stats')
def stats_page():
    html = """
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>Attack Statistics - Honeypot</title>
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <style>
        body{font-family:Arial,Helvetica,sans-serif;margin:20px;background:#f7f8fb}
        .container{max-width:900px;margin:0 auto;background:#fff;padding:20px;border-radius:6px}
        .row{display:flex;gap:20px;align-items:center}
        .stat{flex:1;padding:10px}
        .big{font-size:2rem;font-weight:700}
        .label{color:#666}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Attack Statistics (Last 24h)</h1>
        <div class="row">
          <div class="stat">
            <div class="label">Total recent</div>
            <div id="total" class="big">0</div>
          </div>
          <div style="flex:1">
            <canvas id="riskChart" width="400" height="200"></canvas>
          </div>
        </div>
        <h3>Raw JSON</h3>
        <pre id="raw" style="max-height:300px;overflow:auto;background:#f4f6f8;padding:10px"></pre>
      </div>

      <script>
        const ctx = document.getElementById('riskChart').getContext('2d');
        const chart = new Chart(ctx, {
          type: 'pie',
          data: { labels: ['high','medium','low'], datasets: [{ data: [0,0,0], backgroundColor:['#e63946','#ffb703','#a8dadc'] }]},
          options: { responsive:true }
        });

        async function loadStats() {
          try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            document.getElementById('total').textContent = data.total_recent || 0;
            const breakdown = data.risk_breakdown || {};
            const high = breakdown.high || 0;
            const medium = breakdown.medium || 0;
            const low = breakdown.low || 0;
            chart.data.datasets[0].data = [high, medium, low];
            chart.update();
            document.getElementById('raw').textContent = JSON.stringify(data, null, 2);
          } catch(e) {
            document.getElementById('raw').textContent = 'Error loading stats';
            console.error(e);
          }
        }

        loadStats(); setInterval(loadStats, 10000);
      </script>
    </body>
    </html>
    """
    return html

if __name__ == '__main__':
    # Initialize database
    if init_db():
        logger.info("Starting realtime tracker")
        port = int(os.environ.get('PORT', 8080))
        logger.info(f"Listening on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        logger.error("Failed to initialize database. Exiting.")