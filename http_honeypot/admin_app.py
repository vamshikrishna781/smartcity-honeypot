"""
Admin-only management UI for realtime_tracker.
- Binds to localhost by default (127.0.0.1)
- Requires ADMIN_TOKEN for remote access; localhost allowed without token
- Provides HTML pages for: Recent attacks, Alerts (files), Health
"""
import os
import json
from flask import Flask, request, jsonify, abort, render_template_string, send_file, Response, stream_with_context
import sqlite3
import time

app = Flask(__name__)

# Data paths (match realtime_tracker defaults)
DEFAULT_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'http_honeypot'))
DATA_DIR = os.environ.get('DATA_DIR', DEFAULT_DATA_DIR)
DB_PATH = os.path.join(DATA_DIR, "attacks.db")
EVIDENCE_DIR = os.path.join(DATA_DIR, "evidence")

ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN')  # set to require token for non-local requests

def is_local_request():
    return request.remote_addr in ('127.0.0.1', '::1')

def require_admin():
    if is_local_request():
        return True
    token = request.headers.get('X-Admin-Token') or request.args.get('token')
    return bool(ADMIN_TOKEN and token and token == ADMIN_TOKEN)

def admin_protect(fn):
    def wrapper(*a, **kw):
        if not require_admin():
            return abort(401)
        return fn(*a, **kw)
    wrapper.__name__ = fn.__name__
    return wrapper

def query_db(query, args=(), one=False):
    if not os.path.exists(DB_PATH):
        return [] if not one else None
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(query, args)
    rows = cur.fetchall()
    conn.close()
    return (rows[0] if rows else None) if one else rows

# --- HTML pages -----------------------------------------------------------
@app.route('/admin')
@admin_protect
def admin_index():
    html = """
    <html><head><title>Honeypot Admin</title>
    <style>body{font-family:Arial;margin:20px} a{display:block;margin:8px 0}</style>
    </head><body>
      <h1>🍯 Honeypot Admin</h1>
      <a href="/admin/attacks">Recent attacks (UI)</a>
      <a href="/admin/alerts">Alerts & Evidence (UI)</a>
      <a href="/admin/health">Health (UI)</a>
      <p>Bound to localhost by default. Set ADMIN_TOKEN for remote access.</p>
    </body></html>
    """
    return html

@app.route('/admin/attacks')
@admin_protect
def admin_attacks_page():
    html = """
    <!doctype html><html><head><meta charset="utf-8"><title>Recent Attacks</title>
    <style>body{font-family:Arial;margin:20px} table{border-collapse:collapse;width:100%}
    th,td{padding:8px;border-bottom:1px solid #eee;text-align:left} a.back{display:inline-block;margin-bottom:12px}</style>
    </head><body>
      <a class="back" href="/admin">← Back to Admin</a>
      <h1>Recent Attacks</h1>
      <table id="tbl"><thead><tr><th>Time</th><th>IP</th><th>Path</th><th>Method</th><th>Risk</th></tr></thead>
      <tbody><tr><td colspan="5">Loading…</td></tr></tbody></table>
      <script>
        const tbody = document.querySelector('#tbl tbody');
        // load recent snapshot once
        fetch('/admin/api/attacks').then(r=>r.json()).then(data=>{
          tbody.innerHTML = data.map(a=>`<tr><td>${new Date(a.timestamp*1000).toLocaleString()}</td><td>${a.source_ip}</td><td>${a.path}</td><td>${a.method}</td><td>${a.risk_score}</td></tr>`).join('');
        });
        // SSE real-time updates
        const s = new EventSource('/admin/stream/attacks');
        s.onmessage = e=>{
          try{
            const a = JSON.parse(e.data);
            const row = document.createElement('tr');
            row.innerHTML = `<td>${new Date(a.timestamp*1000).toLocaleString()}</td><td>${a.source_ip}</td><td>${a.path}</td><td>${a.method}</td><td>${a.risk_score}</td>`;
            tbody.insertBefore(row, tbody.firstChild);
          }catch(err){ console.error(err) }
        };
      </script>
    </body></html>
    """
    return html

@app.route('/admin/alerts')
@admin_protect
def admin_alerts_page():
    html = """
    <!doctype html><html><head><meta charset="utf-8"><title>Alerts</title>
    <style>body{font-family:Arial;margin:20px} ul{list-style:none;padding:0} li{margin:6px 0}
    pre{background:#f7f7f7;padding:10px;max-height:300px;overflow:auto} a.back{display:inline-block;margin-bottom:12px}</style></head><body>
      <a class="back" href="/admin">← Back to Admin</a>
      <h1>Alerts & Evidence</h1>
      <div id="list">Loading…</div>
      <div id="viewer" style="margin-top:12px"></div>
      <script>
        async function load(){
          const res = await fetch('/admin/api/alerts');
          const files = await res.json();
          const list = document.getElementById('list');
          if(!files.length){ list.innerHTML='<div>No alert files</div>'; return; }
          list.innerHTML = '<ul>'+files.map(f=>{
            return `<li><a href="#" data-name="${f.name}">${f.name}</a> (${new Date(f.mtime*1000).toLocaleString()}, ${f.size} bytes)</li>`;
          }).join('')+'</ul>';
          document.querySelectorAll('#list a').forEach(a=>{
            a.onclick = async e=>{
              e.preventDefault();
              const name = a.getAttribute('data-name');
              const vr = document.getElementById('viewer');
              vr.innerHTML = 'Loading...';
              const r = await fetch('/admin/alert/'+encodeURIComponent(name));
              if(r.ok){ vr.innerHTML = '<pre>'+await r.text()+'</pre>'; } else { vr.innerHTML='Error'; }
            };
          });
        }
        load(); setInterval(load,10000);
      </script>
    </body></html>
    """
    return html

@app.route('/admin/health')
@admin_protect
def admin_health_page():
    # get basic health info
    db_exists = os.path.exists(DB_PATH)
    files = []
    if os.path.isdir(EVIDENCE_DIR):
        for fn in sorted(os.listdir(EVIDENCE_DIR), reverse=True)[:20]:
            p = os.path.join(EVIDENCE_DIR, fn)
            files.append({'name': fn, 'mtime': os.path.getmtime(p), 'size': os.path.getsize(p)})
    html = f"""
    <!doctype html><html><head><meta charset="utf-8"><title>Health</title>
    <style>body{{font-family:Arial;margin:20px}} pre{{background:#f7f7f7;padding:10px}} a.back{{display:inline-block;margin-bottom:12px}}</style></head><body>
      <a class="back" href="/admin">← Back to Admin</a>
      <h1>Health</h1>
      <p>DB exists: {db_exists}</p>
      <p>DB path: {DB_PATH}</p>
      <h3>Recent evidence files</h3>
      <pre>{json.dumps(files, indent=2)}</pre>
    </body></html>
    """
    return html

# --- JSON endpoints used by UI -------------------------------------------
@app.route('/admin/api/attacks')
@admin_protect
def admin_api_attacks():
    rows = query_db('SELECT timestamp, client_ip, path, method, risk_score FROM attacks ORDER BY timestamp DESC LIMIT 500')
    out = []
    for r in rows:
        out.append({
            'timestamp': r[0],
            'source_ip': r[1],
            'path': r[2],
            'method': r[3],
            'risk_score': r[4]
        })
    return jsonify(out)

@app.route('/admin/api/alerts')
@admin_protect
def admin_api_alerts():
    files = []
    if os.path.isdir(EVIDENCE_DIR):
        for fn in sorted(os.listdir(EVIDENCE_DIR), reverse=True):
            path = os.path.join(EVIDENCE_DIR, fn)
            if not os.path.isfile(path):
                continue
            files.append({'name': fn, 'mtime': os.path.getmtime(path), 'size': os.path.getsize(path)})
    return jsonify(files)

@app.route('/admin/alert/<path:name>')
@admin_protect
def admin_alert_file(name):
    # protect against path traversal
    safe_name = os.path.basename(name)
    path = os.path.join(EVIDENCE_DIR, safe_name)
    if not os.path.isfile(path):
        return abort(404)
    return send_file(path, mimetype='application/json', as_attachment=False)

# --- helper to yield new attacks via SSE ---------------------------------
@app.route('/admin/stream/attacks')
@admin_protect
def stream_attacks():
    def gen():
        last_id = 0
        while True:
            try:
                if not os.path.exists(DB_PATH):
                    time.sleep(1)
                    continue
                conn = sqlite3.connect(DB_PATH)
                cur = conn.cursor()
                cur.execute("SELECT rowid, timestamp, client_ip, path, method, risk_score FROM attacks WHERE rowid > ? ORDER BY rowid ASC", (last_id,))
                rows = cur.fetchall()
                conn.close()
                for r in rows:
                    last_id = r[0]
                    ev = {
                        "rowid": r[0],
                        "timestamp": int(r[1]),
                        "source_ip": r[2],
                        "path": r[3],
                        "method": r[4],
                        "risk_score": r[5]
                    }
                    yield f"data: {json.dumps(ev)}\n\n"
                time.sleep(1)
            except GeneratorExit:
                break
            except Exception:
                time.sleep(1)
    return Response(stream_with_context(gen()), mimetype="text/event-stream")

# --- run ------------------------------------------------------------------
if __name__ == '__main__':
    host = os.environ.get('ADMIN_HOST', '127.0.0.1')
    port = int(os.environ.get('ADMIN_PORT', 5000))
    print(f"Admin UI listening on {host}:{port} (local only). Set ADMIN_TOKEN to require token for remote access.")
    app.run(host=host, port=port, debug=False)