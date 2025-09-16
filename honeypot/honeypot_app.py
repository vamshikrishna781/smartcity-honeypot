import os, hashlib
from datetime import datetime
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)
DATA_DIR = "/app/data"
LOGFILE = os.path.join(DATA_DIR, "requests.log")
os.makedirs(DATA_DIR, exist_ok=True)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_write_payload(payload_bytes, prefix="payload"):
    t = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    filename = f"{prefix}_{t}.bin"
    path = os.path.join(DATA_DIR, filename)
    with open(path, "wb") as f:
        f.write(payload_bytes)
    return filename, sha256_file(path)

def log_entry(remote, method, path, headers, body_filename=None, body_hash=None):
    ts = datetime.utcnow().isoformat()
    entry = {
        "ts": ts,
        "remote": remote,
        "method": method,
        "path": path,
        "headers": dict(headers),
        "body_filename": body_filename,
        "body_hash": body_hash
    }
    with open(LOGFILE, "a") as f:
        f.write(repr(entry) + "\n")
    print("LOG:", entry)

@app.route("/", methods=["GET"])
def index():
    # return """
    # <html><body>
    # <h3>IP Camera</h3>
    # <form action="/login" method="post">
    #   Username: <input name="user"><br>
    #   Password: <input name="pass" type="password"><br>
    #   <input type="submit" value="Login">
    # </form>
    # </body></html>
    # """
            return """
            <html><head>
            <title>IP Camera Login</title>
            <style>
                body { font-family: Arial, sans-serif; background: #f2f2f2; }
                .login-box { background: #fff; padding: 24px; margin: 80px auto; width: 320px; border-radius: 8px; box-shadow: 0 2px 8px #aaa; }
                .login-title { font-size: 1.3em; margin-bottom: 16px; }
                .error-msg { color: #b00; background: #fee; padding: 8px; border-radius: 4px; margin-bottom: 12px; display: none; }
                label { display: block; margin-bottom: 6px; }
                input[type=text], input[type=password] { width: 100%; padding: 8px; margin-bottom: 12px; border: 1px solid #ccc; border-radius: 4px; }
                input[type=submit] { width: 100%; padding: 10px; background: #1976d2; color: #fff; border: none; border-radius: 4px; font-size: 1em; cursor: pointer; }
                input[type=submit]:hover { background: #1565c0; }
            </style>
            </head><body>
            <div class="login-box">
                <div class="login-title">IP Camera Login</div>
                <form id="loginForm" action="/login" method="post" autocomplete="off">
                    <div id="errorMsg" class="error-msg"></div>
                    <label for="user">Username:</label>
                    <input name="user" id="user" type="text" autofocus required>
                    <label for="pass">Password:</label>
                    <input name="pass" id="pass" type="password" required>
                    <input type="submit" value="Login">
                </form>
            </div>
            <script>
                document.getElementById('loginForm').onsubmit = function(e) {
                    var user = document.getElementById('user').value.trim();
                    var pass = document.getElementById('pass').value.trim();
                    var errorMsg = document.getElementById('errorMsg');
                    if (!user || !pass) {
                        errorMsg.textContent = 'Please enter both username and password.';
                        errorMsg.style.display = 'block';
                        e.preventDefault();
                        return false;
                    }
                    errorMsg.style.display = 'none';
                };
            </script>
            </body></html>
            """

@app.route("/login", methods=["POST"])
def login():
    remote = request.remote_addr
    form = request.form.to_dict()
    body = ("|".join([f"{k}={v}" for k, v in form.items()])).encode("utf-8")
    filename, h = safe_write_payload(body, prefix="login")
    log_entry(remote, "POST", "/login", request.headers, filename, h)
    user = form.get("user", "").strip()
    passwd = form.get("pass", "").strip()
    if not user or not passwd:
        return (
            "<html><head><title>IP Camera Login</title></head><body>"
            "<div style='margin:80px auto;width:320px;background:#fff;padding:24px;border-radius:8px;box-shadow:0 2px 8px #aaa;'>"
            "<div style='color:#b00;background:#fee;padding:8px;border-radius:4px;margin-bottom:12px;'>Please enter both username and password.</div>"
            "<a href='/'>Back to Login</a>"
            "</div></body></html>"
        ), 400
    return (
        "<html><head><title>IP Camera Login</title></head><body>"
        "<div style='margin:80px auto;width:320px;background:#fff;padding:24px;border-radius:8px;box-shadow:0 2px 8px #aaa;'>"
        "<div style='color:#b00;background:#fee;padding:8px;border-radius:4px;margin-bottom:12px;'>Incorrect username or password.</div>"
        "<a href='/'>Back to Login</a>"
        "</div></body></html>"
    ), 401

@app.route("/video", methods=["GET","POST"])
def video():
    remote = request.remote_addr
    if request.method == "POST":
        payload = request.get_data() or b""
        filename, h = safe_write_payload(payload, prefix="video")
        log_entry(remote, "POST", "/video", request.headers, filename, h)
        return "OK", 200
    else:
        log_entry(remote, "GET", "/video", request.headers, None, None)
        img_path = os.path.join("/app/templates","placeholder.jpg")
        if os.path.exists(img_path):
            return send_file(img_path, mimetype="image/jpeg")
        return "RTSP Stream Placeholder", 200

@app.route("/<path:anypath>", methods=["GET","POST","PUT","DELETE","OPTIONS"])
def catchall(anypath):
    remote = request.remote_addr
    body = request.get_data() or b""
    filename, h = None, None
    if body:
        filename, h = safe_write_payload(body, prefix=anypath.replace("/","_"))
    log_entry(remote, request.method, f"/{anypath}", request.headers, filename, h)
    return "Not Found", 404

if __name__ == "__main__":
    print("Starting honeypot HTTP server on :5000")
    app.run(host="0.0.0.0", port=5000)

