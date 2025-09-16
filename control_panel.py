from flask import Flask, render_template, request, redirect, url_for
import docker
import subprocess

app = Flask(__name__)
client = docker.from_env()

HONEYPOTS = [
    {"name": "cowrie", "ports": [2222]},
    {"name": "http_honeypot", "ports": [8080]},
    {"name": "mosquitto", "ports": [1883]},
    {"name": "cameraobscura", "ports": [554, 8081]},
    {"name": "riotpot", "ports": [7, 22, 23, 80, 502, 1883, 5683]},  # Add all RiotPot ports
    {"name": "sip_honeypot", "ports": [5060]},
]

@app.route('/')
def index():
    containers = {c.name: c.status for c in client.containers.list(all=True)}
    return render_template('index.html', honeypots=HONEYPOTS, containers=containers)

@app.route('/control/<name>/<action>')
def control(name, action):
    container = client.containers.get(name)
    if action == "start":
        container.start()
    elif action == "stop":
        container.stop()
    elif action == "restart":
        container.restart()
    return redirect(url_for('index'))

@app.route('/test/<name>')
def test(name):
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get(name)
        logs = container.logs(tail=50).decode()
        return f"<pre>{logs}</pre><br><a href='/'>Back</a>"
    except Exception as e:
        return f"<pre>Error: {e}</pre><br><a href='/'>Back</a>"

# Add endpoints for config editing, testing, logs, etc.

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)