from flask import Flask, request, jsonify, render_template_string
import json
import os
import time
from datetime import datetime

app = Flask(__name__)

# Create data directory
DATA_DIR = "/app/data"
os.makedirs(DATA_DIR, exist_ok=True)

def log_request(request_data):
    """Log HTTP requests to file"""
    timestamp = int(time.time())
    filename = os.path.join(DATA_DIR, f"http_attack_{timestamp}.json")
    
    with open(filename, 'w') as f:
        json.dump(request_data, f, indent=2, default=str)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
def catch_all(path):
    """Catch all HTTP requests"""
    
    # Collect request data
    request_data = {
        'timestamp': datetime.now().isoformat(),
        'client_ip': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
        'method': request.method,
        'path': request.path,
        'full_path': request.full_path,
        'headers': dict(request.headers),
        'args': request.args.to_dict(),
        'form': request.form.to_dict(),
        'json': request.get_json(silent=True),
        'data': request.get_data(as_text=True)[:1000],  # Limit data size
        'user_agent': request.headers.get('User-Agent', ''),
        'referer': request.headers.get('Referer', ''),
    }
    
    # Log the request
    log_request(request_data)
    
    print(f"🚨 HTTP Attack: {request_data['client_ip']} -> {request_data['method']} {request_data['path']}")
    
    # Return realistic responses based on path
    if request.method == 'GET' and 'text/html' in request.headers.get('Accept', ''):
        # Return HTML page for browsers
        if path in ['admin', 'login', 'wp-admin', 'administrator']:
            return """
            <html>
            <head><title>Admin Login</title></head>
            <body>
                <h2>Administrator Login</h2>
                <form method="post">
                    <input type="text" name="username" placeholder="Username"><br><br>
                    <input type="password" name="password" placeholder="Password"><br><br>
                    <input type="submit" value="Login">
                </form>
            </body>
            </html>
            """, 200
        
        elif path in ['config.php', 'wp-config.php']:
            return "<?php\n// Configuration file\n$db_host = 'localhost';\n$db_user = 'admin';\n", 200
        
        else:
            return """
            <html>
            <head><title>Smart City IoT Device</title></head>
            <body>
                <h1>Smart City Management System</h1>
                <p>Device ID: SC-IOT-001</p>
                <p>Status: Online</p>
                <p>Last Update: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                <ul>
                    <li><a href="/admin">Admin Panel</a></li>
                    <li><a href="/config">Configuration</a></li>
                    <li><a href="/status">Device Status</a></li>
                </ul>
            </body>
            </html>
            """, 200
    
    # API-like responses
    elif path == 'api/status':
        return jsonify({
            'status': 'online',
            'device_id': 'SC-IOT-001',
            'timestamp': datetime.now().isoformat(),
            'sensors': {
                'temperature': 23.5,
                'humidity': 45.2,
                'traffic_count': 1247
            }
        })
    
    elif path.startswith('api/'):
        return jsonify({'error': 'Unauthorized', 'code': 401}), 401
    
    else:
        # Default response
        return "Smart City Device - Status: OK", 200

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    print("🍯 Starting HTTP Honeypot on port 8080...")
    app.run(host='0.0.0.0', port=8080, debug=False)