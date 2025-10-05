#!/bin/bash

# Smart City Honeypot Setup Script
# Author: Krishna
# Description: Automated setup for multi-protocol IoT honeypot system

set -e

echo "🍯 Smart City Honeypot Setup Starting..."
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root!"
        print_warning "Please run as regular user with sudo privileges"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    print_header "🔍 Checking System Requirements..."
    
    # Update package list
    sudo apt-get update -y
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed!"
        print_status "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker $USER
        rm get-docker.sh
        print_warning "Please log out and log back in for Docker group changes to take effect"
    else
        print_status "Docker is already installed ✓"
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed!"
        print_status "Installing Docker Compose..."
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
    else
        print_status "Docker Compose is already installed ✓"
    fi
    
    # Check if Python 3 is installed
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed!"
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv
    else
        print_status "Python 3 is already installed ✓"
    fi
    
    # Install additional tools
    sudo apt-get install -y sqlite3 curl wget
    
    # Check available disk space (need at least 5GB)
    available_space=$(df . | tail -1 | awk '{print $4}')
    if [ $available_space -lt 5242880 ]; then # 5GB in KB
        print_warning "Low disk space detected. Recommend at least 5GB free space"
    else
        print_status "Sufficient disk space available ✓"
    fi
}

# Create directory structure
create_directories() {
    print_header "📁 Creating Directory Structure..."
    
    # Create data directories
    mkdir -p data/{http_honeypot,cowrie,mosquitto,cameraobscura,riotpot,sip_honeypot,elasticsearch,kibana}
    mkdir -p logs config scripts
    
    # Create honeypot source directories
    mkdir -p http_honeypot CameraObscura riotpot sip_honeypot
    
    # Set proper permissions
    sudo chown -R $USER:$USER data/ || true
    chmod -R 755 data/ || true
    
    print_status "Directory structure created ✓"
}

# Setup Python virtual environment
setup_python_env() {
    print_header "🐍 Setting Up Python Environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_status "Virtual environment created ✓"
    fi
    
    source venv/bin/activate
    pip install --upgrade pip
    
    # Install required packages for CLI tools (FIXED: removed sqlite3)
    cat > requirements.txt << 'EOF'
flask==2.3.3
requests==2.31.0
scapy==2.5.0
colorama==0.4.6
tabulate==0.9.0
pyfiglet==0.8.post1
EOF
    
    pip install -r requirements.txt
    print_status "Python dependencies installed ✓"
}

# Create required honeypot files
create_honeypot_files() {
    print_header "📝 Creating Honeypot Files..."
    
    # Create http_honeypot/realtime_tracker.py if it doesn't exist
    if [ ! -f "http_honeypot/realtime_tracker.py" ]; then
        print_status "Creating realtime_tracker.py..."
        cat > http_honeypot/realtime_tracker.py << 'EOF'
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

@app.route('/', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE'])
@app.route('/<path:path>', methods=['GET','POST','PUT','DELETE'])
def catch_all(path):
    """Main honeypot endpoint"""
    client_ip = request.remote_addr
    
    # Log attack
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('''
            INSERT INTO attacks (timestamp, client_ip, path, method, risk_score)
            VALUES (?, ?, ?, ?, ?)
        ''', (time.time(), client_ip, request.path, request.method, 50))
        conn.commit()
        conn.close()
        logger.info(f"Attack logged: {client_ip} -> {request.method} {request.path}")
    except Exception as e:
        logger.error(f"Database insert failed: {e}")
    
    # Return response
    if request.method == 'GET' and 'text/html' in request.headers.get('Accept', ''):
        return """
        <html><head><title>Smart City Device</title></head>
        <body>
        <h1>Smart City Management Portal</h1>
        <p>Device Status: Online</p>
        <ul>
            <li><a href="/admin">Admin Panel</a></li>
            <li><a href="/config">Configuration</a></li>
            <li><a href="/dashboard">Dashboard</a></li>
        </ul>
        </body></html>
        """, 200
    
    return "Device OK", 200

@app.route('/api/attacks/recent')
def get_recent_attacks():
    """Get recent attacks"""
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
    except Exception as e:
        return jsonify([])

@app.route('/api/stats')
def get_stats():
    """Get attack statistics"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        since = time.time() - (24 * 3600)
        cursor.execute('SELECT COUNT(*) FROM attacks WHERE timestamp > ?', (since,))
        recent_count = cursor.fetchone()[0]
        
        return jsonify({'total_recent': recent_count})
    except Exception as e:
        return jsonify({'total_recent': 0})

@app.route('/dashboard')
def dashboard():
    """Simple dashboard"""
    return """
    <html>
    <head>
        <title>Honeypot Dashboard</title>
        <meta http-equiv="refresh" content="30">
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
            .stats { background: #e8f4fd; padding: 15px; border-radius: 5px; margin: 15px 0; }
            .attacks { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 15px 0; }
            h1 { color: #333; text-align: center; }
            .api-links { background: #d4edda; padding: 15px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🍯 Smart City Honeypot Dashboard</h1>
            
            <div class="stats">
                <h3>📊 System Status</h3>
                <p>✅ Honeypot is running and monitoring</p>
                <p>🔍 Capturing attacks in real-time</p>
                <p>⏰ Last updated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
            </div>
            
            <div class="attacks">
                <h3>🚨 Recent Activity</h3>
                <p>Check the API endpoints below for detailed attack data</p>
            </div>
            
            <div class="api-links">
                <h3>🔗 API Endpoints</h3>
                <ul>
                    <li><a href="/api/attacks/recent">Recent Attacks JSON</a></li>
                    <li><a href="/api/stats">Statistics JSON</a></li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """

if __name__ == '__main__':
    if init_db():
        logger.info("Starting honeypot on port 8080")
        app.run(host='0.0.0.0', port=8080, debug=False)
    else:
        logger.error("Failed to initialize database")
EOF
    fi
    
    # Create http_honeypot/requirements.txt
    cat > http_honeypot/requirements.txt << 'EOF'
flask==2.3.3
requests==2.31.0
EOF
    
    # Create http_honeypot/Dockerfile
    cat > http_honeypot/Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY realtime_tracker.py .
RUN mkdir -p /app/data

EXPOSE 8080

CMD ["python3", "realtime_tracker.py"]
EOF
    
    print_status "Honeypot files created ✓"
}

# Create configuration files
create_configs() {
    print_header "⚙️  Creating Configuration Files..."
    
    # Create Mosquitto config
    mkdir -p mosquitto/config
    cat > mosquitto/config/mosquitto.conf << 'EOF'
# Mosquitto Configuration for Honeypot
listener 1883
allow_anonymous true
log_dest stdout
log_type all
connection_messages true
EOF
    
    # Create Filebeat config
    mkdir -p filebeat
    cat > filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /data/*/attacks.log
    - /data/*/*.json
  fields:
    logtype: honeypot
  fields_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "honeypot-attacks-%{+yyyy.MM.dd}"

logging.level: info
logging.to_stderr: true
EOF
    
    print_status "Configuration files created ✓"
}

# Build and start containers
start_services() {
    print_header "🚀 Building and Starting Services..."
    
    # Check if docker daemon is running
    if ! sudo docker info >/dev/null 2>&1; then
        print_error "Docker daemon is not running!"
        print_status "Starting Docker daemon..."
        sudo systemctl start docker
        sudo systemctl enable docker
        sleep 5
    fi
    
    # Clean up any existing containers
    print_status "Cleaning up existing containers..."
    sudo docker-compose down 2>/dev/null || sudo docker compose down 2>/dev/null || true
    sudo docker system prune -f
    
    # Build and start services
    print_status "Building honeypot containers..."
    if sudo docker-compose up --build -d 2>/dev/null || sudo docker compose up --build -d; then
        print_status "All services started successfully ✓"
    else
        print_error "Failed to start some services!"
        print_status "Checking container status..."
        sudo docker-compose ps 2>/dev/null || sudo docker compose ps
        return 1
    fi
}

# Verify installation
verify_installation() {
    print_header "✅ Verifying Installation..."
    
    sleep 15 # Wait for services to start
    
    # Check container status
    print_status "Checking container status..."
    if sudo docker ps --format "table {{.Names}}\t{{.Status}}" | grep -q "http_honeypot"; then
        print_status "HTTP Honeypot container is running ✓"
    else
        print_warning "HTTP Honeypot container may not be ready yet"
    fi
    
    # Test HTTP honeypot
    for i in {1..5}; do
        if curl -s --connect-timeout 5 http://localhost:8080 >/dev/null 2>&1; then
            print_status "HTTP Honeypot is accessible ✓"
            break
        else
            if [ $i -eq 5 ]; then
                print_warning "HTTP Honeypot may not be ready yet"
            else
                sleep 5
            fi
        fi
    done
}

# Create management scripts
create_management_scripts() {
    print_header "🛠️  Creating Management Scripts..."
    
    # Determine which compose command to use
    COMPOSE_CMD="docker-compose"
    if ! command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker compose"
    fi
    
    # Create start script
    cat > start_honeypot.sh << EOF
#!/bin/bash
echo "🍯 Starting Smart City Honeypot..."
sudo $COMPOSE_CMD up -d
echo "✅ Honeypot started! Access dashboard at: http://localhost:8080/dashboard"
EOF
    
    # Create stop script
    cat > stop_honeypot.sh << EOF
#!/bin/bash
echo "🛑 Stopping Smart City Honeypot..."
sudo $COMPOSE_CMD down
echo "✅ Honeypot stopped!"
EOF
    
    # Create status script
    cat > status_honeypot.sh << EOF
#!/bin/bash
echo "📊 Smart City Honeypot Status:"
echo "=============================="
sudo $COMPOSE_CMD ps
echo ""
echo "🌐 Web Interfaces:"
echo "- HTTP Honeypot: http://localhost:8080"
echo "- Dashboard: http://localhost:8080/dashboard"
echo "- Kibana: http://localhost:5601"
echo "- Elasticsearch: http://localhost:9200"
EOF
    
    # Create logs script
    cat > view_logs.sh << EOF
#!/bin/bash
echo "📋 Recent Honeypot Logs:"
echo "========================"
if [ "\$1" = "follow" ]; then
    sudo $COMPOSE_CMD logs -f
else
    sudo $COMPOSE_CMD logs --tail=50
fi
EOF
    
    # Make scripts executable
    chmod +x *.sh
    
    print_status "Management scripts created ✓"
}

# Display success message and next steps
show_completion() {
    print_header "🎉 Installation Complete!"
    echo ""
    echo "Your Smart City Honeypot is now running!"
    echo ""
    echo -e "${GREEN}🌐 Web Interfaces:${NC}"
    echo "  • HTTP Honeypot:      http://localhost:8080"
    echo "  • Dashboard:          http://localhost:8080/dashboard"
    echo "  • Kibana Dashboard:   http://localhost:5601"
    echo "  • Elasticsearch:      http://localhost:9200"
    echo ""
    echo -e "${BLUE}🔧 Management Commands:${NC}"
    echo "  • Start:    ./start_honeypot.sh"
    echo "  • Stop:     ./stop_honeypot.sh"
    echo "  • Status:   ./status_honeypot.sh"
    echo "  • Logs:     ./view_logs.sh [follow]"
    echo ""
    echo -e "${YELLOW}📡 Exposed Ports:${NC}"
    echo "  • HTTP Honeypot:     8080"
    echo "  • SSH Honeypot:      2222"
    echo "  • MQTT:              1883"
    echo "  • SIP:               5060/udp"
    echo ""
    echo -e "${GREEN}✨ To test your honeypot:${NC}"
    echo "  curl http://localhost:8080/admin"
    echo "  curl http://localhost:8080/api/attacks/recent"
    echo ""
    echo -e "${RED}⚠️  Security Note:${NC}"
    echo "  This honeypot is designed for research/educational purposes."
    echo "  Ensure proper network isolation in production environments."
    echo ""
}

# Main execution
main() {
    print_header "🍯 Smart City IoT Honeypot Setup"
    echo "=================================="
    echo ""
    
    check_root
    check_requirements
    create_directories
    create_honeypot_files
    setup_python_env
    create_configs
    create_management_scripts
    start_services
    verify_installation
    show_completion
}

# Run main function
main "$@"