# 🍯 Smart City IoT Honeypot System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![Real-time Monitoring](https://img.shields.io/badge/Monitoring-Real--time-green)](https://github.com/krishna/smartcity-honeypot)

A comprehensive, multi-protocol honeypot system designed to detect, capture, and analyze attacks targeting smart city IoT infrastructure. This system simulates various IoT devices and services commonly deployed in smart city environments.

![Smart City Honeypot Architecture](https://via.placeholder.com/800x400/1e3a8a/ffffff?text=Smart+City+Honeypot+System)

## 🎯 Overview

This honeypot system provides real-time monitoring and analysis of attacks against smart city infrastructure, including:

- **HTTP/HTTPS Services** - Web interfaces, APIs, management portals
- **SSH Services** - Remote access attempts (via Cowrie)
- **MQTT** - IoT device messaging protocols
- **SIP/VoIP** - Communication system attacks
- **RTSP** - Camera and video stream exploitation
- **Industrial Protocols** - Modbus, CoAP for SCADA/ICS systems

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Smart City Honeypot System                   │
├─────────────────────────────────────────────────────────────────┤
│                        Attack Surface                          │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────┤
│ HTTP (8080) │ SSH (2222)  │ MQTT (1883) │ SIP (5060)  │ More... │
├─────────────┴─────────────┴─────────────┴─────────────┴─────────┤
│                   Real-time Processing                         │
├─────────────────────────────────────────────────────────────────┤
│ Attack Logger │ Risk Scoring │ GeoIP Analysis │ WebRTC Probe  │
├─────────────────────────────────────────────────────────────────┤
│                      Data Storage                              │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────┤
│ SQLite DB   │ JSON Logs   │Elasticsearch│   Kibana    │ Files   │
├─────────────┴─────────────┴─────────────┴─────────────┴─────────┤
│                    Management & Monitoring                     │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────┤
│ Web Dashboard│ CLI Panel  │ REST APIs   │ Real-time   │ Alerts  │
│              │            │             │ Streaming   │         │
└─────────────┴─────────────┴─────────────┴─────────────┴─────────┘
```

## ✨ Key Features

### 🔍 **Advanced Attack Detection**
- **Real-time Monitoring** - Live attack capture and analysis
- **Risk Scoring** - Intelligent threat assessment (0-100 scale)
- **Geographic Intelligence** - IP geolocation and country-based risk
- **Network Fingerprinting** - TOR/VPN/Proxy detection
- **WebRTC Probing** - Client IP discovery and browser fingerprinting
- **Behavioral Analysis** - Attack pattern recognition

### 📊 **Multi-Protocol Honeypots**
| Protocol | Port | Service | Description |
|----------|------|---------|-------------|
| HTTP/HTTPS | 8080 | Web Services | Admin panels, APIs, IoT dashboards |
| SSH | 2222 | Remote Access | Shell access attempts (Cowrie) |
| MQTT | 1883 | IoT Messaging | Device communication protocol |
| SIP | 5060/UDP | VoIP | Communication system attacks |
| RTSP | 554 | Video Streams | Camera exploitation attempts |
| Modbus | 502 | Industrial | SCADA/ICS protocol attacks |
| CoAP | 5683/UDP | IoT Protocol | Constrained device communication |

### 📈 **Analytics & Visualization**
- **Real-time Dashboard** - Live attack monitoring with auto-refresh
- **Elasticsearch Integration** - Full-text search and data indexing
- **Kibana Dashboards** - Advanced analytics and visualization
- **RESTful APIs** - Programmatic access to attack data
- **CLI Management** - Command-line interface for system control

### 🛡️ **Security Intelligence**
- **Threat Attribution** - Source IP analysis and reputation
- **Payload Analysis** - Attack vector classification
- **Time-series Analysis** - Attack frequency and pattern trends
- **Alert System** - High-risk attack notifications
- **Evidence Collection** - Comprehensive attack artifact storage

## 🚀 Quick Start

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+ recommended)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 10GB+ available disk space
- **Network**: Internet connection for threat intelligence
- **Privileges**: User account with sudo access

### One-Command Installation

```bash
# Clone the repository
git clone https://github.com/vamshikrishna781/smartcity-honeypot.git
cd smartcity-honeypot

# Run automated setup
chmod +x setup.sh
./setup.sh
```

The setup script will automatically:
- ✅ Install Docker and Docker Compose
- ✅ Create directory structure
- ✅ Set up Python virtual environment
- ✅ Build honeypot containers
- ✅ Configure services
- ✅ Start monitoring system
- ✅ Create management scripts

### 🚨 Installation Recovery

**If setup fails with sqlite3 error:**

```bash
# Activate the virtual environment
source venv/bin/activate

# Fix the requirements file (sqlite3 is built into Python)
cat > requirements.txt << 'EOF'
flask==2.3.3
requests==2.31.0
scapy==2.5.0
colorama==0.4.6
tabulate==0.9.0
pyfiglet==0.8.post1
EOF

# Install the corrected dependencies
pip install -r requirements.txt

# Continue with the automated setup
./setup.sh
```

**Alternative: Start fresh with fixed setup.sh:**

```bash
# Download the latest fixed setup script
wget https://raw.githubusercontent.com/vamshikrishna781/smartcity-honeypot/main/setup.sh
chmod +x setup.sh
./setup.sh
```

### Manual Installation

If you prefer manual setup:

```bash
# Install dependencies
sudo apt update
sudo apt install docker.io docker-compose python3-pip python3-venv

# Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create directories
mkdir -p data/{http_honeypot,cowrie,mosquitto,elasticsearch,kibana}

# Start services
sudo docker-compose up -d
```

## 🎮 System Management

### Quick Commands

The setup script creates convenient management scripts:

```bash
# Start the honeypot system
./start_honeypot.sh

# Stop the honeypot system
./stop_honeypot.sh

# Check system status
./status_honeypot.sh

# View logs (real-time)
./view_logs.sh follow

# View recent logs
./view_logs.sh
```

### CLI Management Interface

```bash
# Activate Python environment
source venv/bin/activate

# Launch interactive CLI
python cli_panel.py

# Available CLI commands:
# - View container status
# - Monitor real-time attacks
# - Access log files
# - Generate reports
# - System health checks
```

### Docker Commands

```bash
# View running containers
sudo docker ps

# Check specific service logs
sudo docker logs -f http_honeypot
sudo docker logs -f cowrie
sudo docker logs -f elasticsearch

# Restart specific service
sudo docker-compose restart http_honeypot

# Rebuild and restart all services
sudo docker-compose down
sudo docker-compose up --build -d
```

## 🌐 Web Interfaces

### Primary Interfaces

| Service | URL | Description | Credentials |
|---------|-----|-------------|-------------|
| **HTTP Honeypot** | http://localhost:8080 | Main honeypot landing page | N/A |
| **Real-time Dashboard** | http://localhost:8080/dashboard | Live attack monitoring | N/A |
| **Kibana Analytics** | http://localhost:5601 | Advanced data visualization | None required |
| **Elasticsearch API** | http://localhost:9200 | Direct database access | None required |

### API Endpoints

```bash
# Recent attacks (JSON)
curl http://localhost:8080/api/attacks/recent

# Attack statistics
curl http://localhost:8080/api/stats

# System health check
curl http://localhost:8080/health

# Real-time attack feed
curl http://localhost:8080/api/attacks/live
```

### Dashboard Features

The real-time dashboard (http://localhost:8080/dashboard) provides:

- **Live Attack Feed** - Real-time display of incoming attacks
- **Geographic Visualization** - World map showing attack sources
- **Risk Assessment** - Color-coded threat levels
- **Protocol Statistics** - Breakdown by attack type
- **Time-series Charts** - Attack frequency over time
- **Top Attackers** - Most active source IPs

## 🧪 Testing Your Honeypot

### Generate Test Traffic

```bash
# HTTP-based attacks
curl http://localhost:8080/admin
curl http://localhost:8080/wp-admin/
curl http://localhost:8080/config.php
curl http://localhost:8080/../../../etc/passwd
curl "http://localhost:8080/search?q=<script>alert('xss')</script>"

# Advanced HTTP attacks
curl -H "User-Agent: sqlmap/1.0" http://localhost:8080/login
curl -X POST -d "username=admin&password=admin" http://localhost:8080/admin
curl -H "X-Forwarded-For: 192.168.1.1" http://localhost:8080/

# SSH honeypot testing
ssh root@localhost -p 2222
ssh admin@localhost -p 2222

# MQTT testing (requires mosquitto-clients)
mosquitto_pub -h localhost -p 1883 -t "test/topic" -m "malicious_payload"
mosquitto_sub -h localhost -p 1883 -t "#"
```

### Verify Attack Capture

```bash
# Check real-time logs
sudo docker logs -f http_honeypot

# Query attack database
sudo docker exec http_honeypot sqlite3 /app/data/attacks.db \
"SELECT datetime(timestamp, 'unixepoch'), client_ip, path, method, risk_score 
FROM attacks ORDER BY timestamp DESC LIMIT 10;"

# View attack files
ls -la data/http_honeypot/
cat data/http_honeypot/evidence/*.json

# Check API response
curl -s http://localhost:8080/api/attacks/recent | jq '.[0:5]'
```

## 📊 Data Analysis

### Attack Data Structure

Each attack is stored with comprehensive metadata:

```json
{
  "timestamp": "2024-10-05T14:30:25.123Z",
  "client_ip": "192.168.1.100",
  "path": "/admin/login.php",
  "method": "POST",
  "headers": {
    "User-Agent": "curl/7.68.0",
    "Accept": "*/*"
  },
  "risk_score": 75,
  "geo_info": {
    "country": "United States",
    "city": "New York",
    "org": "Example ISP"
  },
  "is_tor": false,
  "is_vpn": true,
  "payload": "username=admin&password=password123"
}
```

### Risk Scoring Algorithm

The system uses intelligent risk scoring (0-100):

- **High Risk (70-100)**: Known attack patterns, suspicious user agents, TOR/VPN usage
- **Medium Risk (40-69)**: Unusual requests, geographic anomalies, rapid requests
- **Low Risk (0-39)**: Normal browsing patterns, legitimate-looking requests

### Elasticsearch Queries

```bash
# Search for high-risk attacks
curl -X GET "localhost:9200/honeypot-attacks-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "risk_score": { "gte": 70 }
    }
  }
}'

# Geographic attack distribution
curl -X GET "localhost:9200/honeypot-attacks-*/_search" -H 'Content-Type: application/json' -d'
{
  "aggs": {
    "countries": {
      "terms": {
        "field": "geo_info.country.keyword"
      }
    }
  }
}'
```

## 📁 Directory Structure

```
smartcity-honeypot/
├── 📄 setup.sh                     # Automated installation script
├── 📄 docker-compose.yml           # Container orchestration
├── 📄 README.md                    # This documentation
├── 📄 requirements.txt             # Python dependencies
├── 📄 cli_panel.py                 # Management CLI interface
├── 📁 data/                        # Attack data storage
│   ├── 📁 http_honeypot/           # HTTP attack logs & database
│   ├── 📁 cowrie/                  # SSH attack logs
│   ├── 📁 mosquitto/               # MQTT logs
│   ├── 📁 elasticsearch/           # Search index data
│   └── 📁 kibana/                  # Dashboard configurations
├── 📁 http_honeypot/               # HTTP honeypot source
│   ├── 📄 realtime_tracker.py     # Main honeypot application
│   ├── 📄 Dockerfile              # Container build instructions
│   └── 📄 requirements.txt        # Python dependencies
├── 📁 scripts/                     # Utility scripts
│   ├── 📄 network_fingerprint.py  # Network analysis tools
│   ├── 📄 realtime_dashboard.py   # Dashboard utilities
│   └── 📄 start_honeypot.sh       # Quick start script
├── 📁 config/                      # Configuration files
│   ├── 📁 mosquitto/               # MQTT broker config
│   └── 📁 filebeat/                # Log shipping config
└── 📁 logs/                        # System logs
```

## ⚙️ Configuration

### Environment Variables

```bash
# Docker environment
export COMPOSE_PROJECT_NAME=smartcity-honeypot
export DOCKER_BUILDKIT=1

# Database settings
export DB_PATH=/app/data/attacks.db
export LOG_LEVEL=INFO

# Network settings
export HONEYPOT_NETWORK=172.20.0.0/16
export HTTP_PORT=8080
export SSH_PORT=2222
export MQTT_PORT=1883
```

### Custom Configuration

#### Modify Ports

Edit `docker-compose.yml` to change exposed ports:

```yaml
services:
  http_honeypot:
    ports:
      - "8080:8080"  # Change to "9090:8080" for port 9090
```

#### Adjust Risk Scoring

Modify the risk scoring algorithm in `http_honeypot/realtime_tracker.py`:

```python
def calculate_risk_score(geo_info, is_tor, is_vpn, headers):
    score = 0
    
    # Custom risk factors
    if is_tor:
        score += 40  # Adjust TOR penalty
    if is_vpn:
        score += 25  # Adjust VPN penalty
    
    # Add custom logic here
    return min(score, 100)
```

#### Database Configuration

To use external databases, modify the connection settings:

```python
# In realtime_tracker.py
DB_PATH = os.path.join(DATA_DIR, "attacks.db")  # SQLite
# Or use PostgreSQL/MySQL for production
```

## 🔧 Troubleshooting

### Common Issues

#### Setup Script Fails with sqlite3 Error

If you see `ERROR: No matching distribution found for sqlite3`:

```bash
# The sqlite3 module is built into Python, not a pip package
# Fix the requirements file and continue:

source venv/bin/activate

# Remove sqlite3 from requirements
cat > requirements.txt << 'EOF'
flask==2.3.3
requests==2.31.0
scapy==2.5.0
colorama==0.4.6
tabulate==0.9.0
pyfiglet==0.8.post1
EOF

# Install corrected dependencies
pip install -r requirements.txt

# Continue with setup
./setup.sh
```

#### Containers Won't Start

```bash
# Check Docker daemon
sudo systemctl status docker
sudo systemctl start docker

# Check for port conflicts
sudo netstat -tulpn | grep :8080

# Review logs
sudo docker-compose logs
```

#### Database Connection Errors

```bash
# Check file permissions
sudo chown -R $USER:$USER data/
ls -la data/http_honeypot/

# Reset database
sudo rm data/http_honeypot/attacks.db
sudo docker-compose restart http_honeypot
```

#### Memory Issues

```bash
# Check system resources
free -h
df -h

# Optimize Elasticsearch memory
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Limit container memory in docker-compose.yml
services:
  elasticsearch:
    mem_limit: 1g
```

#### Network Connectivity

```bash
# Test internal container networking
sudo docker exec http_honeypot ping elasticsearch

# Check firewall rules
sudo ufw status
sudo iptables -L

# Verify DNS resolution
sudo docker exec http_honeypot nslookup google.com
```

### Performance Optimization

#### For High-Traffic Environments

```bash
# Increase file descriptor limits
echo "fs.file-max = 65536" | sudo tee -a /etc/sysctl.conf

# Optimize Docker logging
# Edit /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

#### Database Optimization

```sql
-- SQLite optimization queries
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=1000000;
PRAGMA temp_store=memory;
```

## 🛡️ Security Considerations

### Network Isolation

```bash
# Recommended firewall configuration
sudo ufw deny 22    # Disable SSH on standard port
sudo ufw allow 2222 # Allow SSH honeypot
sudo ufw allow 8080 # Allow HTTP honeypot
sudo ufw allow 1883 # Allow MQTT

# Block direct access to management interfaces
sudo ufw deny 9200  # Elasticsearch
sudo ufw deny 5601  # Kibana

# Enable logging
sudo ufw logging on
```

### Data Protection

- **Sensitive Data**: Attack logs may contain sensitive information
- **Log Rotation**: Implement automated log rotation to manage disk space
- **Backup Strategy**: Regular backups of attack data and configurations
- **Access Control**: Restrict access to honeypot data and management interfaces

```bash
# Setup log rotation
sudo tee /etc/logrotate.d/honeypot << EOF
/path/to/smartcity-honeypot/data/*/attacks.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

### Legal and Ethical Considerations

⚠️ **Important Legal Notice**:

- **Authorization Required**: Only deploy on networks you own or have explicit permission to monitor
- **Data Privacy**: Ensure compliance with local privacy laws (GDPR, CCPA, etc.)
- **Disclosure**: Consider disclosure requirements for monitoring activities
- **Incident Response**: Have procedures for handling discovered threats

### Production Deployment

For production environments:

```bash
# Use SSL/TLS certificates
# Implement proper authentication
# Set up centralized logging
# Configure monitoring alerts
# Establish incident response procedures
```

## 📈 Advanced Features

### Custom Honeypots

Add new honeypot services by creating additional containers:

```yaml
services:
  ftp_honeypot:
    build: ./ftp_honeypot
    ports:
      - "21:21"
    volumes:
      - ./data/ftp_honeypot:/app/data
    networks:
      - honeypot_network
```

### Machine Learning Integration

Implement ML-based attack detection:

```python
# Example: Anomaly detection
from sklearn.ensemble import IsolationForest

def detect_anomalies(attack_features):
    model = IsolationForest(contamination=0.1)
    return model.fit_predict(attack_features)
```

### Real-time Alerting

Set up alerts for high-risk attacks:

```python
# Example: Slack/Discord notifications
import requests

def send_alert(attack_data):
    if attack_data['risk_score'] > 80:
        webhook_url = "YOUR_WEBHOOK_URL"
        message = f"🚨 High-risk attack detected from {attack_data['client_ip']}"
        requests.post(webhook_url, json={"text": message})
```

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Setup

```bash
# Fork the repository
git clone https://github.com/vamshikrishna781/smartcity-honeypot.git
cd smartcity-honeypot

# Create development environment
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Unit tests
python -m pytest tests/

# Integration tests
python -m pytest tests/integration/

# Code coverage
python -m pytest --cov=src tests/
```

### Code Standards

- **PEP 8** compliance for Python code
- **Black** code formatting
- **Flake8** linting
- **Type hints** for new Python code
- **Comprehensive tests** for new features

### Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This honeypot system is designed for:
- ✅ **Educational purposes**
- ✅ **Security research**
- ✅ **Authorized network monitoring**
- ✅ **Threat intelligence gathering**

**NOT intended for**:
- ❌ Unauthorized network monitoring
- ❌ Malicious activities
- ❌ Production environments without proper isolation
- ❌ Violation of local laws or regulations

Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction.


## 🏆 Acknowledgments

Special thanks to:

- **[Cowrie](https://github.com/cowrie/cowrie)** - SSH/Telnet honeypot
- **[Elastic Stack](https://www.elastic.co/)** - Search and analytics
- **[Flask](https://flask.palletsprojects.com/)** - Web framework
- **[Docker](https://www.docker.com/)** - Containerization platform
- **[Eclipse Mosquitto](https://mosquitto.org/)** - MQTT broker

## 🌟 Show Your Support

If this project helped you, please consider:

- ⭐ **Starring** the repository
- 🔄 **Sharing** with the cybersecurity community
- 🐛 **Reporting** bugs and issues
- 🔧 **Contributing** improvements
- 📖 **Improving** documentation

---

**Made with ❤️ for the cybersecurity research community**

*Last updated: October 2024*

# If running locally (not in Docker), export a writable DATA_DIR:
export DATA_DIR="$(pwd)/data/http_honeypot"

## 🗂️ Utility & Management Tools Overview

This project includes several management and monitoring utilities to help you control, observe, and administer the honeypot system. Below is a concise description of each tool, usage examples, and security notes.

### cli_panel.py — Command-line control panel
- Purpose: Interactive CLI to list/start/stop/restart containers, view logs, and start/stop all honeypots.
- Key features:
  - Finds containers by service name or project-prefixed names.
  - Falls back to `docker compose up/down` if containers are missing.
- Usage:
  ```bash
  source venv/bin/activate
  python cli_panel.py
  ```
- Notes: Requires Docker CLI access from the user running the script.

### control_panel.py — Web control panel
- Purpose: Browser-based UI for container control (start/stop/restart) and basic status.
- Bind address: By default binds to `0.0.0.0:5000`. Restrict to `127.0.0.1` if exposing to local host only.
- Usage:
  ```bash
  source venv/bin/activate
  python control_panel.py
  # Open http://127.0.0.1:5000 (or the host IP shown)
  ```
- Security: Do not expose to the internet without authentication and TLS.

### realtime_tracker.py — Main HTTP honeypot & tracker
- Purpose: Simulates HTTP endpoints, logs attacks to SQLite and evidence files, provides APIs for recent attacks and stats.
- Data location: `data/http_honeypot/attacks.db` and `data/http_honeypot/evidence/`.
- Usage (local, writable data dir):
  ```bash
  export DATA_DIR="$(pwd)/data/http_honeypot"
  python http_honeypot/realtime_tracker.py
  ```
- Notes:
  - Admin endpoints (/dashboard, /api/attacks/recent, /api/stats) are protected — only local requests or requests with `ADMIN_TOKEN` allowed.
  - Ensure the process can write `DATA_DIR` (avoid creating `/app` as root).

### admin_app.py — Local admin UI (secure)
- Purpose: Admin-only UI for viewing recent attacks, evidence files, and system health.
- Security model:
  - Binds to `127.0.0.1` by default.
  - Allows localhost access without a token; remote access requires `ADMIN_TOKEN` via header `X-Admin-Token` or `?token=`.
- Usage:
  ```bash
  export DATA_DIR="$(pwd)/data/http_honeypot"
  export ADMIN_TOKEN="$(openssl rand -hex 16)"   # optional for remote access
  python http_honeypot/admin_app.py
  # Open http://127.0.0.1:5000/admin
  ```
- Do not publish this port in production or in Docker without additional access controls.

### realtime_dashboard.py — Live SSE dashboard
- Purpose: Streams new evidence JSON files (SSE) for live monitoring; used for local dashboards and demonstrations.
- Usage:
  ```bash
  export DATA_DIR="$(pwd)/data/http_honeypot"
  python scripts/realtime_dashboard.py
  # Open the printed URL (default http://localhost:8082)
  ```
- Notes: Minimal dependencies; intended for local monitoring.

## 🔒 Security & Deployment Recommendations
- Always bind admin interfaces to loopback (127.0.0.1) or protect with a strong `ADMIN_TOKEN`.
- Use firewall rules (ufw/iptables) to block management ports from the public internet.
- Rotate admin tokens and protect backups (attack logs can contain sensitive data).
- For production or public-facing honeypots, use strict isolation (separate VM/container network, limited egress, monitoring).

## 🚀 Quick Recap: Where to run each tool
- CLI: `python cli_panel.py` (interactive terminal)
- Web control panel: `python control_panel.py` → open http://127.0.0.1:5000
- Honeypot (HTTP): `python http_honeypot/realtime_tracker.py` → public honeypot endpoints
- Admin UI: `python http_honeypot/admin_app.py` → open http://127.0.0.1:5000/admin
- Real-time SSE dashboard: `python scripts/realtime_dashboard.py` → open reported URL
