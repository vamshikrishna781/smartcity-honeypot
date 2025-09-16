#!/bin/bash

set -e

echo "=== Smart City Honeypot Auto Setup ==="

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y git curl python3 python3-pip python3-venv net-tools ufw

# Install Docker & Docker Compose
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    rm get-docker.sh
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Installing Docker Compose..."
    sudo apt install -y docker-compose
fi

# Add current user to docker group
sudo usermod -aG docker $USER

# Enable and start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Setup firewall (optional, open needed ports)
sudo ufw allow 22    # SSH
sudo ufw allow 23    # Telnet
sudo ufw allow 554   # RTSP
sudo ufw allow 8080  # HTTP honeypot
sudo ufw allow 8081  # CameraObscura admin
sudo ufw allow 5060/udp # SIP honeypot
sudo ufw allow 1883  # MQTT
sudo ufw allow 21883 # Riotpot MQTT
sudo ufw allow 502   # Modbus
sudo ufw allow 5683/udp # CoAP
sudo ufw allow 9200  # Elasticsearch
sudo ufw allow 5601  # Kibana

echo "Firewall rules updated. You may need to enable UFW if not already enabled."
echo "To enable: sudo ufw enable"

# Build and run all honeypots
echo "Building and starting honeypot containers..."
sudo docker compose up --build -d

echo "=== Setup Complete! ==="
echo "You may need to log out and log back in for Docker group changes to take effect."
echo "Check running containers with: sudo docker ps"
echo "Access dashboards and logs as described in README.md."