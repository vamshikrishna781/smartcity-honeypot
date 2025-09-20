# Secure the Smart City – IoT Honeypot Challenge

## Problem Statement

**Challenge:**  
Develop an IoT honeypot framework that mimics real smart city devices to attract attackers and analyze their behavior in a controlled environment.

---

## Objectives

- **Emulate vulnerable IoT devices:**  
  Simulate devices such as CCTVs, traffic lights, and sensors commonly found in smart cities.
- **Collect logs:**  
  Capture attack vectors, exploits, and attacker movements for analysis.
- **Generate threat intelligence:**  
  Extract actionable insights from real-world attack data.

---

## Key Features

- **Low-interaction and high-interaction honeypots:**  
  Deploy multiple honeypot types to simulate various device behaviors and vulnerabilities.
- **Comprehensive logging:**  
  Record all attacker interactions and network activity.
- **Dashboard:**  
  Visualize attacker sessions, tactics, techniques, and procedures (TTPs).
- **Alerting system:**  
  Notify on newly observed attack patterns.

---

## Bonus Features

- **Automatic IoC generation:**  
  Extract indicators of compromise from logs.
- **STIX/TAXII export:**  
  Export alerts in industry-standard formats for SOC integration.
- **SIEM integration:**  
  Connect with solutions like Splunk or Azure Sentinel for advanced monitoring.

---

## Project Structure

```
smartcity-honeypot/
├── cowrie/                # SSH/Telnet honeypot
├── http_honeypot/         # HTTP honeypot
├── cameraobscura/         # CCTV/RTSP honeypot
├── riotpot/               # Multi-protocol IoT honeypot
├── sip_honeypot/          # SIP honeypot
├── docker-compose.yml     # Container orchestration
├── requirements.txt       # Python dependencies
├── README.md              # Project documentation
├── LICENSE                # License file
└── .gitignore             # Excludes logs and runtime data
```

> **Note:** All runtime data and logs are excluded from version control (`data/` folder).

---

## Getting Started

To download, install, and run the Smart City IoT Honeypot framework:

1. **Clone the repository from GitHub:**
   ```bash
   git clone https://github.com/vamshikrishna781/smartcity-honeypot.git
   cd smartcity-honeypot
   ```

2. **Run the automated setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

This script will:
- Install required system packages and Docker
- Configure firewall rules
- Build and start all honeypot containers automatically

> **After setup, you may need to log out and log back in for Docker group changes to take effect.  
> Check running containers with:**  
> `sudo docker ps`

Access dashboards and logs as described in the documentation for each honeypot.

---

## Running the Control Panel

To start and use the honeypot control panel:

1. **Ensure all dependencies are installed and containers are running**  
   (use the setup script as described above).

2. **Run the control panel script:**
   ```bash
   python3 control_panel.py
   ```

3. **Follow the on-screen instructions** to interact with and monitor your honeypot services.

> **Tip:**  
> You may need to install additional Python packages if prompted.  
> For example:
> ```bash
> pip3 install -r honeypot/requirements.txt
> ```

---

## Contributing

Contributions, bug reports, and feature requests are welcome!  
Please open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License.

---
