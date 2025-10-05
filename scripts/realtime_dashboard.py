# scripts/realtime_dashboard.py
import sqlite3
import json
import time
from datetime import datetime, timedelta
import os

EVIDENCE_DIR = os.path.join('..', 'data', 'realtime_evidence')
DB_PATH = os.path.join(EVIDENCE_DIR, 'realtime_attacks.db')

def get_recent_attacks(hours=24):
    """Get attacks from the last N hours"""
    since = time.time() - (hours * 3600)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, client_ip, path, method, geo_info, is_tor, is_vpn, risk_score
            FROM attacks 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        ''', (since,))
        
        attacks = cursor.fetchall()
        conn.close()
        
        return attacks
    except Exception as e:
        print(f"❌ Database error: {e}")
        return []

def generate_threat_report():
    """Generate a real-time threat intelligence report"""
    attacks = get_recent_attacks(24)
    
    if not attacks:
        print("📊 No attacks detected in the last 24 hours")
        print("💡 Make sure the realtime_tracker.py is running and receiving traffic")
        return
    
    print(f"🚨 REAL-TIME THREAT REPORT ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
    print("="*60)
    
    # Top attacking IPs
    ip_counts = {}
    tor_attacks = 0
    vpn_attacks = 0
    high_risk_attacks = 0
    countries = {}
    methods = {}
    paths = {}
    
    for attack in attacks:
        timestamp, client_ip, path, method, geo_info_str, is_tor, is_vpn, risk_score = attack
        
        # Count by IP
        ip_counts[client_ip] = ip_counts.get(client_ip, 0) + 1
        
        # Count methods
        methods[method] = methods.get(method, 0) + 1
        
        # Count paths
        paths[path] = paths.get(path, 0) + 1
        
        # Count Tor/VPN
        if is_tor:
            tor_attacks += 1
        if is_vpn:
            vpn_attacks += 1
        if risk_score > 50:
            high_risk_attacks += 1
        
        # Count by country
        if geo_info_str:
            try:
                geo_info = json.loads(geo_info_str)
                country = geo_info.get('country', 'Unknown')
                countries[country] = countries.get(country, 0) + 1
            except:
                pass
    
    print(f"📈 Total Attacks: {len(attacks)}")
    print(f"🔴 High Risk Attacks: {high_risk_attacks}")
    print(f"🧅 Tor Attacks: {tor_attacks}")
    print(f"🔒 VPN/Proxy Attacks: {vpn_attacks}")
    print()
    
    print("🔥 TOP ATTACKING IPs:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {ip}: {count} attacks")
    print()
    
    print("🌍 TOP ATTACKING COUNTRIES:")
    for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {country}: {count} attacks")
    print()
    
    print("🎯 TOP TARGETED PATHS:")
    for path, count in sorted(paths.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {path}: {count} requests")
    print()
    
    print("🛠️ HTTP METHODS:")
    for method, count in sorted(methods.items(), key=lambda x: x[1], reverse=True):
        print(f"   {method}: {count} requests")
    print()
    
    # Recent high-risk attacks
    print("⚠️  RECENT HIGH-RISK ATTACKS:")
    high_risk_found = False
    for attack in attacks[:20]:  # Check last 20 attacks
        timestamp, client_ip, path, method, geo_info_str, is_tor, is_vpn, risk_score = attack
        if risk_score > 50:
            high_risk_found = True
            dt = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
            indicators = []
            if is_tor:
                indicators.append('TOR')
            if is_vpn:
                indicators.append('VPN')
            
            country = 'Unknown'
            if geo_info_str:
                try:
                    geo_info = json.loads(geo_info_str)
                    country = geo_info.get('country', 'Unknown')
                except:
                    pass
            
            indicator_str = f"[{','.join(indicators)}]" if indicators else ""
            print(f"   {dt} | {client_ip} ({country}) | {method} {path} | Risk: {risk_score} {indicator_str}")
    
    if not high_risk_found:
        print("   No high-risk attacks in recent activity")
    
    print()
    print("📁 Evidence stored in:", os.path.abspath(EVIDENCE_DIR))

def show_live_attacks():
    """Show live attacks as they come in"""
    print("🔴 LIVE ATTACK MONITOR (Press Ctrl+C to stop)")
    print("="*50)
    
    last_attack_id = 0
    
    try:
        while True:
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, timestamp, client_ip, path, method, risk_score, is_tor, is_vpn
                    FROM attacks 
                    WHERE id > ?
                    ORDER BY timestamp ASC
                ''', (last_attack_id,))
                
                new_attacks = cursor.fetchall()
                conn.close()
                
                for attack in new_attacks:
                    attack_id, timestamp, client_ip, path, method, risk_score, is_tor, is_vpn = attack
                    dt = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
                    
                    risk_emoji = "🔴" if risk_score > 70 else "🟡" if risk_score > 30 else "🟢"
                    tor_emoji = "🧅" if is_tor else ""
                    vpn_emoji = "🔒" if is_vpn else ""
                    
                    print(f"{risk_emoji} {dt} | {client_ip} | {method} {path} | Risk: {risk_score} {tor_emoji}{vpn_emoji}")
                    last_attack_id = attack_id
                
                time.sleep(2)  # Check every 2 seconds
                
            except sqlite3.OperationalError:
                print("⏳ Waiting for database to be created...")
                time.sleep(5)
            except Exception as e:
                print(f"❌ Error: {e}")
                time.sleep(5)
                
    except KeyboardInterrupt:
        print("\n👋 Live monitor stopped")

def main():
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'live':
        show_live_attacks()
    else:
        try:
            while True:
                os.system('clear' if os.name == 'posix' else 'cls')
                generate_threat_report()
                print("\n🔄 Refreshing in 30 seconds... (Ctrl+C to exit)")
                print("💡 Run 'python3 realtime_dashboard.py live' for live attack monitor")
                time.sleep(30)
        except KeyboardInterrupt:
            print("\n👋 Dashboard stopped")

if __name__ == '__main__':
    main()