# SIGMA - Security Information Gathering & Monitoring System, Main application entry point

import sys
import threading
import time
import logging
import socket
from flask import Flask
from flask_socketio import SocketIO
from datetime import datetime

sys.path.append('.')

from config import Config
from web.routes import init_routes
from modules.log_collector import LogCollector
from modules.system_monitor import SystemMonitor
from modules.rule_engine import RuleEngine
from modules.alert_manager import AlertManager
from modules.virus_total import VirusTotalChecker
from modules.report_generator import ReportGenerator

# Initialize Flask app
app = Flask(__name__, 
            template_folder='web/templates',
            static_folder='web/static')
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize modules
log_collector = LogCollector()
system_monitor = SystemMonitor()
rule_engine = RuleEngine()
alert_manager = AlertManager(Config.ALERT_FILE)
vt_checker = VirusTotalChecker(Config.VIRUSTOTAL_API_KEY)
report_gen = ReportGenerator(Config.REPORTS_DIR)

# Setup logging
logging.basicConfig(
    filename=Config.LOGS_DIR + '/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Initialize routes
init_routes(app, socketio, log_collector, system_monitor, 
            rule_engine, alert_manager, vt_checker, report_gen)

# ==================== BACKGROUND ALERT GENERATOR ====================
def background_alert_monitor():
    """
    Continuously monitor system and generate alerts in background
    Runs every 2 seconds
    """
    print("[Background] Alert monitor thread started")
    
    # Keep track of previous state
    previous_usb_devices = set()
    previous_tasks = set()
    previous_registry_snapshot = {}
    previous_users = set()
    defender_was_disabled = False
    
    while True:
        try:
            print("[Background] Running security analysis...")
            
            # ---------- Collect data with detailed checks ----------
            logs = log_collector.collect_all_logs(24)
            if logs is None:
                print("[ERROR] log_collector.collect_all_logs() returned None")
                logs = []
            if not isinstance(logs, (list, tuple)):
                print(f"[ERROR] logs is not iterable: {type(logs)}")
                logs = []
            
            processes = system_monitor.get_processes()
            if processes is None:
                print("[ERROR] system_monitor.get_processes() returned None")
                processes = []
            if not isinstance(processes, (list, tuple)):
                print(f"[ERROR] processes is not iterable: {type(processes)}")
                processes = []
            
            connections = system_monitor.get_network_connections()
            if connections is None:
                print("[ERROR] system_monitor.get_network_connections() returned None")
                connections = []
            if not isinstance(connections, (list, tuple)):
                print(f"[ERROR] connections is not iterable: {type(connections)}")
                connections = []
            
            print(f"[Background] Collected {len(logs)} logs, {len(processes)} processes, {len(connections)} connections")
            
            # ---------- USB detection ----------
            current_usb = system_monitor.get_usb_devices()
            if current_usb is None:
                print("[ERROR] get_usb_devices() returned None")
                current_usb = set()
            if not isinstance(current_usb, set):
                print(f"[ERROR] current_usb is not a set: {type(current_usb)}")
                current_usb = set()
            new_usb = current_usb - previous_usb_devices
            previous_usb_devices = current_usb
            
            # ---------- Scheduled tasks ----------
            current_tasks = system_monitor.get_scheduled_tasks()
            if current_tasks is None:
                print("[ERROR] get_scheduled_tasks() returned None")
                current_tasks = set()
            if not isinstance(current_tasks, set):
                print(f"[ERROR] current_tasks is not a set: {type(current_tasks)}")
                current_tasks = set()
            new_tasks = current_tasks - previous_tasks
            previous_tasks = current_tasks
            
            # ---------- Registry snapshot ----------
            current_snapshot = system_monitor.get_registry_snapshot()
            if current_snapshot is None:
                print("[ERROR] get_registry_snapshot() returned None")
                current_snapshot = {}
            if not isinstance(current_snapshot, dict):
                print(f"[ERROR] current_snapshot is not a dict: {type(current_snapshot)}")
                current_snapshot = {}
            changed_keys = []
            for key, value in current_snapshot.items():
                if key not in previous_registry_snapshot or previous_registry_snapshot[key] != value:
                    changed_keys.append((key, value))
            for key in previous_registry_snapshot:
                if key not in current_snapshot:
                    changed_keys.append((key, "(deleted)"))
            previous_registry_snapshot = current_snapshot
            
            # ---------- Local users ----------
            current_users = system_monitor.get_local_users()
            if current_users is None:
                print("[ERROR] get_local_users() returned None")
                current_users = set()
            if not isinstance(current_users, set):
                print(f"[ERROR] current_users is not a set: {type(current_users)}")
                current_users = set()
            new_users = current_users - previous_users
            previous_users = current_users
            
            # ---------- Defender status ----------
            defender_disabled = system_monitor.is_defender_disabled()
            # (defender_was_disabled already defined)
            
            # ---------- Rule engine ----------
            new_alerts = rule_engine.analyze_all(logs, processes, connections, Config)
            if new_alerts is None:
                print("[ERROR] rule_engine.analyze_all() returned None")
                new_alerts = []
            if not isinstance(new_alerts, list):
                print(f"[ERROR] new_alerts is not a list: {type(new_alerts)}")
                new_alerts = []
            
            # ---------- Add custom alerts ----------
            for device in new_usb:
                new_alerts.append({
                    'rule_id': 'RULE_006',
                    'rule_name': 'USB Device Inserted',
                    'severity': 'LOW',
                    'timestamp': datetime.now().isoformat(),
                    'details': f'New USB device connected (ID: {device[:80]})',
                    'computer': socket.gethostname()
                })
            
            for task in new_tasks:
                new_alerts.append({
                    'rule_id': 'RULE_007',
                    'rule_name': 'Scheduled Task Created',
                    'severity': 'HIGH',
                    'timestamp': datetime.now().isoformat(),
                    'details': f'New scheduled task: {task}',
                    'computer': socket.gethostname()
                })
            
            for key, val in changed_keys[:5]:
                new_alerts.append({
                    'rule_id': 'RULE_008',
                    'rule_name': 'Registry Key Modified',
                    'severity': 'MEDIUM',
                    'timestamp': datetime.now().isoformat(),
                    'details': f'Registry change: {key} = {str(val)[:80]}',
                    'computer': socket.gethostname()
                })
            
            for user in new_users:
                new_alerts.append({
                    'rule_id': 'RULE_009',
                    'rule_name': 'New User Account Created',
                    'severity': 'HIGH',
                    'timestamp': datetime.now().isoformat(),
                    'details': f'New user: {user}',
                    'computer': socket.gethostname()
                })
            
            if defender_disabled and not defender_was_disabled:
                new_alerts.append({
                    'rule_id': 'RULE_010',
                    'rule_name': 'Windows Defender Disabled',
                    'severity': 'HIGH',
                    'timestamp': datetime.now().isoformat(),
                    'details': 'Windows Defender real‑time protection is disabled',
                    'computer': socket.gethostname()
                })
            defender_was_disabled = defender_disabled
            
            # ---------- Save and notify ----------
            if new_alerts:
                added = alert_manager.add_alerts(new_alerts)
                print(f"[Background] Generated {len(added)} new alerts")
                # for alert in new_alerts:
                #     if alert.get('severity') == 'HIGH':
                #         email_alerter.send_alert(alert)
                socketio.emit('new_alerts', {'count': len(added)})
            else:
                print("[Background] No new alerts detected")
            
        except Exception as e:
            print(f"[Background] Error in alert monitor: {e}")
            logging.error(f"Background alert monitor error: {e}", exc_info=True)
        
        time.sleep(2)


# @app.route('/test')
# def test_page():
#     return "<h1>SIGMA is working!</h1><p>If you see this, Flask is running correctly.</p>"

# ==================== MAIN EXECUTION ====================
if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("REGISTERED ROUTES:")
    print("=" * 60)
    for rule in app.url_map.iter_rules():
        print(f"  {rule.endpoint}: {rule.rule}")
    print("=" * 60 + "\n")
    
    alert_thread = threading.Thread(target=background_alert_monitor, daemon=True)
    alert_thread.start()
    print("✓ Background alert monitor started (runs every 2 seconds)")
    
    # if Config.EMAIL_ALERTS_ENABLED:
    #     print("✓ Email alerts are ENABLED for HIGH severity alerts")
    # else:
    #     print("ℹ️ Email alerts are DISABLED")
    
    logging.info('Starting SIGMA Security Monitor')
    print("""
    ═══════════════════════════════════════════════════════════
                    SIGMA Security Monitor                     
                                                               
        Dashboard: http://localhost:5000                       
        Background monitoring: ACTIVE (every 2 seconds)        
                                                           
         Press Ctrl+C to stop                                    
    ═══════════════════════════════════════════════════════════
    """)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)