
# Rule Engine Module
# Detects security threats using rule-based detection rules
# Includes cooldown mechanism to prevent alert flooding

import logging
import time
import re
from datetime import datetime

class RuleEngine:
    def __init__(self):
        """Initialize the rule engine with 10 detection rules"""
        self.rules = self._initialize_rules()
        self.alert_count = 0
        self.alert_cooldown = {}          # Stores last alert time for each key
        self.default_cooldown = 300        # 5 minutes default cooldown (seconds)
        logging.basicConfig(level=logging.INFO)

    def _initialize_rules(self):
        """Initialize all detection rules with metadata"""
        return [
            {
                'id': 'RULE_001',
                'name': 'Multiple Failed Logins',
                'description': 'Detects potential brute force attacks',
                'severity': 'HIGH',
                'event_id': 4625,
                'threshold': 3,
                'cooldown': 86400
            },
            {
                'id': 'RULE_002',
                'name': 'Suspicious Process Running',
                'description': 'Detects known suspicious processes',
                'severity': 'MEDIUM',
                'processes': ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
                             'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wmic.exe', 'certutil.exe'],
                'cooldown': 86400
            },
            {
                'id': 'RULE_003',
                'name': 'Unusual Port Connection',
                'description': 'Detects connections to known backdoor ports',
                'severity': 'HIGH',
                'ports': [4444, 1337, 31337, 5555, 6666, 6667, 6668, 6669, 8080],
                'cooldown': 86400
            },
            {
                'id': 'RULE_004',
                'name': 'Privilege Escalation',
                'description': 'Detects special privileges assigned',
                'severity': 'HIGH',
                'event_id': 4672,
                'cooldown': 86400
            },
            {
                'id': 'RULE_005',
                'name': 'Service Installation',
                'description': 'Detects new service installations',
                'severity': 'MEDIUM',
                'event_id': 7045,
                'cooldown': 86400
            },
            {
                'id': 'RULE_006',
                'name': 'USB Device Inserted',
                'description': 'Detects USB storage device connection',
                'severity': 'MEDIUM',
                'event_id': 20003,
                'cooldown': 86400
            },
            {
                'id': 'RULE_007',
                'name': 'Scheduled Task Created',
                'description': 'Detects scheduled task creation (persistence)',
                'severity': 'HIGH',
                'event_id': 4698,
                'cooldown': 86400
            },
            {
                'id': 'RULE_008',
                'name': 'Registry Key Modified',
                'description': 'Detects registry modification (malware persistence)',
                'severity': 'MEDIUM',
                'event_id': 4657,
                'cooldown': 86400
            },
            {
                'id': 'RULE_009',
                'name': 'New User Account Created',
                'description': 'Detects creation of new user accounts',
                'severity': 'HIGH',
                'event_id': 4720,
                'cooldown': 86400
            },
            # {
            #     'id': 'RULE_010',
            #     'name': 'Windows Defender Disabled',
            #     'description': 'Detects when Windows Defender is disabled',
            #     'severity': 'HIGH',
            #     'event_id': 5007,
            #     'cooldown': 86400
            # }
        ]

    def _get_alert_key(self, rule_id, indicator):
        """Generate unique key for alert deduplication"""
        return f"{rule_id}_{indicator}"

    def _is_on_cooldown(self, rule_id, indicator):
        """Check if alert is still on cooldown"""
        key = self._get_alert_key(rule_id, indicator)
        if key in self.alert_cooldown:
            last_alert = self.alert_cooldown[key]
            # Get cooldown from rule config (default 300 seconds)
            cooldown = self.default_cooldown
            for rule in self.rules:
                if rule['id'] == rule_id:
                    cooldown = rule.get('cooldown', self.default_cooldown)
                    break
            if time.time() - last_alert < cooldown:
                return True
        return False

    def _record_alert(self, rule_id, indicator):
        """Record that an alert was generated"""
        key = self._get_alert_key(rule_id, indicator)
        self.alert_cooldown[key] = time.time()

    def analyze_logs(self, logs, config=None):
        """Analyze Windows Event Logs for threats. Always returns a list."""
        alerts = []
        if not logs:
            return alerts

        threshold = 3   # default threshold
        if config and hasattr(config, 'FAILED_LOGIN_THRESHOLD'):
            threshold = config.FAILED_LOGIN_THRESHOLD

        # RULE_001: Multiple Failed Logins
        try:
            failed_logins = [log for log in logs if log.get('event_id') == 4625]
            if len(failed_logins) >= threshold:
                if not self._is_on_cooldown('RULE_001', 'multiple_failures'):
                    alert = {
                        'rule_id': 'RULE_001',
                        'rule_name': 'Multiple Failed Logins',
                        'severity': 'HIGH',
                        'timestamp': datetime.now().isoformat(),
                        'count': len(failed_logins),
                        'details': f'{len(failed_logins)} failed login attempts detected'
                    }
                    alerts.append(alert)
                    self._record_alert('RULE_001', 'multiple_failures')
                    logging.warning(f"ALERT: {alert['rule_name']} - {alert['count']} attempts")
        except Exception as e:
            print(f"[RuleEngine] RULE_001 error: {e}")

        # RULE_004: Privilege Escalation
        try:
            priv_events = [log for log in logs if log.get('event_id') == 4672]
            for event in priv_events[:5]:
                indicator = f"source_{event.get('source', 'unknown')}"
                if not self._is_on_cooldown('RULE_004', indicator):
                    alert = {
                        'rule_id': 'RULE_004',
                        'rule_name': 'Privilege Escalation',
                        'severity': 'HIGH',
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': 'Special privileges assigned to logon',
                        'source': event.get('source', 'Unknown'),
                        'computer': event.get('computer', 'Unknown')
                    }
                    alerts.append(alert)
                    self._record_alert('RULE_004', indicator)
                    logging.warning(f"ALERT: {alert['rule_name']} on {alert['computer']}")
        except Exception as e:
            print(f"[RuleEngine] RULE_004 error: {e}")

        # RULE_005: Service Installation
        try:
            service_events = [log for log in logs if log.get('event_id') == 7045]
            for event in service_events[:5]:
                service_name = "unknown"
                if event.get('description'):
                    match = re.search(r'Service Name:\s*([^\s]+)', event['description'])
                    if match:
                        service_name = match.group(1)
                if not self._is_on_cooldown('RULE_005', service_name):
                    alert = {
                        'rule_id': 'RULE_005',
                        'rule_name': 'Service Installation',
                        'severity': 'MEDIUM',
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': f'New service installed: {service_name}',
                        'source': event.get('source', 'Unknown'),
                        'description': event.get('description', '')[:200]
                    }
                    alerts.append(alert)
                    self._record_alert('RULE_005', service_name)
                    logging.info(f"ALERT: {alert['rule_name']} - {service_name}")
        except Exception as e:
            print(f"[RuleEngine] RULE_005 error: {e}")

        # RULE_006: USB Device Inserted (event based, but will also be triggered by WMI in app.py)
        try:
            usb_events = [log for log in logs if log.get('event_id') == 20003]
            for event in usb_events[:5]:
                indicator = f"usb_{event.get('computer', 'unknown')}"
                if not self._is_on_cooldown('RULE_006', indicator):
                    alert = {
                        'rule_id': 'RULE_006',
                        'rule_name': 'USB Device Inserted',
                        'severity': 'LOW',
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': 'USB storage device connected to system',
                        'computer': event.get('computer', 'Unknown')
                    }
                    alerts.append(alert)
                    self._record_alert('RULE_006', indicator)
                    logging.info(f"ALERT: {alert['rule_name']} on {alert['computer']}")
        except Exception as e:
            print(f"[RuleEngine] RULE_006 error: {e}")

        # RULE_007: Scheduled Task Created
        try:
            task_events = [log for log in logs if log.get('event_id') == 4698]
            for event in task_events[:5]:
                indicator = f"task_{event.get('computer', 'unknown')}"
                if not self._is_on_cooldown('RULE_007', indicator):
                    alert = {
                        'rule_id': 'RULE_007',
                        'rule_name': 'Scheduled Task Created',
                        'severity': 'HIGH',
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': 'A new scheduled task was created - possible persistence',
                        'computer': event.get('computer', 'Unknown')
                    }
                    alerts.append(alert)
                    self._record_alert('RULE_007', indicator)
                    logging.warning(f"ALERT: {alert['rule_name']} on {alert['computer']}")
        except Exception as e:
            print(f"[RuleEngine] RULE_007 error: {e}")

        # RULE_008: Registry Key Modified
        try:
            reg_events = [log for log in logs if log.get('event_id') == 4657]
            for event in reg_events[:5]:
                indicator = f"reg_{event.get('computer', 'unknown')}"
                if not self._is_on_cooldown('RULE_008', indicator):
                    alert = {
                        'rule_id': 'RULE_008',
                        'rule_name': 'Registry Key Modified',
                        'severity': 'MEDIUM',
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': 'Registry key modified - possible malware persistence',
                        'computer': event.get('computer', 'Unknown')
                    }
                    alerts.append(alert)
                    self._record_alert('RULE_008', indicator)
                    logging.info(f"ALERT: {alert['rule_name']} on {alert['computer']}")
        except Exception as e:
            print(f"[RuleEngine] RULE_008 error: {e}")

        # RULE_009: New User Account Created
        try:
            user_events = [log for log in logs if log.get('event_id') == 4720]
            for event in user_events[:5]:
                indicator = f"newuser_{event.get('computer', 'unknown')}"
                if not self._is_on_cooldown('RULE_009', indicator):
                    alert = {
                        'rule_id': 'RULE_009',
                        'rule_name': 'New User Account Created',
                        'severity': 'HIGH',
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': 'A new user account was created - possible backdoor account',
                        'computer': event.get('computer', 'Unknown')
                    }
                    alerts.append(alert)
                    self._record_alert('RULE_009', indicator)
                    logging.warning(f"ALERT: {alert['rule_name']} on {alert['computer']}")
        except Exception as e:
            print(f"[RuleEngine] RULE_009 error: {e}")

        # RULE_010: Windows Defender Disabled
        # try:
        #     defender_events = [log for log in logs if log.get('event_id') == 5007]
        #     for event in defender_events[:5]:
        #         indicator = f"defender_{event.get('computer', 'unknown')}"
        #         if not self._is_on_cooldown('RULE_010', indicator):
        #             alert = {
        #                 'rule_id': 'RULE_010',
        #                 'rule_name': 'Windows Defender Disabled',
        #                 'severity': 'HIGH',
        #                 'timestamp': event.get('timestamp', datetime.now().isoformat()),
        #                 'details': 'Windows Defender was disabled - possible malware evasion',
        #                 'computer': event.get('computer', 'Unknown')
        #             }
        #             alerts.append(alert)
        #             self._record_alert('RULE_010', indicator)
        #             logging.critical(f"ALERT: {alert['rule_name']} on {alert['computer']}")
        # except Exception as e:
        #     print(f"[RuleEngine] RULE_010 error: {e}")

        return alerts

    def analyze_processes(self, processes, config=None):
        alerts = []
        if not processes:
            return alerts

        suspicious_list = self._get_suspicious_processes(config)
        alerted_this_run = set()

        try:
            for proc in processes:
                proc_name = proc.get('name', '').lower()
                if proc_name in suspicious_list and proc_name not in alerted_this_run:
                    if not self._is_on_cooldown('RULE_002', proc_name):
                        alert = {
                            'rule_id': 'RULE_002',
                            'rule_name': 'Suspicious Process Running',
                            'severity': 'MEDIUM',
                            'timestamp': proc.get('timestamp', datetime.now().isoformat()),
                            'process_name': proc.get('name', 'Unknown'),
                            'pid': proc.get('pid'),
                            'username': proc.get('username', 'Unknown'),
                            'details': f'Suspicious process detected: {proc.get("name")} (PID: {proc.get("pid")})'
                        }
                        alerts.append(alert)
                        self._record_alert('RULE_002', proc_name)
                        alerted_this_run.add(proc_name)
                        logging.warning(f"ALERT: {alert['rule_name']} - {alert['process_name']}")
        except Exception as e:
            print(f"[RuleEngine] analyze_processes error: {e}")

        return alerts

    def analyze_connections(self, connections, config=None):
        """Analyze network connections for unusual ports (RULE_003). Always returns a list."""
        alerts = []
        if not connections:
            return alerts

        suspicious_ports = self._get_suspicious_ports(config)
        try:
            for conn in connections:
                remote_port = conn.get('remote_port')
                if remote_port and remote_port in suspicious_ports:
                    indicator = f"{conn.get('remote_ip', 'unknown')}:{remote_port}"
                    if not self._is_on_cooldown('RULE_003', indicator):
                        high_risk_ports = [4444, 1337, 31337]
                        severity = 'HIGH' if remote_port in high_risk_ports else 'MEDIUM'
                        alert = {
                            'rule_id': 'RULE_003',
                            'rule_name': 'Unusual Port Connection',
                            'severity': severity,
                            'timestamp': conn.get('timestamp', datetime.now().isoformat()),
                            'remote_ip': conn.get('remote_ip'),
                            'remote_port': remote_port,
                            'process': conn.get('process', 'Unknown'),
                            'pid': conn.get('pid'),
                            'details': f'Connection to suspicious port {remote_port} from {conn.get("process")}'
                        }
                        alerts.append(alert)
                        self._record_alert('RULE_003', indicator)
                        logging.warning(f"ALERT: {alert['rule_name']} - Port {remote_port} to {conn.get('remote_ip')}")
        except Exception as e:
            print(f"[RuleEngine] analyze_connections error: {e}")

        return alerts

    def analyze_all(self, logs, processes, connections, config=None):
        """Run all analysis rules and return combined alerts. Always returns a list."""
        all_alerts = []
        try:
            log_alerts = self.analyze_logs(logs, config)
            if log_alerts is None:
                log_alerts = []
            all_alerts.extend(log_alerts)
        except Exception as e:
            print(f"[RuleEngine] analyze_logs failed: {e}")

        try:
            proc_alerts = self.analyze_processes(processes, config)
            if proc_alerts is None:
                proc_alerts = []
            all_alerts.extend(proc_alerts)
        except Exception as e:
            print(f"[RuleEngine] analyze_processes failed: {e}")

        try:
            conn_alerts = self.analyze_connections(connections, config)
            if conn_alerts is None:
                conn_alerts = []
            all_alerts.extend(conn_alerts)
        except Exception as e:
            print(f"[RuleEngine] analyze_connections failed: {e}")

        self.alert_count += len(all_alerts)
        return all_alerts

    def _get_suspicious_processes(self, config):
        """Get list of suspicious process names from config or default"""
        default = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
                   'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wmic.exe', 'certutil.exe']
        if config and hasattr(config, 'SUSPICIOUS_PROCESSES'):
            return config.SUSPICIOUS_PROCESSES
        return default

    def _get_suspicious_ports(self, config):
        """Get list of suspicious ports from config or default"""
        default = [4444, 1337, 31337, 5555, 6666, 6667, 6668, 6669, 8080]
        if config and hasattr(config, 'SUSPICIOUS_PORTS'):
            return config.SUSPICIOUS_PORTS
        return default

    def clear_cooldown(self, rule_id=None, indicator=None):
        """Clear cooldown for specific alerts (for testing or reset)"""
        if rule_id and indicator:
            key = self._get_alert_key(rule_id, indicator)
            self.alert_cooldown.pop(key, None)
        elif rule_id:
            keys_to_delete = [k for k in self.alert_cooldown if k.startswith(rule_id)]
            for key in keys_to_delete:
                del self.alert_cooldown[key]
        else:
            self.alert_cooldown.clear()

    def get_rule_info(self, rule_id):
        """Get information about a specific rule"""
        for rule in self.rules:
            if rule['id'] == rule_id:
                return rule
        return None

    def get_all_rules(self):
        """Get all detection rules"""
        return self.rules

    def get_statistics(self):
        """Get statistics about rule engine activity"""
        high_count = sum(1 for r in self.rules if r.get('severity') == 'HIGH')
        medium_count = sum(1 for r in self.rules if r.get('severity') == 'MEDIUM')
        return {
            'total_rules': len(self.rules),
            'alerts_generated': self.alert_count,
            'rules_by_severity': {
                'HIGH': high_count,
                'MEDIUM': medium_count,
                'LOW': 0
            }
        }