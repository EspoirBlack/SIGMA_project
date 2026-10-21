"""
Alert Manager Module - Enhanced Version
Stores and manages security alerts
"""

import json
import os
import logging
from datetime import datetime, timedelta

class AlertManager:
    def __init__(self, alert_file):
        self.alert_file = alert_file
        self.alerts = []
        self._load_alerts()
        logging.basicConfig(level=logging.INFO)
        
    def _load_alerts(self):
        # Load alerts from file
        try:
            if os.path.exists(self.alert_file):
                with open(self.alert_file, 'r', encoding='utf-8') as f:
                    self.alerts = json.load(f)
                logging.info(f"Loaded {len(self.alerts)} alerts")
            else:
                self.alerts = []
        except Exception as e:
            logging.error(f"Error loading alerts: {e}")
            self.alerts = []
    
    def _save_alerts(self):
        # Save alerts to file
        try:
            os.makedirs(os.path.dirname(self.alert_file), exist_ok=True)
            with open(self.alert_file, 'w', encoding='utf-8') as f:
                json.dump(self.alerts, f, indent=2, default=str)
        except Exception as e:
            logging.error(f"Error saving alerts: {e}")
    
    def add_alert(self, alert):
        """Add a single alert"""
        if 'id' not in alert:
            alert['id'] = f"ALT_{len(self.alerts)+1}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
        
        self.alerts.insert(0, alert)
        self._save_alerts()
        return alert
    
    def add_alerts(self, alerts):
        """Add multiple alerts with enhanced deduplication"""
        new_alerts = []
        for alert in alerts:
            duplicate = False
            
            # Check last 50 alerts for duplicates
            for existing in self.alerts[:50]:
                # Same rule and similar details within 5 minutes
                if existing.get('rule_id') == alert.get('rule_id'):
                    # For process alerts, check same process name
                    if alert.get('process_name') and existing.get('process_name') == alert.get('process_name'):
                        try:
                            existing_time = datetime.fromisoformat(existing.get('timestamp', ''))
                            current_time = datetime.now()
                            if (current_time - existing_time).seconds < 300:
                                duplicate = True
                                break
                        except:
                            pass
                    # For connection alerts, check same IP and port
                    elif alert.get('remote_ip') and existing.get('remote_ip') == alert.get('remote_ip'):
                        if alert.get('remote_port') == existing.get('remote_port'):
                            try:
                                existing_time = datetime.fromisoformat(existing.get('timestamp', ''))
                                current_time = datetime.now()
                                if (current_time - existing_time).seconds < 300:
                                    duplicate = True
                                    break
                            except:
                                pass
                    # For general alerts without specific indicator
                    elif not alert.get('process_name') and not alert.get('remote_ip'):
                        try:
                            existing_time = datetime.fromisoformat(existing.get('timestamp', ''))
                            current_time = datetime.now()
                            if (current_time - existing_time).seconds < 300:
                                duplicate = True
                                break
                        except:
                            pass
            
            if not duplicate:
                self.add_alert(alert)
                new_alerts.append(alert)
        
        return new_alerts
    
    def get_all_alerts(self, limit=100):
        """Get all alerts"""
        return self.alerts[:limit]
    
    def get_recent_alerts(self, limit=10):
        """Get most recent alerts"""
        return self.alerts[:limit]
    
    def get_alerts_by_severity(self, severity, limit=100):
        """Get alerts by severity"""
        filtered = [a for a in self.alerts if a.get('severity', '').upper() == severity.upper()]
        return filtered[:limit]
    
    def get_alerts_by_rule(self, rule_id, limit=100):
        """Get alerts by rule ID"""
        filtered = [a for a in self.alerts if a.get('rule_id') == rule_id]
        return filtered[:limit]
    
    def get_alerts_by_time(self, hours_back=24, limit=100):
        """Get alerts from last hours"""
        cutoff = datetime.now() - timedelta(hours=hours_back)
        filtered = []
        for alert in self.alerts:
            try:
                alert_time = datetime.fromisoformat(alert.get('timestamp', ''))
                if alert_time >= cutoff:
                    filtered.append(alert)
            except:
                filtered.append(alert)
        return filtered[:limit]
    
    def get_alert_statistics(self):
        """Get alert statistics"""
        stats = {
            'total': len(self.alerts),
            'by_severity': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'by_rule': {},
            'last_24h': 0,
            'last_7d': 0
        }
        
        cutoff_24h = datetime.now() - timedelta(hours=24)
        cutoff_7d = datetime.now() - timedelta(days=7)
        
        for alert in self.alerts:
            severity = alert.get('severity', 'LOW').upper()
            if severity in stats['by_severity']:
                stats['by_severity'][severity] += 1
            
            rule_id = alert.get('rule_id', 'Unknown')
            stats['by_rule'][rule_id] = stats['by_rule'].get(rule_id, 0) + 1
            
            try:
                alert_time = datetime.fromisoformat(alert.get('timestamp', ''))
                if alert_time >= cutoff_24h:
                    stats['last_24h'] += 1
                if alert_time >= cutoff_7d:
                    stats['last_7d'] += 1
            except:
                pass
        
        return stats
    
    def delete_alert(self, alert_id):
        """Delete a specific alert by ID"""
        original_count = len(self.alerts)
        self.alerts = [a for a in self.alerts if a.get('id') != alert_id]
        
        if len(self.alerts) < original_count:
            self._save_alerts()
            logging.info(f"Deleted alert: {alert_id}")
            return True
        return False
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts = []
        self._save_alerts()
        logging.info("All alerts cleared")