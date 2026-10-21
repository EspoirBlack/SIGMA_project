# Windows Event Log Collector Module - Enhanced Version

import win32evtlog
import win32evtlogutil
from datetime import datetime, timedelta
import logging

class LogCollector:
    def __init__(self):
        #self.log_types = ['System', 'Security', 'Application']
        self.log_types = ['Security', 'System', 'Application', 'Microsoft-Windows-DriverFrameworks-UserMode/Operational']
        self.cached_logs = []
        logging.basicConfig(level=logging.INFO)
        
    def collect_logs(self, log_type='System', hours_back=24):
        # Collect Windows event logs
        logs = []
        
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                log_entry = {
                    'timestamp': event.TimeGenerated.Format(),
                    'source': event.SourceName,
                    'event_id': event.EventID & 0x3FFFFFFF,
                    'category': event.EventCategory,
                    'type': event.EventType,
                    'computer': event.ComputerName,
                    'log_type': log_type
                }
                
                try:
                    description = win32evtlogutil.SafeFormatMessage(event, log_type)
                    log_entry['description'] = description
                except:
                    if event.StringInserts:
                        log_entry['description'] = ' '.join(event.StringInserts)
                    else:
                        log_entry['description'] = 'No description available'
                
                logs.append(log_entry)
                
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            print(f"Error collecting {log_type} logs: {e}")
            return []
        
        return logs
    
    def collect_all_logs(self, hours_back=24):
        """Collect logs from all sources"""
        all_logs = []
        for log_type in self.log_types:
            logs = self.collect_logs(log_type, hours_back)
            all_logs.extend(logs)
        
        all_logs.sort(key=lambda x: x['timestamp'], reverse=True)
        return all_logs
    
    def get_failed_logins(self, hours_back=24):
        """Get failed login events"""
        logs = self.collect_logs('Security', hours_back)
        return [log for log in logs if log.get('event_id') == 4625]
    
    def get_successful_logins(self, hours_back=24):
        """Get successful login events"""
        logs = self.collect_logs('Security', hours_back)
        return [log for log in logs if log.get('event_id') == 4624]
    
    def get_process_creation(self, hours_back=24):
        """Get process creation events"""
        logs = self.collect_logs('Security', hours_back)
        return [log for log in logs if log.get('event_id') == 4688]
    
    def search_logs(self, keyword=None, event_id=None, source=None, hours_back=24):
        """Search logs with filters"""
        logs = self.collect_all_logs(hours_back)
        
        filtered = []
        for log in logs:
            matches = True
            if keyword and keyword.lower() not in log.get('description', '').lower():
                matches = False
            if event_id and log.get('event_id') != event_id:
                matches = False
            if source and source.lower() != log.get('source', '').lower():
                matches = False
            if matches:
                filtered.append(log)
        
        return filtered
