"""
Logging System
Provides dual-format logging (JSON and plain text) for alerts.
"""

import json
import os
from datetime import datetime
import threading


class IDSLogger:
    """Dual-format logger for IDS alerts."""
    
    def __init__(self, json_log_path='logs/alerts.json', text_log_path='logs/alerts.log'):
        """
        Initialize logger with file paths.
        
        Args:
            json_log_path: Path to JSON log file
            text_log_path: Path to text log file
        """
        self.json_log_path = json_log_path
        self.text_log_path = text_log_path
        self.lock = threading.Lock()
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(json_log_path), exist_ok=True)
        os.makedirs(os.path.dirname(text_log_path), exist_ok=True)
    
    def log_alert(self, alert):
        """
        Log an alert in both JSON and text formats.
        
        Args:
            alert: Dictionary containing alert information
        """
        with self.lock:
            # Add timestamp if not present
            if 'timestamp' not in alert:
                alert['timestamp'] = datetime.now().timestamp()
            
            # Format timestamp for display
            alert_time = datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            
            # Log to JSON file
            self._log_json(alert)
            
            # Log to text file
            self._log_text(alert, alert_time)
    
    def _log_json(self, alert):
        """Log alert to JSON file."""
        try:
            # Create a copy to avoid modifying original
            log_entry = alert.copy()
            
            # Ensure timestamp is serializable
            if 'timestamp' in log_entry:
                log_entry['timestamp'] = float(log_entry['timestamp'])
            
            with open(self.json_log_path, 'a', encoding='utf-8') as f:
                json.dump(log_entry, f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            print(f"Error writing JSON log: {e}")
    
    def _log_text(self, alert, alert_time):
        """Log alert to text file in human-readable format."""
        try:
            with open(self.text_log_path, 'a', encoding='utf-8') as f:
                f.write(f"[{alert_time}] ")
                f.write(f"SEVERITY: {alert.get('severity', 'UNKNOWN')} | ")
                f.write(f"RULE: {alert.get('rule_name', 'Unknown')} | ")
                f.write(f"SOURCE: {alert.get('src_ip', 'Unknown')} | ")
                
                if alert.get('dst_ip'):
                    f.write(f"DEST: {alert.get('dst_ip')} | ")
                
                if alert.get('dst_port'):
                    f.write(f"PORT: {alert.get('dst_port')} | ")
                
                if alert.get('attack_type'):
                    f.write(f"ATTACK TYPE: {alert.get('attack_type')} | ")
                
                if alert.get('event_count'):
                    f.write(f"EVENTS: {alert.get('event_count')} | ")
                
                if alert.get('message'):
                    f.write(f"MESSAGE: {alert.get('message')}")
                
                f.write('\n')
        except Exception as e:
            print(f"Error writing text log: {e}")
    
    def log_multiple(self, alerts):
        """Log multiple alerts."""
        for alert in alerts:
            self.log_alert(alert)

