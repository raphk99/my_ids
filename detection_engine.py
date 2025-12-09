"""
Detection Engine
Evaluates packets against detection rules and generates alerts.
"""

from rules import FailedLoginRule, PortScanRule, PayloadRule, DDoSRule
import threading
from collections import deque


class DetectionEngine:
    """Main detection engine that evaluates packets against rules."""
    
    def __init__(self, config=None):
        """
        Initialize detection engine with rules.
        
        Args:
            config: Configuration dictionary with rule settings
        """
        self.config = config or {}
        self.rules = []
        self.alerts = deque(maxlen=1000)  # Keep last 1000 alerts in memory
        self.alert_lock = threading.Lock()
        self.total_alerts = 0
        
        # Initialize rules with config or defaults
        self._initialize_rules()
    
    def _initialize_rules(self):
        """Initialize detection rules from config."""
        rules_config = self.config.get('rules', {})
        
        # Failed Login Rule
        failed_login_config = rules_config.get('failed_login', {})
        self.rules.append(FailedLoginRule(
            threshold=failed_login_config.get('threshold', 20),
            time_window=failed_login_config.get('time_window', 60),
            severity=failed_login_config.get('severity', 'HIGH')
        ))
        
        # Port Scan Rule
        port_scan_config = rules_config.get('port_scan', {})
        self.rules.append(PortScanRule(
            threshold=port_scan_config.get('threshold', 10),
            time_window=port_scan_config.get('time_window', 60),
            severity=port_scan_config.get('severity', 'MEDIUM')
        ))
        
        # Payload Rule
        payload_config = rules_config.get('payload', {})
        self.rules.append(PayloadRule(
            threshold=payload_config.get('threshold', 5),
            time_window=payload_config.get('time_window', 300),
            severity=payload_config.get('severity', 'HIGH')
        ))
        
        # DDoS Rule
        ddos_config = rules_config.get('ddos', {})
        self.rules.append(DDoSRule(
            threshold=ddos_config.get('threshold', 100),
            time_window=ddos_config.get('time_window', 10),
            severity=ddos_config.get('severity', 'CRITICAL')
        ))
    
    def process_packet(self, packet_info):
        """
        Process a packet through all detection rules.
        
        Args:
            packet_info: Dictionary with packet information
            
        Returns:
            List of alerts generated (if any)
        """
        alerts = []
        
        for rule in self.rules:
            try:
                alert = rule.check(packet_info)
                if alert:
                    alert['timestamp'] = packet_info.get('timestamp')
                    alerts.append(alert)
            except Exception as e:
                # Log rule evaluation errors but continue processing
                print(f"Error evaluating rule {rule.name}: {e}")
        
        # Store alerts
        if alerts:
            with self.alert_lock:
                for alert in alerts:
                    self.alerts.append(alert)
                    self.total_alerts += 1
        
        return alerts
    
    def get_recent_alerts(self, count=10):
        """Get the most recent alerts."""
        with self.alert_lock:
            return list(self.alerts)[-count:]
    
    def get_statistics(self):
        """Get detection statistics."""
        with self.alert_lock:
            # Count alerts by rule type
            rule_counts = {}
            severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
            source_ips = {}
            
            for alert in self.alerts:
                rule_name = alert.get('rule_name', 'Unknown')
                rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
                
                severity = alert.get('severity', 'MEDIUM')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                src_ip = alert.get('src_ip', 'Unknown')
                source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
            
            # Get top sources
            top_sources = sorted(
                source_ips.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            return {
                'total_alerts': self.total_alerts,
                'rule_counts': rule_counts,
                'severity_counts': severity_counts,
                'top_sources': top_sources,
                'active_rules': len(self.rules)
            }

