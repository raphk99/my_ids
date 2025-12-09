"""
Detection Rule Definitions
Defines various rule classes for detecting different types of attacks.
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict


class BaseRule:
    """Base class for all detection rules."""
    
    def __init__(self, name, threshold, time_window, severity='MEDIUM'):
        """
        Initialize base rule.
        
        Args:
            name: Rule name
            threshold: Number of events to trigger alert
            time_window: Time window in seconds
            severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
        """
        self.name = name
        self.threshold = threshold
        self.time_window = time_window
        self.severity = severity
        self.events = defaultdict(list)  # Track events by source IP
    
    def check(self, packet_info):
        """
        Check if packet matches rule criteria.
        
        Args:
            packet_info: Dictionary with packet information
            
        Returns:
            Alert dictionary if rule triggered, None otherwise
        """
        raise NotImplementedError("Subclasses must implement check method")
    
    def _clean_old_events(self, source_key):
        """Remove events outside the time window."""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        
        self.events[source_key] = [
            event_time for event_time in self.events[source_key]
            if event_time > cutoff_time
        ]
    
    def _add_event(self, source_key):
        """Add an event for the given source."""
        self.events[source_key].append(datetime.now())
        self._clean_old_events(source_key)
    
    def _check_threshold(self, source_key):
        """Check if threshold is exceeded for given source."""
        self._clean_old_events(source_key)
        return len(self.events[source_key]) >= self.threshold


class FailedLoginRule(BaseRule):
    """Detects multiple failed login attempts."""
    
    # Common failed login indicators
    FAILED_LOGIN_PATTERNS = [
        r'failed.*login',
        r'authentication.*failed',
        r'access.*denied',
        r'invalid.*password',
        r'login.*failed',
        r'authentication.*failure',
        r'incorrect.*password',
        r'wrong.*password',
        r'permission.*denied',
        r'access.*refused'
    ]
    
    # Common ports for authentication
    AUTH_PORTS = [22, 21, 23, 80, 443, 3306, 5432, 1433]
    
    def __init__(self, threshold=20, time_window=60, severity='HIGH'):
        super().__init__(
            name='Failed Login Attempts',
            threshold=threshold,
            time_window=time_window,
            severity=severity
        )
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.FAILED_LOGIN_PATTERNS]
    
    def check(self, packet_info):
        """Check for failed login attempts."""
        if not packet_info.get('src_ip') or not packet_info.get('dst_port'):
            return None
        
        # Check if packet is on an authentication port
        if packet_info['dst_port'] not in self.AUTH_PORTS:
            return None
        
        # Check payload for failed login patterns
        payload = packet_info.get('payload', '')
        if not payload:
            return None
        
        # Check if payload matches failed login patterns
        for pattern in self.patterns:
            if pattern.search(payload):
                source_key = packet_info['src_ip']
                self._add_event(source_key)
                
                if self._check_threshold(source_key):
                    return {
                        'rule_name': self.name,
                        'severity': self.severity,
                        'src_ip': packet_info['src_ip'],
                        'dst_ip': packet_info.get('dst_ip'),
                        'dst_port': packet_info['dst_port'],
                        'event_count': len(self.events[source_key]),
                        'message': f"Multiple failed login attempts detected from {packet_info['src_ip']}"
                    }
        
        return None


class PortScanRule(BaseRule):
    """Detects port scanning activity."""
    
    def __init__(self, threshold=10, time_window=60, severity='MEDIUM'):
        super().__init__(
            name='Port Scan',
            threshold=threshold,
            time_window=time_window,
            severity=severity
        )
        self.scan_tracker = defaultdict(set)  # Track unique ports per source IP
    
    def check(self, packet_info):
        """Check for port scanning patterns."""
        if not packet_info.get('src_ip') or not packet_info.get('dst_port'):
            return None
        
        # Only track TCP SYN packets (connection attempts)
        # TCP flags: SYN=2 (0x02). We want SYN without ACK for port scanning
        flags = packet_info.get('flags')
        if flags is None:
            return None
        # Check if SYN flag is set (bit 1) and ACK is not set (bit 4)
        # SYN=2, SYN+ACK=18, so we want flags == 2
        if flags != 2:  # SYN flag only (new connection attempt)
            return None
        
        source_key = packet_info['src_ip']
        dst_port = packet_info['dst_port']
        
        # Track unique ports accessed by this source
        self.scan_tracker[source_key].add(dst_port)
        self._add_event(source_key)
        
        # Check if threshold exceeded
        if self._check_threshold(source_key):
            unique_ports = len(self.scan_tracker[source_key])
            if unique_ports >= self.threshold:
                return {
                    'rule_name': self.name,
                    'severity': self.severity,
                    'src_ip': packet_info['src_ip'],
                    'dst_ip': packet_info.get('dst_ip'),
                    'unique_ports': unique_ports,
                    'event_count': len(self.events[source_key]),
                    'message': f"Port scan detected from {packet_info['src_ip']} ({unique_ports} unique ports)"
                }
        
        return None


class PayloadRule(BaseRule):
    """Detects suspicious payload patterns (SQL injection, XSS, etc.)."""
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"('|(\\')|(;)|(\\;)|(\|)|(\\|))?\s*(or|and)\s+.*(=|>|<|!=)",
        r"union\s+.*select",
        r"exec\s*\(|execute\s*\(",
        r"drop\s+table|delete\s+from|insert\s+into",
        r"1\s*=\s*1|1\s*=\s*'1",
        r"';.*--|/\*.*\*/"
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"<iframe[^>]*>",
        r"<img[^>]*onerror",
        r"eval\s*\(",
        r"alert\s*\("
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r";\s*(rm|cat|ls|pwd|whoami|id|uname)",
        r"\|\s*(rm|cat|ls|pwd|whoami|id|uname)",
        r"`.*`",
        r"\$\(.*\)"
    ]
    
    def __init__(self, threshold=5, time_window=300, severity='HIGH'):
        super().__init__(
            name='Suspicious Payload',
            threshold=threshold,
            time_window=time_window,
            severity=severity
        )
        self.sql_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS]
        self.xss_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.XSS_PATTERNS]
        self.cmd_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.COMMAND_INJECTION_PATTERNS]
    
    def check(self, packet_info):
        """Check for suspicious payload patterns."""
        payload = packet_info.get('payload', '')
        if not payload:
            return None
        
        attack_type = None
        
        # Check for SQL injection
        for pattern in self.sql_patterns:
            if pattern.search(payload):
                attack_type = 'SQL Injection'
                break
        
        # Check for XSS
        if not attack_type:
            for pattern in self.xss_patterns:
                if pattern.search(payload):
                    attack_type = 'XSS'
                    break
        
        # Check for command injection
        if not attack_type:
            for pattern in self.cmd_patterns:
                if pattern.search(payload):
                    attack_type = 'Command Injection'
                    break
        
        if attack_type:
            source_key = packet_info.get('src_ip', 'unknown')
            self._add_event(source_key)
            
            if self._check_threshold(source_key):
                return {
                    'rule_name': self.name,
                    'severity': self.severity,
                    'src_ip': packet_info.get('src_ip'),
                    'dst_ip': packet_info.get('dst_ip'),
                    'attack_type': attack_type,
                    'event_count': len(self.events[source_key]),
                    'message': f"{attack_type} attempt detected from {packet_info.get('src_ip', 'unknown')}"
                }
        
        return None


class DDoSRule(BaseRule):
    """Detects DDoS patterns (high packet rate from single source)."""
    
    def __init__(self, threshold=100, time_window=10, severity='CRITICAL'):
        super().__init__(
            name='DDoS Attack',
            threshold=threshold,
            time_window=time_window,
            severity=severity
        )
    
    def check(self, packet_info):
        """Check for DDoS patterns."""
        if not packet_info.get('src_ip'):
            return None
        
        source_key = packet_info['src_ip']
        self._add_event(source_key)
        
        if self._check_threshold(source_key):
            return {
                'rule_name': self.name,
                'severity': self.severity,
                'src_ip': packet_info['src_ip'],
                'dst_ip': packet_info.get('dst_ip'),
                'packet_rate': len(self.events[source_key]),
                'event_count': len(self.events[source_key]),
                'message': f"High packet rate detected from {packet_info['src_ip']} ({len(self.events[source_key])} packets in {self.time_window}s)"
            }
        
        return None

