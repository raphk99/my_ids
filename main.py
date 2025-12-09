"""
IDS Main Entry Point
Orchestrates all components and manages the IDS system.
"""

import signal
import sys
import yaml
import os
from packet_capture import PacketCapture
from detection_engine import DetectionEngine
from logger import IDSLogger
from dashboard import IDSDashboard


class IDS:
    """Main IDS orchestrator."""
    
    def __init__(self, config_path='config.yaml'):
        """Initialize IDS system."""
        self.config = self._load_config(config_path)
        self.packet_capture = None
        self.detection_engine = None
        self.logger = None
        self.dashboard = None
        self.running = False
    
    def _load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Warning: Config file {config_path} not found. Using defaults.")
            return {}
        except yaml.YAMLError as e:
            print(f"Error parsing config file: {e}")
            return {}
    
    def _packet_callback(self, packet_info):
        """Callback for processed packets."""
        if not self.running:
            return
        
        # Process packet through detection engine
        alerts = self.detection_engine.process_packet(packet_info)
        
        # Log alerts
        if alerts:
            self.logger.log_multiple(alerts)
    
    def start(self):
        """Start the IDS system."""
        print("Initializing IDS System...")
        
        # Initialize components
        network_config = self.config.get('network', {})
        interface = network_config.get('interface')
        
        # Initialize packet capture
        self.packet_capture = PacketCapture(
            interface=interface,
            callback=self._packet_callback
        )
        
        # Initialize detection engine
        self.detection_engine = DetectionEngine(config=self.config)
        
        # Initialize logger
        logging_config = self.config.get('logging', {})
        self.logger = IDSLogger(
            json_log_path=logging_config.get('json_log_path', 'logs/alerts.json'),
            text_log_path=logging_config.get('text_log_path', 'logs/alerts.log')
        )
        
        # Initialize dashboard
        dashboard_config = self.config.get('dashboard', {})
        self.dashboard = IDSDashboard(
            detection_engine=self.detection_engine,
            packet_capture=self.packet_capture,
            refresh_rate=dashboard_config.get('refresh_rate', 1)
        )
        
        # Display interface information
        if interface:
            print(f"Using network interface: {interface}")
        else:
            interfaces = PacketCapture.list_interfaces()
            print(f"Using default interface. Available interfaces: {', '.join(interfaces)}")
        
        print("Starting packet capture...")
        self.packet_capture.start()
        
        self.running = True
        print("IDS System started. Press Ctrl+C to stop.\n")
        
        # Start dashboard (blocks until stopped)
        try:
            self.dashboard.start()
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the IDS system gracefully."""
        if not self.running:
            return
        
        print("\n\nStopping IDS System...")
        self.running = False
        
        if self.packet_capture:
            self.packet_capture.stop()
        
        if self.dashboard:
            self.dashboard.stop()
        
        print("IDS System stopped.")
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals."""
        self.stop()
        sys.exit(0)


def main():
    """Main entry point."""
    # Check if running as root/admin (recommended for packet capture)
    if os.name == 'posix' and os.geteuid() != 0:
        print("Warning: Running without root privileges. Packet capture may be limited.")
        print("Consider running with: sudo python main.py\n")
    
    # Create IDS instance
    ids = IDS()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, ids._signal_handler)
    signal.signal(signal.SIGTERM, ids._signal_handler)
    
    # Start IDS
    try:
        ids.start()
    except Exception as e:
        print(f"Error starting IDS: {e}")
        ids.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()

