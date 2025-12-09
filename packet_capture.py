"""
Packet Capture Module
Captures live network packets using scapy and passes them to the detection engine.
"""

import threading
from scapy.all import sniff, get_if_list, get_if_addr
from scapy.layers.inet import IP, TCP, UDP, ICMP


class PacketCapture:
    """Handles live packet capture from network interfaces."""
    
    def __init__(self, interface=None, callback=None):
        """
        Initialize packet capture.
        
        Args:
            interface: Network interface name (None for default)
            callback: Function to call with each captured packet
        """
        self.interface = interface
        self.callback = callback
        self.running = False
        self.capture_thread = None
        self.packet_count = 0
        
    def _packet_handler(self, packet):
        """Process each captured packet."""
        if not self.running:
            return
            
        self.packet_count += 1
        
        # Extract packet information
        packet_info = self._extract_packet_info(packet)
        
        if packet_info and self.callback:
            self.callback(packet_info)
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from packet."""
        packet_info = {
            'timestamp': float(packet.time),
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'flags': None,
            'payload': None,
            'packet_size': len(packet)
        }
        
        # Extract IP layer information
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto
            
            # Extract TCP layer information
            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = packet[TCP].flags
                
                # Extract payload if available
                if packet[TCP].payload:
                    try:
                        payload = bytes(packet[TCP].payload)
                        # Limit payload size for analysis (first 1024 bytes)
                        packet_info['payload'] = payload[:1024].decode('utf-8', errors='ignore')
                    except:
                        packet_info['payload'] = None
            
            # Extract UDP layer information
            elif UDP in packet:
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
                # Extract payload if available
                if packet[UDP].payload:
                    try:
                        payload = bytes(packet[UDP].payload)
                        packet_info['payload'] = payload[:1024].decode('utf-8', errors='ignore')
                    except:
                        packet_info['payload'] = None
            
            # Extract ICMP layer information
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
        
        return packet_info
    
    def start(self):
        """Start packet capture in a separate thread."""
        if self.running:
            return
        
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
    
    def _capture_loop(self):
        """Main capture loop running in separate thread."""
        try:
            # Filter for IP packets (TCP, UDP, ICMP)
            filter_str = "ip"
            
            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=self._packet_handler,
                stop_filter=lambda x: not self.running,
                store=False  # Don't store packets in memory
            )
        except Exception as e:
            print(f"Error in packet capture: {e}")
            self.running = False
    
    def stop(self):
        """Stop packet capture."""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def get_statistics(self):
        """Get capture statistics."""
        return {
            'packet_count': self.packet_count,
            'running': self.running
        }
    
    @staticmethod
    def list_interfaces():
        """List available network interfaces."""
        return get_if_list()
    
    @staticmethod
    def get_interface_ip(interface):
        """Get IP address of a network interface."""
        try:
            return get_if_addr(interface)
        except:
            return None

