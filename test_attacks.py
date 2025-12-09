"""
Test Scripts for IDS Detection
Simulates various attack patterns to test IDS detection capabilities.

Run these scripts while the IDS is running to trigger alerts.
"""

import socket
import time
import requests
from scapy.all import IP, TCP, send, RandShort
import threading


def test_failed_logins(target_ip="127.0.0.1", target_port=22, count=25):
    """
    Test Failed Login Detection
    Simulates multiple failed SSH login attempts.
    
    Usage: Run this while IDS is monitoring, it will trigger failed login alerts.
    """
    print(f"[*] Testing Failed Login Detection")
    print(f"[*] Sending {count} failed login attempts to {target_ip}:{target_port}")
    
    for i in range(count):
        try:
            # Create a socket connection (simulating login attempt)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Try to connect (this will fail, simulating failed login)
            try:
                sock.connect((target_ip, target_port))
                # Send failed login message
                sock.send(b"SSH-2.0-OpenSSH_7.4\r\n")
                sock.send(b"authentication failed: invalid password\r\n")
            except:
                pass
            finally:
                sock.close()
            
            print(f"[+] Sent failed login attempt {i+1}/{count}")
            time.sleep(0.1)  # Small delay between attempts
            
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("[*] Failed login test completed")


def test_port_scan(target_ip="127.0.0.1", port_range=(8000, 8015)):
    """
    Test Port Scan Detection
    Scans multiple ports to trigger port scan detection.
    
    Usage: Run this while IDS is monitoring, it will trigger port scan alerts.
    """
    print(f"[*] Testing Port Scan Detection")
    print(f"[*] Scanning ports {port_range[0]}-{port_range[1]} on {target_ip}")
    
    open_ports = []
    
    for port in range(port_range[0], port_range[1] + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                open_ports.append(port)
                print(f"[+] Port {port} is open")
            else:
                print(f"[-] Port {port} is closed/filtered")
            
            sock.close()
            time.sleep(0.1)  # Small delay between scans
            
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")
    
    print(f"[*] Port scan completed. Found {len(open_ports)} open ports")
    return open_ports


def test_sql_injection(target_url="http://127.0.0.1:8000/login", count=6):
    """
    Test SQL Injection Detection
    Sends HTTP requests with SQL injection payloads.
    
    Usage: Run this while IDS is monitoring, it will trigger payload alerts.
    Note: You need a web server running or this will just generate network traffic.
    """
    print(f"[*] Testing SQL Injection Detection")
    print(f"[*] Sending {count} SQL injection payloads to {target_url}")
    
    sql_payloads = [
        "admin' OR '1'='1",
        "admin' OR 1=1--",
        "' UNION SELECT * FROM users--",
        "admin'; DROP TABLE users--",
        "' OR 1=1#",
        "admin' OR '1'='1'--"
    ]
    
    for i, payload in enumerate(sql_payloads[:count]):
        try:
            # Send GET request with SQL injection in parameter
            params = {'username': payload, 'password': 'test'}
            response = requests.get(target_url, params=params, timeout=2)
            print(f"[+] Sent SQL injection payload {i+1}: {payload[:30]}...")
            time.sleep(0.2)
        except requests.exceptions.RequestException:
            # Even if server doesn't exist, the packet will be captured
            print(f"[+] Sent SQL injection payload {i+1} (connection may fail): {payload[:30]}...")
            time.sleep(0.2)
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("[*] SQL injection test completed")


def test_xss(target_url="http://127.0.0.1:8000/search", count=5):
    """
    Test XSS Detection
    Sends HTTP requests with XSS payloads.
    
    Usage: Run this while IDS is monitoring, it will trigger payload alerts.
    """
    print(f"[*] Testing XSS Detection")
    print(f"[*] Sending {count} XSS payloads to {target_url}")
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<svg onload=alert('XSS')>"
    ]
    
    for i, payload in enumerate(xss_payloads[:count]):
        try:
            params = {'q': payload}
            response = requests.get(target_url, params=params, timeout=2)
            print(f"[+] Sent XSS payload {i+1}: {payload[:30]}...")
            time.sleep(0.2)
        except requests.exceptions.RequestException:
            print(f"[+] Sent XSS payload {i+1} (connection may fail): {payload[:30]}...")
            time.sleep(0.2)
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("[*] XSS test completed")


def test_ddos(target_ip="127.0.0.1", target_port=80, packet_count=150, delay=0.01):
    """
    Test DDoS Detection
    Sends a high volume of packets rapidly.
    
    Usage: Run this while IDS is monitoring, it will trigger DDoS alerts.
    WARNING: Use responsibly and only on localhost or test networks!
    """
    print(f"[*] Testing DDoS Detection")
    print(f"[*] Sending {packet_count} packets rapidly to {target_ip}:{target_port}")
    print("[!] WARNING: This generates high network traffic. Use only for testing!")
    
    sent = 0
    start_time = time.time()
    
    for i in range(packet_count):
        try:
            # Create and send TCP SYN packet
            packet = IP(dst=target_ip) / TCP(dport=target_port, sport=RandShort(), flags="S")
            send(packet, verbose=False)
            sent += 1
            
            if (i + 1) % 20 == 0:
                print(f"[+] Sent {i+1}/{packet_count} packets")
            
            time.sleep(delay)
            
        except Exception as e:
            print(f"[-] Error sending packet: {e}")
    
    elapsed = time.time() - start_time
    print(f"[*] DDoS test completed: {sent} packets sent in {elapsed:.2f} seconds")
    print(f"[*] Rate: {sent/elapsed:.2f} packets/second")


def test_command_injection(target_url="http://127.0.0.1:8000/execute", count=5):
    """
    Test Command Injection Detection
    Sends HTTP requests with command injection payloads.
    
    Usage: Run this while IDS is monitoring, it will trigger payload alerts.
    """
    print(f"[*] Testing Command Injection Detection")
    print(f"[*] Sending {count} command injection payloads to {target_url}")
    
    cmd_payloads = [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(id)",
        "; rm -rf /"
    ]
    
    for i, payload in enumerate(cmd_payloads[:count]):
        try:
            params = {'cmd': payload}
            response = requests.get(target_url, params=params, timeout=2)
            print(f"[+] Sent command injection payload {i+1}: {payload}")
            time.sleep(0.2)
        except requests.exceptions.RequestException:
            print(f"[+] Sent command injection payload {i+1} (connection may fail): {payload}")
            time.sleep(0.2)
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("[*] Command injection test completed")


def run_all_tests(target_ip="127.0.0.1"):
    """
    Run all attack tests sequentially.
    
    Usage: Run this to test all detection types.
    """
    print("=" * 60)
    print("IDS Attack Simulation Suite")
    print("=" * 60)
    print("\n[*] Starting all attack tests...")
    print("[*] Make sure IDS is running in another terminal!\n")
    
    time.sleep(2)  # Give user time to read
    
    # Test 1: Failed Logins
    print("\n" + "=" * 60)
    test_failed_logins(target_ip, target_port=22, count=25)
    time.sleep(3)
    
    # Test 2: Port Scan
    print("\n" + "=" * 60)
    test_port_scan(target_ip, port_range=(8000, 8015))
    time.sleep(3)
    
    # Test 3: SQL Injection
    print("\n" + "=" * 60)
    test_sql_injection(f"http://{target_ip}:8000/login", count=6)
    time.sleep(3)
    
    # Test 4: XSS
    print("\n" + "=" * 60)
    test_xss(f"http://{target_ip}:8000/search", count=5)
    time.sleep(3)
    
    # Test 5: Command Injection
    print("\n" + "=" * 60)
    test_command_injection(f"http://{target_ip}:8000/execute", count=5)
    time.sleep(3)
    
    # Test 6: DDoS (last, as it's most aggressive)
    print("\n" + "=" * 60)
    test_ddos(target_ip, target_port=80, packet_count=150, delay=0.01)
    
    print("\n" + "=" * 60)
    print("[*] All tests completed!")
    print("[*] Check your IDS dashboard and logs for alerts.")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        test_type = sys.argv[1].lower()
        target = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        
        if test_type == "failed_login":
            test_failed_logins(target, count=25)
        elif test_type == "port_scan":
            test_port_scan(target, port_range=(8000, 8015))
        elif test_type == "sql":
            test_sql_injection(f"http://{target}:8000/login", count=6)
        elif test_type == "xss":
            test_xss(f"http://{target}:8000/search", count=5)
        elif test_type == "ddos":
            test_ddos(target, packet_count=150)
        elif test_type == "cmd":
            test_command_injection(f"http://{target}:8000/execute", count=5)
        else:
            print("Unknown test type. Use: failed_login, port_scan, sql, xss, ddos, cmd")
    else:
        # Run all tests
        run_all_tests()

