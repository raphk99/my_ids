# IDS Testing Guide

This guide explains how to test each detection rule in the IDS system.

## Prerequisites

1. **Start the IDS** in one terminal:
   ```bash
   python main.py
   ```

2. **Install test dependencies** (if not already installed):
   ```bash
   pip install requests
   ```

## Testing Individual Detection Rules

### 1. Failed Login Detection

**What it detects:** Multiple failed authentication attempts (default: 20+ in 1 minute)

**How to test:**

```bash
# Using the test script
python test_attacks.py failed_login

# Or manually with Python
python -c "
import socket, time
for i in range(25):
    try:
        s = socket.socket()
        s.connect(('127.0.0.1', 22))
        s.send(b'authentication failed: invalid password\r\n')
        s.close()
    except: pass
    time.sleep(0.1)
"
```

**Expected result:** After 20+ failed attempts, you should see a HIGH severity alert for "Failed Login Attempts" in the dashboard.

**Lower threshold for faster testing:** Edit `config.yaml`:
```yaml
rules:
  failed_login:
    threshold: 5  # Lower from 20 to 5 for faster testing
    time_window: 60
```

---

### 2. Port Scan Detection

**What it detects:** Rapid connection attempts to multiple different ports (default: 10+ unique ports in 1 minute)

**How to test:**

```bash
# Using the test script
python test_attacks.py port_scan

# Or manually with nmap (if installed)
nmap -p 8000-8015 127.0.0.1

# Or with Python
python -c "
import socket
for port in range(8000, 8015):
    s = socket.socket()
    s.settimeout(0.5)
    s.connect_ex(('127.0.0.1', port))
    s.close()
"
```

**Expected result:** After scanning 10+ different ports, you should see a MEDIUM severity alert for "Port Scan" in the dashboard.

**Lower threshold for faster testing:** Edit `config.yaml`:
```yaml
rules:
  port_scan:
    threshold: 5  # Lower from 10 to 5
```

---

### 3. SQL Injection Detection

**What it detects:** SQL injection patterns in packet payloads (default: 5+ matches in 5 minutes)

**How to test:**

```bash
# Using the test script
python test_attacks.py sql

# Or manually with curl
curl "http://127.0.0.1:8000/login?username=admin' OR '1'='1&password=test"
curl "http://127.0.0.1:8000/login?username=admin' OR 1=1--&password=test"
curl "http://127.0.0.1:8000/login?username=' UNION SELECT * FROM users--&password=test"
```

**Expected result:** After 5+ SQL injection attempts, you should see a HIGH severity alert for "Suspicious Payload" with attack type "SQL Injection".

**Note:** Even if the web server doesn't exist, the packets will be captured and analyzed.

---

### 4. XSS Detection

**What it detects:** Cross-site scripting patterns in packet payloads (default: 5+ matches in 5 minutes)

**How to test:**

```bash
# Using the test script
python test_attacks.py xss

# Or manually with curl
curl "http://127.0.0.1:8000/search?q=<script>alert('XSS')</script>"
curl "http://127.0.0.1:8000/search?q=<img src=x onerror=alert('XSS')>"
```

**Expected result:** After 5+ XSS attempts, you should see a HIGH severity alert for "Suspicious Payload" with attack type "XSS".

---

### 5. Command Injection Detection

**What it detects:** Command injection patterns in packet payloads (default: 5+ matches in 5 minutes)

**How to test:**

```bash
# Using the test script
python test_attacks.py cmd

# Or manually with curl
curl "http://127.0.0.1:8000/execute?cmd=; ls -la"
curl "http://127.0.0.1:8000/execute?cmd=| cat /etc/passwd"
```

**Expected result:** After 5+ command injection attempts, you should see a HIGH severity alert for "Suspicious Payload" with attack type "Command Injection".

---

### 6. DDoS Detection

**What it detects:** High packet rate from a single source (default: 100+ packets in 10 seconds)

**How to test:**

```bash
# Using the test script
python test_attacks.py ddos

# WARNING: This generates high network traffic!
# Only use on localhost or test networks
```

**Expected result:** After sending 100+ packets rapidly, you should see a CRITICAL severity alert for "DDoS Attack".

**Lower threshold for faster testing:** Edit `config.yaml`:
```yaml
rules:
  ddos:
    threshold: 50  # Lower from 100 to 50
    time_window: 10
```

---

## Running All Tests

To test all detection types sequentially:

```bash
python test_attacks.py
```

This will run all attack simulations one after another, giving you time to observe each alert in the IDS dashboard.

## Quick Testing Setup

For faster testing, you can temporarily lower thresholds in `config.yaml`:

```yaml
rules:
  failed_login:
    threshold: 5      # Lower from 20
    time_window: 30   # Lower from 60
  
  port_scan:
    threshold: 5     # Lower from 10
  
  payload:
    threshold: 3     # Lower from 5
  
  ddos:
    threshold: 50    # Lower from 100
    time_window: 5   # Lower from 10
```

**Remember to restore original values after testing!**

## Monitoring Results

While tests are running, watch the IDS dashboard for:

1. **Real-time alerts** in the "Recent Alerts" panel
2. **Statistics** showing total alerts and rule breakdowns
3. **Severity breakdown** showing alert counts by severity
4. **Top sources** showing which IPs triggered the most alerts

Check log files:
- `logs/alerts.json` - Structured JSON logs
- `logs/alerts.log` - Human-readable text logs

## Troubleshooting

**No alerts appearing?**
- Make sure IDS is running and capturing packets
- Check that you're sending enough traffic to exceed thresholds
- Verify the network interface is correct in `config.yaml`
- On Windows, ensure Npcap is installed
- On Linux, run with `sudo` for packet capture

**Alerts appearing too slowly?**
- Lower the thresholds in `config.yaml` temporarily
- Reduce `time_window` values for faster detection
- Increase the attack rate in test scripts

**Can't capture packets?**
- Windows: Install Npcap from https://npcap.com/
- Linux: Run with `sudo python main.py`
- Check available interfaces: `python -c "from scapy.all import get_if_list; print(get_if_list())"`

## Example Test Session

1. **Terminal 1** - Start IDS:
   ```bash
   python main.py
   ```

2. **Terminal 2** - Run tests:
   ```bash
   # Test failed logins
   python test_attacks.py failed_login
   
   # Wait a few seconds, then test port scan
   python test_attacks.py port_scan
   
   # Test SQL injection
   python test_attacks.py sql
   ```

3. **Observe** the IDS dashboard in Terminal 1 for real-time alerts

4. **Check logs**:
   ```bash
   cat logs/alerts.log
   cat logs/alerts.json
   ```

