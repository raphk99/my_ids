# IDS (Intrusion Detection System)

A comprehensive Python-based Intrusion Detection System with live packet capture, multiple detection rules, dual-format logging, and a real-time terminal dashboard.

## Features

- **Live Packet Capture**: Real-time network traffic monitoring using scapy
- **Multiple Detection Types**:
  - Failed login attempts (20+ in 1 minute)
  - Port scan detection
  - Suspicious payload patterns (SQL injection, XSS)
  - DDoS pattern detection
- **Dual Logging**: JSON and plain text formats
- **Terminal Dashboard**: Real-time visualization with rich library

## Installation

1. Create and activate a virtual environment:

   **Windows:**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

   **Linux/Mac:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. **Note**: On Linux, you may need root privileges for packet capture:
```bash
sudo python main.py
```

On Windows, you may need to install Npcap (WinPcap successor) for scapy to work.

## Usage

Make sure your virtual environment is activated, then:

```bash
python main.py
```

The system will:
- Start capturing packets from the default network interface
- Display a real-time terminal dashboard
- Log alerts to `logs/alerts.json` and `logs/alerts.log`
- Apply detection rules defined in `config.yaml`

Press `Ctrl+C` to stop gracefully.

## Configuration

Edit `config.yaml` to customize:
- Detection rule thresholds
- Log file paths
- Network interface selection
- Dashboard refresh rate

## Testing the IDS

To test the IDS and trigger detection alerts, use the provided test scripts:

### Quick Test

1. **Start the IDS** in one terminal:
   ```bash
   python main.py
   ```

2. **Run attack simulations** in another terminal:
   ```bash
   # Test all attack types
   python test_attacks.py
   
   # Or test individual attack types
   python test_attacks.py failed_login
   python test_attacks.py port_scan
   python test_attacks.py sql
   python test_attacks.py xss
   python test_attacks.py ddos
   ```

3. **Observe alerts** in the IDS dashboard

See [TESTING.md](TESTING.md) for detailed testing instructions and examples.

## Project Structure

```
ids/
├── main.py                 # Entry point and orchestrator
├── packet_capture.py       # Live packet capture
├── detection_engine.py     # Rule evaluation
├── rules.py                # Detection rule definitions
├── logger.py               # Dual-format logging
├── dashboard.py             # Terminal UI
├── config.yaml             # Configuration file
├── requirements.txt        # Python dependencies
├── venv/                   # Virtual environment (not in repo)
└── logs/                   # Log files directory
```

## Requirements

- Python 3.7+
- Network interface with packet capture capabilities
- Administrator/root privileges (Linux) or Npcap (Windows)

