# VMware ESX/ESXi Fingerprint Scanner

Sends a SOAP request to a VMware ESX/ESXi host and extracts version and build information.

## Requirements

- Python 3.6 or higher  
- `requests` library  

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/ace00k/ESXi-Fingerprint.git
   cd ESXi-Fingerprint
   ```
2. (Optional) Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install requests
   ```
## Usage

```bash
python3 esxi_fingerprint.py <ip> [--port PORT] [--uri URI]
```

Arguments:

- `<ip>`  
- `--port` (default: 443)  
- `--uri` (default: `/sdk`)  

## Example

```bash
python3 esxi_fingerprint.py 192.168.1.100 --port 443 --uri /sdk
```

## How It Works

1. Builds a SOAP envelope for the `RetrieveServiceContent` call.  
2. Sends a POST request to `https://<ip>:<port><uri>` without SSL verification.  
3. Parses the XML response for:
   - `<vendor>`  
   - `<name>`  
   - `<version>`  
   - `<build>`  
   - `<fullName>`  
4. Prints out identification results or errors.

**Reference:** Rapid7 Metasploit module `auxiliary/scanner/http/vmware_esx_fingerprint_scanner.rb`
