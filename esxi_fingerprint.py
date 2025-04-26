
#!/usr/bin/env python3
import argparse
import re
import requests
import warnings


"""
VMware ESX/ESXi Fingerprint Scanner

Author: Alejandro Baño
Reference: Based on Rapid7 Metasploit module
  auxiliary/scanner/http/vmware_esx_fingerprint_scanner.rb
  (https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/http/vmware_esx_fingerprint_scanner.rb)
License: MIT
"""

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def fingerprint_vmware(ip, port, response_text):
    """
    Process the SOAP response and extract version information.
    Verifies that the response comes from a VMware service and
    pulls out the <name>, <version>, <build>, and <fullName> details.
    """
    if not response_text:
        print(f"[ERROR] http://{ip}:{port} - No response received")
        return False

    if "<vendor>VMware, Inc.</vendor>" not in response_text:
        print(f"[ERROR] http://{ip}:{port} - Response does not appear to be from VMware")
        return False

    os_match    = re.search(r'<name>([\w\s]+)</name>', response_text)
    ver_match   = re.search(r'<version>([\w\s\.]+)</version>', response_text)
    build_match = re.search(r'<build>([\w\s\.\-]+)</build>', response_text)
    full_match  = re.search(r'<fullName>([\w\s\.\-]+)</fullName>', response_text)

    if full_match:
        print(f"\n[+] {ip}:{port} - Identified: {full_match.group(1)}\n")

    if os_match and ver_match and build_match:
        os_info    = os_match.group(1)
        ver_info   = ver_match.group(1)
        build_info = build_match.group(1)
        if "ESX" in os_info or "vCenter" in os_info:
            print(f"[SUCCESS] Fingerprint: {os_info} {ver_info} (build {build_info})")
        return True
    else:
        print(f"[ERROR] http://{ip}:{port} - Could not correctly identify VMware ESXi Version")
        return False

def run_host(ip, port=443, uri="/sdk"):

    soap_data = ( '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        'xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<env:Body>'
                '<RetrieveServiceContent xmlns="urn:vim25">'
                    '<_this type="ServiceInstance">ServiceInstance</_this>'
                '</RetrieveServiceContent>'
            '</env:Body>'
        '</env:Envelope>'
    )

    url = f"https://{ip}:{port}{uri}"
    headers = {
            "SOAPAction": "",  
            "Content-Type": "text/xml"
    }
    try:
        response = requests.post(url, data=soap_data, headers=headers, verify=False, timeout=25)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] http://{ip}:{port}{uri} - {e}")
        return False

    return fingerprint_vmware(ip, port, response.text)

def main():
    parser = argparse.ArgumentParser(description="VMware ESX/ESXi fingerprint scanner")
    parser.add_argument("ip", help="Target host IP address")
    parser.add_argument("--port", type=int, default=443, help="Target port (default: 443)", required=True)
    parser.add_argument("--uri", type=str, default="/sdk", help="URI path to test (default: /sdk)")
    args = parser.parse_args()

    run_host(args.ip, args.port, args.uri)

if __name__ == "__main__":
    main()
