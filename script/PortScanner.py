#!/usr/bin/env python3
import socket
import nmap
import sys

# ... (PORT_ANALYSIS dictionary remains the same) ...
PORT_ANALYSIS = {
    21: {"service": "FTP", "purpose": "...", "risk": "..."},
    22: {"service": "SSH", "purpose": "...", "risk": "..."},
    23: {"service": "Telnet", "purpose": "...", "risk": "..."},
    25: {"service": "SMTP", "purpose": "...", "risk": "..."},
    80: {"service": "HTTP", "purpose": "...", "risk": "..."},
    443: {"service": "HTTPS", "purpose": "...", "risk": "..."},
    445: {"service": "SMB", "purpose": "...", "risk": "..."},
    3306: {"service": "MySQL", "purpose": "...", "risk": "..."},
    3389: {"service": "RDP", "purpose": "...", "risk": "..."},
    8080: {"service": "HTTP Alternate", "purpose": "...", "risk": "..."},
}
DEFAULT_PORTS = list(PORT_ANALYSIS.keys())


# --- THE FIX IS HERE ---
def analyze_and_print_results(results): # Changed 'open_ports' to 'results'
    """
    Analyzes scan results and prints them. Handles both list and dict formats.
    """
    if not results:
        print("\n[+] No open ports found.")
        return

    print("\n--- Scan Results ---")
    
    # Check if we got a dictionary (from Nmap) or a list (from basic scan)
    if isinstance(results, dict):
        # Nmap results with details
        for port, details in sorted(results.items()):
            risk_info = PORT_ANALYSIS.get(port, {})
            nmap_service = f"{details['product']} {details['version']}".strip()
            if not nmap_service:
                nmap_service = details['service']

            print(f"\n[!] Open Port: {port}")
            print(f"    - Service:       {nmap_service}")
            print(f"    - Purpose:       {risk_info.get('purpose', 'Determined by Nmap scan.')}")
            print(f"    - Security Risk: {risk_info.get('risk', 'Investigate unknown ports.')}")
    else:
        # Basic scan results (list of ports)
        for port in sorted(results):
            analysis = PORT_ANALYSIS.get(port, {
                "service": "Unknown",
                "purpose": "No data available in our dictionary.",
                "risk": "An unknown open port could belong to any application..."
            })
            print(f"\n[!] Open Port: {port}")
            print(f"    - Service:   {analysis['service']}")
            print(f"    - Purpose:   {analysis['purpose']}")
            print(f"    - Security Risk: {analysis['risk']}")

    print("\n--- End of Report ---")


def basic_port_scanner(target_host, ports_to_scan):
    # This function is correct and needs no changes
    open_ports = []
    # ... (rest of the function)
    return open_ports


def nmap_port_scanner(target_host):
    """
    Scans a target host for open ports using the python-nmap library.
    Returns a dictionary with detailed service information.
    """
    open_ports_details = {}
    
    try:
        nm = nmap.PortScanner(nmap_search_path=('/opt/homebrew/bin/nmap',))
        # The arguments for the scan
        nm.scan(target_host, arguments='-sS -sV')
        
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(f"[*] Host: {host} ({nm[host].hostname()}) is up.")
                for proto in nm[host].all_protocols():
                    if proto == 'tcp':
                        ports = nm[host][proto].keys()
                        for port in ports:
                            # Get the detailed info for each port
                            service_info = nm[host][proto][port]
                            open_ports_details[port] = {
                                'service': service_info.get('name', 'Unknown'),
                                'product': service_info.get('product', ''),
                                'version': service_info.get('version', '')
                            }
    
    # --- THIS PART WAS MISSING ---
    # This block catches the "Nmap not found" error
    except nmap.PortScannerError:
        print("\n[!] Nmap not found. Please ensure Nmap is installed and in your system's PATH.")
        # Return an empty dictionary on failure
        return {}
    # This block catches any other unexpected errors during the scan
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        # Return an empty dictionary on failure
        return {}
    # --- END OF MISSING PART ---
        
    return open_ports_details


if __name__ == '__main__':
    # This block is correct and needs no changes
    # ... (rest of the main block)
    target = input("Enter the target domain or IP address: ")
    choice = input("Select scanner type:\n1. Basic (socket)\n2. Advanced (Nmap)\nEnter choice (1 or 2): ")
    
    if choice == '1':
        found_ports = basic_port_scanner(target, DEFAULT_PORTS)
        analyze_and_print_results(found_ports)
    elif choice == '2':
        found_ports = nmap_port_scanner(target)
        analyze_and_print_results(found_ports)