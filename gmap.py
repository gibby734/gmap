import nmap
import argparse

def run_nmap(target):
    nm = nmap.PortScanner()
    print(f"\n[+] Scanning {target} with gmap; there is nowhere to hide [+]\n")

    # Run Nmap with maximum scannability
    scan_args = "-A -p- -T4 -Pn -sC -sV --min-rate=2000"
    
    try:
        nm.scan(target, arguments=scan_args)
        print(f"\nScan results for {target}:\n")
        
        # Display results in standard format 
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port]['version']
                    print(f"Port: {port} - State: {state} - Service: {service} - Version: {version}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Nmap scan with aggressive options")
    parser.add_argument("target", help="Target IP or hostname to scan")
    args = parser.parse_args()

    run_nmap(args.target)
