import nmap
import argparse

def print_ascii_header():
    header = r"""
                                                                                                        ___   
                                                                                                     .'/   \  
                     __  __   ___                                 _________   _...._                / /     \ 
  .--./)            |  |/  `.'   `.                               \        |.'      '-.             | |     | 
 /.''\\             |   .-.  .-.   '                               \        .'```'.    '.           | |     | 
| |  | |            |  |  |  |  |  |              __                \      |       \     \          |/`.   .' 
 \`-' /             |  |  |  |  |  |           .:--.'.               |     |        |    |           `.|   |  
 /("'`              |  |  |  |  |  |          / |   \ |              |      \      /    .             ||___|  
 \ '---.            |  |  |  |  |  |          `" __ | |              |     |\`'-.-'   .'              |/___/  
  /'""'.\           |__|  |__|  |__|           .'.''| |              |     | '-....-'`                .'.--.  
 ||     ||                                    / /   | |_            .'     '.                        | |    | 
 \'. __//                                     \ \._,\ '/          '-----------'                      \_\    / 
  `'---'                                       `--'  `"                                               `''--'  
    """
    print(header)

def run_nmap(target):
    print_ascii_header()  # Print the ASCII header
    nm = nmap.PortScanner()
    print(f"\n[+] Scanning {target} with gmap...\n")

    # Run Nmap with maximum scannability flags
    scan_args = "-A -p- -T4 -Pn -sC -sV --min-rate=2000"
    
    try:
        nm.scan(target, arguments=scan_args)
        print(f"\nScan results for {target}:\n")
        
        # Display scan results
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
