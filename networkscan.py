import nmap
import csv
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def print_program_info():
    print("="*60)
    print("Automated Nmap Scanner")
    print("Scan your network for compliance, discovery, or audit purposes.")
    print("You can scan using SYN, TCP, or UDP methods.")
    print("Type 'exit' as the target to quit the program.")
    print("="*60)

def get_scan_args(category, scan_type):
    if category == 'compliance':
        if scan_type == 'syn':
            return '-sS -sV -p-'
        elif scan_type == 'tcp':
            return '-sT -sV -p-'
        elif scan_type == 'udp':
            return '-sU -sV -p 1-1024'
    elif category == 'discovery':
        if scan_type == 'syn':
            return '-sS -sV -p 1-1024'
        elif scan_type == 'tcp':
            return '-sT -sV -p 1-1024'
        elif scan_type == 'udp':
            return '-sU -sV -p 53,67,68,161'
    elif category == 'audit':
        if scan_type == 'syn':
            return '-sS -sV -p 21,23,25,80,443,3389'
        elif scan_type == 'tcp':
            return '-sT -sV -p 21,23,25,80,443,3389'
        elif scan_type == 'udp':
            return '-sU -sV -p 53,123,161,162'
    return ''

def main():
    print_program_info()
    nm = nmap.PortScanner()
    categories = ['compliance', 'discovery', 'audit']
    types = ['syn', 'tcp', 'udp']

    while True:
        target = input("Enter target IP or network (e.g., 192.168.1.1 or 192.168.1.0/24), or 'exit' to quit: ").strip()
        if target.lower() == 'exit':
            print("Exiting program.")
            break

        print(f"Available scan categories: {categories}")
        category = input("Enter scan category: ").strip().lower()
        if category not in categories:
            print("Invalid category. Please try again.")
            continue

        print(f"Available scan types: {types}")
        scan_type = input("Enter scan type: ").strip().lower()
        if scan_type not in types:
            print("Invalid scan type. Please try again.")
            continue

        output_file = input("Enter output CSV file name (default: scan_results.csv): ").strip()
        if not output_file:
            output_file = 'scan_results.csv'

        scan_args = get_scan_args(category, scan_type)
        if not scan_args:
            print("Invalid scan configuration. Please try again.")
            continue

        logging.info('Starting Nmap scan on targets: %s with %s %s scan', target, category, scan_type)
        try:
            nm.scan(hosts=target, arguments=scan_args)
        except nmap.PortScannerError as e:
            logging.error('Nmap scan failed: %s', e)
            continue
        logging.info('Scan completed successfully')

        # Collect scan data
        scan_data = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    row = {
                        'IP Address': host,
                        'Port': port,
                        'Protocol': proto.upper(),
                        'Service': nm[host][proto][port].get('name', 'N/A'),
                        'Version': nm[host][proto][port].get('version', 'N/A'),
                        'State': nm[host][proto][port]['state'],
                        'Timestamp': timestamp,
                        'Scan Type': scan_type.upper()
                    }
                    scan_data.append(row)

        # Define CSV fieldnames
        fieldnames = ['IP Address', 'Port', 'Protocol', 'Service', 'Version', 'State', 'Timestamp', 'Scan Type']

        # Write results to CSV
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in scan_data:
                writer.writerow(row)

        print(f"Scan results saved to {output_file}")
        print(f"Scanned {len(nm.all_hosts())} hosts. {len(scan_data)} open ports found.\n")

if __name__ == "__main__":
    main()