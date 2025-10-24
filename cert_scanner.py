#!/usr/bin/env python3
"""
Certificate Inventory Scanner for CI
Scans SSL certificates of hosts listed in hosts.txt and reports expiry status.
"""

import ssl
import socket
import csv
import sys
from datetime import datetime, timezone
from typing import List, Dict, Tuple
import argparse


def get_certificate_info(hostname: str, port: int = 443) -> Dict[str, str]:
    """
    Retrieve SSL certificate information for a given hostname.
    
    Args:
        hostname: The hostname to check
        port: The port to connect to (default: 443)
    
    Returns:
        Dictionary containing certificate information
    """
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to the host and get certificate
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Extract certificate information
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                # Calculate days until expiry
                not_after = cert.get('notAfter')
                if not_after:
                    # Parse the date string (format: "Dec 31 23:59:59 2023 GMT")
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_to_expiry = (expiry_date - now).days
                else:
                    days_to_expiry = None
                
                return {
                    'host': hostname,
                    'subject': subject.get('commonName', 'Unknown'),
                    'issuer': issuer.get('commonName', 'Unknown'),
                    'days_to_expiry': days_to_expiry,
                    'expiry_date': not_after,
                    'status': 'valid'
                }
                
    except socket.timeout:
        return {
            'host': hostname,
            'subject': 'Connection Timeout',
            'issuer': 'N/A',
            'days_to_expiry': None,
            'expiry_date': None,
            'status': 'timeout'
        }
    except socket.gaierror:
        return {
            'host': hostname,
            'subject': 'DNS Resolution Failed',
            'issuer': 'N/A',
            'days_to_expiry': None,
            'expiry_date': None,
            'status': 'dns_error'
        }
    except ssl.SSLError as e:
        return {
            'host': hostname,
            'subject': f'SSL Error: {str(e)}',
            'issuer': 'N/A',
            'days_to_expiry': None,
            'expiry_date': None,
            'status': 'ssl_error'
        }
    except Exception as e:
        return {
            'host': hostname,
            'subject': f'Error: {str(e)}',
            'issuer': 'N/A',
            'days_to_expiry': None,
            'expiry_date': None,
            'status': 'error'
        }


def read_hosts_file(filename: str) -> List[str]:
    """
    Read hostnames from a text file.
    
    Args:
        filename: Path to the hosts file
    
    Returns:
        List of hostnames
    """
    try:
        with open(filename, 'r') as f:
            hosts = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return hosts
    except FileNotFoundError:
        print(f"Error: {filename} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        sys.exit(1)


def write_csv_report(results: List[Dict[str, str]], filename: str) -> None:
    """
    Write certificate scan results to CSV file.
    
    Args:
        results: List of certificate information dictionaries
        filename: Output CSV filename
    """
    try:
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['host', 'subject', 'issuer', 'days_to_expiry', 'status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'host': result['host'],
                    'subject': result['subject'],
                    'issuer': result['issuer'],
                    'days_to_expiry': result['days_to_expiry'],
                    'status': result['status']
                })
        print(f"Certificate report written to {filename}")
    except Exception as e:
        print(f"Error writing CSV report: {e}")


def main():
    """Main function to run the certificate scanner."""
    parser = argparse.ArgumentParser(description='SSL Certificate Scanner for CI')
    parser.add_argument('--hosts-file', default='hosts.txt', 
                       help='File containing list of hostnames (default: hosts.txt)')
    parser.add_argument('--output', default='cert_report.csv',
                       help='Output CSV file (default: cert_report.csv)')
    parser.add_argument('--warning-days', type=int, default=30,
                       help='Number of days before expiry to warn (default: 30)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    print("🔍 Starting Certificate Inventory Scanner...")
    print(f"📁 Reading hosts from: {args.hosts_file}")
    print(f"⚠️  Warning threshold: {args.warning_days} days")
    print(f"📊 Output file: {args.output}")
    print("-" * 50)
    
    # Read hostnames
    hosts = read_hosts_file(args.hosts_file)
    print(f"Found {len(hosts)} hosts to scan")
    
    # Scan certificates
    results = []
    failed_certificates = []
    
    for i, host in enumerate(hosts, 1):
        print(f"[{i}/{len(hosts)}] Scanning {host}...")
        
        cert_info = get_certificate_info(host)
        results.append(cert_info)
        
        if cert_info['status'] == 'valid':
            days = cert_info['days_to_expiry']
            if days is not None:
                if days < 0:
                    print(f"  ❌ EXPIRED: {days} days ago")
                    failed_certificates.append(host)
                elif days <= args.warning_days:
                    print(f"  ⚠️  WARNING: Expires in {days} days")
                    failed_certificates.append(host)
                else:
                    print(f"  ✅ Valid: {days} days remaining")
            else:
                print(f"  ❓ Unknown expiry date")
                failed_certificates.append(host)
        else:
            print(f"  ❌ ERROR: {cert_info['subject']}")
            failed_certificates.append(host)
    
    # Write CSV report
    write_csv_report(results, args.output)
    
    # Print summary
    print("-" * 50)
    print(f"📊 Scan Summary:")
    print(f"   Total hosts: {len(hosts)}")
    print(f"   Valid certificates: {len([r for r in results if r['status'] == 'valid' and r['days_to_expiry'] and r['days_to_expiry'] > args.warning_days])}")
    print(f"   Failed/expiring: {len(failed_certificates)}")
    
    if failed_certificates:
        print(f"❌ Failed hosts: {', '.join(failed_certificates)}")
        print(f"💥 Pipeline will fail due to certificate issues")
        sys.exit(2)
    else:
        print("✅ All certificates are valid!")
        sys.exit(0)


if __name__ == "__main__":
    main()
