#!/usr/bin/env python3
"""
Subdomain Scanner and Port Checker

This script extracts subdomains for a list of domains using both brute-force and
certificate transparency logs approaches, then checks for open ports on all
discovered subdomains. Results are saved to domain-specific output files.
"""

import argparse
import os
import sys
import time
from datetime import datetime
import json

# Import our custom modules
import subdomain_extractor
import cert_subdomain_extractor
import port_scanner

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Extract subdomains and scan ports for a list of domains.'
    )
    
    # Input options
    parser.add_argument('-d', '--domains', required=True, 
                        help='File containing list of domains')
    parser.add_argument('-w', '--wordlist', default='subdomains.txt',
                        help='Wordlist file containing subdomains for brute-force method')
    
    # Extraction method options
    parser.add_argument('--no-brute-force', action='store_true',
                        help='Disable brute-force subdomain extraction')
    parser.add_argument('--no-cert', action='store_true',
                        help='Disable certificate-based subdomain extraction')
    
    # Subdomain extraction options
    parser.add_argument('-st', '--subdomain-threads', type=int, default=10,
                        help='Number of threads to use for subdomain extraction')
    parser.add_argument('-sr', '--subdomain-rate', type=float, default=0.1,
                        help='Rate limit in seconds between subdomain requests')
    parser.add_argument('-ct', '--cert-threads', type=int, default=5,
                        help='Number of threads to use for certificate-based extraction')
    parser.add_argument('-cr', '--cert-rate', type=float, default=1.0,
                        help='Rate limit in seconds between certificate requests')
    
    # Port scanning options
    parser.add_argument('-p', '--ports', 
                        default='21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
                        help='Ports to scan (comma-separated or range with hyphen)')
    parser.add_argument('-pt', '--port-threads', type=int, default=5,
                        help='Number of threads to use for port scanning')
    parser.add_argument('-pr', '--port-rate', type=float, default=0.5,
                        help='Rate limit in seconds between port scans')
    parser.add_argument('-T', '--timeout', type=int, default=5,
                        help='Timeout in seconds for each port scan')
    
    # Output options
    parser.add_argument('-o', '--output-dir', default='results',
                        help='Directory to save results')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    
    return parser.parse_args()

def setup_output_directory(output_dir):
    """Create output directory if it doesn't exist."""
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        return True
    except Exception as e:
        print(f"Error creating output directory: {e}")
        return False

def read_domains(filename):
    """Read domains from file and return as a list."""
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        sys.exit(1)

def extract_subdomains_for_domain(domain, method, args, output_dir, timestamp):
    """Extract subdomains for a specific domain using the specified method."""
    domain_output_file = os.path.join(output_dir, f"{domain}_{method}_subdomains_{timestamp}.txt")
    
    if method == "brute-force":
        # Override the main function arguments to use our custom arguments
        sys.argv = [
            'subdomain_extractor.py',
            '-d', args.domains,  # We'll filter for this domain in the script
            '-w', args.wordlist,
            '-o', domain_output_file,
            '-t', str(args.subdomain_threads),
            '-r', str(args.subdomain_rate)
        ]
        if args.verbose:
            sys.argv.append('-v')
        
        # Create a temporary file with just this domain
        temp_domain_file = os.path.join(output_dir, f"temp_{domain}_{timestamp}.txt")
        with open(temp_domain_file, 'w') as f:
            f.write(f"{domain}\n")
        
        # Update the domains argument to use our temporary file
        sys.argv[2] = temp_domain_file
        
        # Run subdomain extraction
        subdomain_extractor.main()
        
        # Clean up temporary file
        try:
            os.remove(temp_domain_file)
        except:
            pass
        
    elif method == "cert":
        # Override the main function arguments to use our custom arguments
        sys.argv = [
            'cert_subdomain_extractor.py',
            '-d', args.domains,  # We'll filter for this domain in the script
            '-o', domain_output_file,
            '-t', str(args.cert_threads),
            '-r', str(args.cert_rate)
        ]
        if args.verbose:
            sys.argv.append('-v')
        
        # Create a temporary file with just this domain
        temp_domain_file = os.path.join(output_dir, f"temp_{domain}_{timestamp}.txt")
        with open(temp_domain_file, 'w') as f:
            f.write(f"{domain}\n")
        
        # Update the domains argument to use our temporary file
        sys.argv[2] = temp_domain_file
        
        # Run certificate-based subdomain extraction
        cert_subdomain_extractor.main()
        
        # Clean up temporary file
        try:
            os.remove(temp_domain_file)
        except:
            pass
    
    return domain_output_file

def combine_domain_subdomains(brute_force_file, cert_file, combined_file):
    """Combine and deduplicate subdomains from multiple sources for a domain."""
    subdomains = set()
    
    # Read brute-force subdomains if file exists
    if brute_force_file and os.path.exists(brute_force_file):
        with open(brute_force_file, 'r') as file:
            for line in file:
                subdomains.add(line.strip())
    
    # Read certificate-based subdomains if file exists
    if cert_file and os.path.exists(cert_file):
        with open(cert_file, 'r') as file:
            for line in file:
                subdomains.add(line.strip())
    
    # Write combined unique subdomains
    with open(combined_file, 'w') as file:
        for subdomain in sorted(subdomains):
            file.write(f"{subdomain}\n")
    
    return len(subdomains)

def scan_ports_for_domain(domain, combined_subdomains_file, args, output_dir, timestamp):
    """Scan ports for a specific domain's subdomains."""
    domain_portscan_file = os.path.join(output_dir, f"{domain}_portscan_{timestamp}.json")
    
    # Override the main function arguments to use our custom arguments
    sys.argv = [
        'port_scanner.py',
        '-d', combined_subdomains_file,
        '-p', args.ports,
        '-o', domain_portscan_file,
        '-t', str(args.port_threads),
        '-T', str(args.timeout),
        '-r', str(args.port_rate)
    ]
    if args.verbose:
        sys.argv.append('-v')
    
    # Run port scanning
    port_scanner.main()
    
    return domain_portscan_file

def main():
    """Main function."""
    args = parse_arguments()
    
    # Create timestamp for output files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Setup output directory
    if not setup_output_directory(args.output_dir):
        sys.exit(1)
    
    # Read domains from file
    domains = read_domains(args.domains)
    
    print("=" * 60)
    print(f"Subdomain Scanner and Port Checker")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Domains file: {args.domains}")
    print(f"Output directory: {args.output_dir}")
    print(f"Processing {len(domains)} domains with domain-specific output files")
    print("=" * 60)
    
    # Process each domain separately
    for domain in domains:
        print(f"\n[+] Processing domain: {domain}")
        domain_start_time = time.time()
        
        brute_force_file = None
        cert_file = None
        
        # Step 1a: Extract subdomains using brute-force method
        if not args.no_brute_force:
            print(f"[+] Extracting subdomains for {domain} using brute-force method...")
            start_time = time.time()
            brute_force_file = extract_subdomains_for_domain(
                domain, "brute-force", args, args.output_dir, timestamp
            )
            elapsed = time.time() - start_time
            print(f"[+] Brute-force extraction for {domain} completed in {elapsed:.2f} seconds")
        
        # Step 1b: Extract subdomains using certificate transparency logs
        if not args.no_cert:
            print(f"[+] Extracting subdomains for {domain} using certificate transparency logs...")
            start_time = time.time()
            cert_file = extract_subdomains_for_domain(
                domain, "cert", args, args.output_dir, timestamp
            )
            elapsed = time.time() - start_time
            print(f"[+] Certificate-based extraction for {domain} completed in {elapsed:.2f} seconds")
        
        # Step 1c: Combine and deduplicate subdomains
        combined_file = os.path.join(args.output_dir, f"{domain}_combined_subdomains_{timestamp}.txt")
        print(f"[+] Combining and deduplicating subdomains for {domain}...")
        unique_count = combine_domain_subdomains(brute_force_file, cert_file, combined_file)
        print(f"[+] Combined {unique_count} unique subdomains for {domain}")
        
        # Step 2: Scan ports on discovered subdomains
        if unique_count > 0:
            print(f"[+] Scanning ports on discovered subdomains for {domain}...")
            start_time = time.time()
            portscan_file = scan_ports_for_domain(
                domain, combined_file, args, args.output_dir, timestamp
            )
            elapsed = time.time() - start_time
            print(f"[+] Port scanning for {domain} completed in {elapsed:.2f} seconds")
        else:
            print(f"[!] No subdomains found for {domain}, skipping port scanning")
        
        domain_elapsed = time.time() - domain_start_time
        print(f"[+] Processing for {domain} completed in {domain_elapsed:.2f} seconds")
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Processed {len(domains)} domains with results saved to {args.output_dir}/")
    print(f"Each domain has its own set of output files with the domain name in the filename")
    print("=" * 60)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
