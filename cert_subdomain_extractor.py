#!/usr/bin/env python3
"""
Certificate-based Subdomain Extractor

This script extracts subdomains from certificate transparency logs using crt.sh.
"""

import argparse
import json
import sys
import time
import requests
from urllib.parse import quote
import re
from concurrent.futures import ThreadPoolExecutor

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Extract subdomains from certificate transparency logs.')
    parser.add_argument('-d', '--domains', required=True, help='File containing list of domains')
    parser.add_argument('-o', '--output', default='cert_subdomains.txt', help='Output file for extracted subdomains')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads to use')
    parser.add_argument('-r', '--rate-limit', type=float, default=1.0, help='Rate limit in seconds between requests')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

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

def query_crt_sh(domain, verbose=False):
    """Query crt.sh for certificate information for a domain."""
    url = f"https://crt.sh/?q={quote(domain)}&output=json"
    
    if verbose:
        print(f"[*] Querying crt.sh for {domain}...")
    
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            try:
                return response.json()
            except json.JSONDecodeError:
                if verbose:
                    print(f"[-] Error decoding JSON response for {domain}")
                return []
        else:
            if verbose:
                print(f"[-] Error querying crt.sh for {domain}: HTTP {response.status_code}")
            return []
    except requests.RequestException as e:
        if verbose:
            print(f"[-] Request error querying crt.sh for {domain}: {e}")
        return []

def extract_subdomains_from_cert(cert_data, domain, verbose=False):
    """Extract subdomains from certificate data."""
    subdomains = set()
    

    if 'common_name' in cert_data and cert_data['common_name']:
        common_name = cert_data['common_name'].lower()
        if domain in common_name and common_name != domain:
       
            if common_name.startswith('*.'):
                common_name = common_name[2:]  
            if common_name not in subdomains:
                subdomains.add(common_name)
    
   
    if 'name_value' in cert_data and cert_data['name_value']:
   
        names = re.split(r'[\n,]', cert_data['name_value'])
        for name in names:
            name = name.strip().lower()
            if domain in name and name != domain:
               
                if name.startswith('*.'):
                    name = name[2:] 
                if name not in subdomains:
                    subdomains.add(name)
    
    return subdomains

def extract_subdomains_from_certs(certs, domain, verbose=False):
    """Extract unique subdomains from a list of certificates."""
    all_subdomains = set()
    
    for cert in certs:
        subdomains = extract_subdomains_from_cert(cert, domain, verbose)
        all_subdomains.update(subdomains)
    
    return all_subdomains

def extract_subdomains_for_domain(domain, verbose=False):
    """Extract subdomains for a domain from certificate transparency logs."""
    certs = query_crt_sh(domain, verbose)
    
    if not certs:
        if verbose:
            print(f"[-] No certificates found for {domain}")
        return []
    
    if verbose:
        print(f"[+] Found {len(certs)} certificates for {domain}")
    
    subdomains = extract_subdomains_from_certs(certs, domain, verbose)
    
    if verbose:
        print(f"[+] Extracted {len(subdomains)} unique subdomains for {domain}")
    
    return [f"http://{subdomain}" for subdomain in subdomains]

def extract_subdomains(domains, threads=5, rate_limit=1.0, verbose=False):
    """Extract subdomains for multiple domains using threads with rate limiting."""
    all_subdomains = []
    
    print(f"[*] Starting certificate-based subdomain extraction for {len(domains)} domains...")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_domain = {}
        
        
        for i, domain in enumerate(domains):
            if i > 0 and rate_limit > 0:
                time.sleep(rate_limit)  
            
            future = executor.submit(extract_subdomains_for_domain, domain, verbose)
            future_to_domain[future] = domain
        
  
        for future in future_to_domain:
            domain = future_to_domain[future]
            try:
                subdomains = future.result()
                all_subdomains.extend(subdomains)
                
                if verbose:
                    print(f"[*] Completed extraction for {domain}: Found {len(subdomains)} subdomains")
            except Exception as e:
                print(f"[-] Error extracting subdomains for {domain}: {e}")
    
    return all_subdomains

def save_results(results, output_file):
    """Save results to output file."""
    try:
        with open(output_file, 'w') as file:
            for result in results:
                file.write(f"{result}\n")
        print(f"[+] Results saved to {output_file}")
    except Exception as e:
        print(f"Error saving results to '{output_file}': {e}")

def main():
    """Main function."""
    args = parse_arguments()
    

    domains = read_domains(args.domains)
    print(f"[*] Loaded {len(domains)} domains for certificate-based subdomain extraction")
    

    start_time = time.time()
    subdomains = extract_subdomains(
        domains, 
        threads=args.threads, 
        rate_limit=args.rate_limit, 
        verbose=args.verbose
    )
    

    save_results(subdomains, args.output)
    
    elapsed_time = time.time() - start_time
    print(f"[+] Certificate-based extraction complete. Found {len(subdomains)} subdomains in {elapsed_time:.2f} seconds.")
    
    return args.output

if __name__ == "__main__":
    main()
