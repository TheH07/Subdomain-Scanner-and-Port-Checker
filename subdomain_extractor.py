#!/usr/bin/env python3
"""
Subdomain Extractor Script

This script extracts subdomains for a list of domains using a brute-force approach
with a wordlist of common subdomains.
Optimized version with better error handling and rate limiting.
"""

import argparse
import concurrent.futures
import requests
import sys
import time
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse


requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Extract subdomains from a list of domains.')
    parser.add_argument('-d', '--domains', required=True, help='File containing list of domains')
    parser.add_argument('-w', '--wordlist', default='subdomains.txt', help='Wordlist file containing subdomains')
    parser.add_argument('-o', '--output', default='extracted_subdomains.txt', help='Output file for extracted subdomains')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use')
    parser.add_argument('-r', '--rate-limit', type=float, default=0.1, help='Rate limit in seconds between requests')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def read_file(filename):
    """Read file and return content as a list of lines."""
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        sys.exit(1)

def clean_domain(domain):
    """Clean domain/URL format to ensure proper format for scanning."""

    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
    

    domain = domain.split('/')[0]
    

    domain = domain.split(':')[0]
    
    return domain

def check_subdomain(domain, subdomain, timeout=2, verbose=False):
    """Check if a subdomain exists for a given domain."""
    url = f"http://{subdomain}.{domain}"
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        if verbose:
            print(f"[+] Discovered subdomain: {url}")
        return url
    except (requests.ConnectionError, requests.Timeout, requests.RequestException):
      
        return None

def extract_subdomains(domain, subdomains, threads=10, rate_limit=0.1, verbose=False):
    """Extract subdomains for a given domain using a wordlist with rate limiting."""
    discovered = []
    

    domain = clean_domain(domain)
    
    print(f"[*] Extracting subdomains for {domain}...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_subdomain = {}
        
     
        for i, subdomain in enumerate(subdomains):
            if i > 0 and rate_limit > 0:
                time.sleep(rate_limit)  
            
            future = executor.submit(check_subdomain, domain, subdomain, 2, verbose)
            future_to_subdomain[future] = subdomain
        
        
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                discovered.append(result)
    
    print(f"[*] Found {len(discovered)} subdomains for {domain}")
    return discovered

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
    
 
    domains = read_file(args.domains)
    subdomains = read_file(args.wordlist)
    
    print(f"[*] Loaded {len(domains)} domains and {len(subdomains)} subdomains")
    
    all_discovered = []
    
 
    for domain in domains:
        discovered = extract_subdomains(
            domain, 
            subdomains, 
            threads=args.threads,
            rate_limit=args.rate_limit,
            verbose=args.verbose
        )
        all_discovered.extend(discovered)
    

    save_results(all_discovered, args.output)
    
    print(f"[+] Extraction complete. Found {len(all_discovered)} subdomains in total.")
    return args.output

if __name__ == "__main__":
    main()
