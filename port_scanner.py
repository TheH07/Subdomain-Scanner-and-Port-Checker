#!/usr/bin/env python3
"""
Port Scanner Script

This script scans for open ports on a list of domains/subdomains using python-nmap.
Optimized version with better domain resolution handling.
"""

import argparse
import nmap
import sys
import socket
from concurrent.futures import ThreadPoolExecutor
import json
import time
import re
from urllib.parse import urlparse

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Scan ports for a list of domains/subdomains.')
    parser.add_argument('-d', '--domains', required=True, help='File containing list of domains/subdomains')
    parser.add_argument('-p', '--ports', default='21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
                        help='Ports to scan (comma-separated or range with hyphen)')
    parser.add_argument('-o', '--output', default='port_scan_results.json', help='Output file for scan results')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads to use')
    parser.add_argument('-T', '--timeout', type=int, default=5, help='Timeout in seconds for each scan')
    parser.add_argument('-r', '--rate-limit', type=float, default=0.5, help='Rate limit in seconds between scans')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def read_domains(filename):
    """Read domains from file and return as a list."""
    try:
        with open(filename, 'r') as file:
            domains = []
            for line in file:
                line = line.strip()
                if line:
                    
                    domains.append(clean_domain(line))
            return domains
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

def resolve_domain(domain):
    """Resolve domain to IP address with better error handling."""
    try:
    
        return socket.gethostbyname(domain)
    except socket.gaierror:
       
        if not domain.startswith('www.'):
            try:
                return socket.gethostbyname(f"www.{domain}")
            except socket.gaierror:
                return None
        return None
    except Exception:
        return None

def scan_ports(domain, ports, timeout=5, verbose=False):
    """Scan ports for a given domain using nmap with improved error handling."""
    result = {
        "domain": domain,
        "ip": None,
        "ports": {},
        "error": None
    }
    

    ip = resolve_domain(domain)
    if not ip:
        if verbose:
            print(f"[-] Could not resolve domain: {domain}")
        result["error"] = "Domain resolution failed"
        return result
    
    result["ip"] = ip
    
    if verbose:
        print(f"[*] Scanning ports for {domain} ({ip})...")
    
   
    nm = nmap.PortScanner()
    
    try:
  
        nm.scan(ip, ports, arguments=f'-T4 --host-timeout {timeout}s')
        
       
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                lport = sorted(nm[ip][proto].keys())
                for port in lport:
                    state = nm[ip][proto][port]['state']
                    service = nm[ip][proto][port]['name']
                    
                    result["ports"][port] = {
                        "state": state,
                        "service": service
                    }
                    
                    if verbose and state == 'open':
                        print(f"[+] {domain}:{port} - {state} ({service})")
    except nmap.PortScannerError as e:
        if verbose:
            print(f"[-] Nmap error scanning {domain}: {e}")
        result["error"] = f"Nmap scan error: {str(e)}"
    except Exception as e:
        if verbose:
            print(f"[-] Error scanning {domain}: {e}")
        result["error"] = f"Scan error: {str(e)}"
    
    return result

def scan_domains(domains, ports, threads=5, timeout=5, rate_limit=0.5, verbose=False):
    """Scan ports for multiple domains using threads with rate limiting."""
    results = []
    total_domains = len(domains)
    
    print(f"[*] Starting port scan for {total_domains} domains with {threads} threads...")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_domain = {}
        
   
        for i, domain in enumerate(domains):
            if i > 0 and rate_limit > 0:
                time.sleep(rate_limit)  
            
            future = executor.submit(scan_ports, domain, ports, timeout, verbose)
            future_to_domain[future] = domain
            
            if verbose:
                print(f"[*] Queued scan for {domain} ({i+1}/{total_domains})")
        
   
        completed = 0
        for future in future_to_domain:
            result = future.result()
            results.append(result)
            
            completed += 1
            if verbose:
                domain = result["domain"]
                open_ports = sum(1 for port_info in result["ports"].values() if port_info["state"] == "open")
                print(f"[*] Completed {completed}/{total_domains}: {domain} - Found {open_ports} open ports")
    
   
    successful_scans = sum(1 for r in results if r["ip"] is not None)
    domains_with_open_ports = sum(1 for r in results if any(port_info["state"] == "open" for port_info in r["ports"].values()))
    
    print(f"[*] Port scan completed. {successful_scans}/{total_domains} domains resolved successfully.")
    print(f"[*] Found open ports on {domains_with_open_ports} domains.")
    
    return results

def save_results(results, output_file):
    """Save scan results to a JSON file."""
    try:
        with open(output_file, 'w') as file:
            json.dump(results, file, indent=4)
        print(f"[+] Results saved to {output_file}")
    except Exception as e:
        print(f"Error saving results to '{output_file}': {e}")

def main():
    """Main function."""
    args = parse_arguments()
    
  
    domains = read_domains(args.domains)
    print(f"[*] Loaded {len(domains)} domains for port scanning")
    
  
    results = scan_domains(
        domains, 
        args.ports, 
        threads=args.threads, 
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        verbose=args.verbose
    )
    

    save_results(results, args.output)
    
    return args.output

if __name__ == "__main__":
    main()
