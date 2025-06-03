# Subdomain Scanner and Port Checker

A comprehensive tool for extracting subdomains from a list of domains and checking open ports on all discovered subdomains.

## Features

- Extract subdomains using multiple methods:
  - Brute-force approach with a wordlist
  - Certificate Transparency logs via crt.sh
- Combine and deduplicate results from multiple sources
- Scan for open ports on discovered subdomains
- Multithreaded execution for faster performance
- Rate limiting to avoid being blocked by target servers
- Detailed output in both text and JSON formats
- Comprehensive error handling and domain resolution
- Configurable options for threads, timeouts, and ports to scan

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)
- nmap (Network Mapper tool)

### Setup

1. Clone or download this repository:

```bash
git clone https://github.com/yourusername/subdomain-scanner.git
cd subdomain-scanner
```

2. Install the required dependencies:

```bash
pip install python-nmap requests
```

3. Make sure you have nmap installed on your system:

- For Ubuntu/Debian:
  ```bash
  sudo apt-get install nmap
  ```
- For CentOS/RHEL:
  ```bash
  sudo yum install nmap
  ```
- For macOS:
  ```bash
  brew install nmap
  ```
- For Windows:
  Download and install from [nmap.org](https://nmap.org/download.html)

## Usage

The tool consists of three main scripts:

1. `subdomain_extractor.py` - Extracts subdomains for a list of domains
2. `port_scanner.py` - Scans for open ports on a list of domains/subdomains
3. `subdomain_port_scanner.py` - Combines both functionalities in a single workflow

### Main Script Usage

```bash
python subdomain_port_scanner.py -d domains.txt -w subdomains.txt -o results -v
```

#### Command-line Options

- `-d, --domains`: File containing list of domains (required)
- `-w, --wordlist`: Wordlist file containing subdomains for brute-force method (default: subdomains.txt)

**Extraction Method Options:**
- `--no-brute-force`: Disable brute-force subdomain extraction
- `--no-cert`: Disable certificate-based subdomain extraction

**Subdomain Extraction Options:**
- `-st, --subdomain-threads`: Number of threads for brute-force subdomain extraction (default: 10)
- `-sr, --subdomain-rate`: Rate limit in seconds between brute-force subdomain requests (default: 0.1)
- `-ct, --cert-threads`: Number of threads for certificate-based extraction (default: 5)
- `-cr, --cert-rate`: Rate limit in seconds between certificate requests (default: 1.0)

**Port Scanning Options:**
- `-p, --ports`: Ports to scan (default: common ports like 21,22,23,25,80,443,etc.)
- `-pt, --port-threads`: Number of threads for port scanning (default: 5)
- `-pr, --port-rate`: Rate limit in seconds between port scans (default: 0.5)
- `-T, --timeout`: Timeout in seconds for each port scan (default: 5)

**Output Options:**
- `-o, --output-dir`: Directory to save results (default: results)
- `-v, --verbose`: Enable verbose output

### Using Individual Scripts

#### Subdomain Extractor (Brute-Force Method)

```bash
python subdomain_extractor.py -d domains.txt -w subdomains.txt -o extracted_subdomains.txt -t 10 -r 0.1 -v
```

#### Certificate-Based Subdomain Extractor

```bash
python cert_subdomain_extractor.py -d domains.txt -o cert_subdomains.txt -t 5 -r 1.0 -v
```

#### Port Scanner

```bash
python port_scanner.py -d domains.txt -p "80,443,8080" -o port_scan_results.json -t 5 -T 5 -r 0.5 -v
```

## Input File Format

### Domains File

The domains file should contain one domain per line:

```
example.com
google.com
microsoft.com
```

### Subdomains Wordlist

The subdomains wordlist should contain one subdomain prefix per line:

```
www
mail
admin
blog
shop
```

## Output Format

### Domain-Specific Output Files

The script now saves results in separate files for each domain, with the domain name included in the filename:

- **Brute-force method output**: `[domain]_brute-force_subdomains_[timestamp].txt`
- **Certificate-based method output**: `[domain]_cert_subdomains_[timestamp].txt`
- **Combined unique subdomains**: `[domain]_combined_subdomains_[timestamp].txt`
- **Port scan results**: `[domain]_portscan_[timestamp].json`

This organization makes it easy to identify and manage results for each domain separately.

### Subdomain Extraction Output

The subdomain extraction results are saved as text files with one subdomain URL per line:

Example content:
```
http://www.example.com
http://mail.example.com
http://admin.example.com
```

### Port Scanning Output

The port scanning results are saved as a JSON file with the following structure:

```json
[
    {
        "domain": "example.com",
        "ip": "93.184.216.34",
        "ports": {
            "80": {
                "state": "open",
                "service": "http"
            },
            "443": {
                "state": "open",
                "service": "https"
            }
        },
        "error": null
    }
]
```

## Examples

### Basic Usage

```bash
python subdomain_port_scanner.py -d domains.txt
```

### Scan Specific Ports

```bash
python subdomain_port_scanner.py -d domains.txt -p "80,443,8080,8443"
```

### Increase Threads for Faster Scanning

```bash
python subdomain_port_scanner.py -d domains.txt -st 20 -pt 10
```

### Adjust Rate Limiting

```bash
python subdomain_port_scanner.py -d domains.txt -sr 0.2 -pr 1.0
```

## Tips for Effective Use

1. **Start with a small list of domains** for testing before running on a large dataset
2. **Adjust thread counts** based on your system's capabilities and network conditions
3. **Use rate limiting** to avoid being blocked by target servers
4. **Customize the ports** to scan based on your specific needs
5. **Use verbose mode** (`-v`) to see detailed progress during execution

## Limitations

- The subdomain extraction uses a brute-force approach and may not find all subdomains
- Port scanning is limited by network conditions and firewall rules
- Some servers may block or rate-limit requests, affecting results
- The tool requires proper permissions to run nmap scans

## Troubleshooting

- If you encounter "Permission denied" errors with nmap, try running the script with sudo
- If domain resolution fails, check your internet connection and DNS settings
- If the script runs slowly, try reducing the number of threads or increasing rate limits

## License

This project is licensed under the MIT License - see the LICENSE file for details.
