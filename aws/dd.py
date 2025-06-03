import requests
import re
import time
import os
import random
from concurrent.futures import ThreadPoolExecutor, as_completed


user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/15.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.5993.117 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Version/15.0 Safari/605.1.15"
]


proxies_file = "proxies.txt"


def load_proxies(proxies_file):
    proxies = []
    if os.path.exists(proxies_file):
        with open(proxies_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"): 
                    proxies.append(line)
    return proxies


proxies_list = load_proxies(proxies_file)


output_file = "domains.txt"
existing_domains = set()


if os.path.exists(output_file):
    with open(output_file, "r", encoding="utf-8") as f:
        for line in f:
            existing_domains.add(line.strip())


excluded_extensions = ['.crt', '.jsp', '.pdf', '.heading', '.options', '.outer', '.text', '.title', '.stl']


def extract_all_domains(text):
    pattern = re.compile(r'\b(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    all_domains = set(pattern.findall(text))

    filtered_domains = {d for d in all_domains if not any(d.endswith(ext) for ext in excluded_extensions)}
    return filtered_domains


def fetch_with_proxy(cert_id, proxy):
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip, deflate"
    }
    
    url = f"http://crt.sh/?id={cert_id}&opt=text"  

    proxy_parts = proxy.split(":")
    ip = proxy_parts[0]
    port = proxy_parts[1]
    auth = (proxy_parts[2], proxy_parts[3]) 
    
    proxies = {"http": f"http://{ip}:{port}", "https": f"http://{ip}:{port}"}  
    
    try:
        response = requests.get(url, headers=headers, proxies=proxies, auth=auth, timeout=10)
        if response.status_code == 200:
            text = response.text
            domains = extract_all_domains(text)
            return cert_id, domains
    except Exception as e:
        print(f"[{cert_id}] Error: {e}")
    return cert_id, set()


with open(output_file, "a", encoding="utf-8") as f:
    for cert_id in range(1, 100):  
        if proxies_list:
            proxy = random.choice(proxies_list)  
            cert_id, domains = fetch_with_proxy(cert_id, proxy)
            
            new_domains = domains - existing_domains
            for domain in sorted(new_domains):
                f.write(domain + "\n")
                existing_domains.add(domain)

            print(f"[{cert_id}] Found: {len(domains)} | New added: {len(new_domains)}")

        time.sleep(random.uniform(1, 3))  

print("\n✅ تم جمع الدومينات مع استبعاد الامتدادات المحددة واستخدام البروكسيات من الملف.")
