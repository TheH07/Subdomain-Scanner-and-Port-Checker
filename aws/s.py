import requests
import re
import time
import os
import random

# قائمة User-Agents مختلفة
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/15.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.5993.117 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Version/15.0 Safari/605.1.15"
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0"
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36"
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240"
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko"
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36"
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
    "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36"
    

]

# ملف الإخراج
output_file = "domains.txt"
existing_domains = set()

# تحميل الدومينات السابقة إن وجدت
if os.path.exists(output_file):
    with open(output_file, "r", encoding="utf-8") as f:
        for line in f:
            existing_domains.add(line.strip())

# قائمة الامتدادات التي يجب استبعادها
excluded_extensions = ['.lint','.png','.crl','.crt', '.jsp', '.pdf', '.heading', '.options', '.outer', '.text', '.title', '.stl']

# دالة استخراج جميع النطاقات من النص واستثناء الامتدادات
def extract_all_domains(text):
    pattern = re.compile(r'\b(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    all_domains = set(pattern.findall(text))
    
    # استبعاد الامتدادات المحددة
    filtered_domains = {d for d in all_domains if not any(d.endswith(ext) for ext in excluded_extensions)}
    
    return filtered_domains

# جمع البيانات من نطاق محدد
with open(output_file, "a", encoding="utf-8") as f:
    for cert_id in range(1, 100):  # غيّر المدى حسب الحاجة
        headers = {
            "User-Agent": random.choice(user_agents)
        }

        url = f"https://crt.sh/?id={cert_id}&opt=text"
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                text = response.text
                domains = extract_all_domains(text)
                new_domains = domains - existing_domains

                for domain in sorted(new_domains):
                    f.write(domain + "\n")
                    existing_domains.add(domain)

                print(f"[{cert_id}] Found: {len(domains)} | New added: {len(new_domains)}")
        except Exception as e:
            print(f"[{cert_id}] Error: {e}")

        time.sleep(1)  # تأخير آمن لتجنب الحظر

print("\n✅ تم جمع الدومينات مع استبعاد الامتدادات المحددة.")
