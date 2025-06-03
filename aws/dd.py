import requests
import re
import time
import os
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# قائمة User-Agents عشوائية
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/15.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.5993.117 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Version/15.0 Safari/605.1.15"
]

# ملف البروكسيات
proxies_file = "proxies.txt"

# قراءة البروكسيات من الملف
def load_proxies(proxies_file):
    proxies = []
    if os.path.exists(proxies_file):
        with open(proxies_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):  # تجاهل الأسطر الفارغة والتعليقات
                    proxies.append(line)
    return proxies

# تحميل البروكسيات
proxies_list = load_proxies(proxies_file)

# ملف الإخراج
output_file = "domains.txt"
existing_domains = set()

# تحميل الدومينات السابقة إن وجدت
if os.path.exists(output_file):
    with open(output_file, "r", encoding="utf-8") as f:
        for line in f:
            existing_domains.add(line.strip())

# قائمة الامتدادات التي يجب استبعادها
excluded_extensions = ['.crt', '.jsp', '.pdf', '.heading', '.options', '.outer', '.text', '.title', '.stl']

# دالة استخراج جميع النطاقات من النص واستبعاد الامتدادات
def extract_all_domains(text):
    pattern = re.compile(r'\b(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    all_domains = set(pattern.findall(text))
    # استبعاد الامتدادات المحددة
    filtered_domains = {d for d in all_domains if not any(d.endswith(ext) for ext in excluded_extensions)}
    return filtered_domains

# دالة لجلب البيانات مع البروكسي
def fetch_with_proxy(cert_id, proxy):
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip, deflate"
    }
    
    url = f"http://crt.sh/?id={cert_id}&opt=text"  # تعديل البروتوكول إلى HTTP
    # بروكسي مع المصادقة
    proxy_parts = proxy.split(":")
    ip = proxy_parts[0]
    port = proxy_parts[1]
    auth = (proxy_parts[2], proxy_parts[3])  # بيانات المصادقة (اسم المستخدم وكلمة المرور)
    
    proxies = {"http": f"http://{ip}:{port}", "https": f"http://{ip}:{port}"}  # استخدام HTTP هنا
    
    try:
        response = requests.get(url, headers=headers, proxies=proxies, auth=auth, timeout=10)
        if response.status_code == 200:
            text = response.text
            domains = extract_all_domains(text)
            return cert_id, domains
    except Exception as e:
        print(f"[{cert_id}] Error: {e}")
    return cert_id, set()

# جمع البيانات باستخدام البروكسيات
with open(output_file, "a", encoding="utf-8") as f:
    for cert_id in range(1, 100):  # غيّر المدى حسب الحاجة
        if proxies_list:
            proxy = random.choice(proxies_list)  # اختيار بروكسي عشوائي من القائمة
            cert_id, domains = fetch_with_proxy(cert_id, proxy)
            
            new_domains = domains - existing_domains
            for domain in sorted(new_domains):
                f.write(domain + "\n")
                existing_domains.add(domain)

            print(f"[{cert_id}] Found: {len(domains)} | New added: {len(new_domains)}")

        time.sleep(random.uniform(1, 3))  # تأخير عشوائي بين الطلبات

print("\n✅ تم جمع الدومينات مع استبعاد الامتدادات المحددة واستخدام البروكسيات من الملف.")
