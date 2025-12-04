#########################################
# Author: Aryan
# Copyright: 2025 Aryan
# GitHub: https://github.com/giriaryan694-a11y
# Note: Unauthorized copying without credit is prohibited
#########################################

import os
import re
import time
import requests
import pyfiglet
import math
import subprocess
from termcolor import colored
from colorama import Fore, Style
import google.generativeai as genai
import openai
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

# === OPTIONAL: LOCAL AI SUPPORT ===
try:
    from llama_cpp import Llama
    HAS_LOCAL_LIB = True
except ImportError:
    HAS_LOCAL_LIB = False

# === OPTIONAL: BROWSER SUPPORT ===
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False

# === CLEAR SCREEN & BANNER ===
os.system("clear")
banner = pyfiglet.figlet_format("ARY-PEN-AI")
Banner = colored(banner, "red")
print(Banner)
print(Fore.YELLOW + "          ..:: Made by Aryan Giri ::..")
print()
print(Fore.YELLOW + "  ⚠ This tool is only made for educational & research purposes ⚠")
print(Style.RESET_ALL)

# === GLOBAL STORAGE ===
CRAWLED_URLS = set()

# === READ API KEYS ===
def read_api_keys(file_path="keys.txt"):
    keys = {"GEMINI_API": None, "CHATGPT_API": None}
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    if key in keys: keys[key] = value.strip()
    except FileNotFoundError: pass
    return keys

# === READ SCOPE FILE ===
def read_scope_file(file_path):
    allowed_domains = set()
    if not file_path: return None
    try:
        with open(file_path, "r") as f:
            for line in f:
                domain = line.strip().lower().replace("http://", "").replace("https://", "").split('/')[0]
                if domain: allowed_domains.add(domain)
        print(Fore.GREEN + f"[+] Loaded {len(allowed_domains)} domains from scope file.")
        return allowed_domains
    except FileNotFoundError:
        print(Fore.RED + f"[!] Scope file not found. Defaulting to single target.")
        return None

# === SETUP SELENIUM DRIVER ===
def setup_selenium():
    if not HAS_SELENIUM:
        return None
    
    print(Fore.YELLOW + "[*] Launching Headless Chrome (This may take a moment)...")
    options = Options()
    options.add_argument("--headless") 
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        return driver
    except Exception as e:
        print(Fore.RED + f"[!] Selenium Init Failed: {e}")
        return None

# === OFFLINE MODEL SETUP ===
def setup_offline_model():
    if not HAS_LOCAL_LIB:
        print(Fore.RED + "[!] 'llama-cpp-python' missing. Cannot use offline mode.")
        return None
    
    print(Fore.CYAN + "\n=== Offline Model Setup ===")
    model_path = input(Fore.GREEN + "Path to .gguf file (Enter to skip): ").strip()
    if not model_path or not os.path.exists(model_path): return None

    # GPU Check
    try:
        gpu_info = subprocess.check_output("nvidia-smi -L", shell=True).decode()
        print(Fore.GREEN + "GPUs Detected:\n" + gpu_info)
        gpu_id = input(Fore.GREEN + "GPU ID (Enter for default): ").strip()
        if gpu_id: os.environ["CUDA_VISIBLE_DEVICES"] = gpu_id
    except: pass

    print(Fore.MAGENTA + f"[*] Loading Model...")
    try:
        llm = Llama(model_path=model_path, n_gpu_layers=-1, n_ctx=4096, verbose=False)
        return llm
    except Exception as e:
        print(Fore.RED + f"[!] Model Load Error: {e}")
        return None

# === FETCHER (HYBRID) ===
def fetch_url(url, driver=None, cookies=None):
    """
    Fetches URL. 
    If 'driver' is provided, uses Selenium.
    If 'driver' is None, uses standard Requests.
    """
    if driver:
        # === SELENIUM MODE ===
        try:
            driver.get(url)
            # Smart Scroll for Lazy Loading
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(1.5) 
            return driver.page_source
        except Exception as e:
            print(Fore.RED + f"[!] Selenium Error: {e}")
            return None
    else:
        # === REQUESTS MODE ===
        headers = {'User-Agent': 'Mozilla/5.0 (Security-Research-Tool)'}
        if cookies: headers['Cookie'] = cookies
        try:
            res = requests.get(url, headers=headers, timeout=10)
            return res.text if res.status_code == 200 else None
        except Exception as e:
            print(Fore.RED + f"[!] Requests Error: {e}")
            return None

# === EXTRACT PARAMS & HEADERS ===
def extract_inputs(url, html):
    inputs = {"url_params": [], "form_inputs": [], "potential_headers": []}
    
    # 1. URL Params
    parsed = urlparse(url)
    if parsed.query:
        for key in parse_qs(parsed.query).keys(): inputs["url_params"].append(key)

    # 2. Form Inputs
    soup = BeautifulSoup(html, 'html.parser')
    for form in soup.find_all('form'):
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name: inputs["form_inputs"].append(name)
    
    # 3. Headers Regex
    header_patterns = [
        r"['\"](Authorization)['\"]\s*[:=]\s*['\"]([^'\"]+)['\"]",
        r"['\"](Bearer)['\"]\s*[:=]\s*['\"]([^'\"]+)['\"]",
        r"['\"](X-[a-zA-Z0-9-_]+)['\"]\s*[:=]\s*['\"]([^'\"]+)['\"]",
        r"['\"]([a-zA-Z0-9-_]*api[_-]?key)['\"]\s*[:=]\s*['\"]([^'\"]+)['\"]",
        r"['\"]([a-zA-Z0-9-_]*client[_-]?secret)['\"]\s*[:=]\s*['\"]([^'\"]+)['\"]",
        r"['\"]([a-zA-Z0-9-_]*token)['\"]\s*[:=]\s*['\"]([^'\"]+)['\"]"
    ]
    
    found = set()
    for pattern in header_patterns:
        for match in re.findall(pattern, html, re.IGNORECASE):
            val = match[1]
            if len(val) > 40: val = val[:20] + "...[TRUNCATED]"
            found.add(f"{match[0]}: {val}")

    inputs["potential_headers"] = list(found)
    return inputs

# === UNIFIED AI ANALYSIS ===
def analyze_with_ai(model_choice, html_code, page_url, inputs, api_keys, full_scan_mode, local_llm=None):
    
    if full_scan_mode:
        code_to_send = html_code
        if len(html_code) > 100000:
            print(Fore.MAGENTA + f"    [!] Large file ({len(html_code)} chars). Processing full code...")
    else:
        code_to_send = html_code[:15000]
        if len(html_code) > 15000:
             print(Fore.CYAN + f"    [i] Code truncated to first 15k chars (Light Mode).")

    input_summary = ""
    if inputs["url_params"]: input_summary += f"URL Parameters: {', '.join(inputs['url_params'])}\n"
    if inputs["form_inputs"]: input_summary += f"Form Fields: {', '.join(inputs['form_inputs'])}\n"
    if inputs["potential_headers"]: input_summary += f"Detected Headers/Secrets: {', '.join(inputs['potential_headers'])}\n"
    if not input_summary: input_summary = "No user inputs detected."

    prompt = f"""
You are a cybersecurity analyst. Target: {page_url}

=== EXTRACTED DATA ===
{input_summary}
======================

Task:
1. **Analyze Headers & Secrets:** Check 'Detected Headers' for hardcoded API keys/JWTs.
2. **Analyze Inputs:** Check URL Params/Forms for SQLi, RCE, XSS.
3. **Source Code:** Scan HTML/JS for logic flaws or DOM XSS.

Report Format:
Start response STRICTLY with: "CONFIDENCE: [HIGH/MEDIUM/LOW]"

1. **Vulnerabilities:** List issues.
2. **Analysis:** Risk assessment.
3. **Safe Verification (PoC):** BENIGN proofs only (e.g. alert(1)).
4. **Remediation:** Fix suggestions.

SOURCE CODE:
{code_to_send} 
""" 
    results = {}

    # --- GEMINI ---
    if "gemini" in model_choice or "multi" in model_choice:
        if api_keys.get("GEMINI_API"):
            try:
                genai.configure(api_key=api_keys["GEMINI_API"])
                model = genai.GenerativeModel('gemini-2.0-flash') 
                response = model.generate_content(prompt)
                results["gemini"] = response.text
            except Exception as e: results["gemini"] = f"Error: {e}"

    # --- OPENAI ---
    if "chatgpt" in model_choice or "multi" in model_choice:
        if api_keys.get("CHATGPT_API"):
            try:
                client = openai.OpenAI(api_key=api_keys["CHATGPT_API"])
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}]
                )
                results["chatgpt"] = response.choices[0].message.content
            except Exception as e: results["chatgpt"] = f"Error: {e}"

    # --- LOCAL ---
    if "local" in model_choice and local_llm:
        print(Fore.CYAN + "[*] Analyzing with Local LLM...")
        try:
            output = local_llm.create_chat_completion(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2, max_tokens=2000
            )
            results["local"] = output['choices'][0]['message']['content']
        except Exception as e: results["local"] = f"Error: {e}"

    return results

# === HELPER FUNCTIONS ===
def clean_url(url): return url.strip().rstrip(")/")

def extract_internal_files(base_url, html, allowed_scope_domains):
    soup = BeautifulSoup(html, 'html.parser')
    found = set()
    base_domain = urlparse(base_url).netloc
    
    for tag in soup.find_all(['a', 'script', 'link']):
        href = tag.get('href') or tag.get('src')
        if href:
            full_url = urljoin(base_url, href)
            href_domain = urlparse(full_url).netloc
            is_in_scope = False
            if allowed_scope_domains:
                for scope in allowed_scope_domains:
                    if scope in href_domain: is_in_scope = True; break
            elif href_domain == base_domain: is_in_scope = True

            if is_in_scope and not any(full_url.endswith(ext) for ext in ['.png', '.jpg', '.css', '.pdf', '.ico']):
                found.add(full_url)
    return list(found)

def parse_confidence(text):
    match = re.search(r"CONFIDENCE:\s*(HIGH|MEDIUM|LOW)", text, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"

def save_report(filename, url, reports):
    if not filename: return
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*60}\nREPORT: {url}\nTIME: {time.strftime('%Y-%m-%d %H:%M:%S')}\n{'='*60}\n")
            for model, text in reports.items(): f.write(f"\n--- {model.upper()} ---\n{text}\n")
            f.write("\n" + "-"*60 + "\n")
    except Exception as e: print(Fore.RED + f"[!] File Error: {e}")

# === MAIN SCAN LOOP ===
def scan_site(start_url, cookies=None, model_choice="gemini", api_keys=None, delay=0, output_file=None, min_confidence="LOW", crawl_limit=50, allowed_scope=None, full_scan_mode=False, local_llm=None, use_selenium=False):
    start_url = clean_url(start_url)
    
    # === HYBRID ENGINE SELECTION ===
    driver = None
    if use_selenium:
        driver = setup_selenium()
        if not driver:
            print(Fore.RED + "[!] Falling back to Standard Requests Mode.")
            # Code continues with driver=None, effectively using requests
    
    scan_queue = set([start_url])
    
    # Always use Requests for initial robots/sitemap (It's faster)
    robots = fetch_url(urljoin(start_url, "/robots.txt"), None, cookies)
    if robots: scan_queue.update([urljoin(start_url, line.split(":")[1].strip()) for line in robots.splitlines() if "allow:" in line.lower()])
    
    pending_urls = sorted(list(scan_queue))
    processed_count = 0
    limit_display = "UNLIMITED" if crawl_limit == 0 else str(crawl_limit)
    limit_val = math.inf if crawl_limit == 0 else crawl_limit

    engine_name = "SELENIUM (Browser Mode)" if driver else "REQUESTS (Fast Mode)"
    print(Fore.BLUE + f"\n=== Scanning Target: {start_url} ===")
    print(Fore.YELLOW + f"[*] Engine: {engine_name}")
    
    while pending_urls and processed_count < limit_val:
        current_url = pending_urls.pop(0)
        if current_url in CRAWLED_URLS: continue
        CRAWLED_URLS.add(current_url)
        processed_count += 1

        if processed_count > 1 and delay > 0:
             print(Fore.MAGENTA + f"... Sleeping {delay}s ...")
             time.sleep(delay)

        print(Fore.BLUE + f"\n[{processed_count}/{limit_display}] Analyzing: {current_url}")
        
        # === HYBRID FETCH ===
        html = fetch_url(current_url, driver, cookies)
        
        if not html:
            print(Fore.RED + "[-] Failed to fetch.")
            continue

        # Extract
        new_links = extract_internal_files(current_url, html, allowed_scope)
        for link in new_links:
            if link not in CRAWLED_URLS and link not in pending_urls: pending_urls.append(link)
        
        inputs = extract_inputs(current_url, html)
        if inputs["potential_headers"]:
             print(Fore.MAGENTA + f"    [!] Detected Headers: {inputs['potential_headers']}")

        # Analyze
        reports = analyze_with_ai(model_choice, html, current_url, inputs, api_keys, full_scan_mode, local_llm)
        
        should_save = False
        for model, report in reports.items():
            confidence = parse_confidence(report)
            color = Fore.RED + Style.BRIGHT if confidence == "HIGH" else Fore.GREEN
            print(f"{color}\n--- {model.upper()} (Confidence: {confidence}) ---")
            
            allowed = ["HIGH", "MEDIUM", "LOW", "ALL"]
            if min_confidence == "ALL" or allowed.index(confidence) <= allowed.index(min_confidence):
                # === PRINT FULL REPORT ===
                print(Style.RESET_ALL + report) 
                # =========================
                should_save = True
            else:
                print(Style.DIM + f"[Skipping low confidence report]")

        if should_save and output_file:
            save_report(output_file, current_url, reports)
            # Optional: Add small indicator that file was saved, without implying truncation
            print(Fore.GREEN + f"[+] Report appended to {output_file}")

    if driver: driver.quit()
    print(Fore.GREEN + f"\n[+] Scan Complete.")

# === MAIN ===
if __name__ == "__main__":
    api_keys = read_api_keys("keys.txt")

    local_llm = None
    if HAS_LOCAL_LIB: local_llm = setup_offline_model()

    target = input(Fore.GREEN + "\nEnter start URL: ")
    cookie_input = input(Fore.GREEN + "Enter cookies (optional): ").strip()
    cookies = cookie_input if cookie_input else None

    # === NEW: EXPLICIT ENGINE SELECTION ===
    print(Fore.CYAN + "\nSelect Fetch Engine:")
    print("  1) Standard Mode (Requests) - FAST, Static HTML only")
    print("  2) Browser Mode (Selenium)  - SLOW, Renders JS/SPAs")
    if not HAS_SELENIUM: print(Fore.RED + "     (Selenium library not detected)")
    
    eng_choice = input("Choice (Default 1): ").strip()
    use_selenium = True if eng_choice == "2" else False
    
    print(Fore.CYAN + "\nSelect AI Model:")
    print("  1) Gemini")
    print("  2) GPT-4o-mini")
    print("  3) Multi-Model")
    if local_llm: print("  4) Offline Model")
    c = input("Choice: ").strip()
    model_choice = "gemini" 
    if c == "2": model_choice = "chatgpt"
    elif c == "3": model_choice = "multi"
    elif c == "4" and local_llm: model_choice = "local"

    print(Fore.CYAN + "\nAnalysis Depth:")
    print("  1) Light (15k chars)")
    print("  2) Deep (Full Code)")
    full_scan_mode = True if input("Choice: ").strip() == "2" else False

    delay = float(input(Fore.GREEN + "\nRate limit (0 for none): ") or 0)
    
    print(Fore.CYAN + "\nMax pages to scan (0 = Unlimited):")
    try: limit_input = int(input(Fore.GREEN + "Limit: ").strip())
    except: limit_input = 50 
    
    print(Fore.CYAN + "\nLoad Scope File? (Enter to skip):")
    scope_file = input(Fore.GREEN + "Filename: ").strip()
    allowed_scope = read_scope_file(scope_file) if scope_file else None

    output_file = input(Fore.GREEN + "\nSave report to (Enter to skip): ").strip()
    
    print(Fore.CYAN + "\nMinimum Confidence to Save?")
    print("  1) LOW")
    print("  2) MEDIUM")
    print("  3) HIGH")
    print("  4) ALL")
    conf = input("Choice: ").strip()
    min_conf = "LOW"
    if conf == "2": min_conf = "MEDIUM"
    elif conf == "3": min_conf = "HIGH"
    elif conf == "4": min_conf = "ALL"

    scan_site(target, cookies, model_choice, api_keys, delay, output_file, min_conf, limit_input, allowed_scope, full_scan_mode, local_llm, use_selenium)
