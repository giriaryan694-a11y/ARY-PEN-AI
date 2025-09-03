#########################################
# Author: Aryan
# Copyright: 2025 Aryan
# GitHub: https://github.com/giriaryan694-a11y
# Note: Unauthorized copying without credit is prohibited
#########################################

import os
import re
import requests
import pyfiglet
from termcolor import colored
from colorama import Fore
import google.generativeai as genai
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# === CLEAR SCREEN & BANNER ===
os.system("clear")
banner = pyfiglet.figlet_format("ARY-PEN-AI")
Banner = colored(banner, "red")
print(Banner)
print(Fore.YELLOW + "          ..:: Made by Aryan Giri ::..")
print()
print(Fore.YELLOW + "  ⚠ This tool is only made for educational & research purposes ⚠")
print()

# === READ API KEY ===
try:
    with open("key.txt", "r") as f:
        GOOGLE_API_KEY = f.read().strip()
except FileNotFoundError:
    print(Fore.RED + "[!] key.txt not found. Please create a file named key.txt with your Gemini API key.")
    exit()

# === SETUP GOOGLE GEMINI ===
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

# === FUNCTIONS ===

def clean_url(url):
    return url.strip().rstrip(")/")

def fetch_url(url, cookies=None):
    headers = {}
    if cookies:
        headers['Cookie'] = cookies
    try:
        res = requests.get(url, headers=headers, timeout=10)
        return res.text if res.status_code == 200 else None
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching {url}: {e}")
        return None

def analyze_html_with_gemini(html_code, page_url):
    prompt = f"""
You are a professional penetration tester. Review the following HTML/JS source code from: {page_url}
Identify any security issues like XSS, insecure forms, exposed APIs, hardcoded credentials, or outdated libraries.
Give actionable, brief recommendations.

Detect any security vulnerabilities (XSS, CSRF, exposed APIs, hidden paths, hardcoded creds, etc.) and provide a brief explanation with suggestions. also give payloads for PoC
SOURCE:
{html_code}
"""
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"[!] Gemini Error: {e}"

def extract_internal_files(base_url, html):
    soup = BeautifulSoup(html, 'html.parser')
    found = set()

    for tag in soup.find_all(['a', 'script', 'link']):
        href = tag.get('href') or tag.get('src')
        if href:
            if href.startswith('/'):
                full_url = urljoin(base_url, href)
            elif base_url in href:
                full_url = href
            elif href.startswith("http"):
                continue
            else:
                full_url = urljoin(base_url, '/' + href)

            if any(full_url.endswith(ext) for ext in ['.php', '.js', '.html', '.txt', '/', '.env']):
                found.add(full_url)

    return list(found)

def scan_site(url, cookies=None):
    url = clean_url(url)
    print(Fore.BLUE + f"\n=== Scanning: {url} ===\n")

    # Step 1: robots.txt
    robots = fetch_url(urljoin(url, "/robots.txt"), cookies)
    if robots:
        print(Fore.GREEN + "[+] robots.txt found:\n", robots)
    else:
        print(Fore.GREEN + "[-] robots.txt not found.")

    # Step 2: sitemap.xml
    sitemap = fetch_url(urljoin(url, "/sitemap.xml"), cookies)
    sitemap_urls = []
    if sitemap:
        print(Fore.GREEN + "[+] Sitemap found. Parsing...")
        soup = BeautifulSoup(sitemap, "xml")
        sitemap_urls = [loc.text for loc in soup.find_all("loc")]
    else:
        print(Fore.RED + "[-] Sitemap not found.")

    if not sitemap_urls:
        print(Fore.GREEN + "[!] Falling back to homepage.")
        sitemap_urls = [url]

    all_targets = set(sitemap_urls)

    print(Fore.GREEN + "[*] Extracting internal files from homepage...")
    homepage = fetch_url(url, cookies)
    if homepage:
        links = extract_internal_files(url, homepage)
        all_targets.update(links)

    # Step 3: Analyze each file
    for target in sorted(all_targets):
        print(Fore.BLUE + f"\n[+] Analyzing: {target}")
        html = fetch_url(target, cookies)
        if html:
            result = analyze_html_with_gemini(html, target)
            print(Fore.GREEN + "[*] Vulnerability Report:\n", result)
        else:
            print("[-] Could not fetch source code.")

# === MAIN ===
if __name__ == "__main__":
    target = input(Fore.GREEN + "Enter target URL (e.g., http://testphp.vulnweb.com/): ")
    print(Fore.YELLOW + "Example cookie input format: name=value; name2=value2")
    cookie_input = input(Fore.GREEN + "Enter cookies (press Enter for none): ").strip()
    cookies = cookie_input if cookie_input else None

    scan_site(target, cookies)