# ARY-PEN-AI 🛡️

A **Next-Generation AI-Powered Vulnerability Scanner & Hardening Assistant** designed for modern defensive security research. It combines web crawling, dynamic analysis, and powerful AI reasoning to uncover logical flaws, insecure patterns, and weak configurations.

> ⚠️ **Disclaimer:** Use only on systems you own or have explicit permission to test. This tool is for **educational and research** purposes.

---

## 🌟 Key Features

### 🧠 Multi‑Model AI Support

* **Cloud Models:** Google Gemini (Free‑tier friendly), OpenAI GPT‑4o‑mini.
* **Offline Models:** Local GGUF LLMs using **llama.cpp** (GPU‑accelerated supported).
* Automatic fallback in case one API key fails.

### 🕷️ Hybrid Crawling Engine

* **Fast Requests Mode:** Ideal for static or lightweight sites.
* **Browser Mode (Selenium):** Renders JavaScript-heavy frameworks (React, Vue, Angular).
* **Deep Spidering:** Unlimited recursive crawling with domain scope control.

### 🔍 Intelligent Input & Code Analysis

* Extracts URL parameters, forms, cookies, headers, and hidden fields.
* Searches for secrets, API tokens, misconfigurations, and outdated libraries.
* AI-based analysis detects logical vulnerabilities such as:

  * XSS
  * SQL Injection
  * Hardcoded keys
  * Authentication/authorization flaws

### 💰 Smart Budget Control

* **Light Scan:** Optimized for API cost saving.
* **Deep Scan:** Full-context, logic-heavy analysis.

### 🛡️ Smart Reporting

* Confidence filtering: **High / Medium / Low / All**.
* Safe PoCs with benign payloads like `alert(1)`.
* Generates structured reports for documentation or bug bounty research.

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/giriaryan694-a11y/ARY-PEN-AI.git
cd ARY-PEN-AI
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional) Enable Offline/GPU Mode

**CPU Only:**

```bash
pip install llama-cpp-python
```

**NVIDIA GPU:**

```bash
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python --upgrade --force-reinstall --no-cache-dir
```

---

## 🔑 Configuration

Create a file named **keys.txt** in the project root:

```
GEMINI_API=Your_Gemini_Key
CHATGPT_API=Your_OpenAI_Key
```

Supports using just one API key if the other expires.

---

## 🚀 Usage

Run the tool using:

```bash
python main.py
```

### Interactive Options

1. **Target URL** – Example: `http://testphp.vulnweb.com/`
2. **Fetch Engine** – Requests or Selenium
3. **AI Model** – Gemini / GPT / Multi‑Model / Offline
4. **Analysis Depth** – Light or Deep
5. **Scope Control** – Load `scope.txt` for allowed domains
6. **Report Confidence** – High / Medium / Low / ALL

---

## 📂 Project Structure

(Updated with scope.txt example below)

```
main.py     → Main tool logic
keys.txt          → API keys (not pushed to Git)
requirements.txt  → Dependency list
scope.txt         → (Optional) Allowed domains for crawling
reports.txt       → Generated vulnerability report
```

---

## 📘 Example: scope.txt

```
testphp.vulnweb.com
rest.vulnweb.com
api.google.com
developer.mozilla.org
```

### How It Works

* **One domain per line:** The tool reads each entry individually.
* **Protocols optional:** Both `https://example.com` and `example.com` are accepted.
* **Subdomain logic:** Adding a base domain (e.g., `vulnweb.com`) allows scanning of all its subdomains.
* **Strict mode:** When `scope.txt` is loaded, ONLY domains listed here are crawled. External links are ignored.

## 📸 Screenshots

(Add screenshots of terminal output or UI here.)

---

## 🤝 Contributing

Contributions are welcome! Open an issue before major feature changes.

---

## 📜 License

Copyright © 2025 **Aryan Giri**.
Unauthorized copying without credit is prohibited.

Made with ❤️, Python, and a passion for security research.
