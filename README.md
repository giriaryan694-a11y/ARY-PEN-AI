
# ![ARY-PEN-AI](https://github.com/giriaryan694-a11y/ARY-PEN-AI/blob/main/image.png)

# ARY-PEN-AI 🚀

**ARY-PEN-AI** is an advanced web vulnerability scanning tool powered by **Google Gemini AI**.  
It automates the process of analyzing websites for common security issues such as:

- XSS (Cross-Site Scripting)  
- CSRF (Cross-Site Request Forgery)  
- Exposed APIs  
- Hidden files & paths  
- Hardcoded credentials  
- Outdated libraries  

All findings are accompanied by actionable recommendations and proof-of-concept payloads, making it perfect for **ethical hacking, penetration testing, and security research**.  

> ⚠ **Disclaimer:** This tool is made for educational and research purposes only. The developer is not responsible for any illegal usage.

---

## 🌟 Features

- Scans `robots.txt` & `sitemap.xml`
- Extracts internal files (.php, .js, .html, .txt)
- Analyzes source code with **Google Gemini AI**
- Provides vulnerability reports with suggested fixes
- Works fully offline except for fetching website data and calling Gemini API
- Friendly CLI interface with colorful banners and alerts

---

## 🛠 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/giriaryan694-a11y/ARY-PEN-AI.git
   cd ARY-PEN-AI
   ```

2. Install required Python modules:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🔑 Create Your Google Gemini API Key

To use ARY-PEN-AI, you need a Google Gemini API key:

1. Go to [Google AI Studio](https://aistudio.google.com/).  
2. Sign in with your Google account.  
3. Navigate to the [API Key page](https://aistudio.google.com/apikey).  
4. Click **"Get API key"** and follow the instructions.  
5. Copy your API key into a file named `key.txt` in the project root.

---

## 🚀 Usage

Run the script and provide the target URL:

```bash
python main.py
```

Example:

```
Enter target URL (e.g., http://testphp.vulnweb.com/): http://testphp.vulnweb.com/
```

The tool will:

1. Scan `robots.txt` and `sitemap.xml`
2. Extract internal files from the homepage
3. Analyze each page with Google Gemini AI
4. Print vulnerability reports and suggested fixes

---

## 📸 Screenshot

![ARY-PEN-AI Demo](https://example.com/png.png)

---

## ⚡ Notes

- Make sure `key.txt` contains only your API key.  
- Recommended for **ethical hacking labs** and **web security research**.  
- Fully compatible with Python 3.10+ on Linux & Windows.  

---

## 💡 Contributing

Feel free to contribute improvements, add new features, or optimize AI analysis!  

---

## 📜 License

This project is licensed under the MIT - see the [LICENSE](LICENSE) file for details.  
