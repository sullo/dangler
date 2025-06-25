# The Dangler

**The Dangler** is a headless, automated pixel and third-party resource audit tool for web security testers.  
It crawls a target website, discovers all pages, captures all external requests (pixels, JS, CSS, images), verifies whether external domains are alive, and highlights any misconfigurations or risks — all in an easy-to-read JSON and HTML report.

---

## 📦 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/dangler.git
   cd dangler
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

   *(If you don't have a `package.json`, initialize first with:)*  
   ```bash
   npm init -y
   npm install playwright
   ```

---

## 🏃‍♂️ Usage

Run **The Dangler** from your terminal:

```bash
node dangler.js --url <target-site> [options]
```

### Required:
- `--url` or `-u` — Target website to crawl.

### Common options:
- `--output` or `-o` — Base name for output files (`.json` and `.html`). Default: `dangler_output`.
- `--max-pages` or `-m` — Max pages to crawl. Default: `50`.
- `--proxy` or `-p` — Proxy URL (e.g. for Burp/ZAP).
- `--timeout` or `-t` — Timeout for remote resource checks in milliseconds. Default: `5000` (5 seconds).
- `--debug` or `-d` — Enable debug output for extra detail.

### Example:
```bash
node dangler.js --url https://example.com --output myreport --max-pages 20 --proxy http://localhost:8080 --timeout 10000
```

### Outputs:
- `myreport.json` — raw data for analysis.
- `myreport.html` — clean, readable report with failures, third-party domains, and a scan summary.

---

##  Copyright

(c) Hack.LLC 2025
