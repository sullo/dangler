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

3. Install Playwright browsers:
   ```bash
   npx playwright install
   ```

   *(If you don't have a `package.json`, initialize first with:)*  
   ```bash
   npm init -y
   npm install playwright
   npx playwright install
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
- `--cookie` or `-C` — Set cookies for the browser session. Accepts a string in the format you'd copy from a browser or proxy, e.g. `foo=bar; baz=qux; Path=/; Domain=example.com; Secure`. You can use this flag multiple times.
- `--header` or `-H` — Set extra HTTP headers for all requests. Use multiple times for multiple headers, e.g. `-H "X-Test: foo" -H "User-Agent: custom"`.
- `--debug` or `-d` — Enable debug output for extra detail.

### Example:
```bash
node dangler.js --url https://example.com \
  --output myreport \
  --max-pages 20 \
  --proxy http://localhost:8080 \
  --timeout 10000 \
  --cookie "foo=bar; baz=qux; Path=/; Domain=example.com; Secure" \
  --cookie "session=abc123; HttpOnly" \
  --header "X-Test: foo" \
  --header "User-Agent: custom UA"
```

- This will set the cookies `foo=bar`, `baz=qux` (with Path, Domain, Secure), and `session=abc123` (with HttpOnly), and send the specified HTTP headers with every request.

### Outputs:
- `myreport.json`