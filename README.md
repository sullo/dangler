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
- `--manual` or `-M` — Open a non-headless browser window for manual login or interaction. Close the window to continue the scan with your session.
- `--debug` or `-d` — Enable debug output for extra detail.

### Additional Options

- `--max-resources <num>`, `-R <num>`: Maximum number of remote resources to check (default: 1000). If this limit is reached, the scan will end early with a warning.

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
  --header "User-Agent: custom UA" \
  --manual
```

- This will set the cookies `foo=bar`, `baz=qux` (with Path, Domain, Secure), and `session=abc123` (with HttpOnly), send the specified HTTP headers with every request, and allow you to log in manually before the scan continues.

### Outputs:
- `myreport.json`

## Authentication Methods

When scanning sites that require authentication, Dangler supports several methods for providing credentials:

### 1. Using Cookies (via CLI)
You can pass one or more cookies directly on the command line using the `--cookie` or `-C` flag.  
Example:
```sh
node dangler.js --url https://example.com \
  --cookie "sessionid=YOUR_SESSION_COOKIE; Path=/; Domain=example.com; Secure"
```
You can repeat the `--cookie` flag to add multiple cookies.

### 2. Using Custom Headers (via CLI)
You can add arbitrary HTTP headers (such as `Authorization` or custom tokens) using the `--header` or `-H` flag.  
Example:
```sh
node dangler.js --url https://example.com \
  --header "Authorization: Bearer YOUR_TOKEN_HERE" \
  --header "X-Custom-Header: value"
```
You can repeat the `--header` flag to add multiple headers.

### 3. Using Manual Mode and Browser
For complex authentication (such as multi-factor or SSO), use the `--manual` or `-M` flag to launch the browser in interactive mode:
```sh
node dangler.js --url https://example.com --manual
```
This will open a browser window where you can log in manually. Once authenticated, Dangler will continue crawling with your session.

---

### Capturing Cookies and Headers with a Proxy

If you're unsure which cookies or headers are needed, or want to capture them from a real login session, you can use a proxy tool like **Burp Suite** or **OWASP ZAP**:

1. Set your browser to use the proxy (e.g., Burp).
2. Log in to the target site through the browser.
3. Inspect the requests in the proxy to find the relevant cookies and headers.
4. Copy these values and supply them to Dangler using the `--cookie` and `--header` flags as shown above.

---

