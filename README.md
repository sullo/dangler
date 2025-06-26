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

### Resource and Performance Options

- `--max-resources` or `-R` — Maximum number of remote resources to check (default: 1000). If this limit is reached, the scan will end early with a warning.
- `--threads-crawl` or `-tc` — Number of concurrent page crawlers to use (default: 5).
- `--threads-resource` or `-tr` — Number of concurrent resource checks to use (default: 10).

### Crawling Behavior Options

- `--robots` or `-r` — Honor robots.txt rules when crawling. Fetches and parses robots.txt from the target domain and respects Disallow/Allow directives and Crawl-delay settings.

### Help

- `--help` or `-h` — Show help message with all available options.

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
  --robots \
  --manual
```

- This will set the cookies `foo=bar`, `baz=qux` (with Path, Domain, Secure), and `session=abc123` (with HttpOnly), send the specified HTTP headers with every request, honor robots.txt rules, and allow you to log in manually before the scan continues.

### Outputs:
- `myreport.json` — Detailed JSON report with all findings
- `myreport/index.html` — HTML report with summary and detailed breakdowns
- `myreport/dns-failures.html` — List of DNS failures
- `myreport/connect-failures.html` — List of connection failures  
- `myreport/http-failures.html` — List of HTTP failures
- `myreport/all-resources.html` — All resources checked
- `myreport/unique-resources.html` — Unique resources (deduplicated)
- `myreport/console-log.html` — Console output during scan

## Takeover Detection

The Dangler includes intelligent takeover detection that focuses on domains where user-created content is actually possible:

- **DNS failures** — Always flagged as potential takeovers
- **TCP failures** — Always flagged as potential takeovers  
- **HTTP 4xx failures** — Only flagged as potential takeovers for domains in the takeover targets list
- **HTTP 5xx failures** — Not flagged as takeovers (server errors)

The takeover detection system uses fingerprint-based validation to identify vulnerable services. When a resource fails to load from a known takeover target domain, The Dangler performs additional checks:

1. **DNS/Connection Failures**: If a domain doesn't resolve or can't be reached, it's flagged as a potential takeover opportunity
2. **Fingerprint Validation**: For domains that do respond, the tool checks the response content against known service fingerprints to determine if the service is vulnerable

### Takeover States

The tool categorizes takeover opportunities with visual indicators:

- 🚨 **DNS failure + takeover target** — High priority: Domain doesn't resolve and is in the takeover targets list
- ⚠️ **DNS failure** — Medium priority: Domain doesn't resolve but not in takeover targets  
- ❌ **Fingerprint found** — Confirmed vulnerable: Domain responds and matches a known vulnerable fingerprint

### Takeover Targets Database

The takeover targets and fingerprints are sourced from the comprehensive database maintained by the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz/) project. This community-driven repository contains verified takeover targets for hundreds of services including:

- Cloud platforms (AWS, Azure, Google Cloud)
- CDN services (Cloudflare, Fastly, Akamai)
- Hosting providers (GitHub Pages, Heroku, Netlify)
- SaaS platforms (Shopify, Zendesk, Intercom)
- And many more...

The `fingerprints.json` file contains the latest verified takeover targets with their associated fingerprints, CNAME patterns, and vulnerability status. This database is automatically updated and maintained by the can-i-take-over-xyz community.

### Customizing Takeover Detection

You can modify the `fingerprints.json` file to:
- Add new takeover targets for your specific assessment needs
- Remove targets that are no longer relevant
- Update fingerprints for services that have changed their error responses

The file format follows the structure used by the can-i-take-over-xyz project, ensuring compatibility and easy updates.

## Robots.txt Support

When using the `--robots` flag, The Dangler will:

1. Fetch `/robots.txt` from the target domain immediately after connection
2. Parse User-agent, Disallow, Allow, and Crawl-delay directives
3. Respect the rules during crawling:
   - Skip URLs that match Disallow patterns
   - Allow URLs that match Allow patterns (overrides Disallow)
   - Apply Crawl-delay timing between requests
4. Cache robots.txt rules to avoid repeated fetches

Example robots.txt behavior:
```
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/
Crawl-delay: 1
```

With `--robots` flag:
- ✅ Crawls: `https://example.com/public/page`
- ❌ Skips: `https://example.com/admin/dashboard`
- ❌ Skips: `https://example.com/private/data`
- ⏱️ Waits 1 second between requests

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

