// Modern Chromium user agent (Chrome 124 on macOS)
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.91 Safari/537.36';
// The Dangler - dangler.js
// Full version: HTTP status code, deduped resources, clear failure output

const { chromium } = require('playwright');
const dns = require('dns');
const net = require('net');
const fs = require('fs');

// === CLI FLAG PARSER ===
const args = process.argv.slice(2);
const validFlags = new Set([
  '--url', '-u',
  '--debug', '-d',
  '--output', '-o',
  '--max-pages', '-m',
  '--proxy', '-p',
  '--timeout', '-t',
  '--cookie', '-C',
  '--header', '-H',
  '--manual', '-M'
]);

const flags = {
  url: '',
  debug: false,
  output: 'dangler_output',
  maxPages: 50,
  proxy: '',
  timeout: 5000,
  cookies: [],
  headers: [],
  manual: false
};

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg.startsWith('-') && !validFlags.has(arg)) {
    console.error(`Unknown flag: ${arg}`);
    process.exit(1);
  }
  if (arg === '--url' || arg === '-u') {
    flags.url = args[i + 1];
    i++;
  } else if (arg === '--debug' || arg === '-d') {
    flags.debug = true;
  } else if (arg === '--output' || arg === '-o') {
    flags.output = args[i + 1];
    i++;
  } else if (arg === '--max-pages' || arg === '-m') {
    flags.maxPages = parseInt(args[i + 1], 10);
    if (isNaN(flags.maxPages) || flags.maxPages < 1) {
      console.error('--max-pages must be a positive integer.');
      process.exit(1);
    }
    i++;
  } else if (arg === '--proxy' || arg === '-p') {
    flags.proxy = args[i + 1];
    i++;
  } else if (arg === '--timeout' || arg === '-t') {
    flags.timeout = parseInt(args[i + 1], 10);
    if (isNaN(flags.timeout) || flags.timeout < 1000) {
      console.error('--timeout must be at least 1000ms (1 second).');
      process.exit(1);
    }
    i++;
  } else if (arg === '--cookie' || arg === '-C') {
    flags.cookies.push(args[i + 1]);
    i++;
  } else if (arg === '--header' || arg === '-H') {
    flags.headers.push(args[i + 1]);
    i++;
  } else if (arg === '--manual' || arg === '-M') {
    flags.manual = true;
  }
}

if (!flags.url) {
  console.error('Usage: node dangler.js --url <target> [--debug] [--output -dir>] [--max-pages <num>] [--proxy <url>] [--timeout <ms>] [--cookie <cookieString>] [--header <headerString>] [--manual]');
  process.exit(1);
}

const REMOTE_TIMEOUT_MS = flags.timeout;

const outputBase = flags.output.replace(/\.(json|html)$/i, '');

// New logic for output directory and filenames
const outputDir = outputBase;
const useOutputDir = !outputBase.includes('/') && !outputBase.includes('\\');
let outputJson, outputHtml;
if (useOutputDir) {
  outputJson = `${outputDir}/dangler-report.json`;
  outputHtml = `${outputDir}/index.html`;
} else {
  outputJson = `${outputBase}.json`;
  outputHtml = `${outputBase}.html`;
}

let startDomain;
try {
  startDomain = (new URL(flags.url)).hostname;
} catch (e) {
  console.error(`Invalid URL provided: ${flags.url}`);
  process.exit(1);
}
const allowedDomains = [startDomain];
const maxPages = flags.maxPages;

const results = [];
const hostCheckCache = new Map();
const urlCheckCache = new Map();

let totalRemoteResources = 0;
let potentialTakeovers = 0;
const allDiscoveredPages = new Set();

// Helper to format date as MM/DD/YYYY HH:MM:SS (24-hour)
function formatLocalDate(date) {
  const pad = n => n.toString().padStart(2, '0');
  return `${pad(date.getMonth() + 1)}/${pad(date.getDate())}/${date.getFullYear()} ` +
         `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

// Track scan start time (local)
const scanStartDate = new Date();
let scanStartLocal = formatLocalDate(scanStartDate);
let scanStopLocal = '';
let scanDuration = '';

// === HELPERS ===

function stripQuery(url) {
  try {
    const u = new URL(url);
    u.search = '';
    return u.toString();
  } catch {
    return url;
  }
}

function getPath(url) {
  try {
    return new URL(url).pathname || '/';
  } catch {
    return '/';
  }
}

function escapeHtml(text) {
  if (typeof text !== 'string') return '';
  // Proper HTML encoding - whitelist approach: only allow safe characters
  return text.replace(/./g, function(char) {
    const code = char.charCodeAt(0);
    // Allow alphanumeric, space, and basic punctuation
    if ((code >= 48 && code <= 57) || // 0-9
        (code >= 65 && code <= 90) || // A-Z
        (code >= 97 && code <= 122) || // a-z
        code === 32 || // space
        code === 44 || // comma
        code === 46 || // period
        code === 45 || // hyphen
        code === 95) { // underscore
      return char;
    }
    return '&#x' + code.toString(16) + ';';
  });
}

function sanitizeUrl(url) {
  if (typeof url !== 'string') return '';
  
  try {
    const parsed = new URL(url);
    // Whitelist safe protocols
    const safeProtocols = ['http:', 'https:', 'ftp:', 'mailto:', 'tel:'];
    if (!safeProtocols.includes(parsed.protocol)) {
      return '#blocked'; // Block javascript:, data:, vbscript:, etc.
    }
    
    // Escape quotes in the URL to prevent breaking href attribute
    return parsed.toString().replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
  } catch {
    // If URL parsing fails, it's probably not a valid URL anyway
    return '#invalid';
  }
}

async function withTimeout(promise, ms) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(`Timeout after ${ms} ms`)), ms);
  });
  // Ensure the original promise's rejection is always handled
  return Promise.race([
    promise.finally(() => clearTimeout(timeoutId)).catch(() => {}),
    timeout
  ]);
}

async function resolveHost(hostname) {
  if (!hostname) return false;
  return withTimeout(new Promise((resolve) => {
    dns.lookup(hostname, (err) => {
      resolve(!err);
    });
  }), REMOTE_TIMEOUT_MS).catch(() => false);
}

async function checkTCP(hostname) {
  if (!hostname) return false;
  return withTimeout(new Promise((resolve) => {
    const socket = net.connect(80, hostname);
    
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  }), REMOTE_TIMEOUT_MS).catch(() => false);
}

async function checkHTTP(url) {
  if (!url.startsWith('http')) return { ok: false, status: 0 };
  return withTimeout(fetch(url, { method: 'HEAD' })
    .then(res => ({ ok: res.status < 400, status: res.status }))
  , REMOTE_TIMEOUT_MS).catch(() => ({ ok: false, status: 0 }));
}

async function analyzeJS(url) {
  if (!url.startsWith('http')) return false;
  return withTimeout(
    fetch(url)
      .then(res => res.text())
      .then(js =>
        /createElement\s*\(\s*['"]script['"]\s*\)/i.test(js) ||
        /\$\.getScript/i.test(js) ||
        /import\s*\(/i.test(js)
      ),
    REMOTE_TIMEOUT_MS
  ).catch(() => false);
}

async function getHostCheck(hostname) {
  if (!hostname) return { resolves: false, tcpOk: false };
  if (hostCheckCache.has(hostname)) {
    if (flags.debug) console.log(`Host cache HIT: ${hostname}`);
    return hostCheckCache.get(hostname);
  }
  if (flags.debug) console.log(`Host cache MISS: ${hostname} -> checking...`);
  const resolves = await resolveHost(hostname);
  const tcpOk = await checkTCP(hostname);

  const result = { resolves, tcpOk };
  hostCheckCache.set(hostname, result);
  return result;
}

async function getUrlCheck(url) {
  if (!url.startsWith('http')) return { httpOk: false, httpStatusCode: 0, loadsOtherJS: false };

  const ext = url.split('?')[0].split('.').pop().toLowerCase();
  const cacheKey = (ext === 'js' || ext === 'css') ? stripQuery(url) : url;

  if (urlCheckCache.has(cacheKey)) {
    if (flags.debug) console.log(`URL cache HIT: ${cacheKey}`);
    return urlCheckCache.get(cacheKey);
  }

  if (flags.debug) console.log(`URL cache MISS: ${cacheKey} -> checking...`);
  const httpRes = await checkHTTP(url);
  let loadsOtherJS = false;
  if (ext === 'js') {
    loadsOtherJS = await analyzeJS(url);
  }

  const result = { httpOk: httpRes.ok, httpStatusCode: httpRes.status, loadsOtherJS };
  urlCheckCache.set(cacheKey, result);
  return result;
}

// === Spinner ===
const spinnerChars = ['|', '/', '-', '\\'];
let spinnerIndex = 0;
let spinnerInterval;

function startSpinner(message) {
  process.stdout.write(message + '\n');
  spinnerInterval = setInterval(() => {
    process.stdout.write(`\r${spinnerChars[spinnerIndex++]} `);
    spinnerIndex %= spinnerChars.length;
  }, 100);
}

function stopSpinner() {
  clearInterval(spinnerInterval);
  process.stdout.write('\r ');
  process.stdout.write('\r');
}

// === REPORT ===
function writeReportsAndExit() {
  stopSpinner();
  // Set stop time and duration
  const scanStopDate = new Date();
  scanStopLocal = formatLocalDate(scanStopDate);
  const durationMs = scanStopDate - scanStartDate;
  const hours = Math.floor(durationMs / 3600000);
  const minutes = Math.floor((durationMs % 3600000) / 60000);
  const seconds = Math.floor((durationMs % 60000) / 1000);
  scanDuration = `${hours}h ${minutes}m ${seconds}s`;

  // Create output directory if needed
  if (useOutputDir) {
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
  }
  fs.writeFileSync(outputJson, JSON.stringify(results, null, 2));
  console.log(`\nJSON report saved to: ${outputJson}`);

  const pagesCrawled = results.length;
  const totalPagesFound = allDiscoveredPages.size;

  // --- Failures to console ---
  const failures = [];
  results.forEach(page => {
    page.resources.forEach(r => {
      if (!r.resolves || !r.tcpOk || !r.httpOk) {
        let reason = [];
        if (!r.resolves) reason.push("DNS failure");
        else if (!r.tcpOk) reason.push("TCP failure");
        else if (!r.httpOk) reason.push(`HTTP ${r.httpStatusCode}`);
        failures.push(`   [!] ${r.url} (${reason.join(', ')}) on ${page.page}`);
      }
    });
  });

  if (failures.length > 0) {
    console.log(`\n❌ Failures:`);
    failures.forEach(failure => console.log(failure));
  }

  // --- HTML ---
  let html = `<html><head><title>Dangler Report</title><style>
    body { font-family: sans-serif; margin: 40px; }
    table { border-collapse: collapse; margin-bottom: 20px; }
    .halfwidth { width: 50%; min-width: 350px; }
    td.label { font-weight: bold; text-align: left; width: 40%; background: #f0f0f0; }
    td.value { text-align: left; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #f0f0f0; }
    a { color: #0645AD; }
    small { color: #666; font-size: smaller; }
  </style></head><body>
  <h1>The Dangler</h1>
  <hr>
  <h2>Details</h2>
  <table class="halfwidth">
    <tr><td class="label">Target</td><td class="value">${escapeHtml(flags.url)}</td></tr>
    <tr><td class="label">Max Pages</td><td class="value">${escapeHtml(String(flags.maxPages))}</td></tr>
    <tr><td class="label">CLI Args</td><td class="value">dangler.js ${escapeHtml(process.argv.slice(2).join(' '))}</td></tr>
  </table>`;

  // --- Summary Table ---
  html += `<h2>Summary</h2>
   <table class="halfwidth">
   <tr><td class="label">Start</td><td class="value">${escapeHtml(scanStartLocal)}</td></tr>
   <tr><td class="label">Stop</td><td class="value">${escapeHtml(scanStopLocal)}</td></tr>
   <tr><td class="label">Duration</td><td class="value">${escapeHtml(scanDuration)}</td></tr>
   <tr><td class="label">Pages Crawled</td><td class="value">${pagesCrawled} of ${totalPagesFound}</td></tr>
   <tr><td class="label">Remote Resources Checked</td><td class="value">${totalRemoteResources}</td></tr>
   <tr><td class="label">Potential Takeovers</td><td class="value">${potentialTakeovers}</td></tr>
   </table>`;

  // --- Count failure types and unique resources ---
  let dnsFailures = 0, connectFailures = 0, httpFailures = 0;
  const allCheckedResources = [];
  results.forEach(page => {
    page.resources.forEach(r => {
      allCheckedResources.push(r.url);
      if (!r.resolves) dnsFailures++;
      else if (!r.tcpOk) connectFailures++;
      else if (!r.httpOk) httpFailures++;
    });
  });
  const totalChecked = allCheckedResources.length;
  const uniqueChecked = new Set(allCheckedResources).size;

  // --- Details Table ---
  html += `<h2>Details</h2>
   <table class="halfwidth">
   <tr><td class="label">DNS Failures</td><td class="value">${dnsFailures}</td></tr>
   <tr><td class="label">Connect Failures</td><td class="value">${connectFailures}</td></tr>
   <tr><td class="label">HTTP Failures</td><td class="value">${httpFailures}</td></tr>
   <tr><td class="label">Total Resources Checked</td><td class="value">${totalChecked}</td></tr>
   <tr><td class="label">Total Unique Resources</td><td class="value">${uniqueChecked}</td></tr>
   </table>`;

  // --- Failures Table ---
  html += `<h2>Failures: Could Not Resolve or Retrieve</h2><table><tr><th>Resource URL</th><th>Parent Page</th><th>Reason</th></tr>`;
  results.forEach(page => {
    page.resources.forEach(r => {
      if (!r.resolves || !r.tcpOk || !r.httpOk) {
        let reason = [];
        if (!r.resolves) reason.push("DNS failure");
        else if (!r.tcpOk) reason.push("TCP failure");
        else if (!r.httpOk) reason.push(`HTTP ${r.httpStatusCode}`);
        html += `<tr>
          <td><a href="${sanitizeUrl(r.url)}" target="_blank">${escapeHtml(r.url)}</a></td>
          <td><a href="${sanitizeUrl(page.page)}" target="_blank">${escapeHtml(getPath(page.page))}</a></td>
          <td>${escapeHtml(reason.join(", "))}</td>
        </tr>`;
      }
    });
  });
  html += `</table>`;

  // --- Unique Offsite Resources ---
  html += `<h2>Unique Offsite Resources<br><small style="font-size: smaller;">(cache busters dropped)</small></h2>
  <table><tr><th>Resource URL</th><th>Count</th></tr>`;
  const unique = {};
  results.forEach(page => {
    page.resources.forEach(r => {
      const key = stripQuery(r.url);
      unique[key] = (unique[key] || 0) + 1;
    });
  });
  const sortedUnique = Object.entries(unique).sort((a, b) => b[1] - a[1]);
  sortedUnique.forEach(([key, count]) => {
    html += `<tr><td><a href="${sanitizeUrl(key)}" target="_blank">${escapeHtml(key)}</a></td><td>${count}</td></tr>`;
  });
  html += `</table>`;

  try {
    fs.writeFileSync(outputHtml, html);
    console.log(`HTML report saved to: ${outputHtml}`);
  } catch (error) {
    console.error(`Failed to write HTML report: ${error.message}`);
  }

  process.exit();
}

process.on('SIGINT', () => {
  console.log('\nCTRL+C caught — writing reports...');
  writeReportsAndExit();
});

// === MAIN ===
(async () => {
  console.log(`The Dangler: Starting audit on ${flags.url}`);
  if (flags.debug) console.log('Debug mode ON');

  // Prepare context options before browser creation
  const contextOptions = { userAgent: DEFAULT_USER_AGENT };
  if (flags.proxy) {
    contextOptions.proxy = { server: flags.proxy };
    contextOptions.ignoreHTTPSErrors = true;
    console.warn('[!] Proxy mode: ignoring certificate errors for browser traffic. Results may include insecure connections.');
  }

  let scanContext, scanPage;

  if (flags.manual) {
    console.log('[Manual Mode] You must come back to this terminal and press ENTER to continue after logging in.');
    console.log('[Manual Mode] Press ENTER now to open the browser window.');
    await new Promise(resolve => process.stdin.once('data', resolve));
    const browserManual = await chromium.launch({ headless: false });
    const contextManual = await browserManual.newContext(contextOptions);
    const pageManual = await contextManual.newPage();
    console.log('[Manual Mode] Please log in or interact with the browser window.');
    console.log('[Manual Mode] When finished, press ENTER in this terminal to continue. Do NOT close the browser window yourself.');
    await pageManual.goto(flags.url);
    await new Promise(resolve => process.stdin.once('data', resolve));
    // Extract cookies and storage from manual session
    const cookies = await contextManual.cookies();
    await browserManual.close();
    // Re-launch browser in headless mode for the scan
    const browser2 = await chromium.launch({ headless: true });
    const context2 = await browser2.newContext(contextOptions);
    const page2 = await context2.newPage();
    await context2.addCookies(cookies);
    scanContext = context2;
    scanPage = page2;
    console.log('[Manual Mode] Scan will continue with your session cookies.');
  } else {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext(contextOptions);
    const page = await context.newPage();
    scanContext = context;
    scanPage = page;
  }

  // Add cookies if specified
  if (flags.cookies.length > 0) {
    const defaultDomain = startDomain;
    let allCookies = [];
    for (const cookieString of flags.cookies) {
      allCookies = allCookies.concat(parseCookieString(cookieString, defaultDomain));
    }
    // Remove undefined attributes (Playwright will error if they're present)
    allCookies = allCookies.map(c => {
      const out = {};
      for (const k in c) {
        if (c[k] !== undefined) out[k] = c[k];
      }
      return out;
    });
    if (flags.debug) console.log('Setting cookies:', allCookies);
    await scanContext.addCookies(allCookies);
  }

  // Add headers if specified, but only for target domain and subdomains
  let extraHeaders = null;
  if (flags.headers.length > 0) {
    extraHeaders = parseHeaders(flags.headers);
    if (flags.debug) console.log('Setting extra HTTP headers (scoped):', extraHeaders);
    scanPage.route('**', (route, request) => {
      try {
        const reqUrl = new URL(request.url());
        // Check if hostname matches target domain or subdomain
        if (reqUrl.hostname === startDomain || reqUrl.hostname.endsWith('.' + startDomain)) {
          // Merge headers
          const merged = { ...request.headers(), ...extraHeaders };
          route.continue({ headers: merged });
        } else {
          route.continue();
        }
      } catch (e) {
        route.continue();
      }
    });
  }

  const queue = [flags.url];
  const visitedPages = new Set();
  allDiscoveredPages.add(flags.url);

  // Handler-scoped variables
  let resources = [];
  let uniqueUrls = new Set();
  scanPage.on('request', request => {
    const reqUrl = request.url();
    if (reqUrl.startsWith('blob:')) return;
    const domain = new URL(reqUrl).hostname;
    const isInternal = allowedDomains.some(d => domain.endsWith(d));
    if (!isInternal && !uniqueUrls.has(reqUrl)) {
      resources.push({ url: reqUrl, domain, resourceType: request.resourceType() });
      uniqueUrls.add(reqUrl);
    }
  });

  try {
    while (queue.length > 0 && visitedPages.size < maxPages) {
      const url = queue.shift();
      if (visitedPages.has(url)) continue;

      const pagesCrawled = visitedPages.size + 1;
      console.log(`\n[#${pagesCrawled}/${maxPages}] Crawling: ${url}`);

      visitedPages.add(url);

      // Reset for this crawl
      resources = [];
      uniqueUrls = new Set();

      startSpinner('Crawling page...');
      try {
        await scanPage.goto(url, { waitUntil: 'networkidle' });
      } catch (error) {
        stopSpinner();
        if (flags.debug) console.log(`Failed to load ${url}: ${error.message}`);
        continue;
      }
      stopSpinner();

      const hrefs = await scanPage.$$eval('a[href]', as => as.map(a => a.href));
      hrefs.forEach(href => {
        try {
          const u = new URL(href);
          if (allowedDomains.some(d => u.hostname.endsWith(d)) && !visitedPages.has(u.href)) {
            queue.push(u.href);
            allDiscoveredPages.add(u.href);
          }
        } catch {}
      });

      startSpinner('Validating resources...');
      try {
        for (const r of resources) {
          try {
            totalRemoteResources++;
            const hostCheck = await getHostCheck(r.domain);
            r.resolves = hostCheck.resolves;
            r.tcpOk = hostCheck.tcpOk;

            const urlCheck = await getUrlCheck(r.url);
            r.httpOk = urlCheck.httpOk;
            r.httpStatusCode = urlCheck.httpStatusCode;
            r.loadsOtherJS = r.resourceType === 'script' ? urlCheck.loadsOtherJS : false;

            r.possibleTakeover = !r.resolves || !r.tcpOk || !r.httpOk;
            if (r.possibleTakeover) potentialTakeovers++;
          } catch (resourceError) {
            if (flags.debug) console.log(`Error validating resource ${r.url}: ${resourceError.message}`);
            // Set default values for failed resource
            r.resolves = false;
            r.tcpOk = false;
            r.httpOk = false;
            r.httpStatusCode = 0;
            r.loadsOtherJS = false;
            r.possibleTakeover = true;
            potentialTakeovers++;
          }
        }
      } catch (error) {
        stopSpinner();
        if (flags.debug) console.log(`Error validating resources for ${url}: ${error.message}`);
        // Continue with the page even if resource validation fails
      }
      stopSpinner();

      results.push({ page: url, resources });
    }
  } catch (error) {
    stopSpinner(); // Ensure spinner is stopped on any error
    console.error(`Fatal error during crawling: ${error.message}`);
    if (flags.debug) console.error(error.stack);
  } finally {
    // Always close browser resources
    try {
      await scanContext.browser().close();
    } catch (error) {
      console.error(`Error closing browser: ${error.message}`);
    }
  }

  writeReportsAndExit();
})();

// Helper to parse cookie string like from a proxy
function parseCookieString(cookieString, defaultDomain) {
  // Split by semicolon, trim whitespace
  const parts = cookieString.split(';').map(p => p.trim()).filter(Boolean);
  const cookies = [];
  let attributes = {};
  let pairs = [];
  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx > 0) {
      const name = part.slice(0, eqIdx).trim();
      const value = part.slice(eqIdx + 1).trim();
      // Check for known attributes
      const lname = name.toLowerCase();
      if (['path', 'domain', 'expires', 'samesite'].includes(lname)) {
        attributes[lname] = value;
      } else {
        pairs.push({ name, value });
      }
    } else {
      // Attributes like Secure, HttpOnly
      const lname = part.toLowerCase();
      if (['secure', 'httponly'].includes(lname)) {
        attributes[lname] = true;
      }
    }
  }
  // For each name/value, create a cookie object with attributes
  for (const pair of pairs) {
    cookies.push({
      name: pair.name,
      value: pair.value,
      domain: attributes.domain || defaultDomain,
      path: attributes.path || '/',
      expires: attributes.expires ? new Date(attributes.expires).getTime() / 1000 : undefined,
      sameSite: attributes.samesite ? attributes.samesite : undefined,
      secure: attributes.secure || false,
      httpOnly: attributes.httponly || false
    });
  }
  return cookies;
}

// Helper to parse headers
function parseHeaders(headerStrings) {
  const headers = {};
  for (const h of headerStrings) {
    const idx = h.indexOf(':');
    if (idx === -1) {
      console.error(`Invalid header format: ${h}`);
      process.exit(1);
    }
    const name = h.slice(0, idx).trim();
    const value = h.slice(idx + 1).trim();
    if (!name) {
      console.error(`Invalid header name in: ${h}`);
      process.exit(1);
    }
    headers[name] = value;
  }
  return headers;
}
