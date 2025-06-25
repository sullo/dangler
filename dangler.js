// The Dangler - dangler.js
// Full version: HTTP status code, deduped resources, clear failure output

const { chromium } = require('playwright');
const dns = require('dns');
const net = require('net');
const fs = require('fs');

// === CLI FLAG PARSER ===
const args = process.argv.slice(2);
const flags = {
  url: '',
  debug: false,
  output: 'dangler_output',
  maxPages: 50,
  proxy: '',
  timeout: 5000
};

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
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
  }
}

if (!flags.url) {
  console.error('Usage: node dangler.js --url <target> [--debug] [--output <base>] [--max-pages <num>] [--proxy <url>] [--timeout <ms>]');
  process.exit(1);
}

const REMOTE_TIMEOUT_MS = flags.timeout;

const outputBase = flags.output.replace(/\.(json|html)$/i, '');
const outputJson = `${outputBase}.json`;
const outputHtml = `${outputBase}.html`;

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
  
  try {
    fs.writeFileSync(outputJson, JSON.stringify(results, null, 2));
    console.log(`\nJSON report saved to: ${outputJson}`);
  } catch (error) {
    console.error(`Failed to write JSON report: ${error.message}`);
  }

  const pagesCrawled = results.length;
  const totalPagesFound = allDiscoveredPages.size;
  const timestamp = new Date().toISOString();

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
  let html = `<html><head><title>The Dangler Report</title><style>
    body { font-family: sans-serif; margin: 40px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #f0f0f0; }
    a { color: #0645AD; }
    small { color: #666; font-size: smaller; }
  </style></head><body>
  <h1>The Dangler</h1>
  <hr>
  <p><strong>Target:</strong> ${flags.url}<br>
  <strong>Max Pages:</strong> ${flags.maxPages}<br>
  <strong>Timestamp:</strong> ${timestamp}</p>`;

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

  // --- Summary Table ---
  html += `<h2>Scan Summary</h2><table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Pages Crawled</td><td>${pagesCrawled} of ${totalPagesFound}</td></tr>
  <tr><td>Remote Resources Checked</td><td>${totalRemoteResources}</td></tr>
  <tr><td>Potential Takeovers</td><td>${potentialTakeovers}</td></tr>
  </table></body></html>`;

  try {
    fs.writeFileSync(outputHtml, html);
    console.log(`HTML report saved to: ${outputHtml}`);
  } catch (error) {
    console.error(`Failed to write HTML report: ${error.message}`);
  }

  console.log(`\n=== Dangler Scan Summary ===`);
  console.log(`Target Site: ${flags.url}`);
  console.log(`Max Pages: ${flags.maxPages}`);
  console.log(`Pages Crawled: ${pagesCrawled} of ${totalPagesFound}`);
  console.log(`Remote Resources Checked: ${totalRemoteResources}`);
  console.log(`Potential Takeovers: ${potentialTakeovers}`);

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

  const browser = await chromium.launch({ headless: true });
  const contextOptions = {};
  if (flags.proxy) {
    contextOptions.proxy = { server: flags.proxy };
    contextOptions.ignoreHTTPSErrors = true;
    console.warn('[!] Proxy mode: ignoring certificate errors for browser traffic. Results may include insecure connections.');
  }
  const context = await browser.newContext(contextOptions);
  const page = await context.newPage();

  const queue = [flags.url];
  const visitedPages = new Set();
  allDiscoveredPages.add(flags.url);

  // Handler-scoped variables
  let resources = [];
  let uniqueUrls = new Set();
  page.on('request', request => {
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
        await page.goto(url, { waitUntil: 'networkidle' });
      } catch (error) {
        stopSpinner();
        if (flags.debug) console.log(`Failed to load ${url}: ${error.message}`);
        continue;
      }
      stopSpinner();

      const hrefs = await page.$$eval('a[href]', as => as.map(a => a.href));
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
      await browser.close();
    } catch (error) {
      console.error(`Error closing browser: ${error.message}`);
    }
  }

  writeReportsAndExit();
})();
