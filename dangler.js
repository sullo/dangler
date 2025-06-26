// Modern Chromium user agent (Chrome 124 on macOS)
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.91 Safari/537.36';
// The Dangler - dangler.js
// Full version: HTTP status code, deduped resources, clear failure output

const { chromium } = require('playwright');
const dns = require('dns');
const net = require('net');
const fs = require('fs');

// Load takeover targets
let takeoverTargets = [];
try {
  const takeoverData = fs.readFileSync('fingerprints.json', 'utf8');
  const takeoverConfig = JSON.parse(takeoverData);
  takeoverTargets = takeoverConfig.filter(entry => entry.vulnerable === true).map(entry => ({
    cname: entry.cname,
    fingerprint: entry.fingerprint,
    nxdomain: entry.nxdomain,
    service: entry.service
  }));
} catch (error) {
  console.warn('Warning: Could not load fingerprints.json, using empty list');
  takeoverTargets = [];
}

// Helper function to check if a domain is a potential takeover target
function isTakeoverTarget(domain) {
  return takeoverTargets.some(target => 
    target.cname.some(cname => domain === cname || domain.endsWith('.' + cname))
  );
}

// Robots.txt parsing and checking
const robotsCache = new Map();

async function fetchRobotsTxt(baseUrl, page) {
  try {
    const robotsUrl = new URL('/robots.txt', baseUrl).toString();
    const response = await page.goto(robotsUrl, { 
      waitUntil: 'domcontentloaded',
      timeout: REMOTE_TIMEOUT_MS
    });
    
    if (response && response.ok()) {
      return await page.textContent('body');
    }
  } catch (error) {
    if (flags.debug) console.log(`[DEBUG] Failed to fetch robots.txt: ${error.message}`);
  }
  return null;
}

function parseRobotsTxt(content) {
  const rules = {
    userAgents: [],
    disallow: [],
    allow: [],
    crawlDelay: null
  };
  
  if (!content) return rules;
  
  const lines = content.split('\n').map(line => line.trim());
  let currentUserAgent = '*';
  
  for (const line of lines) {
    if (line.startsWith('User-agent:')) {
      currentUserAgent = line.substring(11).trim();
      if (currentUserAgent === '*' || currentUserAgent.toLowerCase() === 'dangler') {
        rules.userAgents.push(currentUserAgent);
      }
    } else if (line.startsWith('Disallow:') && rules.userAgents.includes(currentUserAgent)) {
      const path = line.substring(9).trim();
      if (path) rules.disallow.push(path);
    } else if (line.startsWith('Allow:') && rules.userAgents.includes(currentUserAgent)) {
      const path = line.substring(6).trim();
      if (path) rules.allow.push(path);
    } else if (line.startsWith('Crawl-delay:') && rules.userAgents.includes(currentUserAgent)) {
      const delay = parseInt(line.substring(12).trim(), 10);
      if (!isNaN(delay)) rules.crawlDelay = delay;
    }
  }
  
  return rules;
}

function isUrlAllowed(url, robotsRules) {
  if (!robotsRules || robotsRules.userAgents.length === 0) {
    return true; // No robots.txt or no rules for our user agent
  }
  
  const urlPath = new URL(url).pathname;
  
  // Check allow rules first (more specific)
  for (const allowPath of robotsRules.allow) {
    if (urlPath.startsWith(allowPath)) {
      return true;
    }
  }
  
  // Check disallow rules
  for (const disallowPath of robotsRules.disallow) {
    if (urlPath.startsWith(disallowPath)) {
      return false;
    }
  }
  
  return true; // Default allow if no specific rules match
}

async function getRobotsRules(baseUrl, page) {
  if (robotsCache.has(baseUrl)) {
    return robotsCache.get(baseUrl);
  }
  
  const content = await fetchRobotsTxt(baseUrl, page);
  const rules = parseRobotsTxt(content);
  robotsCache.set(baseUrl, rules);
  
  if (flags.debug && content) {
    console.log(`[DEBUG] Loaded robots.txt for ${baseUrl}:`, rules);
  }
  
  return rules;
}

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
  '--manual', '-M',
  '--max-resources', '-R',
  '--threads-crawl', '-tc',
  '--threads-resource', '-tr',
  '--help', '-h',
  '--robots', '-r'
]);

const flags = {
  url: '',
  debug: false,
  output: 'dangler_output',
  maxPages: 50,
  maxResources: 1000,
  threadsCrawl: 5,
  threadsResource: 10,
  proxy: '',
  timeout: 5000,
  cookies: [],
  headers: [],
  manual: false,
  robots: false
};

const usageString = `\nUsage: node dangler.js --url <target> [options]\n\nRequired:\n  --url, -u <target>           Target website to crawl\n\nCommon options:\n  --output, -o <base>          Base name for output files (.json, .html). Default: dangler_output\n  --max-pages, -m <num>        Max pages to crawl. Default: 50\n  --proxy, -p <url>            Proxy URL (e.g. for Burp/ZAP)\n  --timeout, -t <ms>           Timeout for remote resource checks in ms. Default: 5000\n  --cookie, -C <cookie>        Set cookies for the browser session (can use multiple times)\n  --header, -H <header>        Set extra HTTP headers (can use multiple times)\n  --manual, -M                 Open browser for manual login/interaction\n  --debug, -d                  Enable debug output\n  --max-resources, -R <num>    Max number of remote resources to check (default: 1000)\n  --threads-crawl, -tc <num>   Number of concurrent page crawlers (default: 5)\n  --threads-resource, -tr <num>Number of concurrent resource checks (default: 10)\n  --robots, -r                 Honor robots.txt rules when crawling\n  --help, -h                   Show this help message\n`;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--help' || arg === '-h') {
    console.log(usageString);
    process.exit(0);
  }
  if (arg.startsWith('-') && !validFlags.has(arg)) {
    console.error(`Unknown flag: ${arg}`);
    console.error(usageString);
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
  } else if (arg === '--max-resources' || arg === '-R') {
    flags.maxResources = parseInt(args[i + 1], 10);
    if (isNaN(flags.maxResources) || flags.maxResources < 1) {
      console.error('--max-resources must be a positive integer.');
      process.exit(1);
    }
    i++;
  } else if (arg === '--threads-crawl' || arg === '-tc') {
    flags.threadsCrawl = parseInt(args[i + 1], 10);
    if (isNaN(flags.threadsCrawl) || flags.threadsCrawl < 1) {
      console.error('--threads-crawl must be a positive integer.');
      process.exit(1);
    }
    i++;
  } else if (arg === '--threads-resource' || arg === '-tr') {
    flags.threadsResource = parseInt(args[i + 1], 10);
    if (isNaN(flags.threadsResource) || flags.threadsResource < 1) {
      console.error('--threads-resource must be a positive integer.');
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
  } else if (arg === '--robots' || arg === '-r') {
    flags.robots = true;
  }
}

if (!flags.url) {
  console.error(usageString);
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

// Host match cache for takeover detection
const hostMatchCache = new Map();

// Fingerprint cache for optimization
const fingerprintCache = new Map();

// Helper function to check if a domain is a potential takeover target
function checkHostInFingerprints(hostname) {
  if (hostMatchCache.has(hostname)) {
    return hostMatchCache.get(hostname);
  }
  
  const match = takeoverTargets.find(target => 
    target.cname.some(cname => {
      // Create regex that matches end of hostname
      const regex = new RegExp(`\\.${cname.replace(/\./g, '\\.')}$`);
      return hostname === cname || regex.test(hostname);
    })
  );
  
  const result = match ? { 
    matches: true, 
    fingerprint: match.fingerprint, 
    service: match.service,
    nxdomain: match.nxdomain 
  } : { matches: false };
  
  hostMatchCache.set(hostname, result);
  return result;
}

let totalRemoteResources = 0;
let potentialTakeovers = 0;
const allDiscoveredPages = new Set();

// Add a variable to capture console output
let consoleLogBuffer = '';
const origConsoleLog = console.log;
const origConsoleWarn = console.warn;
const origConsoleError = console.error;
console.log = function(...args) {
  const msg = args.map(String).join(' ');
  consoleLogBuffer += msg + '\n';
  origConsoleLog.apply(console, args);
};
console.warn = function(...args) {
  const msg = args.map(String).join(' ');
  consoleLogBuffer += '[WARN] ' + msg + '\n';
  origConsoleWarn.apply(console, args);
};
console.error = function(...args) {
  const msg = args.map(String).join(' ');
  consoleLogBuffer += '[ERROR] ' + msg + '\n';
  origConsoleError.apply(console, args);
};

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
  if (flags.debug) console.log('[DEBUG] Resolving:', hostname);
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
  
  const hostname = new URL(url).hostname;
  const hostMatch = checkHostInFingerprints(hostname);
  
  try {
    const response = await withTimeout(fetch(url), REMOTE_TIMEOUT_MS);
    const result = { ok: response.status < 400, status: response.status };
    
    // If it's a takeover target, check fingerprint
    if (hostMatch.matches && !hostMatch.nxdomain) {
      // Check fingerprint cache first
      if (fingerprintCache.has(hostname)) {
        const cachedResult = fingerprintCache.get(hostname);
        result.takeoverVulnerable = cachedResult.takeoverVulnerable;
        result.takeoverService = cachedResult.takeoverService;
        result.takeoverReason = cachedResult.takeoverReason;
        if (flags.debug) console.log(`[DEBUG] Fingerprint cache HIT for ${hostname}`);
      } else {
        // Perform fingerprint check and cache result
        const content = await response.text();
        const fingerprintFound = content.includes(hostMatch.fingerprint);
        
        result.takeoverVulnerable = fingerprintFound;
        result.takeoverService = hostMatch.service;
        result.takeoverReason = fingerprintFound ? 'Fingerprint found' : 'Fingerprint not found';
        
        // Cache the fingerprint result
        fingerprintCache.set(hostname, {
          takeoverVulnerable: result.takeoverVulnerable,
          takeoverService: result.takeoverService,
          takeoverReason: result.takeoverReason
        });
        
        if (flags.debug) console.log(`[DEBUG] Fingerprint cache MISS for ${hostname} -> checked and cached`);
      }
    }
    
    return result;
  } catch (err) {
    if (flags.debug) console.log('[DEBUG] checkHTTP error for', url, ':', err && err.message);
    return { ok: false, status: 0, error: err };
  }
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

// At the top, define a function to check/increment the resource request count
function incResourceRequestOrExit() {
  totalRemoteResources++;
  if (totalRemoteResources > flags.maxResources) {
    console.warn(`Max resources checked (${flags.maxResources}) reached. Ending scan.`);
    writeReportsAndExit();
    process.exit();
  }
}

// Patch getHostCheck to increment only on cache miss
async function getHostCheck(hostname) {
  if (!hostname) return { resolves: false, tcpOk: false };
  if (hostCheckCache.has(hostname)) {
    if (flags.debug) console.log(`Host cache HIT: ${hostname}`);
    return hostCheckCache.get(hostname);
  }
  incResourceRequestOrExit();
  if (flags.debug) console.log(`[DEBUG] Host cache MISS: ${hostname} -> checking...`);
  const resolves = await resolveHost(hostname);
  const tcpOk = await checkTCP(hostname);
  if (flags.debug) console.log(`[DEBUG] Host: ${hostname}, Resolves: ${resolves}, TCP: ${tcpOk}`);
  const result = { resolves, tcpOk };
  hostCheckCache.set(hostname, result);
  return result;
}

// Patch getUrlCheck to increment only on cache miss
async function getUrlCheck(url) {
  if (!url.startsWith('http')) return { httpOk: false, httpStatusCode: 0, loadsOtherJS: false };

  const ext = url.split('?')[0].split('.').pop().toLowerCase();
  const cacheKey = (ext === 'js' || ext === 'css') ? stripQuery(url) : url;

  if (urlCheckCache.has(cacheKey)) {
    if (flags.debug) console.log(`URL cache HIT: ${cacheKey}`);
    return urlCheckCache.get(cacheKey);
  }
  incResourceRequestOrExit();
  if (flags.debug) console.log(`URL cache MISS: ${cacheKey} -> checking...`);
  const httpRes = await checkHTTP(url);
  let loadsOtherJS = false;
  if (ext === 'js') {
    loadsOtherJS = await analyzeJS(url);
  }
  // Always provide httpOk and httpStatusCode, even if fetch failed
  const result = { 
    httpOk: !!(httpRes && httpRes.ok), 
    httpStatusCode: httpRes && typeof httpRes.status === 'number' ? httpRes.status : 0, 
    loadsOtherJS,
    takeoverVulnerable: httpRes && httpRes.takeoverVulnerable ? httpRes.takeoverVulnerable : false,
    takeoverService: httpRes && httpRes.takeoverService ? httpRes.takeoverService : null,
    takeoverReason: httpRes && httpRes.takeoverReason ? httpRes.takeoverReason : null
  };
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
   <tr><td class="label">Potential Takeovers</td><td class="value"><a href="potential-takeovers.html">${potentialTakeovers}</a></td></tr>
   <tr><td class="label">Console Log</td><td class="value"><a href="console-log.html">View</a></td></tr>
   </table>`;

  // --- Count failure types and unique resources ---
  let dnsFailures = 0, connectFailures = 0, httpFailures = 0;
  const allCheckedResources = [];
  const uniqueSet = new Set();
  results.forEach(page => {
    page.resources.forEach(r => {
      allCheckedResources.push(r.url);
      const stripped = stripQuery(r.url);
      uniqueSet.add(stripped);
      if (!r.resolves) dnsFailures++;
      else if (!r.tcpOk) connectFailures++;
      else if (!r.httpOk) httpFailures++;
    });
  });
  const totalChecked = totalRemoteResources;
  const uniqueChecked = uniqueSet.size;

  // --- Details Table ---
  html += `<h2>Details</h2>
   <table class="halfwidth" style="width:100%;max-width:100vw;table-layout:fixed;">
   <tr><td class="label">DNS Failures</td><td class="value"><a href="dns-failures.html">${dnsFailures}</a></td></tr>
   <tr><td class="label">Connect Failures</td><td class="value"><a href="connect-failures.html">${connectFailures}</a></td></tr>
   <tr><td class="label">HTTP Failures</td><td class="value"><a href="http-failures.html">${httpFailures}</a></td></tr>
   <tr><td class="label">Total Resources Checked</td><td class="value"><a href="all-resources.html">${totalChecked}</a></td></tr>
   <tr><td class="label">Total Unique Resources</td><td class="value"><a href="unique-resources.html">${uniqueChecked}</a></td></tr>
   </table>`;

  // --- Generate subpages ---
  function writeSubpage(filename, title, rows, columns, total, makeLinks, makeLinksBothCols) {
    // Sort rows by the first column (Resource URL)
    rows = rows.slice().sort((a, b) => a[0].localeCompare(b[0]));
    let subHtml = `<html><head><title>${title} - Dangler Report</title><meta name="referrer" content="no-referrer"><style>
      body { font-family: sans-serif; margin: 40px; }
      table { border-collapse: collapse; margin-bottom: 20px; width: 100%; max-width: 100vw; table-layout: fixed; }
      .halfwidth { width: 100%; min-width: 350px; }
      td.label { font-weight: bold; text-align: left; width: 40%; background: #f0f0f0; }
      td.value { text-align: left; }
      th, td { border: 1px solid #ddd; padding: 8px; word-break: break-all; }
      th { background: #f0f0f0; }
      a { color: #0645AD; }
      small { color: #666; font-size: smaller; }
    </style></head><body>
    <h1>The Dangler</h1>
    <hr>
    <a href="index.html">&larr; Back to Summary</a>
    <h2>${title}${typeof total === 'number' ? `: ${total}` : ''}</h2>`;
    if (rows.length > 0) {
      subHtml += `<table><tr>`;
      for (const col of columns) subHtml += `<th>${escapeHtml(col)}</th>`;
      subHtml += `</tr>`;
      for (const row of rows) {
        subHtml += `<tr>`;
        for (let i = 0; i < row.length; ++i) {
          let cell = row[i];
          let isInternal = typeof cell === 'string' && cell.trim().endsWith('.html');
          if (typeof makeLinks === 'function' && makeLinks(row, i)) {
            if (isInternal) {
              subHtml += `<td><a href="${sanitizeUrl(cell)}">${escapeHtml(cell)}</a></td>`;
            } else {
              subHtml += `<td><a href="${sanitizeUrl(cell)}" target="_blank">${escapeHtml(cell)}</a></td>`;
            }
          } else if (makeLinksBothCols) {
            if (isInternal) {
              subHtml += `<td><a href="${sanitizeUrl(cell)}">${escapeHtml(cell)}</a></td>`;
            } else {
              subHtml += `<td><a href="${sanitizeUrl(cell)}" target="_blank">${escapeHtml(cell)}</a></td>`;
            }
          } else if (makeLinks && i === 0) {
            if (isInternal) {
              subHtml += `<td><a href="${sanitizeUrl(cell)}">${escapeHtml(cell)}</a></td>`;
            } else {
              subHtml += `<td><a href="${sanitizeUrl(cell)}" target="_blank">${escapeHtml(cell)}</a></td>`;
            }
          } else {
            subHtml += `<td>${escapeHtml(cell)}</td>`;
          }
        }
        subHtml += `</tr>`;
      }
      subHtml += `</table>`;
    } else {
      subHtml += `<p>No data available for this section.</p>`;
    }
    subHtml += `</body></html>`;
    const outPath = useOutputDir ? `${outputDir}/${filename}` : filename;
    fs.writeFileSync(outPath, subHtml);
  }

  // Prepare data for subpages
  const dnsRows = [], connectRows = [], httpRows = [], allRows = [], takeoverRows = [];
  results.forEach(page => {
    page.resources.forEach(r => {
      allRows.push([r.url, page.page]);
      if (!r.resolves) {
        dnsRows.push([r.url, page.page]);
        takeoverRows.push([r.url, page.page, 'DNS failure']);
      }
      else if (!r.tcpOk) connectRows.push([r.url, page.page]);
      else if (!r.httpOk) {
        httpRows.push([r.url, page.page, String(r.httpStatusCode)]);
        // Only include HTTP failures from takeover target domains
        if (isTakeoverTarget(r.domain)) {
          takeoverRows.push([r.url, page.page, `HTTP ${r.httpStatusCode}`]);
        }
      }
    });
  });
  const uniqueRows = Array.from(uniqueSet).map(url => [url]);
  writeSubpage('dns-failures.html', 'DNS Failures', dnsRows, ['Resource URL', 'Parent Page'], dnsRows.length, false, true);
  writeSubpage('connect-failures.html', 'Connect Failures', connectRows, ['Resource URL', 'Parent Page'], connectRows.length, false, true);
  writeSubpage('http-failures.html', 'HTTP Failures', httpRows, ['Resource URL', 'Parent Page', 'HTTP Status'], httpRows.length, (row, i) => i === 0 || i === 1);
  writeSubpage('potential-takeovers.html', 'Potential Takeovers', takeoverRows, ['Resource URL', 'Parent Page', 'Failure Type'], takeoverRows.length, (row, i) => i === 0 || i === 1);
  writeSubpage('all-resources.html', 'All Resources Checked', allRows, ['Resource URL', 'Parent Page'], allRows.length, false, true);
  writeSubpage('unique-resources.html', 'Unique Resources Checked', uniqueRows, ['Resource URL'], uniqueRows.length, true);

  // --- Failures Table ---
  // (Removed as requested)

  // --- Unique Offsite Resources ---
  // (Removed as requested)

  // Also update main report tables to 100% width and responsive
  html = html.replace(/<table class=\"halfwidth\"[^>]*>/g, '<table class="halfwidth" style="width:100%;max-width:100vw;table-layout:fixed;">');

  try {
    fs.writeFileSync(outputHtml, html);
    console.log(`HTML report saved to: ${outputHtml}`);
  } catch (error) {
    console.error(`Failed to write HTML report: ${error.message}`);
  }

  // At the end of writeReportsAndExit, write the console log page
  function writeConsoleLogPage() {
    let subHtml = `<html><head><title>Console Log - Dangler Report</title><meta name="referrer" content="no-referrer"><style>
      body { font-family: sans-serif; margin: 40px; }
      pre { background: #f8f8f8; border: 1px solid #ddd; padding: 16px; overflow-x: auto; }
      a { color: #0645AD; }
    </style></head><body>
    <h1>The Dangler</h1>
    <hr>
    <a href="index.html">&larr; Back to Summary</a>
    <h2>Console Log</h2>
    <pre>${escapeHtml(consoleLogBuffer)}</pre>
    </body></html>`;
    const outPath = useOutputDir ? `${outputDir}/console-log.html` : 'console-log.html';
    fs.writeFileSync(outPath, subHtml);
  }

  // Call this at the end of writeReportsAndExit
  writeConsoleLogPage();

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
  const startOrigin = (new URL(flags.url)).origin;
  scanPage.on('request', request => {
    const reqUrl = request.url();
    if (reqUrl.startsWith('blob:')) return;
    const reqOrigin = new URL(reqUrl).origin;
    const isInternal = reqOrigin === startOrigin;
    const stripped = stripQuery(reqUrl);
    if (!isInternal && !uniqueUrls.has(stripped)) {
      resources.push({ url: reqUrl, domain: new URL(reqUrl).hostname, resourceType: request.resourceType() });
      uniqueUrls.add(stripped);
    }
  });

  const maxResources = flags.maxResources;

  // Add a simple async pool utility
  async function asyncPool(poolLimit, array, iteratorFn) {
    const ret = [];
    const executing = new Set();
    
    for (const item of array) {
      const p = Promise.resolve().then(() => iteratorFn(item));
      ret.push(p);
      executing.add(p);
      
      // Wait if we've reached the pool limit
      if (executing.size >= poolLimit) {
        await Promise.race(executing);
      }
      
      // Clean up when promise completes
      p.finally(() => executing.delete(p));
    }
    
    return Promise.all(ret);
  }

  try {
    // Load robots.txt rules if enabled (after browser setup)
    let robotsRules = null;
    if (flags.robots) {
      const baseUrl = new URL(flags.url).origin;
      robotsRules = await getRobotsRules(baseUrl, scanPage);
      if (flags.debug) {
        console.log(`[DEBUG] Robots.txt enabled for ${baseUrl}`);
      }
    }

    // Shared state for all crawl workers
    const queue = [flags.url];
    const visitedPages = new Set();
    allDiscoveredPages.add(flags.url);

    // Crawl worker function
    async function crawlWorker() {
      while (queue.length > 0 && visitedPages.size < maxPages && totalRemoteResources < maxResources) {
        const url = queue.shift();
        if (!url || visitedPages.has(url)) continue;

        // Check robots.txt if enabled
        if (flags.robots && robotsRules) {
          if (!isUrlAllowed(url, robotsRules)) {
            if (flags.debug) console.log(`[DEBUG] Skipping ${url} (disallowed by robots.txt)`);
            continue;
          }
        }

        const pagesCrawled = visitedPages.size + 1;
        console.log(`\n[#${pagesCrawled}/${maxPages}] Crawling: ${url}`);

        visitedPages.add(url);

        // Apply crawl delay if specified in robots.txt
        if (flags.robots && robotsRules && robotsRules.crawlDelay) {
          if (flags.debug) console.log(`[DEBUG] Crawl delay: ${robotsRules.crawlDelay}s`);
          await new Promise(resolve => setTimeout(resolve, robotsRules.crawlDelay * 1000));
        }

        // Make these local to the worker
        let resources = [];
        let uniqueUrls = new Set();

        scanPage.on('request', request => {
          const reqUrl = request.url();
          if (reqUrl.startsWith('blob:')) return;
          const reqOrigin = new URL(reqUrl).origin;
          const isInternal = reqOrigin === startOrigin;
          const stripped = stripQuery(reqUrl);
          if (!isInternal && !uniqueUrls.has(stripped)) {
            resources.push({ url: reqUrl, domain: new URL(reqUrl).hostname, resourceType: request.resourceType() });
            uniqueUrls.add(stripped);
          }
        });

        startSpinner('Crawling page...');
        try {
          await scanPage.goto(url, { waitUntil: 'networkidle' });
        } catch (error) {
          stopSpinner();
          if (flags.debug) console.log(`Failed to load ${url}: ${error.message}`);
          scanPage.removeAllListeners('request');
          continue;
        }
        stopSpinner();
        scanPage.removeAllListeners('request');

        const hrefs = await scanPage.$$eval('a[href]', as => as.map(a => a.href));
        hrefs.forEach(href => {
          try {
            const u = new URL(href);
            if (allowedDomains.some(d => u.hostname.endsWith(d)) && !visitedPages.has(u.href)) {
              // Check robots.txt if enabled
              if (flags.robots && robotsRules) {
                if (!isUrlAllowed(u.href, robotsRules)) {
                  if (flags.debug) console.log(`[DEBUG] Not queueing ${u.href} (disallowed by robots.txt)`);
                  return;
                }
              }
              queue.push(u.href);
              allDiscoveredPages.add(u.href);
            }
          } catch {}
        });

        startSpinner('Validating resources...');
        try {
          await asyncPool(flags.threadsResource, resources, async (r) => {
            if (totalRemoteResources >= maxResources) return;
            try {
              const hostCheck = await getHostCheck(r.domain);
              r.resolves = hostCheck.resolves;
              r.tcpOk = hostCheck.tcpOk;

              const urlCheck = await getUrlCheck(r.url);
              r.httpOk = urlCheck.httpOk;
              r.httpStatusCode = urlCheck.httpStatusCode;
              r.loadsOtherJS = r.resourceType === 'script' ? urlCheck.loadsOtherJS : false;

              // Takeover detection logic
              const hostMatch = checkHostInFingerprints(r.domain);
              
              if (!r.resolves) {
                // Host doesn't resolve
                if (hostMatch.matches) {
                  // 🚨 DANGER: Host doesn't resolve + in fingerprints
                  r.takeoverVulnerable = true;
                  r.takeoverService = hostMatch.service;
                  r.takeoverReason = 'DNS failure + takeover target';
                  r.takeoverIcon = '🚨';
                } else {
                  // ⚠️ WARNING: Host doesn't resolve but not in fingerprints
                  r.takeoverVulnerable = false;
                  r.takeoverReason = 'DNS failure';
                  r.takeoverIcon = '⚠️';
                }
              } else {
                // Host resolves - check if fingerprint validation was done
                if (hostMatch.matches && r.httpOk && urlCheck.takeoverVulnerable) {
                  // ❌ VULNERABLE: Host resolves + fingerprint matches
                  r.takeoverVulnerable = true;
                  r.takeoverService = urlCheck.takeoverService;
                  r.takeoverReason = urlCheck.takeoverReason;
                  r.takeoverIcon = '❌';
                }
                // No icon for resolved hosts that aren't vulnerable
              }

              r.possibleTakeover = r.takeoverVulnerable;
              if (r.possibleTakeover) potentialTakeovers++;
            } catch (resourceError) {
              if (flags.debug) console.log(`Error validating resource ${r.url}: ${resourceError.message}`);
              // Set default values for failed resource
              r.resolves = false;
              r.tcpOk = false;
              r.httpOk = false;
              r.httpStatusCode = 0;
              r.loadsOtherJS = false;
              r.takeoverVulnerable = false;
              r.possibleTakeover = false;
            }
          });
        } catch (error) {
          stopSpinner();
          if (flags.debug) console.log(`Error validating resources for ${url}: ${error.message}`);
          // Continue with the page even if resource validation fails
        }
        stopSpinner();

        results.push({ page: url, resources });

        if (visitedPages.size >= maxPages) {
          console.warn(`Max pages crawled (${maxPages}) reached. Ending scan.`);
          writeReportsAndExit();
          return;
        }
        if (totalRemoteResources >= maxResources) {
          console.warn(`Max resources checked (${maxResources}) reached. Ending scan.`);
          writeReportsAndExit();
          return;
        }
      }
    }

    // Launch crawl workers
    await asyncPool(flags.threadsCrawl, Array(flags.threadsCrawl).fill(0), crawlWorker);

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

