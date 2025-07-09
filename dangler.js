// Modern Chromium user agent (Chrome 124 on macOS)
const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
// The Dangler - dangler.js
// Full version: HTTP status code, deduped resources, clear failure output

const { chromium } = require('playwright');
const dns = require('dns');
const net = require('net');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const cheerio = require('cheerio');

// Pre-compiled regex patterns for performance
const REGEX_PATTERNS = {
  // File extension patterns
  FILE_EXTENSION: /\.(json|html)$/i,
  
  // HTML encoding patterns
  HTML_CHAR: /./g,
  
  // URL sanitization patterns
  QUOTE_ESCAPE: /"/g,
  SINGLE_QUOTE_ESCAPE: /'/g,
  
  // JavaScript analysis patterns
  CREATE_ELEMENT_SCRIPT: /createElement\s*\(\s*['"]script['"]\s*\)/i,
  JQUERY_GETSCRIPT: /\$\.getScript/i,
  DYNAMIC_IMPORT: /import\s*\(/i,
  
  // Table class replacement pattern
  TABLE_CLASS_REPLACE: /<table class=\"halfwidth\"[^>]*>/g,
  
  // Dot escaping pattern for CNAME matching
  DOT_ESCAPE: /\./g
};

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
  '--robots', '-r',
  '--pool-size', '-ps',
  '--insecure', '-k',
  '--restrict-path', '-rp',
  '--skip-pattern', '-sp',
  '--exclude-path', '-ep',
  '--user-agent', '-ua'
]);

const flags = {
  url: '',
  debug: false,
  output: 'report',
  maxPages: 50,
  maxResources: 5000,
  threadsCrawl: 5,
  threadsResource: 20,
  proxy: '',
  timeout: 5000,
  cookies: [],
  headers: [],
  manual: false,
  robots: false,
  poolSize: 10,
  insecure: false,
  restrictPaths: [],
  skipPatterns: [],
  excludePaths: [],
  userAgent: ''
};

const usageString = `\nUsage: node dangler.js --url <target> [options]\n\nRequired:\n  --url, -u <target>           Target website to crawl\n\nCommon options:\n  --output, -o <base>          Base name for output files (.json, .html). Default: report\n  --max-pages, -m <num>        Max pages to crawl. Default: 50\n  --proxy, -p <url>            Proxy URL (e.g. for Burp/ZAP)\n  --timeout, -t <ms>           Timeout for remote resource checks in ms. Default: 5000\n  --cookie, -C <cookie>        Set cookies for the browser session (can use multiple times)\n  --header, -H <header>        Set extra HTTP headers (can use multiple times)\n  --manual, -M                 Open browser for manual login/interaction\n  --debug, -d                  Enable debug output\n  --max-resources, -R <num>    Max number of remote resources to check (default: 5000)\n  --threads-crawl, -tc <num>   Number of concurrent page crawlers (default: 5)\n  --threads-resource, -tr <num>Number of concurrent resource checks (default: 20)\n  --pool-size, -ps <num>       Connection pool size per host (default: 10)\n  --robots, -r                 Honor robots.txt rules when crawling\n  --insecure, -k               Ignore HTTPS certificate errors\n  --restrict-path, -rp <path>  Only crawl URLs starting with this path (can use multiple times)\n  --skip-pattern, -sp <regex>  Skip URLs matching this regex pattern (can use multiple times)\n  --exclude-path, -ep <path>   Skip URLs containing this path (can use multiple times)\n  --user-agent, -ua <string>   Override the default user agent string\n  --help, -h                   Show this help message\n\nNote: For --skip-pattern, regex metacharacters must be escaped (e.g., \\?, \\(, \\))\n`;

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
  } else if (arg === '--pool-size' || arg === '-ps') {
    flags.poolSize = parseInt(args[i + 1], 10);
    if (isNaN(flags.poolSize) || flags.poolSize < 1 || flags.poolSize > 100) {
      console.error('--pool-size must be between 1 and 100.');
      process.exit(1);
    }
    i++;
  } else if (arg === '--insecure' || arg === '-k') {
    flags.insecure = true;
  } else if (arg === '--restrict-path' || arg === '-rp') {
    flags.restrictPaths.push(args[i + 1]);
    i++;
  } else if (arg === '--skip-pattern' || arg === '-sp') {
    flags.skipPatterns.push(args[i + 1]);
    i++;
  } else if (arg === '--exclude-path' || arg === '-ep') {
    flags.excludePaths.push(args[i + 1]);
    i++;
  } else if (arg === '--user-agent' || arg === '-ua') {
    flags.userAgent = args[i + 1];
    i++;
  }
}

if (!flags.url) {
  console.error(usageString);
  process.exit(1);
}

// Validate regex patterns
for (let i = 0; i < flags.skipPatterns.length; i++) {
  try {
    const pattern = flags.skipPatterns[i];
    
    // Check for known problematic patterns
    const dangerousPatterns = [
      /\(\w+\+\)\+\w+/,           // (a+)+b
      /\(\w+\|\w+\)\*/,           // (a|aa)*
      /^\w+\(\w+\+\)\*\$/,        // ^a(a+)*$
      /\(\w+\+\)\*/,              // (a+)*
      /\(\w+\|\w+\)\+\w+/,        // (a|aa)+b
    ];
    
    for (const dangerous of dangerousPatterns) {
      if (dangerous.test(pattern)) {
        console.error(`Potentially dangerous regex pattern detected: ${pattern}`);
        console.error(`This pattern could cause ReDoS (Regex Denial of Service).`);
        console.error(`Please use a simpler pattern or escape special characters.`);
        process.exit(1);
      }
    }
    
    // Test compilation
    new RegExp(pattern, 'i');
  } catch (error) {
    console.error(`Invalid regex pattern: ${flags.skipPatterns[i]}`);
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

// Validate paths start with /
for (let i = 0; i < flags.restrictPaths.length; i++) {
  if (!flags.restrictPaths[i].startsWith('/')) {
    console.error(`Restrict path must start with /: ${flags.restrictPaths[i]}`);
    process.exit(1);
  }
}

for (let i = 0; i < flags.excludePaths.length; i++) {
  if (!flags.excludePaths[i].startsWith('/')) {
    console.error(`Exclude path must start with /: ${flags.excludePaths[i]}`);
    process.exit(1);
  }
}

const REMOTE_TIMEOUT_MS = flags.timeout;

const outputBase = flags.output.replace(REGEX_PATTERNS.FILE_EXTENSION, '');

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

// State variables (must be declared before use)
let totalRemoteResources = 0;
let potentialTakeovers = 0;
const allDiscoveredPages = new Set();
const results = [];
const hostCheckCache = new Map();
const urlCheckCache = new Map();
const hostMatchCache = new Map(); // Host match cache for takeover detection
const fingerprintCache = new Map(); // Fingerprint cache for optimization

// Dependency chain tracking
let currentRequestChain = [];
let chainIdCounter = 0;
const requestChains = new Map(); // Maps request URL to its chain info

// Exit control
let shouldExit = false;
let exitReason = '';
let reachedResourceLimit = false;

// === Iframe Tracking ===
const trackedFrames = [];

// Chain tracking class
class RequestChain {
  constructor(url, parentChain = null, triggerType = 'initial') {
    this.id = ++chainIdCounter;
    this.url = url;
    this.parentChain = parentChain;
    this.triggerType = triggerType; // 'initial', 'script', 'xhr', 'fetch', 'link', 'img', etc.
    this.timestamp = Date.now();
    this.children = [];
    this.chainDepth = parentChain ? parentChain.chainDepth + 1 : 0;
    
    if (parentChain) {
      parentChain.children.push(this);
    }
  }
  
  getFullChain() {
    const chain = [];
    let current = this;
    while (current) {
      chain.unshift({
        url: current.url,
        triggerType: current.triggerType,
        timestamp: current.timestamp
      });
      current = current.parentChain;
    }
    return chain;
  }
  
  getChainString() {
    const chain = this.getFullChain();
    return chain.map((item, index) => {
      try {
        const url = new URL(item.url);
        const domain = url.hostname;
        const path = url.pathname;
        
        // Truncate long paths intelligently
        let displayPath = path;
        if (path.length > 30) {
          const lastSlash = path.lastIndexOf('/');
          if (lastSlash > 0) {
            const filename = path.substring(lastSlash + 1);
            if (filename.length > 20) {
              displayPath = path.substring(0, lastSlash + 1) + filename.substring(0, 17) + '...';
            } else {
              displayPath = '...' + path.substring(path.length - 27);
            }
          } else {
            displayPath = path.substring(0, 27) + '...';
          }
        }
        
        const prefix = index === 0 ? '' : ' → ';
        return `${prefix}${domain}${displayPath}`;
      } catch (e) {
        // Fallback to just domain if URL parsing fails
        const domain = item.url.split('/')[2] || item.url;
        const prefix = index === 0 ? '' : ' → ';
        return `${prefix}${domain}`;
      }
    }).join('');
  }
  
  getChainDepth() {
    return this.chainDepth;
  }
}

// Console capture variables
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

// Scan timing variables
const scanStartDate = new Date();
let scanStartLocal = formatLocalDate(scanStartDate);
let scanStopLocal = '';
let scanDuration = '';

let startDomain;
try {
  startDomain = (new URL(flags.url)).hostname;
} catch (e) {
  console.error(`Invalid URL provided: ${flags.url}`);
  process.exit(1);
}
const allowedDomains = [startDomain];
const maxPages = flags.maxPages;

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

// Helper function to check if a domain is a potential takeover target and return details
function checkHostInFingerprints(hostname) {
  if (hostMatchCache.has(hostname)) {
    return hostMatchCache.get(hostname);
  }
  
  const match = takeoverTargets.find(target => 
    target.cname.some(cname => {
      // Create regex that matches end of hostname
      const regex = new RegExp(`\\.${cname.replace(REGEX_PATTERNS.DOT_ESCAPE, '\\.')}$`);
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

// Robots.txt parsing and checking
const robotsCache = new Map();

async function fetchRobotsTxt(baseUrl, page) {
  try {
    const robotsUrl = new URL('/robots.txt', baseUrl).toString();
    const response = await page.goto(robotsUrl, { 
      waitUntil: 'domcontentloaded',
      timeout: 5000
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

   // === Tracking Setup ===
   function setupTracking(scanPage, context, url, source) {
    // Add debug prints for navigation and redirect events
    scanPage.on('framenavigated', frame => {
      if (flags.debug) {
        console.log(`[DEBUG][${source.toUpperCase()}][NAV] Frame navigated: ${frame.url()}`);
      }
      // Track manual top-level navigations
      if (source === 'manual' && frame.parentFrame() === null) {
        if (!globalThis.manualVisitedPages) globalThis.manualVisitedPages = [];
        const navUrl = frame.url();
        if (navUrl && !globalThis.manualVisitedPages.includes(navUrl)) {
          globalThis.manualVisitedPages.push(navUrl);
        }
      }
    });
    scanPage.on('request', request => {
      if (flags.debug && request.isNavigationRequest()) {
        console.log(`[DEBUG][${source.toUpperCase()}][NAV] Navigation request: ${request.url()}`);
      }
    });
    // Log all console messages for debugging document.cookie activity
    scanPage.on('console', msg => {
      if (flags.debug) {
        console.log(`[DEBUG][${source.toUpperCase()}][PAGE_CONSOLE] ${msg.type()}: ${msg.text()}`);
      }
    });
    // Log response headers for all finished navigation requests
    scanPage.on('requestfinished', async request => {
      if (flags.debug && request.isNavigationRequest()) {
        try {
          const response = await request.response();
          if (response) {
            const headers = response.headers();
            console.log(`[DEBUG][${source.toUpperCase()}][NAV] requestfinished for: ${request.url()}`);
            // console.log(`[DEBUG][${source.toUpperCase()}][NAV] Headers (JSON):`, JSON.stringify(headers, null, 2));
          }
        } catch (e) {
          console.log(`[DEBUG][${source.toUpperCase()}][NAV] Error getting response for: ${request.url()} - ${e.message}`);
        }
      }
    });
    // Track network requests for manual mode
    scanPage.on('request', request => {
      if (source === 'manual') {
        if (!globalThis.manualTrackedRequests) globalThis.manualTrackedRequests = [];
        globalThis.manualTrackedRequests.push({
          url: request.url(),
          method: request.method(),
          resourceType: request.resourceType(),
          frameUrl: request.frame() ? request.frame().url() : '',
          timestamp: Date.now(),
          source: 'manual'
        });
      }
    });
    // Track frame/iframe events for manual mode
    scanPage.on('frameattached', frame => {
      if (source === 'manual') {
        if (!globalThis.manualTrackedFrames) globalThis.manualTrackedFrames = [];
        globalThis.manualTrackedFrames.push({
          parent: url,
          method: 'manual',
          frameUrl: frame.url(),
          timestamp: Date.now(),
          source: 'manual'
        });
      }
    });
  }

// === MAIN ===
(async () => {
  console.log(`The Dangler: Starting audit on ${flags.url}`);
  if (flags.debug) console.log('Debug mode ON');

  // Prepare context options before browser creation
  const contextOptions = { userAgent: flags.userAgent || DEFAULT_USER_AGENT };
  if (flags.proxy) {
    contextOptions.proxy = { server: flags.proxy };
    contextOptions.ignoreHTTPSErrors = true;
    console.warn('[!] Proxy mode: ignoring certificate errors for browser traffic. Results may include insecure connections.');
  }
  if (flags.insecure) {
    contextOptions.ignoreHTTPSErrors = true;
    console.warn('[!] Insecure mode: ignoring certificate errors. Results may include insecure connections.');
  }

  let browser, context;
  let manualResources = [];
  let manualFrames = [];
  if (flags.manual) {
    console.log('[Manual Mode] You must come back to this terminal and press ENTER to continue after logging in.');
    console.log('[Manual Mode] Press ENTER now to open the browser window.');
    await new Promise(resolve => process.stdin.once('data', resolve));
    const browserManual = await chromium.launch({ headless: false });
    const contextManual = await browserManual.newContext(contextOptions);
    const pageManual = await contextManual.newPage();
    setupTracking(pageManual, contextManual, flags.url, 'manual');
    console.log('[Manual Mode] Please log in or interact with the browser window.');
    await pageManual.goto(flags.url);
    console.log('[Manual Mode] When finished, press ENTER in this terminal to continue. Do NOT close the browser window yourself.');
    await new Promise(resolve => process.stdin.once('data', resolve));
    // Extract cookies and storage from manual session
    const cookies = await contextManual.cookies();
    // Merge manual tracked requests and frames
    if (globalThis.manualTrackedRequests) {
      // Group manual requests by their top-level frame URL
      const manualPageMap = new Map();
      for (const req of globalThis.manualTrackedRequests) {
        // Find the closest visited page for this request
        let pageUrl = req.frameUrl || flags.url;
        if (globalThis.manualVisitedPages && globalThis.manualVisitedPages.includes(pageUrl)) {
          // ok
        } else if (globalThis.manualVisitedPages && globalThis.manualVisitedPages.length > 0) {
          // fallback: use last visited page
          pageUrl = globalThis.manualVisitedPages[globalThis.manualVisitedPages.length - 1];
        }
        if (!manualPageMap.has(pageUrl)) manualPageMap.set(pageUrl, []);
        manualPageMap.get(pageUrl).push({
          url: req.url,
          domain: (new URL(req.url)).hostname,
          resourceType: req.resourceType,
          chainString: 'Manual',
          source: 'manual'
        });
      }
      // For each manual page, validate resources and add to results and allDiscoveredPages
      for (const [pageUrl, resources] of manualPageMap.entries()) {
        // Validate each resource (DNS, TCP, HTTP)
        await asyncPool(flags.threadsResource, resources, async (r) => {
          const hostCheck = await getHostCheck(r.domain);
          r.resolves = hostCheck.resolves;
          r.tcpOk = hostCheck.tcpOk;
          let urlCheck = null;
          if (r.resolves) {
            urlCheck = await getUrlCheck(r.url);
            r.httpOk = urlCheck.httpOk;
            r.httpStatusCode = urlCheck.httpStatusCode;
            r.loadsOtherJS = urlCheck.loadsOtherJS;
            r.takeoverVulnerable = urlCheck.takeoverVulnerable;
            r.takeoverService = urlCheck.takeoverService;
            r.takeoverReason = urlCheck.takeoverReason;
          } else {
            r.httpOk = false;
            r.httpStatusCode = 0;
            r.loadsOtherJS = false;
          }
        });
        results.unshift({ page: pageUrl, resources });
        allDiscoveredPages.add(pageUrl);
      }
    }
    if (globalThis.manualTrackedFrames) {
      manualFrames = globalThis.manualTrackedFrames.map(f => ({
        parent: f.parent,
        method: f.method,
        frameUrl: f.frameUrl,
        source: 'manual'
      }));
    }
    await browserManual.close();
    // Re-launch browser in headless mode for the scan
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext(contextOptions);
    // await context.addCookies(cookies);
    console.log('[Manual Mode] Scan will continue with your session cookies.');
  } else {
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext(contextOptions);
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
    await context.addCookies(allCookies);
  }

  // Add headers if specified, but only for target domain and subdomains
  let extraHeaders = null;
  if (flags.headers.length > 0) {
    extraHeaders = parseHeaders(flags.headers);
    if (flags.debug) console.log('Setting extra HTTP headers (scoped):', extraHeaders);
    context.route('**', (route, request) => {
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

  const maxResources = flags.maxResources;

  // Add a simple async pool utility
  async function asyncPool(poolLimit, array, iteratorFn) {
    const ret = [];
    const executing = new Set();
    let completed = 0;
    const total = array.length;
    
    for (const item of array) {
      const p = Promise.resolve().then(async () => {
        const result = await iteratorFn(item);
        completed++;
        if (flags.debug && total > 10) {
          console.log(`[DEBUG] Resource validation progress: ${completed}/${total} (${Math.round(completed/total*100)}%)`);
        }
        return result;
      });
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
      robotsRules = await getRobotsRules(baseUrl, context.newPage());
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
      if (flags.debug) {
        console.log(`[DEBUG] Crawl worker starting`);
        console.log(`[DEBUG] results array at start of worker:`, results, results.length, results === globalThis.results ? 'global' : 'local');
      }
      try {
        while (queue.length > 0 && visitedPages.size < maxPages) {
          // Check resource limit at the start of each iteration
          if (totalRemoteResources >= maxResources) {
            if (flags.debug) console.log(`[DEBUG] Resource limit reached, exiting crawl worker`);
            break;
          }
          
          const url = queue.shift();
          if (!url || visitedPages.has(url)) continue;

          if (flags.debug) {
            console.log(`[DEBUG] Processing URL: ${url}`);
            console.log(`[DEBUG] Current totalRemoteResources: ${totalRemoteResources}, maxResources: ${maxResources}`);
          }

          // Check robots.txt if enabled
          if (flags.robots && robotsRules) {
            if (!isUrlAllowed(url, robotsRules)) {
              if (flags.debug) console.log(`[DEBUG] Skipping ${url} (disallowed by robots.txt)`);
              continue;
            }
          }

          // Calculate queue length for display
          let queueLen = queue.length + visitedPages.size;
          let queueLimit = flags.maxPages;
          let denom = queueLen > 0 ? queueLen : 1;
          let maxReached = false;
          if (queueLen >= queueLimit) {
            denom = `${queueLimit}--MAX`;
            maxReached = true;
          }
          const pagesCrawled = visitedPages.size + 1;
          console.log(`\n[#${pagesCrawled}/${denom}] Crawling: ${url}`);

          visitedPages.add(url);

          // Apply crawl delay if specified in robots.txt
          if (flags.robots && robotsRules && robotsRules.crawlDelay) {
            if (flags.debug) console.log(`[DEBUG] Crawl delay: ${robotsRules.crawlDelay}s`);
            await new Promise(resolve => setTimeout(resolve, robotsRules.crawlDelay * 1000));
          }

          // Make these local to the worker
          let resources = [];
          let uniqueUrls = new Set();

          const scanPage = await context.newPage();
          setupTracking(scanPage, context, url, 'automated');
          
          // Track the current page as the root of the chain
          const pageChain = new RequestChain(url, null, 'page');
          currentRequestChain = [pageChain]; // Initialize with the page chain
          
          scanPage.on('request', request => {
            const reqUrl = request.url();
            if (reqUrl.startsWith('blob:')) return;
            
            const reqOrigin = new URL(reqUrl).origin;
            const isInternal = reqOrigin === startOrigin;
            const stripped = stripQuery(reqUrl);
            
            if (!isInternal && !uniqueUrls.has(stripped)) {
              // Create a chain entry for this request
              const resourceType = request.resourceType();
              const triggerType = resourceType === 'script' ? 'script' : 
                                resourceType === 'xhr' ? 'xhr' :
                                resourceType === 'fetch' ? 'fetch' :
                                resourceType === 'stylesheet' ? 'link' :
                                resourceType === 'image' ? 'img' :
                                resourceType === 'font' ? 'font' : 'other';
              
              // Find the current active chain (most recent script or the page itself)
              let parentChain = pageChain;
              if (currentRequestChain.length > 0) {
                parentChain = currentRequestChain[currentRequestChain.length - 1];
              }
              
              const requestChain = new RequestChain(reqUrl, parentChain, triggerType);
              requestChains.set(reqUrl, requestChain);
              
              // If this is a script, add it to the current chain for future requests
              if (resourceType === 'script') {
                currentRequestChain.push(requestChain);
              }
              
              resources.push({ 
                url: reqUrl, 
                domain: new URL(reqUrl).hostname, 
                resourceType: resourceType,
                chainId: requestChain.id,
                chainDepth: requestChain.getChainDepth(),
                chainString: requestChain.getChainString()
              });
              uniqueUrls.add(stripped);
            }
          });
          
          // Track when scripts finish loading to remove them from the chain
          scanPage.on('response', async response => {
            const respUrl = response.url();
            const headers = response.headers();
            if (flags.debug) {
              console.log(`[DEBUG][COOKIES] Response for: ${respUrl}`);
              console.log(`[DEBUG][COOKIES] All headers for ${respUrl}:`, headers);
            }
            let setCookieHeaders = headers['set-cookie'];
            if (flags.debug) {
              console.log(`[DEBUG][COOKIES] Raw Set-Cookie headers for ${respUrl}:`, setCookieHeaders);
            }
            if (setCookieHeaders) {
              if (!Array.isArray(setCookieHeaders)) setCookieHeaders = [setCookieHeaders];
              for (const cookieStr of setCookieHeaders) {
                if (flags.debug) {
                  console.log(`[DEBUG][COOKIES] Attempting to parse Set-Cookie string: ${cookieStr}`);
                }
                const parsed = parseCookieString(cookieStr, startDomain); // Pass startDomain for accurate parsing
                if (flags.debug) {
                  console.log(`[DEBUG][COOKIES] Parsed cookie:`, parsed);
                  console.log(`[DEBUG][COOKIES] Tracking cookie with mainDomain: ${startDomain}`);
                }
                // Ensure parsed is an array of cookie objects before tracking
                if (Array.isArray(parsed)) {
                  for (const p of parsed) {
                    trackCookie(p, respUrl, 'header', startDomain);
                  }
                } else if (parsed) { // Handle single cookie object returned by parseCookieString
                  trackCookie(parsed, respUrl, 'header', startDomain);
                }
              }
            } else {
              if (flags.debug) {
                console.log(`[DEBUG][COOKIES] No Set-Cookie header found for: ${respUrl}`);
              }
            }
            if (response.request().resourceType() === 'script') {
              // Remove the script from current chain when it finishes loading
              currentRequestChain = currentRequestChain.filter(chain => chain.url !== respUrl);
            }
          });

          startSpinner('Crawling page...');
          try {
            await scanPage.goto(url, { waitUntil: 'domcontentloaded', timeout: flags.timeout });

            // After page load, extract all cookies from the context, including those set by JS
            const allCookies = await context.cookies(url); // Get cookies for the current URL
            // if (flags.debug) {
            //   console.log(`[DEBUG][COOKIES] All cookies in context after navigation to ${url}:`);
            //   console.log(JSON.stringify(allCookies, null, 2));
            // }

            // Feed all browser cookies into the trackedCookies map
            for (const cookie of allCookies) {
              // The 'setVia' indicates that this was captured from the browser context, not a header
              trackCookie(cookie, url, 'browser', startDomain);
            }

            // Wait for dynamic content to load
            await new Promise(resolve => setTimeout(resolve, 2000));

            // --- Static Extraction: HTML/JS/Resources ---
            let staticResources = [];
            try {
              const rawHtml = await scanPage.content();
              staticResources = extractStaticResources(rawHtml, url);
              // Add static resources to the resources array, but mark them as staticOnly if not already present
              for (const sres of staticResources) {
                // Only add if not already present in resources (by url/content)
                if (sres.url && !resources.some(r => r.url === sres.url)) {
                  resources.push({
                    url: sres.url,
                    domain: sres.url ? (new URL(sres.url, url)).hostname : '',
                    resourceType: sres.type,
                    chainString: sres.presentButNotLoaded ? 'Static (not loaded)' : (sres.domOnly ? 'DOM-only' : 'Static'),
                    staticOnly: true,
                    presentButNotLoaded: sres.presentButNotLoaded,
                    domOnly: sres.domOnly,
                    pageUrl: url
                  });
                }
                // For inline scripts, send content to JS analyzer in future
                // (for now, just note presence)
                if (sres.inline && sres.type === 'script' && sres.content) {
                  resources.push({
                    url: '[inline script]',
                    domain: '',
                    resourceType: 'script-inline',
                    chainString: 'Inline',
                    staticOnly: true,
                    presentButNotLoaded: false,
                    domOnly: false,
                    pageUrl: url,
                    scriptContent: sres.content
                  });
                }
              }
            } catch (e) {
              if (flags.debug) console.log(`[DEBUG][STATIC EXTRACTION] Error extracting static resources: ${e.message}`);
            }

            // --- Meta Refresh Detection ---
            try {
              const metaRefresh = await scanPage.$('meta[http-equiv="refresh" i]');
              if (metaRefresh) {
                const content = await metaRefresh.getAttribute('content');
                if (content) {
                  // Format: "5; url=https://example.com/" or "0;URL='/foo'"
                  const match = content.match(/url\s*=\s*['"]?([^'";]+)['"]?/i);
                  if (match && match[1]) {
                    let refreshUrl = match[1].trim();
                    // If relative, resolve against current page
                    try {
                      refreshUrl = (new URL(refreshUrl, url)).href;
                    } catch {}
                    if (!visitedPages.has(refreshUrl) && !queue.includes(refreshUrl)) {
                      queue.push(refreshUrl);
                      allDiscoveredPages.add(refreshUrl);
                      if (flags.debug) console.log(`[DEBUG][META REFRESH] Added meta refresh URL to queue: ${refreshUrl}`);
                    }
                  }
                }
              }
            } catch (e) {
              if (flags.debug) console.log(`[DEBUG][META REFRESH] Error detecting meta refresh: ${e.message}`);
            }

            // --- Noscript Iframe Detection ---
            try {
              const rawHtml = await scanPage.content();
              // Find all <noscript>...</noscript> blocks
              const noscriptMatches = rawHtml.match(/<noscript[\s\S]*?<\/noscript>/gi);
              if (noscriptMatches) {
                for (const noscript of noscriptMatches) {
                  // Find all <iframe ...> inside this noscript
                  const iframeMatches = noscript.match(/<iframe[^>]+src=["']?([^"'>\s]+)["']?[^>]*>/gi);
                  if (iframeMatches) {
                    for (const iframeTag of iframeMatches) {
                      // Extract src attribute
                      const srcMatch = iframeTag.match(/src=["']?([^"'>\s]+)["']?/i);
                      if (srcMatch && srcMatch[1]) {
                        trackedFrames.push({
                          parent: url,
                          method: 'HTML (noscript)',
                          frameUrl: srcMatch[1]
                        });
                      }
                    }
                  }
                }
              }
            } catch (e) {
              if (flags.debug) console.log(`[DEBUG][NOSCRIPT IFRAME] Error detecting noscript iframes: ${e.message}`);
            }
          } catch (error) {
            stopSpinner();
            if (error.message.includes('ERR_CERT_') || error.message.includes('CERT_')) {
              console.error(`\n❌ SSL Certificate Error: ${error.message}`);
              console.error(`💡 Try using the --insecure (-k) flag to ignore certificate errors:`);
              console.error(`   node dangler.js --url ${flags.url} --insecure`);
              process.exit(1);
            }
            if (flags.debug) console.log(`Failed to load ${url}: ${error.message}`);
            scanPage.removeAllListeners('request');
            continue;
          }
          stopSpinner();
          scanPage.removeAllListeners('request');

          if (flags.debug) {
            console.log(`[DEBUG] Found ${resources.length} external resources on ${url}`);
            if (resources.length > 0) {
              console.log(`[DEBUG] Sample resources:`, resources.slice(0, 3).map(r => r.url));
            } else {
              console.log(`[DEBUG] No external resources found - checking if page loaded properly`);
              try {
                const title = await scanPage.title();
                console.log(`[DEBUG] Page title: "${title}"`);
              } catch (e) {
                console.log(`[DEBUG] Could not get page title: ${e.message}`);
              }
            }
          }

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
                
                // Check path restrictions
                if (flags.restrictPaths.length > 0) {
                  const pathMatches = flags.restrictPaths.some(path => u.pathname.startsWith(path));
                  if (!pathMatches) {
                    console.log(`[SKIP] Skipping ${u.href} (not in restricted paths: ${flags.restrictPaths.join(', ')})`);
                    return;
                  }
                }
                
                // Check exclude paths
                for (const excludePath of flags.excludePaths) {
                  if (u.pathname.includes(excludePath)) {
                    console.log(`[SKIP] Skipping ${u.href} (exclude path: ${excludePath})`);
                    return;
                  }
                }
                
                // Check skip patterns
                for (const pattern of flags.skipPatterns) {
                  try {
                    // Use a timeout-based approach for regex testing
                    let regexResult = false;
                    const timeoutId = setTimeout(() => {
                      // Timeout - assume no match for safety
                      if (flags.debug) console.log(`[DEBUG] Regex timeout for pattern: ${pattern}`);
                    }, 50); // 50ms timeout for regex operations
                    
                    const regex = new RegExp(pattern, 'i');
                    regexResult = regex.test(u.pathname);
                    clearTimeout(timeoutId);
                    
                    if (regexResult) {
                      console.log(`[SKIP] Skipping ${u.href} (skip pattern: ${pattern})`);
                      return;
                    }
                  } catch (error) {
                    if (flags.debug) console.log(`[DEBUG] Regex error for pattern ${pattern}: ${error.message}`);
                  }
                }
                
                queue.push(u.href);
                allDiscoveredPages.add(u.href);
              }
            } catch {}
          });

          if (flags.debug) {
            console.log(`[DEBUG] About to start resource validation for ${url}`);
            console.log(`[DEBUG] Before validation - totalRemoteResources: ${totalRemoteResources}, maxResources: ${maxResources}`);
          }

          // Limit the number of resources to validate to the remaining allowed resources
          let allowed = Math.max(0, maxResources - totalRemoteResources);
          let toValidate = resources.slice(0, allowed);
          let toSkip = resources.slice(allowed);
          toSkip.forEach(r => {
            r.resolves = false;
            r.tcpOk = false;
            r.httpOk = false;
            r.httpStatusCode = 0;
            r.loadsOtherJS = false;
            r.skippedDueToLimit = true;
          });

          if (flags.debug) {
            console.log(`[DEBUG] Validating ${toValidate.length} resources, skipping ${toSkip.length} due to resource limit`);
          }

          startSpinner('Validating resources...');
          try {
            if (toValidate.length > 0) {
              if (flags.debug) {
                console.log(`[DEBUG] Processing ${toValidate.length} resources with ${flags.threadsResource} concurrent threads`);
              }
              // Process only allowed resources
              await asyncPool(flags.threadsResource, toValidate, async (r) => {
                try {
                  const hostCheck = await getHostCheck(r.domain);
                  r.resolves = hostCheck.resolves;
                  r.tcpOk = hostCheck.tcpOk;

                  let urlCheck = null;
                  // Early exit: skip HTTP check if DNS fails
                  if (!r.resolves) {
                    r.httpOk = false;
                    r.httpStatusCode = 0;
                    r.loadsOtherJS = false;
                  } else {
                    // Only do HTTP check if DNS resolves
                    urlCheck = await getUrlCheck(r.url);
                    r.httpOk = urlCheck.httpOk;
                    r.httpStatusCode = urlCheck.httpStatusCode;
                    r.loadsOtherJS = urlCheck.loadsOtherJS;
                  }

                  // Check for potential takeover
                  if (!r.resolves || (r.httpStatusCode >= 400 && r.httpStatusCode < 500)) {
                    const hostname = extractHostname(r.url);
                    if (isTakeoverTarget(hostname)) {
                      r.takeoverVulnerable = true;
                      r.takeoverService = 'Known Takeover Target';
                      potentialTakeovers++;
                    }
                  }

                  totalRemoteResources++;
                  if (flags.debug && totalRemoteResources % 10 === 0) {
                    console.log(`[DEBUG] Processed ${totalRemoteResources} resources`);
                  }
                } catch (resourceError) {
                  if (flags.debug) {
                    console.error(`[DEBUG] Error processing resource ${r.url}: ${resourceError.message}`);
                  }
                  r.resolves = false;
                  r.tcpOk = false;
                  r.httpOk = false;
                  r.httpStatusCode = 0;
                  r.loadsOtherJS = false;
                  totalRemoteResources++;
                }
              });
            }
          } catch (error) {
            if (flags.debug) {
              console.error(`[DEBUG] Error during resource validation: ${error.message}`);
            }
          }
          stopSpinner();

          // Always push results for the current page after resource validation
          if (flags.debug) {
            console.log(`[DEBUG] About to push results for ${url}: ${resources.length} resources`);
            console.log(`[DEBUG] Results array length before push: ${results.length}`);
          }
          results.push({ page: url, resources });
          if (flags.debug) {
            console.log(`[DEBUG] Pushed results for ${url}: ${resources.length} resources`);
            console.log(`[DEBUG] Total results array length after push: ${results.length}`);
            console.log(`[DEBUG] results array after push:`, results, results.length, results === globalThis.results ? 'global' : 'local');
          }
          await scanPage.close();
        }
        if (flags.debug) {
          console.log(`[DEBUG] Crawl worker loop completed normally`);
        }
      } catch (error) {
        if (flags.debug) {
          console.error(`[DEBUG] Crawl worker error: ${error.message}`);
          console.error(`[DEBUG] Crawl worker stack: ${error.stack}`);
        }
      }
      if (flags.debug) {
        console.log(`[DEBUG] Crawl worker function ending`);
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
      await browser.close();
    } catch (error) {
      console.error(`Error closing browser: ${error.message}`);
    }
  }

  writeReportsAndExit();
})();

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
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
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
    return parsed.toString().replace(REGEX_PATTERNS.QUOTE_ESCAPE, '&quot;').replace(REGEX_PATTERNS.SINGLE_QUOTE_ESCAPE, '&#x27;');
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

async function resolveHost(hostname, maxRetries = 3, delayMs = 250) {
  if (!hostname) {
    if (flags.debug) console.log('[DEBUG] resolveHost: Empty hostname provided');
    return false;
  }

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const dnsTimeout = Math.max(REMOTE_TIMEOUT_MS, 10000);
      const result = await withTimeout(new Promise((resolve) => {
        dns.lookup(hostname, { all: false }, (err, address, family) => {
          if (err) {
            if (flags.debug) console.log(`[DEBUG] resolveHost: DNS lookup failed for "${hostname}" (attempt ${attempt}): ${err.code} - ${err.message}`);
            resolve(false);
          } else {
            resolve(true);
          }
        });
      }), dnsTimeout);
      if (result) return true;
    } catch (error) {
      if (flags.debug) console.log(`[DEBUG] resolveHost: DNS timeout/error for "${hostname}" (attempt ${attempt}): ${error.message}`);
    }
    if (attempt < maxRetries) {
      await new Promise(res => setTimeout(res, delayMs));
    }
  }
  return false;
}

async function checkTCP(hostname) {
  if (!hostname) return false;
  
  try {
    return await withTimeout(new Promise((resolve) => {
      const socket = net.connect(80, hostname);
      
      socket.on('connect', () => {
        if (flags.debug) console.log(`[DEBUG] TCP connection successful for ${hostname}`);
        socket.destroy();
        resolve(true);
      });
      
      socket.on('error', (err) => {
        if (flags.debug) console.log(`[DEBUG] TCP connection failed for ${hostname}:`, err.message);
        socket.destroy();
        resolve(false);
      });
      
      socket.on('timeout', () => {
        if (flags.debug) console.log(`[DEBUG] TCP connection timeout for ${hostname}`);
        socket.destroy();
        resolve(false);
      });
      
      // Set socket timeout
      socket.setTimeout(REMOTE_TIMEOUT_MS);
    }), REMOTE_TIMEOUT_MS);
  } catch (error) {
    if (flags.debug) console.log(`[DEBUG] TCP check error for ${hostname}:`, error.message);
    return false;
  }
}

async function checkHTTP(url) {
  if (!url.startsWith('http')) return { ok: false, status: 0 };
  
  const hostname = new URL(url).hostname;
  const hostMatch = checkHostInFingerprints(hostname);
  
  try {
    const response = await withTimeout(customFetch(url), REMOTE_TIMEOUT_MS);
    const result = { ok: response.status < 400, status: response.status };
    
    // Only check fingerprint if it's a takeover target and not nxdomain
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
    // For non-takeover targets, no fingerprint checking is done - much faster!
    
    return result;
  } catch (err) {
    if (flags.debug) console.log('[DEBUG] checkHTTP error for', url, ':', err && err.message);
    return { ok: false, status: 0, error: err };
  }
}

async function analyzeJS(url) {
  if (!url.startsWith('http')) return false;
  return withTimeout(
    customFetch(url)
      .then(res => res.text())
      .then(js =>
        REGEX_PATTERNS.CREATE_ELEMENT_SCRIPT.test(js) ||
        REGEX_PATTERNS.JQUERY_GETSCRIPT.test(js) ||
        REGEX_PATTERNS.DYNAMIC_IMPORT.test(js)
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
  if (!hostname) {
    if (flags.debug) console.log('[DEBUG] getHostCheck: Empty hostname provided');
    return { resolves: false, tcpOk: false };
  }
  
  if (hostCheckCache.has(hostname)) {
    if (flags.debug) console.log(`[DEBUG] getHostCheck: Cache HIT for "${hostname}"`);
    return hostCheckCache.get(hostname);
  }
  
  // if (flags.debug) console.log(`[DEBUG] getHostCheck: Cache MISS for "${hostname}" -> starting checks...`);
  incResourceRequestOrExit();
  
  // if (flags.debug) console.log(`[DEBUG] getHostCheck: Calling resolveHost for "${hostname}"`);
  const resolves = await resolveHost(hostname);
  // if (flags.debug) console.log(`[DEBUG] getHostCheck: resolveHost result for "${hostname}": ${resolves}`);
  
  // if (flags.debug) console.log(`[DEBUG] getHostCheck: Calling checkTCP for "${hostname}"`);
  const tcpOk = await checkTCP(hostname);
  // if (flags.debug) console.log(`[DEBUG] getHostCheck: checkTCP result for "${hostname}": ${tcpOk}`);
  
  const result = { resolves, tcpOk };
  // if (flags.debug) console.log(`[DEBUG] getHostCheck: Final result for "${hostname}": resolves=${resolves}, tcpOk=${tcpOk}`);
  
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
  if (flags.debug) {
    console.log(`[DEBUG] writeReportsAndExit called with results.length = ${results.length}`);
    console.log(`[DEBUG] results array in writeReportsAndExit:`, results, results.length, results === globalThis.results ? 'global' : 'local');
    results.forEach((result, idx) => {
      console.log(`[DEBUG] Result[${idx}]: page=${result.page}, resources=${result.resources.length}`);
    });
  }
  
  if (flags.debug) {
    console.log(`[DEBUG] writeReportsAndExit called with ${results.length} results`);
    results.forEach((result, index) => {
      console.log(`[DEBUG] Result ${index}: page=${result.page}, resources=${result.resources.length}`);
    });
  }

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
  
  // Create a clean copy of results to avoid circular references
  const cleanResults = results.map(page => ({
    page: page.page,
    resources: page.resources.map(r => {
      // Create a clean resource object with only serializable properties
      const cleanResource = {
        url: r.url,
        domain: r.domain,
        resourceType: r.resourceType,
        resolves: r.resolves,
        tcpOk: r.tcpOk,
        httpOk: r.httpOk,
        httpStatusCode: r.httpStatusCode,
        loadsOtherJS: r.loadsOtherJS,
        chainString: r.chainString || 'Direct'
      };
      
      // Only add takeover properties if they exist
      if (r.takeoverVulnerable !== undefined) cleanResource.takeoverVulnerable = r.takeoverVulnerable;
      if (r.takeoverService !== undefined) cleanResource.takeoverService = r.takeoverService;
      if (r.takeoverReason !== undefined) cleanResource.takeoverReason = r.takeoverReason;
      if (r.takeoverIcon !== undefined) cleanResource.takeoverIcon = r.takeoverIcon;
      if (r.possibleTakeover !== undefined) cleanResource.possibleTakeover = r.possibleTakeover;
      
      return cleanResource;
    })
  }));
  
  // Custom replacer function to handle circular references
  const seen = new WeakSet();
  const replacer = (key, value) => {
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        return '[Circular Reference]';
      }
      seen.add(value);
    }
    return value;
  };
  
  try {
    fs.writeFileSync(outputJson, JSON.stringify(cleanResults, replacer, 2));
    console.log(`\nJSON report saved to: ${outputJson}`);
  } catch (error) {
    console.error(`Failed to write JSON report: ${error.message}`);
    // Fallback: write a minimal report
    const minimalResults = cleanResults.map(page => ({
      page: page.page,
      resources: page.resources.map(r => ({
        url: r.url,
        domain: r.domain,
        resolves: r.resolves,
        tcpOk: r.tcpOk,
        httpOk: r.httpOk,
        httpStatusCode: r.httpStatusCode
      }))
    }));
    fs.writeFileSync(outputJson, JSON.stringify(minimalResults, null, 2));
    console.log(`\nMinimal JSON report saved to: ${outputJson}`);
  }

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
    <tr><td class="label">Target</td><td class="value"><a href="${sanitizeUrl(flags.url)}" target="_blank">${escapeHtml(flags.url)}</a></td></tr>
    <tr><td class="label">Max Pages</td><td class="value">${escapeHtml(String(flags.maxPages))}</td></tr>
    <tr><td class="label">Command Line</td><td class="value">dangler.js ${escapeHtml(process.argv.slice(2).join(' '))}</td></tr>
  </table>`;

  // --- Summary Table ---
  html += `<h2>Summary</h2>
   <table class="halfwidth">
   <tr><td class="label">Start</td><td class="value">${escapeHtml(scanStartLocal)}</td></tr>
   <tr><td class="label">Stop</td><td class="value">${escapeHtml(scanStopLocal)}</td></tr>
   <tr><td class="label">Duration</td><td class="value">${escapeHtml(scanDuration)}</td></tr>
   <tr><td class="label">Pages Crawled</td><td class="value"><a href="crawled-urls.html">${pagesCrawled} of ${totalPagesFound}</a></td></tr>
   <tr><td class="label">Remote Resources Checked</td><td class="value">${totalRemoteResources}</td></tr>
   <tr><td class="label">Potential Takeovers</td><td class="value"><a href="potential-takeovers.html">${potentialTakeovers}</a></td></tr>
   <tr><td class="label">Console Log</td><td class="value"><a href="console-log.html">View</a></td></tr>
   <tr><td class="label">Cookies</td><td class="value"><a href="cookies.html">View</a></td></tr>
   <tr><td class="label">Frames</td><td class="value"><a href="frames.html">${trackedFrames.length} detected</a></td></tr>
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

 

  // Prepare data for subpages
  const dnsRows = [], connectRows = [], httpRows = [], takeoverRows = [];
  results.forEach(page => {
    page.resources.forEach(r => {
      // Skip data URLs, blob URLs, and inline scripts for DNS failures
      if (
        (!r.url || typeof r.url !== 'string') ||
        r.url.startsWith('data:') ||
        r.url.startsWith('blob:') ||
        r.url === '[inline script]'
      ) {
        return;
      }
      if (!r.resolves) {
        dnsRows.push([r.url, extractHostname(r.url), page.page, r.chainString || 'Direct']);
        takeoverRows.push([r.url, extractHostname(r.url), page.page, 'DNS failure', r.chainString || 'Direct']);
      }
      else if (!r.tcpOk) {
        connectRows.push([r.url, extractHostname(r.url), page.page, r.chainString || 'Direct']);
      }
      else if (!r.httpOk) {
        httpRows.push([r.url, page.page, String(r.httpStatusCode)]);
        if (isTakeoverTarget(r.domain)) {
          takeoverRows.push([r.url, extractHostname(r.url), page.page, `HTTP ${r.httpStatusCode}`, r.chainString || 'Direct']);
        }
      }
    });
  });
  const uniqueRows = Array.from(uniqueSet).map(url => [url]);
  writeSubpage('dns-failures.html', 'DNS Failures', dnsRows, ['Resource URL', 'Hostname', 'Parent Page', 'Dependency Chain'], dnsRows.length, (row, i) => i === 0 || i === 2);
  writeSubpage('connect-failures.html', 'Connect Failures', connectRows, ['Resource URL', 'Hostname', 'Parent Page', 'Dependency Chain'], connectRows.length, (row, i) => i === 0 || i === 2);
  writeSubpage('http-failures.html', 'HTTP Failures', httpRows, ['Resource URL', 'Parent Page', 'HTTP Status'], httpRows.length, (row, i) => i === 0 || i === 1);
  writeSubpage('potential-takeovers.html', 'Potential Takeovers', takeoverRows, ['Resource URL', 'Hostname', 'Parent Page', 'Failure Type', 'Dependency Chain'], takeoverRows.length, (row, i) => i === 0 || i === 1 || i === 2);
  writeSubpage('unique-resources.html', 'Unique Resources Checked', uniqueRows, ['Resource URL'], uniqueRows.length, true);
  
  // Create dependency chains page
  const chainRows = [];
  results.forEach(page => {
    page.resources.forEach(r => {
      chainRows.push([
        r.url, 
        extractHostname(r.url), 
        page.page, 
        r.chainString || 'Direct', 
        r.resourceType
      ]);
    });
  });
  // Sort by chain depth (deepest first) - using the original chainDepth for sorting but not displaying
  chainRows.sort((a, b) => {
    const aResource = results.flatMap(p => p.resources).find(r => r.url === a[0]);
    const bResource = results.flatMap(p => p.resources).find(r => r.url === b[0]);
    const aDepth = aResource ? (aResource.chainDepth || 0) : 0;
    const bDepth = bResource ? (bResource.chainDepth || 0) : 0;
    return bDepth - aDepth;
  });
  writeSubpage('dependency-chains.html', 'Dependency Chains', chainRows, ['Resource URL', 'Hostname', 'Parent Page', 'Dependency Chain', 'Resource Type'], chainRows.length, (row, i) => i === 0 || i === 2);

  // Create crawled URLs page
  const crawledRows = [];
  results.forEach(page => {
    crawledRows.push([page.page]);
  });
  writeSubpage('crawled-urls.html', 'Crawled URLs', crawledRows, ['URL'], crawledRows.length, true);

  // --- Failures Table ---
  // (Removed as requested)

  // --- Unique Offsite Resources ---
  // (Removed as requested)

  // Also update main report tables to 100% width and responsive
  html = html.replace(REGEX_PATTERNS.TABLE_CLASS_REPLACE, '<table class="halfwidth" style="width:100%;max-width:100vw;table-layout:fixed;">');

  try {
    fs.writeFileSync(outputHtml, html);
    console.log(`HTML report saved to: ${outputHtml}`);
  } catch (error) {
    console.error(`Failed to write HTML report: ${error.message}`);
  }

  // Call this at the end of writeReportsAndExit
  writeConsoleLogPage();

  // Clean up connection pool
  if (flags.debug) {
    const poolStats = connectionPool.getStats();
    console.log('[DEBUG] Connection pool stats:');
    console.dir(poolStats, { depth: 4, colors: true });
  }
  connectionPool.destroy();

  // --- Cookies Report Page ---
  const cookieRows = [];
  if (flags.debug) {
    console.log(`[DEBUG] Inside writeReportsAndExit: trackedCookies.size before populating cookieRows: ${trackedCookies.size}`);
  }
  for (const cookie of trackedCookies.values()) {
    const greenCheck = '<span style="color:green;font-size:1.2em;font-weight:bold;">&#10003;</span>';
    const redX = '<span style="color:red;font-size:1.2em;font-weight:bold;">&#10007;</span>';
    let secureCell = '';
    if (cookie.secure) {
      secureCell = greenCheck;
    } else if (!cookie.secure && cookie.source && cookie.source.startsWith('https:')) {
      secureCell = redX;
    }
    cookieRows.push([
      escapeHtml(String(cookie.name)),
      withHoverDecoded(cookie.value),
      escapeHtml(String(cookie.domain)),
      escapeHtml(String(cookie.path)),
      escapeHtml(String(cookie.source)),
      escapeHtml(cookie.party),
      secureCell, // Secure
      cookie.httpOnly ? greenCheck : '',
      escapeHtml(cookie.sameSite || ''),
      (cookie.expires === -1 ? 'End of session' : (cookie.expires ? new Date(cookie.expires * 1000).toLocaleString() : '')),
      escapeHtml(cookie.setVia),
      cookie.isParentDomain ? greenCheck : '',
      cookie.isLongLived ? greenCheck : '',
      cookie.isKnownTracker ? greenCheck : ''
    ]);
  }
  
// Cookie report columns:
// 0 - Name
// 1 - Value
// 2 - Domain
// 3 - Path
// 4 - Source
// 5 - Party
// 6 - Secure
// 7 - HttpOnly
// 8 - SameSite
// 9 - Expires
// 10 - Set Via
// 11 - Parent Domain
// 12 - Long Lived
// 13 - Known Tracker

  writeSubpage(
    'cookies.html',
    'Cookies Set During Crawl',
    cookieRows,
    [
      'Name', 'Value', 'Domain', 'Path', 'Source', 'Party', 'Secure', 'HttpOnly', 'SameSite', 'Expires', 'Set<br>Via',
      'Parent<br>Domain', 'Long<br>Lived', 'Known<br>Tracker'
    ],
    cookieRows.length,
    (row, i) => i === 0 || i === 4, // Linkify only name and source, not domain
    false,
    [1, 6, 7, 11, 12, 13] // Allow raw HTML (greenCheck) in these columns
  );
  
  if (flags.debug) {
    console.log(`[DEBUG] Writing cookies report page. Total cookies tracked: ${trackedCookies.size}`);
    if (trackedCookies.size > 0) {
      const sample = Array.from(trackedCookies.values()).slice(0, 3);
      console.dir(sample, { depth: null, colors: true });
    }
  }
  
  if (flags.debug) {
    console.log(`[DEBUG][COOKIES] Crawl complete. Final trackedCookies size: ${trackedCookies.size}`);
    if (trackedCookies.size > 0) {
      const sample = Array.from(trackedCookies.values()).slice(0, 3);
      console.dir(sample, { depth: null, colors: true });
    }
  }
  
  // --- Frames Report Page ---
  const frameRows = trackedFrames.map(f => [f.parent, f.method, f.frameUrl, f.source || 'automated']);
  writeSubpage(
    'frames.html',
    'Frames Detected During Crawl',
    frameRows,
    ['Injected Into Page', 'Method', 'Frame Target URL', 'Source'],
    frameRows.length,
    (row, i) => i === 0 || i === 2, // Linkify parent and frame target
    false,
    []
  );
  
  // --- All Resources Report Page ---
  const allRows = [];
  results.forEach(page => {
    page.resources.forEach(r => {
      allRows.push([r.url, page.page, r.source || (page.page === 'Manual Session' ? 'manual' : 'automated')]);
    });
  });
  writeSubpage('all-resources.html', 'All Resources Checked', allRows, ['Resource URL', 'Parent Page', 'Source'], allRows.length, false, true);
  
  process.exit();
}

// Write console log page
function writeConsoleLogPage() {
  let subHtml = `<html><head><title>Console Log - Dangler Report</title><meta name="referrer" content="no-referrer"><style>
    body { font-family: sans-serif; margin: 40px; background: #fff; color: #222; }
    pre { background: #f0f0f0; padding: 20px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; color: #222; }
    a { color: #0645AD; }
    h1 { color: #222; }
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

// Custom HTTP client with connection pooling and keep-alive
async function customFetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    try {
      const parsedUrl = new URL(url);
      const protocol = parsedUrl.protocol;
      const hostname = parsedUrl.hostname;
      const port = parsedUrl.port || (protocol === 'https:' ? 443 : 80);
      const path = parsedUrl.pathname + parsedUrl.search;
      
      const agent = connectionPool.getAgent(protocol, hostname, port);
      
      const requestOptions = {
        hostname,
        port,
        path,
        method: options.method || 'GET',
        headers: {
          'User-Agent': DEFAULT_USER_AGENT,
          'Accept': '*/*',
          'Accept-Encoding': 'gzip, deflate, br',
          'Connection': 'keep-alive',
          'Cache-Control': 'no-cache',
          ...options.headers
        },
        agent,
        timeout: REMOTE_TIMEOUT_MS
      };

      const client = protocol === 'https:' ? https : http;
      const req = client.request(requestOptions, (res) => {
        let data = '';
        
        // Handle compression
        let stream = res;
        const contentEncoding = res.headers['content-encoding'];
        if (contentEncoding === 'gzip') {
          const zlib = require('zlib');
          stream = res.pipe(zlib.createGunzip());
        } else if (contentEncoding === 'deflate') {
          const zlib = require('zlib');
          stream = res.pipe(zlib.createInflate());
        } else if (contentEncoding === 'br') {
          const zlib = require('zlib');
          stream = res.pipe(zlib.createBrotliDecompress());
        }
        
        stream.on('data', (chunk) => {
          data += chunk;
        });
        
        stream.on('end', () => {
          resolve({
            ok: res.statusCode < 400,
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: res.headers,
            text: () => Promise.resolve(data),
            json: () => Promise.resolve(JSON.parse(data))
          });
        });
        
        stream.on('error', (err) => {
          reject(err);
        });
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (options.body) {
        req.write(options.body);
      }
      
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}

// Connection pool for HTTP/HTTPS requests with keep-alive
class ConnectionPool {
  constructor(poolSize = 10) {
    this.agents = new Map();
    this.maxSockets = poolSize; // Max connections per host
    this.maxFreeSockets = Math.max(2, Math.floor(poolSize / 2)); // Max idle connections per host
    this.timeout = 60000; // Keep-alive timeout (60 seconds)
  }

  getAgent(protocol, hostname, port) {
    const key = `${protocol}//${hostname}:${port}`;
    
    if (!this.agents.has(key)) {
      const agentOptions = {
        keepAlive: true,
        keepAliveMsecs: 1000,
        maxSockets: this.maxSockets,
        maxFreeSockets: this.maxFreeSockets,
        timeout: this.timeout,
        scheduling: 'fifo'
      };

      const agent = protocol === 'https:' 
        ? new https.Agent(agentOptions)
        : new http.Agent(agentOptions);
      
      this.agents.set(key, agent);
    }
    
    return this.agents.get(key);
  }

  destroy() {
    for (const agent of this.agents.values()) {
      agent.destroy();
    }
    this.agents.clear();
  }

  getStats() {
    const stats = {
      totalAgents: this.agents.size,
      agents: {}
    };
    
    for (const [key, agent] of this.agents.entries()) {
      stats.agents[key] = {
        requests: agent.requests,
        sockets: agent.sockets,
        freeSockets: agent.freeSockets
      };
    }
    
    return stats;
  }
}

// Global connection pool instance (after flags are defined)
const connectionPool = new ConnectionPool(flags.poolSize);

// Helper to format date as MM/DD/YYYY HH:MM:SS (24-hour)
function formatLocalDate(date) {
  const pad = n => n.toString().padStart(2, '0');
  return `${pad(date.getMonth() + 1)}/${pad(date.getDate())}/${date.getFullYear()} ` +
         `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

// Add this before the main async function or at the top-level scope:
let sigintCaught = false;
process.on('SIGINT', () => {
  if (sigintCaught) return; // Prevent double handling
  sigintCaught = true;
  console.log('\n[!] Scan interrupted by user (Ctrl+C). Writing partial report...');
  try {
    writeReportsAndExit();
  } catch (e) {
    console.error('Failed to write report on interrupt:', e.message);
    // Try to write a minimal report as last resort
    try {
      const minimalData = {
        error: 'Circular reference prevented full report',
        timestamp: new Date().toISOString(),
        pages: results.length,
        resources: totalRemoteResources
      };
      fs.writeFileSync(outputJson, JSON.stringify(minimalData, null, 2));
      console.log(`Minimal report saved to: ${outputJson}`);
    } catch (finalError) {
      console.error('Could not write any report:', finalError.message);
    }
    process.exit(1);
  }
});

// Helper function to extract hostname from URL
function extractHostname(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return '';
  }
}

// Safe regex testing function with timeout protection
async function safeRegexTest(pattern, text, timeoutMs = 100) {
  return new Promise((resolve) => {
    const timeoutId = setTimeout(() => {
      resolve(false); // Timeout - assume no match for safety
    }, timeoutMs);
    
    try {
      const regex = new RegExp(pattern, 'i');
      const result = regex.test(text);
      clearTimeout(timeoutId);
      resolve(result);
    } catch (error) {
      clearTimeout(timeoutId);
      resolve(false); // Error - assume no match for safety
    }
  });
}

// === Cookie Tracking ===
const trackedCookies = new Map(); // key: name|domain|path, value: {name, value, domain, path, source, party, secure, httpOnly, sameSite, expires, setVia, isParentDomain, isThirdParty, isSecondParty, isFirstParty, isLongLived, isInsecure, isMissingSecure, isMissingHttpOnly, isSameSiteNoneNoSecure, isKnownTracker}

// Helper to classify party
function classifyCookieParty(cookieDomain, mainDomain) {
  if (!cookieDomain) return 'unknown';
  if (cookieDomain === mainDomain || cookieDomain.endsWith('.' + mainDomain)) return 'first';
  // Second party: same eTLD but not same domain
  const getETLD = d => d.split('.').slice(-2).join('.');
  if (getETLD(cookieDomain) === getETLD(mainDomain)) return 'second';
  return 'third';
}

// Helper to check parent domain
function isParentDomain(cookieDomain, mainDomain) {
  return cookieDomain && cookieDomain.startsWith('.') && cookieDomain !== '.' + mainDomain;
}

// Helper to check known trackers (simple list)
const knownTrackers = ['doubleclick.net', 'google-analytics.com', 'googletagmanager.com', 'facebook.com', 'adnxs.com'];
function isKnownTrackerDomain(domain) {
  return knownTrackers.some(tracker => domain && domain.includes(tracker));
}

// Listen for Set-Cookie headers and JS-set cookies
function trackCookie(cookie, sourceUrl, setVia, mainDomain) {
  const key = `${cookie.name}|${cookie.domain}|${cookie.path}`;
  if (trackedCookies.has(key)) {
    if (flags.debug) console.log(`[DEBUG] Skipping duplicate cookie: ${key}`);
    return; // Only track first instance
  }
  if (flags.debug) console.log(`[DEBUG] Tracking cookie: ${key} via ${setVia} from ${sourceUrl}`);
  const party = classifyCookieParty(cookie.domain, mainDomain);
  const parentDomain = isParentDomain(cookie.domain, mainDomain);
  const isThirdParty = party === 'third';
  const isSecondParty = party === 'second';
  const isFirstParty = party === 'first';
  const isLongLived = cookie.expires && (cookie.expires * 1000 - Date.now() > 1000 * 60 * 60 * 24 * 365); // >1yr
  const isInsecure = !cookie.secure && sourceUrl.startsWith('https:');
  const isMissingSecure = !cookie.secure;
  const isMissingHttpOnly = !cookie.httpOnly;
  const isSameSiteNoneNoSecure = cookie.sameSite === 'None' && !cookie.secure;
  const isKnownTracker = isKnownTrackerDomain(cookie.domain);
  trackedCookies.set(key, {
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain,
    path: cookie.path,
    source: sourceUrl,
    party,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
    expires: cookie.expires,
    setVia,
    isParentDomain: parentDomain,
    isThirdParty,
    isSecondParty,
    isFirstParty,
    isLongLived,
    isInsecure,
    isMissingSecure,
    isMissingHttpOnly,
    isSameSiteNoneNoSecure,
    isKnownTracker
  });
}

function writeSubpage(filename, title, rows, columns, total, makeLinks, makeLinksBothCols, columnsToAllowHtml = []) {
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
  </style>`;
  // Inject hover tooltip CSS/JS for cookies.html
  if (filename === 'cookies.html') {
    subHtml += `
    <style>
      .hover-tooltip {
        position: relative;
        cursor: pointer;
      }
      .hover-tooltip .tooltip-box {
        display: none;
        position: absolute;
        z-index: 1000;
        background: #222;
        color: #fff;
        padding: 6px 12px;
        border-radius: 4px;
        font-size: 0.95em;
        white-space: pre-wrap;
        max-width: 400px;
        left: 0;
        top: 120%;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
      }
      .hover-tooltip:hover .tooltip-box {
        display: block;
      }
    </style>
    <script>
      document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.hover-tooltip').forEach(function(el) {
          el.addEventListener('mouseenter', function(e) {
            let tooltip = el.querySelector('.tooltip-box');
            if (!tooltip) {
              tooltip = document.createElement('div');
              tooltip.className = 'tooltip-box';
              tooltip.textContent = el.getAttribute('data-hover-decoded');
              el.appendChild(tooltip);
            }
            tooltip.style.display = 'block';
          });
          el.addEventListener('mouseleave', function(e) {
            let tooltip = el.querySelector('.tooltip-box');
            if (tooltip) tooltip.style.display = 'none';
          });
        });
      });
    </script>`;
  }
  subHtml += `</head><body>
  <h1>The Dangler</h1>
  <hr>
  <a href="index.html">&larr; Back to Summary</a>
  <h2>${title}${typeof total === 'number' ? `: ${total}` : ''}</h2>`;

  if (rows.length > 0) {
    // Add colgroup for cookies.html to set specific column widths
    if (filename === 'cookies.html') {
      subHtml += `<table style="table-layout:fixed;width:100%;"><colgroup>
        <col style="width:170px;">
        <col style="width:250px;">
        <col style="width:170px;">
        <col>
        <col style="width:220px;">
        <col>
        <col>
        <col>
        <col>
        <col>
        <col>
        <col>
        <col>
      </colgroup>`;
    } else {
      subHtml += `<table>`;
    }
    subHtml += `<tr>`;
    for (const col of columns) subHtml += `<th>${typeof col === 'string' ? col.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/&lt;br&gt;/g, '<br>') : escapeHtml(col)}</th>`;
    subHtml += `</tr>`;
    for (const row of rows) {
      subHtml += `<tr>`;
      for (let i = 0; i < row.length; ++i) {
        let cell = row[i];
        // For the Secure column (index 6), allow raw HTML
        if (i === 6 && title.startsWith('Cookies Set During Crawl')) {
          subHtml += `<td style="text-align:center;vertical-align:middle;">${cell}</td>`;
        } else if (filename === 'cookies.html' && i === 0) {
          // Name column: plain text, no link
          subHtml += `<td>${escapeHtml(cell)}</td>`;
        } else if (typeof makeLinks === 'function' && makeLinks(row, i)) {
          let isInternal = typeof cell === 'string' && cell.trim().endsWith('.html');
          if (isInternal) {
            subHtml += `<td><a href="${sanitizeUrl(cell)}">${escapeHtml(cell)}</a></td>`;
          } else {
            subHtml += `<td><a href="${sanitizeUrl(cell)}" target="_blank">${escapeHtml(cell)}</a></td>`;
          }
        } else if (makeLinksBothCols) {
          let isInternal = typeof cell === 'string' && cell.trim().endsWith('.html');
          if (isInternal) {
            subHtml += `<td><a href="${sanitizeUrl(cell)}">${escapeHtml(cell)}</a></td>`;
          } else {
            subHtml += `<td><a href="${sanitizeUrl(cell)}" target="_blank">${escapeHtml(cell)}</a></td>`;
          }
        } else if (makeLinks && i === 0) {
          let isInternal = typeof cell === 'string' && cell.trim().endsWith('.html');
          if (isInternal) {
            subHtml += `<td><a href="${sanitizeUrl(cell)}">${escapeHtml(cell)}</a></td>`;
          } else {
            subHtml += `<td><a href="${sanitizeUrl(cell)}" target="_blank">${escapeHtml(cell)}</a></td>`;
          }
        } else if (columnsToAllowHtml.includes(i)) {
          subHtml += `<td>${cell}</td>`;
        } else {
          subHtml += `<td>${escapeHtml(cell)}</td>`;
        }
      }
      subHtml += `</tr>\n`;
    }
    subHtml += `</table>`;
  } else {
    subHtml += `<p>No data available for this section.</p>`;
  }

  subHtml += `</body></html>`;
  const outPath = useOutputDir ? `${outputDir}/${filename}` : filename;
  fs.writeFileSync(outPath, subHtml);
}

// Helper to safely escape HTML for tooltips
function escapeTooltip(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Helper to wrap a value with a span for hover tooltip (URL-decoded, XSS-safe)
function withHoverDecoded(value) {
  let decoded = '';
  try {
    decoded = decodeURIComponent(value);
  } catch (e) {
    decoded = value;
  }
  return `<span class="hover-tooltip" data-hover-decoded="${escapeTooltip(decoded)}">${escapeHtml(value)}</span>`;
}

// === Static Extraction Utilities ===
function extractStaticResources(html, pageUrl) {
  const $ = cheerio.load(html);
  const resources = [];
  // Extract <script src="...">
  $('script[src]').each((i, el) => {
    resources.push({
      type: 'script',
      url: $(el).attr('src'),
      inline: false,
      domOnly: false,
      presentButNotLoaded: false,
      pageUrl
    });
  });
  // Extract inline <script> blocks
  $('script:not([src])').each((i, el) => {
    resources.push({
      type: 'script',
      content: $(el).html(),
      inline: true,
      domOnly: false,
      presentButNotLoaded: false,
      pageUrl
    });
  });
  // Extract <link rel="stylesheet" href="...">
  $('link[rel="stylesheet"][href]').each((i, el) => {
    resources.push({
      type: 'stylesheet',
      url: $(el).attr('href'),
      inline: false,
      domOnly: true,
      presentButNotLoaded: false,
      pageUrl
    });
  });
  // Extract <img src="...">
  $('img[src]').each((i, el) => {
    resources.push({
      type: 'image',
      url: $(el).attr('src'),
      inline: false,
      domOnly: true,
      presentButNotLoaded: false,
      pageUrl
    });
  });
  // Extract comments (for future: commented-out code/resources)
  const comments = [];
  function findComments(node) {
    if (!node) return;
    if (node.type === 'comment') {
      comments.push(node.data);
    }
    if (node.children) {
      node.children.forEach(findComments);
    }
  }
  findComments($.root()[0]);
  comments.forEach(comment => {
    // Simple regex to find script/link/img tags in comments (future: improve)
    const scriptMatch = comment.match(/<script[^>]*src=["']([^"'>]+)["'][^>]*>/gi);
    if (scriptMatch) {
      scriptMatch.forEach(tag => {
        const src = (tag.match(/src=["']([^"'>]+)["']/i) || [])[1];
        if (src) {
          resources.push({
            type: 'script',
            url: src,
            inline: false,
            domOnly: false,
            presentButNotLoaded: true,
            pageUrl
          });
        }
      });
    }
    const linkMatch = comment.match(/<link[^>]*href=["']([^"'>]+)["'][^>]*>/gi);
    if (linkMatch) {
      linkMatch.forEach(tag => {
        const href = (tag.match(/href=["']([^"'>]+)["']/i) || [])[1];
        if (href) {
          resources.push({
            type: 'stylesheet',
            url: href,
            inline: false,
            domOnly: true,
            presentButNotLoaded: true,
            pageUrl
          });
        }
      });
    }
    const imgMatch = comment.match(/<img[^>]*src=["']([^"'>]+)["'][^>]*>/gi);
    if (imgMatch) {
      imgMatch.forEach(tag => {
        const src = (tag.match(/src=["']([^"'>]+)["']/i) || [])[1];
        if (src) {
          resources.push({
            type: 'image',
            url: src,
            inline: false,
            domOnly: true,
            presentButNotLoaded: true,
            pageUrl
          });
        }
      });
    }
  });
  return resources;
}
