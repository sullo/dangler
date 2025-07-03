## Security Checks
- malicious JS/domains
- postmessage/risky js (eval, etc.)
- Outdated JS

## Coverage Gaps
- Static JS and HTML parsing (currently only network requests)
- DOM parsing
- Handle infinite scroll / load-more patterns (optional)
- Static parsing/analysis
- manual browsing
- Use browser devtools protocol to trace call stacks for resource loads, or instrument JS to log resource creation
- Statically Referenced but Not Loaded, or dynamically loaded but not triggered
- DOM-Only or Inert Content
- Commented code (static analysis catches?)
- Shadow DOM: Traverse Shadow DOM, templates, and custom elements after page load.
- Workers which load resources
- Different browser features/UA
- Simulate clicks, scrolls, and other interactions to trigger more resource loads.

## Data Points
- geolocaiton for resources
- forms: logins, captcha
- Whois lookup
- captcha use
- copyright outdated/missing
- comments
- JS used (like Builtwith) and versions

## Features
- Database
- CSV/export report
- JSON reports to match all HTML
- sortable tables
- filterable tables

## Efficiency
- parallel page loading

## Questions
- cloudflare cgi for bot detection?

## Productize
- login
- credit system
- SSRF protection
- Track site changes (hashing)

## AI Potential
- analyze comments and provide summary
- analyze potential takeoverse
- JS versioning

## Testing
- tracking pixel from major sources: facebook, google, etc.
- tracking code is registered properly
- Browser block list as source?

# Comparison/Competitors
- https://www.observepoint.com/

