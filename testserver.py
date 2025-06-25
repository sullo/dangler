#!/usr/bin/env python3
import http.server
import socketserver
import sys

PORT = 8001

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            # Fixed HTML with proper escaping
            self.wfile.write(b"""
<head>
<title>Broken Test Page</title>
<script src="https://thisdoesntexistithink.com/somefile.js"></script>
<script src="https://rvasec.com/somethingnothere.png"></script>
<link rel="stylesheet" href="https://c0.wp.com/c/6.7.2/wp-includes/css/dist/block-library/style.min.css">
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Open+Sans%3A400%2C300%2C600%2C700%2C800&ver=6.7.2">

<!-- XSS Test Cases as Remote Resources -->
<script src="javascript:alert('xss')"></script>
<script src="data:text/html,<script>alert('xss')</script>"></script>
<script src="vbscript:msgbox('xss')"></script>
<script src="file:///etc/passwd"></script>
<script src="about:blank"></script>
<script src="chrome://settings"></script>

<link rel="stylesheet" href="https://example.com/path with spaces">
<link rel="stylesheet" href="https://example.com/path&quot;with&quot;quotes">
<link rel="stylesheet" href="https://example.com/path'with'single'quotes">
<link rel="stylesheet" href="https://example.com/path<with>angle>brackets">
<link rel="stylesheet" href="https://example.com/path&with&amps">
<link rel="stylesheet" href="https://example.com/path<script>alert('xss')</script>">

<img src="not-a-url">
<img src="http://">
<img src="https://">
<img src="ftp://">
<img src="mailto:">
<img src="tel:">

<script src="https://example.com/path?param=&quot;value&quot;&other=<script>"></script>
<script src="https://example.com/path#fragment<script>alert('xss')</script>"></script>
<script src="https://example.com/path%3Cscript%3Ealert('xss')%3C/script%3E"></script>
<script src="https://example.com/path&lt;script&gt;alert('xss')&lt;/script&gt;"></script>
<script src="https://cirt.net/somethingnothere.js">https://cirt.net/somethingnothere.js</script>
<script src="http://localhost:4567/test.js">http://localhost:4567/test.js</script>

<!-- Safe URLs for Comparison -->
<script src="https://example.com/safe.js"></script>
<link rel="stylesheet" href="https://example.com/path-with-hyphens.css">
<img src="https://example.com/path_with_underscores.png">
<link rel="stylesheet" href="https://example.com/path.with.dots.css">
<script src="https://example.com/path,with,commas.js"></script>

</head>
<body>
<h1>Broken HTML Page for The Dangler Test</h1>
<p>This page is missing the &lt;html&gt; tag and has bad includes.</p>
<p>The dangler.js parser should detect all the remote resources above as potential takeover targets.</p>

<h1>URL Protocol Tests (as links for reference)</h1>
<a href="javascript:alert('xss')">javascript:alert('xss')</a><br>
<a href="data:text/html,<script>alert('xss')</script>">data:text/html,<script>alert('xss')</script></a><br>
<a href="vbscript:msgbox('xss')">vbscript:msgbox('xss')</a><br>
<a href="file:///etc/passwd">file:///etc/passwd</a><br>
<a href="about:blank">about:blank</a><br>
<a href="chrome://settings">chrome://settings</a><br>

<h1>URL with Special Characters Tests (as links for reference)</h1>
<a href="https://example.com/path with spaces">https://example.com/path with spaces</a><br>
<a href="https://example.com/path&quot;with&quot;quotes">https://example.com/path"with"quotes</a><br>
<a href="https://example.com/path'with'single'quotes">https://example.com/path'with'single'quotes</a><br>
<a href="https://example.com/path<with>angle>brackets">https://example.com/path<with>angle>brackets</a><br>
<a href="https://example.com/path&with&amps">https://example.com/path&with&amps</a><br>
<a href="https://example.com/path<script>alert('xss')</script>">https://example.com/path<script>alert('xss')</script></a><br>

<h1>Malformed URL Tests (as links for reference)</h1>
<a href="not-a-url">not-a-url</a><br>
<a href="http://">http://</a><br>
<a href="https://">https://</a><br>
<a href="ftp://">ftp://</a><br>
<a href="mailto:">mailto:</a><br>
<a href="tel:">tel:</a><br>

<h1>Edge Case Tests (as links for reference)</h1>
<a href="https://example.com/path?param=&quot;value&quot;&other=<script>">https://example.com/path?param="value"&other=<script></a><br>
<a href="https://example.com/path#fragment<script>alert('xss')</script>">https://example.com/path#fragment<script>alert('xss')</script></a><br>
<a href="https://example.com/path%3Cscript%3Ealert('xss')%3C/script%3E">https://example.com/path%3Cscript%3Ealert('xss')%3C/script%3E</a><br>
<a href="https://example.com/path&lt;script&gt;alert('xss')&lt;/script&gt;">https://example.com/path&lt;script&gt;alert('xss')&lt;/script&gt;</a><br>

<h1>Safe URLs for Comparison (as links for reference)</h1>
<a href="https://example.com/safe">https://example.com/safe</a><br>
<a href="https://example.com/path-with-hyphens">https://example.com/path-with-hyphens</a><br>
<a href="https://example.com/path_with_underscores">https://example.com/path_with_underscores</a><br>
<a href="https://example.com/path.with.dots">https://example.com/path.with.dots</a><br>
<a href="https://example.com/path,with,commas">https://example.com/path,with,commas</a><br>
<a href="https://cirt.net/somethingnothere.js">https://cirt.net/somethingnothere.js</a><br>
<a href="http://localhost:4567/test.js">http://localhost:4567/test.js</a><br>

</body>
""")
        else:
            self.send_error(404, "File Not Found")

try:
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"🚀 Serving test page at http://localhost:{PORT}")
        print("Press Ctrl+C to stop the server")
        httpd.serve_forever()
except OSError as e:
    if e.errno == 48:  # Address already in use
        print(f"❌ Port {PORT} is already in use. Try a different port or kill the process using it.")
        print(f"   You can kill it with: lsof -ti:{PORT} | xargs kill -9")
    else:
        print(f"❌ Error starting server: {e}")
    sys.exit(1)
except KeyboardInterrupt:
    print("\n👋 Server stopped by user")
    sys.exit(0)
