#!/usr/bin/env python3
import http.server
import socketserver
import sys
import os

PORT = 8001

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"""User-agent: *
Disallow: /private/
Disallow: /admin/
Allow: /public/
Crawl-delay: 1
""")
        elif self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            # Fixed HTML with proper escaping
            self.wfile.write(b"""
<head>
<title>Broken Test Page</title>
<script src="https://thisdoesntexistithink.com/somefile.js"></script>
<script src="https://rvasec.com/somethingnothere.png"></script>
<script src="https://github.com/sullo/nikto/somethingnothere.png"></script>

<link rel="stylesheet" href="https://c0.wp.com/c/6.7.2/wp-includes/css/dist/block-library/style.min.css">
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Open+Sans%3A400%2C300%2C600%2C700%2C800&ver=6.7.2">

		<!-- Facebook Pixel Code -->
		<script>
			var aepc_pixel = {"pixel_id":"aaa126749094662441","user":{"em":"aaaa1f0172fb0217bbd3ef802215b85276e6a0e8d487e49643565555c9a70f974e9","external_id":"1"},"enable_advanced_events":"yes","fire_delay":"0","can_use_sku":"yes"},
				aepc_pixel_args = [],
				aepc_extend_args = function( args ) {
					if ( typeof args === 'undefined' ) {
						args = {};
					}

					for(var key in aepc_pixel_args)
						args[key] = aepc_pixel_args[key];

					return args;
				};

			// Extend args
			if ( 'yes' === aepc_pixel.enable_advanced_events ) {
				aepc_pixel_args.userAgent = navigator.userAgent;
				aepc_pixel_args.language = navigator.language;

				if ( document.referrer.indexOf( document.domain ) < 0 ) {
					aepc_pixel_args.referrer = document.referrer;
				}
			}

						!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?
				n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;
				n.push=n;n.loaded=!0;n.version='2.0';n.agent='dvpixelcaffeinewordpress';n.queue=[];t=b.createElement(e);t.async=!0;
				t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,
				document,'script','https://connect.facebook.net/en_US/fbevents.js');
			
						fbq('init', aepc_pixel.pixel_id, aepc_pixel.user);

							setTimeout( function() {
				fbq('track', "PageView", aepc_pixel_args);
			}, aepc_pixel.fire_delay * 1000 );
					</script>
				<noscript><img height="1" width="1" style="display:none" src="https://www.facebook.com/tr?id=aaa126749094662441&ev=PageView&noscript=1"
			/></noscript>
				<!-- End Facebook Pixel Code -->

<!-- XSS Test Cases as Remote Resources -->
<script src="javascript:alert('xss')"></script>
<script src="data:text/html,<script>alert('xss')</script>"></script>
<script src="vbscript:msgbox('xss')"></script>
<script src="file:///etc/passwd"></script>
<script src="about:blank"></script>
<script src="chrome://settings"></script>

<link rel="stylesheet" href="https://nosuch-thing-example.com/path with spaces">
<link rel="stylesheet" href="https://nosuch-thing-example.com/path&quot;with&quot;quotes">
<link rel="stylesheet" href="https://nosuch-thing-example.com/path'with'single'quotes">
<link rel="stylesheet" href="https://nosuch-thing-example.com/path<with>angle>brackets">
<link rel="stylesheet" href="https://nosuch-thing-example.com/path&with&amps">
<link rel="stylesheet" href="https://nosuch-thing-example.com/path<script>alert('xss')</script>">

<img src="not-a-url">
<img src="http://">
<img src="https://">
<img src="ftp://">
<img src="mailto:">
<img src="tel:">

<script src="https://example.com/path?param=&quot;value&quot;&other=<script>"></script>
<script src="https://nosuch-thing-example.com/path#fragment<script>alert('xss')</script>"></script>
<script src="https://nosuch-thing-example.com/path%3Cscript%3Ealert('xss')%3C/script%3E"></script>
<script src="https://nosuch-thing-example.com/path&lt;script&gt;alert('xss')&lt;/script&gt;"></script>
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

<h2>Navigation to Subdirectories</h2>
<ul>
<li><a href="/public/">Public Directory</a></li>
<li><a href="/private/">Private Directory (should be blocked by robots.txt)</a></li>
<li><a href="/admin/">Admin Directory (should be blocked by robots.txt)</a></li>
</ul>

<h1>URL Protocol Tests (as links for reference)</h1>
<a href="javascript:alert('xss')">javascript:alert('xss')</a><br>
<a href="data:text/html,<script>alert('xss')</script>">data:text/html,<script>alert('xss')</script></a><br>
<a href="vbscript:msgbox('xss')">vbscript:msgbox('xss')</a><br>
<a href="file:///etc/passwd">file:///etc/passwd</a><br>
<a href="about:blank">about:blank</a><br>
<a href="chrome://settings">chrome://settings</a><br>
<a href="/public">public</a><br>
<a href="/private">private</a><br>
<a href="/admin">admin</a><br>

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

<img src="https://cirt.net/files/alienlogo_3.gif">
<img src="https://cirt.net/files/alienlogo_3.gif">
<img src="https://cirt.net/files/alienlogo_3.gif">

</body>
""")
        elif self.path == "/public/" or self.path == "/public/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head>
    <title>Public Directory</title>
    <script src="https://example.com/public-script.js"></script>
    <link rel="stylesheet" href="https://example.com/public-style.css">
</head>
<body>
    <h1>Public Directory</h1>
    <p>This directory should be allowed by robots.txt</p>
    <p><a href="/">Back to Home</a></p>
    <p><a href="/public/page2.html">Page 2</a></p>
    <p><a href="/public/page3.html">Page 3</a></p>
    
    <img src="https://example.com/public-image.jpg">
    <script src="https://cdn.example.com/public-library.js"></script>
</body>
</html>""")
        elif self.path == "/public/page2.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head>
    <title>Public Page 2</title>
    <script src="https://example.com/page2-script.js"></script>
</head>
<body>
    <h1>Public Page 2</h1>
    <p>This is page 2 in the public directory</p>
    <p><a href="/public/">Back to Public Directory</a></p>
    <p><a href="/">Back to Home</a></p>
    
    <img src="https://example.com/page2-image.png">
</body>
</html>""")
        elif self.path == "/public/page3.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head>
    <title>Public Page 3</title>
    <link rel="stylesheet" href="https://example.com/page3-style.css">
</head>
<body>
    <h1>Public Page 3</h1>
    <p>This is page 3 in the public directory</p>
    <p><a href="/public/">Back to Public Directory</a></p>
    <p><a href="/">Back to Home</a></p>
    
    <script src="https://example.com/page3-script.js"></script>
</body>
</html>""")
        elif self.path == "/private/" or self.path == "/private/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head>
    <title>Private Directory</title>
    <script src="https://example.com/private-script.js"></script>
    <link rel="stylesheet" href="https://example.com/private-style.css">
</head>
<body>
    <h1>Private Directory</h1>
    <p>This directory should be blocked by robots.txt</p>
    <p><a href="/">Back to Home</a></p>
    <p><a href="/private/secret.html">Secret Page</a></p>
    
    <img src="https://example.com/private-image.jpg">
    <script src="https://cdn.example.com/private-library.js"></script>
</body>
</html>""")
        elif self.path == "/private/secret.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head>
    <title>Secret Page</title>
    <script src="https://example.com/secret-script.js"></script>
</head>
<body>
    <h1>Secret Page</h1>
    <p>This is a secret page that should be blocked by robots.txt</p>
    <p><a href="/private/">Back to Private Directory</a></p>
    <p><a href="/">Back to Home</a></p>
    
    <img src="https://example.com/secret-image.png">
</body>
</html>""")
        elif self.path == "/admin/" or self.path == "/admin/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head>
    <title>Admin Directory</title>
    <script src="https://example.com/admin-script.js"></script>
    <link rel="stylesheet" href="https://example.com/admin-style.css">
</head>
<body>
    <h1>Admin Directory</h1>
    <p>This directory should be blocked by robots.txt</p>
    <p><a href="/">Back to Home</a></p>
    <p><a href="/admin/dashboard.html">Admin Dashboard</a></p>
    
    <img src="https://example.com/admin-image.jpg">
    <script src="https://cdn.example.com/admin-library.js"></script>
</body>
</html>""")
        elif self.path == "/admin/dashboard.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <script src="https://example.com/dashboard-script.js"></script>
</head>
<body>
    <h1>Admin Dashboard</h1>
    <p>This is an admin dashboard that should be blocked by robots.txt</p>
    <p><a href="/admin/">Back to Admin Directory</a></p>
    <p><a href="/">Back to Home</a></p>
    
    <img src="https://example.com/dashboard-image.png">
</body>
</html>""")
        else:
            self.send_error(404, "File Not Found")

try:
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"🚀 Serving test page at http://localhost:{PORT}")
        print("📁 Available directories:")
        print("   - /public/ (allowed by robots.txt)")
        print("   - /private/ (blocked by robots.txt)")
        print("   - /admin/ (blocked by robots.txt)")
        print("📄 robots.txt available at http://localhost:{PORT}/robots.txt")
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
