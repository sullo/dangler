#!/usr/bin/env python3
import http.server
import socketserver

PORT = 8080

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            # Broken HTML with specified script and link includes
            self.wfile.write(b"""
<head>
<title>Broken Test Page</title>
<script src="https://thisdoesntexistithink.com/somefile.js"></script>
<script src="https://rvasec.com/somethingnothere.png"></script>
<link rel="stylesheet" href="https://c0.wp.com/c/6.7.2/wp-includes/css/dist/block-library/style.min.css">
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Open+Sans%3A400%2C300%2C600%2C700%2C800&ver=6.7.2">
<body>
<h1>Broken HTML Page for The Dangler Test</h1>
<p>This page is missing the &lt;html&gt; tag and has bad includes.</p>
</body>
""")
        else:
            self.send_error(404, "File Not Found")

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"🚀 Serving test page at http://localhost:{PORT}")
    httpd.serve_forever()
