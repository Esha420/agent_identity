#!/usr/bin/env python3
"""Synthetic Staging Web Server for Incident Investigation Verification."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

DEFAULT_PAGE = """<!DOCTYPE html>
<html>
<head><title>Example Domain</title></head>
<body>
<h1>Example Domain</h1>
<p>Test page for browser agent verification.</p>
</body>
</html>
"""

STAGING_ERROR_PAGE = """<!DOCTYPE html>
<html>
<head><title>500 Internal Server Error</title></head>
<body>
<h1>HTTP 500: Database Connection Pool Exhausted</h1>
<p>Critical: Unable to acquire connection to postgres-cluster after 30000ms.</p>
</body>
</html>
"""

class StagingRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/staging-error":
            body = STAGING_ERROR_PAGE.encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = DEFAULT_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_HEAD(self):
        if self.path == "/staging-error":
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

    def log_message(self, format, *args):
        sys.stdout.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))
        sys.stdout.flush()

def run(port=8089):
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, StagingRequestHandler)
    print(f"[*] Synthetic Staging Web Server listening on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
