# The install step's fixture (ADR-052): a page that can only be served if `six`, which the
# standard library does not have, was installed before the run and given to the app.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import six


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"install fixture: six {six.__version__}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
