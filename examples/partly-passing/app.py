"""A notes search small enough to read, written the safe way on purpose."""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer


def search(db, term):
    # The values travel beside the query rather than inside it, which is what V1.2.4 asks for.
    return db.execute("select * from notes where t = ?", [term]).fetchall()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>notes</body></html>")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
