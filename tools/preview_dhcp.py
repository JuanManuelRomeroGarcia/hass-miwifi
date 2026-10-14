"""Serve only the DHCP fixture and panel assets on loopback (no router access)."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / "custom_components/miwifi/www"), **kwargs)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            content = (ROOT / "tools/dhcp-preview.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        elif path.startswith("/miwifi_static/"):
            self.path = self.path.removeprefix("/miwifi_static")
            super().do_GET()
        else:
            self.send_error(404)


if __name__ == "__main__":
    print("DHCP fixture: http://127.0.0.1:8766 (Ctrl+C to stop)", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8766), Handler).serve_forever()
