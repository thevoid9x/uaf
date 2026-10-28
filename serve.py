import http.server
import re
import subprocess
from pathlib import Path

PORT = 8000
ROOT = Path(__file__).resolve().parent

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

def local_ip():
    try:
        output = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"],
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "localhost"

    for line in output.splitlines():
        if "inet" in line and "127.0.0.1" not in line:
            match = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", line)
            if match and match.group(1).startswith("192.168."):
                return match.group(1)

    return "localhost"

if __name__ == "__main__":
    with http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as server:
        print(f"http://{local_ip()}:{PORT}/")
        server.serve_forever()