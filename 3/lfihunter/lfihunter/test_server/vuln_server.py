"""
A deliberately vulnerable test server for validating lfihunter.
Simulates a classic ?page= LFI, including a fake filesystem so we don't
need to touch real system files, plus a php://filter-style base64 wrapper.
"""
import base64
import http.server
import urllib.parse

FAKE_FS = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    "etc/hosts": "127.0.0.1 localhost\n",
    "windows/win.ini": "[extensions]\ntxt=notepad.exe\n",
    "proc/self/environ": "PATH=/usr/bin:/bin\nHOME=/root\n",
}

REAL_INDEX_SOURCE = "<?php\n// fake index.php source for base64 wrapper test\necho 'hello';\n?>"


def resolve_traversal(raw_path: str) -> str:
    # Very naive "vulnerable" resolution: strip ../ sequences and look up
    # the remainder directly, simulating an app with a weak/no filter.
    cleaned = raw_path.replace("..%2f", "../").replace("..%252f", "../")
    cleaned = cleaned.replace("....//", "../")
    cleaned = cleaned.replace("\\", "/")
    cleaned = cleaned.rstrip("\x00")
    parts = [p for p in cleaned.split("/") if p not in ("..", "")]
    return "/".join(parts)


class VulnHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        page = qs.get("page", [""])[0]
        page = urllib.parse.unquote(page)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        if page.startswith("php://filter"):
            self.wfile.write(base64.b64encode(REAL_INDEX_SOURCE.encode()))
            return

        if page.startswith("data://"):
            # simulate data wrapper decode for the sanity check payload
            self.wfile.write(b"Hello")
            return

        resolved = resolve_traversal(page)
        if resolved in FAKE_FS:
            self.wfile.write(FAKE_FS[resolved].encode())
        else:
            self.wfile.write(b"<html>404 not found</html>")

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", 8877), VulnHandler)
    server.serve_forever()
