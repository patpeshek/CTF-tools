#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
serve.py — мини HTTP-сервер для раздачи скриптов и приёма файлов (lab/CTF).

  python serve.py --dir . --port 8000
  python serve.py --dir . --port 8000 --upload
  python serve.py --dir . --port 8000 --upload --token s3cr3t

GET  — обычная раздача файлов из --dir.
POST — если --upload: сохраняет тело запроса в --dir (имя из URL или X-Filename).
       С --token требуется ?token=... или заголовок X-Token.

Только для своих стендов. Не выставляй в интернет.
"""
from __future__ import annotations

# Windows: консоль/pipe не должны падать на Unicode (—, →, «», █).
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import http.server
import os
import socketserver
import urllib.parse


def make_handler(root, upload, token):
    root = os.path.abspath(root)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=root, **kw)

        def log_message(self, fmt, *args):
            print("[%s] %s" % (self.address_string(), fmt % args))

        def _allowed(self):
            if not token:
                return True
            if self.headers.get("X-Token") == token:
                return True
            q = urllib.parse.urlparse(self.path).query
            return urllib.parse.parse_qs(q).get("token", [""])[0] == token

        def do_POST(self):
            if not upload:
                self.send_error(403, "upload disabled")
                return
            if not self._allowed():
                self.send_error(403, "bad token")
                return
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > 100 * 1024 * 1024:
                self.send_error(400, "bad size")
                return
            name = self.headers.get("X-Filename")
            if not name:
                name = os.path.basename(urllib.parse.urlparse(self.path).path) or "upload.bin"
            name = os.path.basename(name)
            path = os.path.join(root, name)
            data = self.rfile.read(length)
            open(path, "wb").write(data)
            print(f"[+] saved {len(data)} b -> {path}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK\n")

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--upload", action="store_true")
    ap.add_argument("--token")
    args = ap.parse_args()

    handler = make_handler(args.dir, args.upload, args.token)
    with socketserver.TCPServer((args.bind, args.port), handler) as httpd:
        print(f"[+] http://{args.bind}:{args.port}/  dir={os.path.abspath(args.dir)}")
        print(f"[+] upload={'on' if args.upload else 'off'} token={'yes' if args.token else 'no'}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] stop")


if __name__ == "__main__":
    main()
