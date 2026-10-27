#!/usr/bin/env python3
"""Compare public file-serving workflows against a previously built Go www binary."""

import argparse
from contextlib import contextmanager
from html.parser import HTMLParser
import http.client
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.parse import unquote, urljoin


@contextmanager
def running(binary, root):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen([str(binary), "-q", "-r", str(root), "-p", str(port)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError(log.read().decode())
                    time.sleep(0.02)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def request(port, path, method="GET", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


class Links(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.links = set()
        self.feed(body.decode())

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for key, value in attrs:
                if key == "href":
                    self.links.add(unquote(urljoin("http://test/", value)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("go_binary", type=Path)
    parser.add_argument("rust_binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name in ("file.txt", ".hidden", "a & <b>.txt", "a?#% ü.txt"):
            (root / name).write_bytes(b"0123456789")
        (root / "sub").mkdir()
        (root / "sub/index.html").write_text("<h1>Hello</h1>")
        with running(args.go_binary.resolve(), root) as old, running(args.rust_binary.resolve(), root) as new:
            checks = 0
            for path, method, headers in [
                ("/file.txt", "GET", {}),
                ("/file.txt", "HEAD", {}),
                ("/.hidden", "GET", {}),
                ("/a%3F%23%25%20%C3%BC.txt", "GET", {}),
                ("/sub/", "GET", {}),
                ("/file.txt", "GET", {"Range": "bytes=2-5"}),
                ("/file.txt", "GET", {"Range": "bytes=-3"}),
            ]:
                a, b = request(old, path, method, headers), request(new, path, method, headers)
                assert (a[0], a[2]) == (b[0], b[2]), (path, method, headers, a, b)
                checks += 1
            for path in ("/sub?x=1", "/sub/index.html?x=1"):
                a, b = request(old, path), request(new, path)
                assert a[0] == b[0] == 301
                assert urljoin("http://test" + path, a[1]["Location"]) == urljoin("http://test" + path, b[1]["location"])
                checks += 1
            a, b = request(old, "/"), request(new, "/")
            assert a[0] == b[0] == 200
            assert Links(a[2]).links == Links(b[2]).links
            checks += 1
            modified = request(old, "/file.txt")[1]["Last-Modified"]
            assert request(old, "/file.txt", headers={"If-Modified-Since": modified})[0] == request(new, "/file.txt", headers={"If-Modified-Since": modified})[0] == 304
            checks += 1
            for path in ("/missing", "/file.txt/missing"):
                assert request(old, path)[0] == request(new, path)[0] == 404
                checks += 1
            print(f"Passed {checks} Go/Rust compatibility scenarios")


if __name__ == "__main__":
    main()
