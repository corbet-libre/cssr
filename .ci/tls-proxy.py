"""Linux CI-only HTTPS fixture forwarding solely to its sibling sqld child."""
import http.client
import http.server
import os
from pathlib import Path
import ssl
import sys
import time


class OwnedBackend:
    """Discover the one loopback listener held by the shell's sqld child."""

    def __init__(self, pid):
        self.proc = Path("/proc") / str(pid)
        self.parent = os.getppid()
        deadline = time.monotonic() + 10
        while True:
            listeners = self.listeners()
            if len(listeners) == 1:
                self.listener = listeners[0]
                return
            if len(listeners) > 1:
                raise RuntimeError("fixture startup: ambiguous owned sqld listeners")
            if time.monotonic() >= deadline:
                raise RuntimeError("fixture startup: owned sqld listener deadline")
            time.sleep(0.05)

    def listeners(self):
        status = dict(line.split(":", 1) for line in (self.proc / "status").read_text().splitlines())
        if int(status["PPid"]) != self.parent or status["State"].strip().startswith(("Z", "X")):
            raise RuntimeError("fixture ownership: sqld is not a live sibling child")
        inodes = set()
        for descriptor in (self.proc / "fd").iterdir():
            try:
                link = os.readlink(descriptor)
            except FileNotFoundError:
                continue  # An unrelated transient descriptor may close.
            if link.startswith("socket:[") and link.endswith("]"):
                inodes.add(link[8:-1])
        listeners = []
        for row in (self.proc / "net/tcp").read_text().splitlines()[1:]:
            fields = row.split()
            address, port = fields[1].split(":")
            if fields[3] == "0A" and address == "0100007F" and fields[9] in inodes:
                listeners.append((int(port, 16), fields[9]))
        return listeners

    def connect(self):
        if self.listeners() != [self.listener]:
            raise RuntimeError("fixture ownership: original sqld listener unavailable")
        connection = http.client.HTTPConnection("127.0.0.1", self.listener[0], timeout=10)
        try:
            connection.connect()
            # A port reused by another service must fail before even a health
            # request is sent. This connection never redirects or reconnects.
            if self.listeners() != [self.listener]:
                raise RuntimeError("fixture ownership: sqld lost its listener during connect")
            return connection
        except BaseException:
            connection.close()
            raise


class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def setup(self):
        self.request.settimeout(10)
        self.request.do_handshake()
        super().setup()

    def forward(self):
        if not self.path.startswith("/") or self.path.startswith("//") or self.headers.get("Transfer-Encoding"):
            self.send_error(400)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if not 0 <= size <= 1_048_576:
            self.send_error(413)
            return
        data = self.rfile.read(size) if size else None
        if size and len(data) != size:
            self.send_error(400)
            return
        connection = None
        try:
            connection = self.server.backend.connect()
            connection.request(self.command, self.path, body=data, headers={
                "Content-Type": self.headers.get("Content-Type", "application/json"),
                "User-Agent": "cvld-library-maintenance",
            })
            response = connection.getresponse()
            body = response.read(1_048_577)
            if len(body) > 1_048_576:
                raise RuntimeError("synthetic fixture response exceeds bound")
            self.send_response(response.status)
            self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (OSError, ValueError, KeyError, RuntimeError, http.client.HTTPException):
            self.send_error(502, "Owned fixture backend unavailable")
        finally:
            if connection is not None:
                connection.close()

    do_GET = forward
    do_POST = forward

def main():
    certificate, key, pid, ready = sys.argv[1:]
    backend = OwnedBackend(int(pid))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy) as server:
        server.backend = backend
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
        connection = backend.connect()
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError("fixture startup: owned sqld is not healthy")
            response.read(1_048_576)
        finally:
            connection.close()
        # Publish only after TLS, ownership and health are established. Atomic
        # rename prevents the parent from reading a partially written URL.
        path = Path(ready)
        temporary = path.with_suffix(".pending")
        with temporary.open("x") as output:
            output.write(f"https://127.0.0.1:{server.server_port}\n")
        temporary.replace(path)
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, http.client.HTTPException) as error:
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"Fixture startup/ownership failed: {detail}", file=sys.stderr)
        sys.exit(1)
