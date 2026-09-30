"""CI-only TLS endpoint for the public synthetic sqld integration fixture."""
import http.server
import ssl
import sys
import urllib.request

class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def forward(self):
        size = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(size) if size else None
        headers = {"Content-Type": self.headers.get("Content-Type", "application/json"),
                   "User-Agent": "cvld-library-maintenance"}
        request = urllib.request.Request("http://127.0.0.1:8080" + self.path,
                                         data=data, headers=headers, method=self.command)
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read()
            self.send_response(response.status)
            self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    do_GET = forward
    do_POST = forward

server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), Proxy)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
