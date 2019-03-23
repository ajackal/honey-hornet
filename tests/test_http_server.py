from http.server import BaseHTTPRequestHandler, HTTPServer


class XmlAuth(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def do_POST(self):
        self._set_headers()
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        password = b'TestPassword123'
        if password in body:
            self.wfile.write(b"<login>message='OK'</login>")
        else:
            self.wfile.write(b"<login>message='FAILED'</login>")


def run(server_class=HTTPServer, handler_class=XmlAuth, port=9191):
    server_address = ('127.0.0.1', port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


if __name__ == '__main__':
    run()
