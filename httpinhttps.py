#!venv/bin/python3

import os, ssl, warnings
from tornado import httpserver, ioloop, web
from urllib3.exceptions import InsecureRequestWarning
from config import *

# Generate self-signed cert (optional: can skip if you already have certs)
os.system("openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -subj '/CN=mylocalhost'")

# Silence insecure cert warnings (if you're using self-signed)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

def make_app():
    return web.Application([
        (r"/(.*)", web.StaticFileHandler, {"path": os.getcwd(), "default_filename": "index.html"})
    ], debug=False)

def main():
    app = make_app()
    server = httpserver.HTTPServer(app, ssl_options={
        "certfile": "cert.pem",
        "keyfile": "key.pem",
    })
    server.listen(EMBED_PORT)
    print(f"Serving HTTPS at https://localhost:{EMBED_PORT}")
    ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()
