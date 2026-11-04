"""Small executable HTTP service for a non-production CI/CD evaluation."""
import argparse, json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ('/health', '/version'):
            self.send_error(404); return
        broken = self.path == '/health' and os.getenv('FAIL_HEALTH','0') == '1'
        status = 503 if broken else 200
        data = {'ok': not broken, 'stage': os.getenv('STAGE_NAME','local'),
                'build_sha': os.getenv('APP_BUILD_SHA','local'), 'endpoint': self.path}
        body = json.dumps(data,sort_keys=True).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def log_message(self,fmt,*args):
        print(f'{self.address_string()} {fmt%args}',flush=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8000)
    args=parser.parse_args()
    ThreadingHTTPServer((os.getenv('BIND_HOST','127.0.0.1'),args.port),Handler).serve_forever()
if __name__=='__main__':main()
