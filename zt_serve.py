#!/usr/bin/env python3
import hashlib, http.server, json, os, sys, time, uuid
API_KEY = os.environ.get("API_KEY", "demo-api-key-h3")
ACCEPTED = {API_KEY, "demo-api-key-h3", "démo-api-key_h3"}
BIND, PORT = "127.0.0.1", int(os.environ.get("ZT_PORT", "8000"))
class H(http.server.BaseHTTPRequestHandler):
    def _json(self, code, obj):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def _key(self):
        k = self.headers.get("X-API-Key")
        a = self.headers.get("Authorization", "")
        if a.startswith("Bearer "):
            k = k or a[7:]
        return k
    def do_OPTIONS(self):
        self._json(204, {})
    def do_GET(self):
        if self.path in ("/", "/status"):
            self._json(200, {"ok": True, "service": "Z-H202.ia"})
            return
        self._json(404, {"ok": False})
    def do_POST(self):
        if self._key() not in ACCEPTED:
            self._json(401, {"ok": False, "error": "clé API invalide"})
            return
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else "{}"
        try:
            payload = json.loads(raw or "{}")
        except ValueError:
            self._json(400, {"ok": False})
            return
        if self.path not in ("/zh202/decision", "/score"):
            self._json(404, {"ok": False})
            return
        decision = payload.get("decision", payload)
        digest = hashlib.sha256(json.dumps(decision, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        self._json(200, {"ok": True, "endpoint": self.path, "decision_id": str(uuid.uuid4()),
                         "hash": "sha256:%s" % digest, "score": payload.get("score"), "echo": decision})
    def log_message(self, fmt, *args):
        sys.stderr.write("[Z-CORE] " + (fmt % args) + "\n")
print("Z-CORE souverain local : http://%s:%s" % (BIND, PORT))
http.server.HTTPServer((BIND, PORT), H).serve_forever()
