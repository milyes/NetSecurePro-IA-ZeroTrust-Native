#!/usr/bin/env python3
import hashlib, http.server, json, os, pathlib, sys, time, uuid
API_KEY = os.environ.get("API_KEY", "demo-api-key-h3")
ACCEPTED = {API_KEY, "demo-api-key-h3", "démo-api-key_h3"}
BIND, PORT = "127.0.0.1", int(os.environ.get("ZT_PORT", "8000"))
ROOT = pathlib.Path(__file__).resolve().parent
HTML = {
    "/": "index.html",
    "/index.html": "index.html",
    "/exec_bin.html": "exec_bin.html",
    "/exec": "exec_bin.html",
    "/IA_Parkinson_Logic.html": "IA_Parkinson_Logic.html",
    "/IA_Parkinson_Logic_mobile.html": "IA_Parkinson_Logic_mobile.html",
    "/ia_parkinson_logic_doctor.html": "ia_parkinson_logic_doctor.html",
    "/IA_Fraude_Carte_Logic.html": "IA_Fraude_Carte_Logic.html",
    "/RBC_Chatbot_Cartes_Logic.html": "RBC_Chatbot_Cartes_Logic.html",
}

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
        if code != 204:
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
        path = self.path.split("?", 1)[0]
        if path in HTML:
            fp = ROOT / HTML[path]
            if fp.exists():
                data = fp.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if path in ("/", "/index.html"):
                self._json(200, {"ok": True, "hint": "index.html absent, utiliser /exec"})
                return
        if path in ("/status",):
            self._json(200, {"ok": True, "service": "Z-H202.ia", "bin": "exec_bin"})
            return
        self._json(404, {"ok": False, "error": "introuvable"})
    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if self._key() not in ACCEPTED:
            self._json(401, {"ok": False, "error": "clé API invalide"})
            return
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else "{}"
        try:
            payload = json.loads(raw or "{}")
        except ValueError:
            self._json(400, {"ok": False, "error": "JSON invalide"})
            return
        if path not in ("/zh202/decision", "/score"):
            self._json(404, {"ok": False, "error": "introuvable"})
            return
        decision = payload.get("decision", payload)
        digest = hashlib.sha256(json.dumps(decision, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        self._json(200, {
            "ok": True, "endpoint": path, "decision_id": str(uuid.uuid4()),
            "sealed_at": int(time.time()), "hash": "sha256:%s" % digest,
            "score": payload.get("score"), "echo": decision,
        })
    def log_message(self, fmt, *args):
        sys.stderr.write("[Z-CORE] " + (fmt % args) + "\n")

if BIND != "127.0.0.1":
    raise SystemExit("loopback uniquement")
print("Z-CORE exec_bin : http://%s:%s/" % (BIND, PORT))
print("GET /  /exec  /status   POST /score")
http.server.HTTPServer((BIND, PORT), H).serve_forever()
