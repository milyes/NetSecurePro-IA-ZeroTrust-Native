#!/usr/bin/env python3
# NetSecurePro IA — Zero Trust Native + Z-H202.ia
# Python 3.8+ stdlib — 0 pip — loopback only for serve
import argparse, hashlib, http.client, http.server, ipaddress, json, os, pathlib, re, socket, ssl, sys, time, uuid

API_KEY = os.environ.get("API_KEY", "demo-api-key-h3")
ACCEPTED = {API_KEY, "demo-api-key-h3", "démo-api-key_h3"}
SOVEREIGN_LOCAL = os.environ.get("SOVEREIGN_LOCAL", "1") in ("1", "true", "TRUE", "yes")
BIND, PORT = "127.0.0.1", int(os.environ.get("ZT_PORT", "8000"))
ROOT = pathlib.Path(__file__).resolve().parent
USER_AGENT = "ZeroTrustNative-ZH202/1.5"

FORBIDDEN = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
]
NETS = [ipaddress.ip_network(n) for n in FORBIDDEN]
HTML = {
    "/": "index.html", "/index.html": "index.html",
    "/exec": "exec_bin.html", "/exec_bin.html": "exec_bin.html",
    "/zh202": "ZH202.html", "/ZH202.html": "ZH202.html",
    "/IA_Parkinson_Logic.html": "IA_Parkinson_Logic.html",
    "/IA_Parkinson_Logic_mobile.html": "IA_Parkinson_Logic_mobile.html",
    "/ia_parkinson_logic_doctor.html": "ia_parkinson_logic_doctor.html",
    "/IA_Fraude_Carte_Logic.html": "IA_Fraude_Carte_Logic.html",
    "/RBC_Chatbot_Cartes_Logic.html": "RBC_Chatbot_Cartes_Logic.html",
}

def _canon(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip

def _forbidden(ip):
    ip = _canon(ip)
    if SOVEREIGN_LOCAL and ip.is_loopback:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_unspecified or ip.is_multicast:
        return True
    for n in NETS:
        try:
            if ip in n:
                return True
        except Exception:
            pass
    return False

def _parse(url):
    url = re.sub(r"://::ffff:([0-9.]+)/", r"://[::ffff:\1]/", url)
    m = re.match(r"^(https?)://(\[[^\]]+\]|[^:/]+)(:(\d+))?(/.*)?$", url)
    if not m:
        raise ValueError("URL invalide")
    scheme, host, _, port, path = m.groups()
    host = host.strip("[]")
    port = int(port) if port else (443 if scheme == "https" else 80)
    return scheme, host, port, path or "/"

def validate_zero_trust(url):
    scheme, host, port, path = _parse(url)
    ips = set()
    try:
        ips.add(ipaddress.ip_address(host))
    except ValueError:
        try:
            for res in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
                ips.add(ipaddress.ip_address(res[4][0]))
        except socket.gaierror as e:
            return False, [], "DNS: %s" % e
    if not ips:
        return False, [], "Aucune IP"
    for ip in ips:
        if _forbidden(ip):
            return False, [], "IP interdite: %s" % _canon(ip)
    loop = all(_canon(ip).is_loopback for ip in ips)
    if scheme != "https" and not (SOVEREIGN_LOCAL and loop):
        return False, [], "HTTPS exigé"
    return True, list(ips), "OK"

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
        return k or (a[7:] if a.startswith("Bearer ") else "")
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
        if path in ("/", "/status"):
            self._json(200, {"ok": True, "service": "Z-H202.ia", "mode": "sovereign-local"})
            return
        self._json(404, {"ok": False})
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
        if path not in ("/score", "/zh202/decision"):
            self._json(404, {"ok": False})
            return
        decision = payload.get("decision", payload)
        digest = hashlib.sha256(json.dumps(decision, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        self._json(200, {
            "ok": True, "module": "Z-H202.ia", "endpoint": path,
            "decision_id": str(uuid.uuid4()), "sealed_at": int(time.time()),
            "hash": "sha256:%s" % digest, "score": payload.get("score"), "echo": decision,
        })
    def log_message(self, fmt, *args):
        sys.stderr.write("[Z-CORE] " + (fmt % args) + "\n")

def selftest():
    for t in ["http://127.0.0.1/", "http://169.254.169.254/", "http://100.64.0.1/",
              "http://::ffff:169.254.169.254/", "https://httpbin.org/get"]:
        ok, ips, reason = validate_zero_trust(t)
        print(("ALLOW" if ok else "BLOCK"), t, "<-", reason)

def serve():
    if BIND != "127.0.0.1":
        raise SystemExit("loopback uniquement")
    print("Z-H202 + Zero Trust : http://%s:%s" % (BIND, PORT))
    print("GET /zh202 /exec /status   POST /score /zh202/decision")
    http.server.HTTPServer((BIND, PORT), H).serve_forever()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("cmd", nargs="?", default="serve", choices=["serve", "selftest"])
    a = p.parse_args()
    if a.cmd == "selftest":
        selftest()
    else:
        serve()
