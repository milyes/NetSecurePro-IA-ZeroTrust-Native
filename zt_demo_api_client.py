#!/usr/bin/env python3
# Z-CORE / NetSecurePro — client API zéro-confiance natif
# Python 3.8+ — stdlib uniquement
# Clé démo : démo-api-key_h3
# Ordre : IP interdite d'abord, puis exigence HTTPS

import ipaddress, json, os, re, socket, ssl, http.client

API_KEY = os.environ.get("API_KEY", "démo-api-key_h3")
BASE_URL = os.environ.get("API_BASE_URL", "https://httpbin.org")
TIMEOUT = int(os.environ.get("API_TIMEOUT", "15"))
USER_AGENT = "ZeroTrustNative-API/1.0"

FORBIDDEN_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("2001:db8::/32"),
]

def _canon(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip

def _is_forbidden(ip):
    ip = _canon(ip)
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_unspecified or ip.is_multicast:
        return True
    for net in FORBIDDEN_NETS:
        try:
            if ip in net:
                return True
        except Exception:
            continue
    return False

def _normalize_url(url):
    return re.sub(r"://::ffff:([0-9.]+)/", r"://[::ffff:\1]/", url)

def _parse_url(url):
    url = _normalize_url(url)
    m = re.match(r"^(https?)://(\[[^\]]+\]|[^:/]+)(:(\d+))?(/.*)?$", url)
    if not m:
        raise ValueError("URL invalide")
    scheme, host, _, port, path = m.groups()
    host = host.strip("[]")
    port = int(port) if port else (443 if scheme == "https" else 80)
    return scheme, host, port, path or "/"

def validate_zero_trust(url):
    scheme, host, port, path = _parse_url(url)
    all_ips = set()
    try:
        all_ips.add(ipaddress.ip_address(host))
    except ValueError:
        try:
            for res in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
                all_ips.add(ipaddress.ip_address(res[4][0]))
        except socket.gaierror as exc:
            return False, [], "Résolution DNS refusée: %s" % exc
    if not all_ips:
        return False, [], "Aucune IP résolue"
    for ip in all_ips:
        if _is_forbidden(ip):
            return False, [], "IP interdite: %s" % _canon(ip)
    if scheme != "https":
        return False, [], "Schéma non-TLS refusé (zéro-confiance exige HTTPS)"
    return True, list(all_ips), "OK"

def zero_trust_request(url, method="GET", headers=None, body=None, timeout=TIMEOUT):
    scheme, host, port, path = _parse_url(url)
    allowed, pinned_ips, reason = validate_zero_trust(url)
    if not allowed:
        raise ConnectionRefusedError("BLOCK: %s" % reason)
    last_err, ip_to_pin, raw_sock = None, None, None
    for candidate in pinned_ips:
        try:
            raw_sock = socket.create_connection((str(candidate), port), timeout=timeout)
            ip_to_pin = candidate
            break
        except OSError as exc:
            last_err = exc
    if raw_sock is None:
        raise ConnectionError("Aucune IP validée joignable: %s" % last_err)
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
    hdrs = {
        "Host": host,
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "X-API-Key": API_KEY,
        "Authorization": "Bearer %s" % API_KEY,
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)
    payload = body.encode("utf-8") if body else None
    if payload is not None and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "application/json"
        hdrs["Content-Length"] = str(len(payload))
    conn = http.client.HTTPSConnection(str(ip_to_pin), port, timeout=timeout, context=ctx)
    conn.sock = tls_sock
    conn.request(method.upper(), path, body=payload, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read().decode("utf-8", errors="replace")
    status = resp.status
    conn.close()
    return status, raw

def api_get(path, base_url=BASE_URL):
    status, raw = zero_trust_request(base_url.rstrip("/") + path, "GET")
    if status >= 400:
        raise RuntimeError("HTTP %s: %s" % (status, raw[:400]))
    try:
        return json.loads(raw)
    except ValueError:
        return raw

def api_post(path, payload, base_url=BASE_URL):
    status, raw = zero_trust_request(
        base_url.rstrip("/") + path, "POST",
        body=json.dumps(payload, ensure_ascii=False),
    )
    if status >= 400:
        raise RuntimeError("HTTP %s: %s" % (status, raw[:400]))
    try:
        return json.loads(raw)
    except ValueError:
        return raw

if __name__ == "__main__":
    print("API_KEY  = %s" % API_KEY)
    print("BASE_URL = %s" % BASE_URL)
    print()
    for t in [
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "http://100.64.0.1/",
        "http://::ffff:169.254.169.254/",
        "https://httpbin.org/get",
    ]:
        try:
            allowed, ips, reason = validate_zero_trust(t)
            if not allowed:
                print("BLOCK  %s  <- %s" % (t, reason))
                continue
            status, raw = zero_trust_request(t, "GET")
            print("ALLOW  %s  -> HTTP %s" % (t, status))
        except Exception as exc:
            print("BLOCK  %s  <- %s" % (t, exc))
    print()
    print("--- GET /headers ---")
    try:
        print(json.dumps(api_get("/headers"), indent=2, ensure_ascii=False))
    except Exception as exc:
        print("Démo non exécutée: %s" % exc)
