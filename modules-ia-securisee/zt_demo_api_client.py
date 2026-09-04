import urllib.request
import urllib.error
import ssl
import json

API_KEY = "démo-api-key_h3"
BASE_URL = "https://httpbin.org"

BLOCKED_IPS = ["127.0.0.1", "169.254.169.254", "100.64.0.1", "::ffff:169.254.169.254"]

def is_blocked(url):
    for ip in BLOCKED_IPS:
        if ip in url: return True
    return False

def secure_get(path):
    url = f"{BASE_URL}{path}"
    if is_blocked(url):
        print(f"BLOCK {url} <- IP interdite")
        return None
    
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {API_KEY}")
    req.add_header("X-Api-Key", API_KEY)
    req.add_header("User-Agent", "ZeroTrustNative-API/1.0")
    
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"ALLOW {url} -> HTTP {resp.status}")
            return resp.read().decode()
    except Exception as e:
        print(f"ERROR: {e}")
        return None

if __name__ == "__main__":
    secure_get("/get")
    secure_get("http://127.0.0.1/")

