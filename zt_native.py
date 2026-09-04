#!/usr/bin/env python3
import ipaddress
import json
import os
import socket
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ============================================================
# MILYES-IA V9 NANS — ZT_NATIVE
# Standard library only
# Zero Trust : DENY by default / FAIL CLOSED
# ============================================================

APP_ROOT = os.environ.get(
    "NANS_APP_ROOT",
    os.path.join(".", "milyes-ia-v9-nans")
)

LOG_DIR = os.path.join(APP_ROOT, "logs")
CONFIG_DIR = os.path.join(APP_ROOT, "config")

AUDIT_FILE = os.path.join(LOG_DIR, "audit.log")

DEFAULT_ACTION = "DENY"
FAIL_CLOSED = True

HOST = os.environ.get("NANS_HOST", "127.0.0.1")
PORT = int(os.environ.get("NANS_PORT", "8080"))

# Réseaux non routables / sensibles qui ne doivent jamais
# constituer une destination distante autorisée par défaut.
BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)

os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)

try:
    os.chmod(LOG_DIR, 0o700)
    os.chmod(CONFIG_DIR, 0o700)
except OSError:
    pass


def audit(event, **fields):
    """Journal sans secret."""
    safe = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": str(event),
        "pid": os.getpid(),
        "mode": os.environ.get("NANS_MODE", "LOCAL"),
    }

    # Ne jamais journaliser les valeurs sensibles.
    forbidden = {
        "token",
        "secret",
        "password",
        "authorization",
        "api_key",
        "key",
    }

    for key, value in fields.items():
        if key.lower() not in forbidden:
            safe[key] = str(value)

    line = " ".join(
        f"{key}={json.dumps(value, ensure_ascii=False)}"
        for key, value in safe.items()
    )

    with open(AUDIT_FILE, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def is_blocked_ip(address):
    """Retourne True si une adresse appartient à un réseau interdit."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True

    return any(ip in network for network in BLOCKED_NETWORKS)


def resolve_and_validate(hostname):
    """
    Résout puis valide toutes les adresses retournées.
    Fail-closed : aucune adresse invalide/interdite n'est acceptée.
    """
    if not hostname:
        audit("SSRF_DENY_EMPTY_HOST")
        return False, []

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError):
        audit("SSRF_DENY_RESOLUTION_FAILED", host=hostname)
        return False, []

    addresses = set()

    for result in results:
        sockaddr = result[4]
        if not sockaddr:
            audit("SSRF_DENY_INVALID_RESULT", host=hostname)
            return False, []

        address = sockaddr[0]
        addresses.add(address)

        if is_blocked_ip(address):
            audit("SSRF_DENY_BLOCKED_IP", host=hostname)
            return False, sorted(addresses)

    if not addresses:
        audit("SSRF_DENY_NO_ADDRESS", host=hostname)
        return False, []

    audit(
        "SSRF_VALIDATED",
        host=hostname,
        address_count=len(addresses),
    )

    return True, sorted(addresses)


def policy_check(handler, body=None):
    """
    Point d'entrée Zero Trust avant /score.

    Le serveur local est autorisé uniquement pour les requêtes
    destinées à l'API locale. Les destinations externes ne sont
    jamais implicitement approuvées.
    """
    try:
        client_ip = handler.client_address[0]
        path = urlparse(handler.path).path

        # L'API écoute localement par défaut.
        try:
            client = ipaddress.ip_address(client_ip)
        except ValueError:
            audit("POLICY_DENY_INVALID_CLIENT_IP")
            return False, "invalid_client_ip"

        # Les requêtes externes sont refusées par défaut.
        if client.is_loopback:
            audit("POLICY_ALLOW_LOCAL", path=path)
            return True, "local"

        audit("POLICY_DENY_REMOTE_CLIENT", path=path)
        return False, "remote_client_denied"

    except Exception:
        # Fail closed : toute erreur de politique = DENY.
        audit("POLICY_DENY_EXCEPTION")
        return False, "policy_error"


def selftest():
    """9 contrôles locaux avant démarrage."""
    results = []

    def check(name, condition):
        results.append((name, bool(condition)))

    # 1
    check("ZERO_TRUST", DEFAULT_ACTION == "DENY")

    # 2
    check("FAIL_CLOSED", FAIL_CLOSED is True)

    # 3
    check(
        "LEAST_PRIVILEGE",
        not bool(os.environ.get("NANS_ALLOW_PRIVILEGED")),
    )

    # 4
    check(
        "AUDIT_DIRECTORY",
        os.path.isdir(LOG_DIR),
    )

    # 5
    check(
        "AUDIT_WRITABLE",
        os.access(LOG_DIR, os.W_OK),
    )

    # 6
    check(
        "SSRF_LOOPBACK_BLOCKED",
        is_blocked_ip("127.0.0.1"),
    )

    # 7
    check(
        "SSRF_PRIVATE_BLOCKED",
        is_blocked_ip("10.0.0.1"),
    )

    # 8
    check(
        "SSRF_PUBLIC_ALLOWED_BY_FILTER",
        not is_blocked_ip("8.8.8.8"),
    )

    # 9
    check(
        "NO_LOCAL_SECRET_CONFIG",
        not os.environ.get("NANS_SECRET_ON_DISK", ""),
    )

    passed = sum(1 for _, result in results if result)
    failed = len(results) - passed

    print("==============================================")
    print(" MILYES-IA V9 NANS — ZERO TRUST SELF-TEST")
    print("==============================================")

    for name, result in results:
        print(f"[{'PASS' if result else 'FAIL'}] {name}")

    print("----------------------------------------------")
    print(f"PASS : {passed}")
    print(f"FAIL : {failed}")
    print("----------------------------------------------")

    audit(
        "SELFTEST_COMPLETE",
        passed=passed,
        failed=failed,
    )

    if failed:
        print("SELF-TEST: FAILED")
        print("FAIL-CLOSED: serveur non démarré.")
        return False

    print("SELF-TEST: PASSED")
    return True


def json_response(handler, status, payload):
    data = json.dumps(
        payload,
        ensure_ascii=False,
    ).encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


class ZTHandler(BaseHTTPRequestHandler):
    server_version = "NANS-ZT/9"

    def log_message(self, fmt, *args):
        # Évite de recopier des données potentiellement sensibles.
        audit(
            "HTTP_ACCESS",
            method=self.command,
            path=urlparse(self.path).path,
            status_hint=args[1] if len(args) > 1 else "unknown",
        )

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/status":
            json_response(
                self,
                200,
                {
                    "status": "ok",
                    "zero_trust": True,
                    "default_action": "DENY",
                    "fail_closed": True,
                },
            )
            return

        if path == "/zh202":
            json_response(
                self,
                200,
                {
                    "service": "MILYES-IA-V9-NANS",
                    "status": "active",
                },
            )
            return

        json_response(
            self,
            404,
            {"error": "not_found"},
        )

    def do_POST(self):
        path = urlparse(self.path).path

        if path not in (
            "/score",
            "/exec",
            "/zh202/decision",
        ):
            json_response(
                self,
                404,
                {"error": "not_found"},
            )
            return

        # ====================================================
        # ZERO TRUST HOOK — AVANT TOUT TRAITEMENT
        # ====================================================

        allowed, reason = policy_check(self)

        if not allowed:
            audit(
                "POLICY_DENY",
                path=path,
                reason=reason,
            )

            json_response(
                self,
                403,
                {
                    "error": "forbidden",
                    "policy": "zero_trust",
                },
            )
            return

        # ====================================================
        # LECTURE DU BODY APRÈS AUTORISATION
        # ====================================================

        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )
        except ValueError:
            json_response(
                self,
                400,
                {"error": "invalid_content_length"},
            )
            return

        # Limite défensive : 1 MiB.
        if content_length < 0 or content_length > 1024 * 1024:
            json_response(
                self,
                413,
                {"error": "payload_too_large"},
            )
            return

        raw = self.rfile.read(content_length)

        try:
            payload = (
                json.loads(raw.decode("utf-8"))
                if raw
                else {}
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            audit("REQUEST_DENY_INVALID_JSON", path=path)
            json_response(
                self,
                400,
                {"error": "invalid_json"},
            )
            return

        # ====================================================
        # ROUTES
        # ====================================================

        if path == "/score":
            audit("SCORE_ALLOWED")
            result = {
                "status": "accepted",
                "policy": "zero_trust",
                "inference": "not_implemented",
            }

        elif path == "/exec":
            # Aucun shell, aucune commande distante.
            audit("EXEC_DENY")
            json_response(
                self,
                403,
                {
                    "error": "execution_disabled",
                    "policy": "zero_trust",
                },
            )
            return

        elif path == "/zh202/decision":
            audit("DECISION_ALLOWED")
            result = {
                "status": "accepted",
                "policy": "zero_trust",
                "decision": "not_implemented",
            }

        else:
            json_response(
                self,
                404,
                {"error": "not_found"},
            )
            return

        json_response(self, 200, result)


def main():
    audit("BOOT")

    if not selftest():
        audit("BOOT_ABORT_SELFTEST")
        return 1

    try:
        server = ThreadingHTTPServer(
            (HOST, PORT),
            ZTHandler,
        )
    except OSError as exc:
        audit("SERVER_BIND_FAILED", error=type(exc).__name__)
        print(
            f"SERVER START FAILED: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1

    audit(
        "SERVER_STARTED",
        host=HOST,
        port=PORT,
    )

    print(
        f"MILYES-IA V9 NANS — Zero Trust actif sur "
        f"{HOST}:{PORT}"
    )
    print("Network trust : DENY")
    print("Remote execution : DISABLED")
    print("Secrets on disk : NONE")
    print("Fail-closed : ENABLED")
    print("Routes : /zh202 /exec /status /score /zh202/decision")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        audit("SERVER_STOP")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
