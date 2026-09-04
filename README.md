# NetSecurePro IA — Zero Trust Native

[![Zero Dependency](https://img.shields.io/badge/dependencies-0-brightgreen)](#)
[![Python](https://img.shields.io/badge/python-3.8%2B%20stdlib-blue)](#)
[![SSRF](https://img.shields.io/badge/SSRF-blocked-red)](#)

Client et serveur API 100 % Python stdlib. 0 dépendance pip. 0 cloud obligatoire.

Auteur : Mohammed Ilyes Zoubirou — NetSecurePro IA — Montréal, Québec.

## Démo validée

BLOCK http://127.0.0.1/ — IP interdite
BLOCK http://169.254.169.254/ — metadata
BLOCK http://100.64.0.1/ — CGNAT
BLOCK http://::ffff:169.254.169.254/ — IPv4-mapped
ALLOW https://httpbin.org/get — HTTP 200

## Dépôt

Nom : NetSecurePro-IA-ZeroTrust-Native

## Routes serve

GET /status
POST /zh202/decision
POST /score

## Installation

python3 zt_demo_api_client.py selftest

## Serveur local

python3 zt_demo_api_client.py serve

SOVEREIGN_LOCAL=1 API_BASE_URL=http://127.0.0.1:8000 python3 zt_demo_api_client.py get /status

## Accroche Parkinson

fetch("http://127.0.0.1:8000/score", {
  method: "POST",
  headers: {"Content-Type": "application/json", "X-API-Key": "demo-api-key-h3"},
  body: JSON.stringify({source: "ia_parkinson_logic", score: window.dernierScore})
});

© 2026 Mohammed Ilyes Zoubirou — NetSecurePro IA
