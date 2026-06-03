#!/usr/bin/env python3
"""
sec_headers.py — UACHO LAB
Analizador de Security Headers
Uso: python3 sec_headers.py <URL> [--tor]
"""

import sys
import urllib.request
import urllib.error
import socket
import ssl
import argparse
from datetime import datetime

# ──────────────────────────────────────────────
SECURITY_HEADERS = [
    {
        "header": "Strict-Transport-Security",
        "label": "HSTS",
        "severity": "CRITICO",
        "desc": "Sin HSTS el browser puede conectar por HTTP. Vectores: SSL strip, MITM."
    },
    {
        "header": "Content-Security-Policy",
        "label": "CSP",
        "severity": "CRITICO",
        "desc": "Sin CSP el XSS puede cargar scripts externos sin restriccion."
    },
    {
        "header": "X-Frame-Options",
        "label": "X-Frame-Options",
        "severity": "ADVERTENCIA",
        "desc": "Sin este header la pagina es embebible en iframes. Vector: Clickjacking."
    },
    {
        "header": "X-Content-Type-Options",
        "label": "X-Content-Type-Options",
        "severity": "ADVERTENCIA",
        "desc": "Sin este header el browser puede interpretar tipos MIME incorrectos."
    },
    {
        "header": "X-XSS-Protection",
        "label": "X-XSS-Protection",
        "severity": "ADVERTENCIA",
        "desc": "Header legacy pero indicador de configuracion de seguridad basica."
    },
    {
        "header": "Referrer-Policy",
        "label": "Referrer-Policy",
        "severity": "INFO",
        "desc": "Sin este header se filtra la URL completa en el Referer a terceros."
    },
    {
        "header": "Permissions-Policy",
        "label": "Permissions-Policy",
        "severity": "INFO",
        "desc": "Sin este header el sitio puede acceder a camara, mic, geolocalizacion."
    },
]

LEAK_HEADERS = [
    "X-Powered-By",
    "Server",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
]

SEVERITY_ORDER = {"CRITICO": 0, "ADVERTENCIA": 1, "INFO": 2}
SEVERITY_LABEL = {
    "CRITICO":    "[CRITICO]   ",
    "ADVERTENCIA": "[ADVERTENCIA]",
    "INFO":       "[INFO]      ",
    "OK":         "[OK]        ",
    "EXPUESTO":   "[EXPUESTO]  ",
}

# ──────────────────────────────────────────────

def separator(char="=", width=60):
    return char * width

def fetch_headers(url, use_tor=False):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if use_tor:
        # Tor proxy via socket — urllib no soporta SOCKS nativo,
        # necesita requests+socks o proxychains externo
        print("[!] Para Tor usa: proxychains python3 sec_headers.py <URL>")
        print("    (urllib no soporta SOCKS5 nativo sin dependencias)\n")

    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "Mozilla/5.0 (UACHO-LAB sec_headers/1.0)")

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return dict(resp.headers), resp.status, resp.url
    except urllib.error.HTTPError as e:
        # HEAD puede estar bloqueado, intentamos GET
        req2 = urllib.request.Request(url, method="GET")
        req2.add_header("User-Agent", "Mozilla/5.0 (UACHO-LAB sec_headers/1.0)")
        with urllib.request.urlopen(req2, context=ctx, timeout=10) as resp:
            return dict(resp.headers), resp.status, resp.url
    except Exception as e:
        print(f"[ERROR] No se pudo conectar: {e}")
        sys.exit(1)

def analyze(url, use_tor=False):
    lines = []

    def p(s=""):
        lines.append(s)
        print(s)

    p(separator())
    p(f" UACHO LAB — Security Headers Analyzer")
    p(f" Fecha   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p(f" Target  : {url}")
    p(separator())

    headers, status, final_url = fetch_headers(url, use_tor)

    if final_url != url:
        p(f" Redirect: {final_url}")

    p(f" HTTP Status: {status}")
    p()

    # ── Security Headers ──
    p("[SEC HDR]")
    p(separator("-", 60))

    missing = []
    present = []

    for h in SECURITY_HEADERS:
        # Case-insensitive search
        found = next((v for k, v in headers.items() if k.lower() == h["header"].lower()), None)
        if found:
            present.append((h, found))
        else:
            missing.append(h)

    # Primero los faltantes ordenados por severidad
    missing.sort(key=lambda x: SEVERITY_ORDER[x["severity"]])
    for h in missing:
        p(f" {SEVERITY_LABEL[h['severity']]} Falta {h['label']}")
        p(f"   -> {h['desc']}")

    p()

    # Los presentes
    if present:
        p(" Headers de seguridad presentes:")
        for h, val in present:
            p(f" {SEVERITY_LABEL['OK']} {h['label']}: {val}")

    p()

    # ── Info Leaks ──
    p("[INFO LEAK]")
    p(separator("-", 60))

    leaks_found = []
    for lh in LEAK_HEADERS:
        val = next((v for k, v in headers.items() if k.lower() == lh.lower()), None)
        if val:
            leaks_found.append((lh, val))

    if leaks_found:
        for name, val in leaks_found:
            p(f" {SEVERITY_LABEL['EXPUESTO']} {name}: {val}")
    else:
        p(f" {SEVERITY_LABEL['OK']} Sin headers de informacion expuestos.")

    p()

    # ── Todos los headers recibidos ──
    p("[TODOS LOS HEADERS]")
    p(separator("-", 60))
    for k, v in sorted(headers.items()):
        p(f" {k}: {v}")

    p()
    p(separator())
    p(f" Analisis completo. {len(missing)} headers de seguridad faltantes.")
    p(separator())

    return lines

def save_output(lines, url):
    # Nombre de archivo desde la URL
    safe = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "-")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sec_headers_{safe}_{ts}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[*] Output guardado en: {filename}")

# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="UACHO LAB — Security Headers Analyzer",
        epilog="Ejemplo: python3 sec_headers.py https://profint.com.ar --save"
    )
    parser.add_argument("url", help="URL target (con https://)")
    parser.add_argument("--tor", action="store_true", help="Usar Tor (via proxychains)")
    parser.add_argument("--save", action="store_true", help="Guardar output en txt")

    args = parser.parse_args()

    url = args.url
    if not url.startswith("http"):
        url = "https://" + url

    lines = analyze(url, args.tor)

    if args.save:
        save_output(lines, url)

if __name__ == "__main__":
    main()
