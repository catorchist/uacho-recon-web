#!/usr/bin/env python3
"""
form_analyzer.py — UACHO LAB v2
Analizador de formularios HTML
Uso: python3 form_analyzer.py <URL> [--save]
Sin dependencias externas.
"""

import sys
import argparse
import ssl
import urllib.request
from datetime import datetime
from html.parser import HTMLParser

# ──────────────────────────────────────────────

CSRF_HINTS = [
    "__requestverificationtoken",
    "csrf", "_token", "authenticity_token",
    "csrftoken", "_csrf", "xsrf", "form_token",
    "nonce", "_wpnonce", "woocommerce-login-nonce",
    "woocommerce-register-nonce",
]

SENSITIVE_NAMES = [
    "password", "passwd", "pass", "pwd",
    "credit_card", "cc_number", "cvv", "cvc",
    "ssn", "dni", "cuit", "pin",
]

BOTCHECK_HINTS = [
    "botcheck", "honeypot", "bot_check", "form_botcheck", "hp_",
]

SKIP_MAXLENGTH = {
    "hidden", "submit", "button", "checkbox",
    "radio", "file", "image", "reset", "color",
    "date", "datetime-local", "month", "week",
    "time", "range", "number",
}

# ──────────────────────────────────────────────

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)

        if tag == "form":
            self._current = {
                "action":  a.get("action", "(sin action)"),
                "method":  a.get("method", "GET").upper(),
                "enctype": a.get("enctype", "application/x-www-form-urlencoded"),
                "id":      a.get("id", ""),
                "name":    a.get("name", ""),
                "fields":  [],
            }

        elif self._current is not None and tag in ("input", "select", "textarea", "button"):
            ftype = a.get("type", "text") if tag == "input" else tag
            if tag == "button":
                ftype = a.get("type", "submit")

            field = {
                "tag":          tag,
                "type":         ftype,
                "name":         a.get("name", ""),
                "id":           a.get("id", ""),
                "value":        a.get("value", ""),
                "placeholder":  a.get("placeholder", ""),
                "required":     "required" in a,
                "autocomplete": a.get("autocomplete", ""),
                "maxlength":    a.get("maxlength", None),
            }
            self._current["fields"].append(field)

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def fetch_html(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 (UACHO-LAB form_analyzer/2.0)")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="replace"), resp.url
    except Exception as e:
        print(f"[ERROR] No se pudo conectar: {e}")
        sys.exit(1)


def sep(char="=", w=55):
    return char * w


def analyze_form(form, idx, target_url):
    lines = []

    def p(s=""):
        lines.append(s)
        print(s)

    form_label = form.get("id") or form.get("name") or str(idx + 1)
    p(f"[FORM #{form_label}]")
    p(f"TARGET: {target_url}")
    p(f"METODO: {form['method']}")

    input_fields = [f for f in form["fields"] if f["tag"] != "button"]
    for f in input_fields:
        ftype = f["type"].lower()
        fname = f["name"] or "(sin nombre)"
        fval  = f"  value='{f['value']}'" if f["value"] and ftype == "hidden" else ""
        p(f"[{ftype:<8}] {fname}{fval}")

        if ftype not in SKIP_MAXLENGTH and f["maxlength"] is None:
            p(f"RIESGO: Sin maxlength.")

        if ftype == "password":
            ac = f["autocomplete"].lower()
            if ac not in ("off", "new-password", "current-password"):
                p(f"RIESGO: Campo password sin autocomplete=off.")

        if form["method"] == "GET":
            if any(s in fname.lower() for s in SENSITIVE_NAMES):
                p(f"RIESGO ALTO: Campo sensible '{fname}' enviado por GET.")

    if form["action"].startswith("http://"):
        p(f"RIESGO ALTO: Form action usa HTTP: {form['action']}")

    csrf_fields = [
        f for f in form["fields"]
        if any(hint in f["name"].lower() for hint in CSRF_HINTS)
    ]
    csrf_count = len(csrf_fields)

    if csrf_count == 0:
        p("RIESGO ALTO: Sin CSRF tokens.")

    p(f"\nCSRF tokens: {csrf_count}")

    for cf in csrf_fields:
        p(f"  -> '{cf['name']}' (type={cf['type']})")

    for f in form["fields"]:
        if any(hint in f["name"].lower() for hint in BOTCHECK_HINTS):
            p(f"INFO: Campo honeypot/botcheck detectado: '{f['name']}'")

    hidden = [f for f in form["fields"] if f["type"] == "hidden"
              and not any(hint in f["name"].lower() for hint in CSRF_HINTS)]
    if hidden:
        p(f"INFO: {len(hidden)} campo(s) hidden no-CSRF: "
          + ", ".join(f["name"] for f in hidden))

    p(sep())
    return lines


def analyze(url):
    lines = []

    def p(s=""):
        lines.append(s)
        print(s)

    p(sep())
    p(f" UACHO LAB — Form Analyzer v2")
    p(f" Fecha  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p(f" Target : {url}")
    p(sep())
    p()

    html, final_url = fetch_html(url)

    if final_url != url:
        p(f" Redirect -> {final_url}")
        p()

    parser = FormParser()
    parser.feed(html)

    if not parser.forms:
        p(" No se encontraron formularios.")
        p(sep())
        return lines

    p(f" Formularios encontrados: {len(parser.forms)}")
    p()

    for idx, form in enumerate(parser.forms):
        form_lines = analyze_form(form, idx, final_url)
        lines.extend(form_lines)
        lines.append("")

    p(f" Total: {len(parser.forms)} formulario(s).")
    p(sep())

    return lines


def save_output(lines, url):
    safe = url.replace("https://", "").replace("http://", "") \
               .replace("/", "_").replace(".", "-")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"forms_{safe}_{ts}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[*] Guardado en: {filename}")
    return filename


def main():
    parser = argparse.ArgumentParser(
        description="UACHO LAB — Form Analyzer v2",
        epilog="Ejemplo: python3 form_analyzer.py https://profint.com.ar/ingresar --save"
    )
    parser.add_argument("url", help="URL target")
    parser.add_argument("--save", action="store_true", help="Guardar output en txt")
    args = parser.parse_args()

    url = args.url
    if not url.startswith("http"):
        url = "https://" + url

    result = analyze(url)

    if args.save:
        save_output(result, url)


if __name__ == "__main__":
    main()
