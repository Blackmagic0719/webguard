def check_headers(headers):
    issues = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    security_headers = {
        "content-security-policy": "Missing Content-Security-Policy header — allows XSS attacks",
        "x-frame-options": "Missing X-Frame-Options — vulnerable to clickjacking",
        "strict-transport-security": "Missing HSTS — downgrade attacks possible",
        "x-content-type-options": "Missing X-Content-Type-Options — MIME sniffing risk",
        "referrer-policy": "Missing Referrer-Policy — data leakage risk",
        "permissions-policy": "Missing Permissions-Policy — browser features uncontrolled",
        "x-xss-protection": "Missing X-XSS-Protection header",
    }

    for header, message in security_headers.items():
        if header not in headers_lower:
            issues.append({"type": "missing", "header": header.title(), "message": message, "severity": "medium"})

    # Check for dangerous headers exposing info
    if "x-powered-by" in headers_lower:
        issues.append({
            "type": "info_leak",
            "header": "X-Powered-By",
            "message": f"Server technology exposed: {headers_lower['x-powered-by']}",
            "severity": "low"
        })

    if "server" in headers_lower:
        server = headers_lower["server"]
        if any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "php/"]):
            issues.append({
                "type": "info_leak",
                "header": "Server",
                "message": f"Detailed server version exposed: {server}",
                "severity": "low"
            })

    return issues
