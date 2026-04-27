def check_csp(headers):
    issues = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    csp = headers_lower.get("content-security-policy", "")

    if not csp:
        return [{"message": "No Content-Security-Policy header found", "severity": "high"}]

    # Check for unsafe directives
    dangerous = {
        "unsafe-inline": "CSP allows 'unsafe-inline' — inline scripts/styles can execute",
        "unsafe-eval": "CSP allows 'unsafe-eval' — dynamic code execution permitted",
        "unsafe-hashes": "CSP allows 'unsafe-hashes' — weakens CSP protection",
    }

    for directive, message in dangerous.items():
        if directive in csp:
            issues.append({"directive": directive, "message": message, "severity": "medium"})

    # Check wildcard sources
    if "* " in csp or csp.endswith("*"):
        issues.append({"message": "CSP uses wildcard (*) source — overly permissive", "severity": "medium"})

    # Check for missing important directives
    important = ["default-src", "script-src", "object-src"]
    for d in important:
        if d not in csp:
            issues.append({"message": f"Missing '{d}' directive in CSP", "severity": "low"})

    if not issues:
        issues.append({"message": "CSP appears well configured", "severity": "ok"})

    return issues
