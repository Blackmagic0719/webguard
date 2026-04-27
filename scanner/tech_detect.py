def detect_technologies(headers, html=""):
    techs = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Server tech from headers
    if "x-powered-by" in headers_lower:
        techs.append({"name": headers_lower["x-powered-by"], "category": "Backend"})
    if "server" in headers_lower:
        techs.append({"name": headers_lower["server"], "category": "Server"})

    # CMS / Framework detection from HTML
    html_lower = html.lower() if html else ""
    signatures = {
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Drupal": ["drupal", "sites/all", "sites/default"],
        "Joomla": ["joomla", "/components/com_"],
        "Laravel": ["laravel_session", "laravel"],
        "Django": ["csrfmiddlewaretoken", "__django"],
        "React": ["react-dom", "data-reactroot", "_next/static"],
        "Vue.js": ["vue.js", "__vue__", "v-if="],
        "Angular": ["ng-version", "angular"],
        "jQuery": ["jquery.min.js", "jquery-"],
        "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
        "Cloudflare": ["cloudflare", "__cf_bm"],
        "Google Analytics": ["google-analytics.com", "gtag("],
    }

    for tech, sigs in signatures.items():
        for sig in sigs:
            if sig in html_lower:
                techs.append({"name": tech, "category": "Framework/CMS"})
                break

    # Cookies
    if "set-cookie" in headers_lower:
        cookie = headers_lower["set-cookie"].lower()
        if "phpsessid" in cookie:
            techs.append({"name": "PHP", "category": "Backend"})
        if "jsessionid" in cookie:
            techs.append({"name": "Java/JSP", "category": "Backend"})
        if "asp.net" in cookie:
            techs.append({"name": "ASP.NET", "category": "Backend"})

    # Deduplicate
    seen = set()
    unique = []
    for t in techs:
        if t["name"] not in seen:
            seen.add(t["name"])
            unique.append(t)

    return unique
