import socket, json, subprocess, requests

def _dig(rtype, hostname, timeout=5):
    try:
        out = subprocess.check_output(
            ["dig","+short", rtype, hostname],
            timeout=timeout, stderr=subprocess.DEVNULL).decode().strip()
        return [l.strip() for l in out.splitlines() if l.strip()]
    except Exception:
        return []

def run_osint(hostname):
    results = {}

    # DNS
    dns = {}
    for rt in ("A","MX","NS","TXT","AAAA","CNAME"):
        recs = _dig(rt, hostname)
        if recs:
            dns[rt] = recs
    results["dns"] = dns

    # IP geo
    try:
        ip = socket.gethostbyname(hostname)
        geo = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query",
            timeout=6).json()
        results["ip_info"] = {
            "ip": ip,
            "country":  geo.get("country",""),
            "region":   geo.get("regionName",""),
            "city":     geo.get("city",""),
            "isp":      geo.get("isp",""),
            "org":      geo.get("org",""),
            "asn":      geo.get("as",""),
        }
    except Exception as e:
        results["ip_info"] = {"ip": "Unresolvable", "error": str(e)[:60]}

    # WHOIS
    try:
        raw = subprocess.check_output(
            ["whois", hostname], timeout=10,
            stderr=subprocess.DEVNULL).decode(errors="ignore")
        want = ["Registrar","Registrant Organization","Creation Date",
                "Expiry Date","Updated Date","Name Server","DNSSEC"]
        fields = {}
        for line in raw.splitlines():
            for w in want:
                if line.strip().startswith(w+":"):
                    key = w
                    val = line.split(":",1)[-1].strip()
                    if key not in fields and val:
                        fields[key] = val
        results["whois"] = fields or {"note": "No WHOIS data returned"}
    except Exception as e:
        results["whois"] = {"error": str(e)[:60]}

    # HaveIBeenPwned domain breach lookup (public list, no key)
    try:
        resp = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={"User-Agent": "WebGuard-SecurityScanner"},
            timeout=8)
        if resp.status_code == 200:
            root = hostname.split(".")[-2] if "." in hostname else hostname
            hits = [b for b in resp.json()
                    if root.lower() in b.get("Domain","").lower()
                    or root.lower() in b.get("Name","").lower()]
            results["breaches"] = [{
                "name":        b.get("Name"),
                "domain":      b.get("Domain"),
                "breach_date": b.get("BreachDate"),
                "pwn_count":   b.get("PwnCount"),
                "data_classes":b.get("DataClasses",[])[:5],
                "is_verified": b.get("IsVerified"),
            } for b in hits[:10]]
        else:
            results["breaches"] = []
    except Exception:
        results["breaches"] = []

    # SPF / DMARC
    email_sec = []
    spf_recs  = _dig("TXT", hostname)
    spf_found = [r for r in spf_recs if "v=spf1" in r]
    if spf_found:
        email_sec.append({"check":"SPF","status":"present","value":spf_found[0][:80]})
    else:
        email_sec.append({"check":"SPF","status":"missing",
                          "message":"No SPF record — email spoofing possible","severity":"high"})

    dmarc_recs = _dig("TXT", f"_dmarc.{hostname}")
    dmarc_found = [r for r in dmarc_recs if "v=DMARC1" in r]
    if dmarc_found:
        email_sec.append({"check":"DMARC","status":"present","value":dmarc_found[0][:80]})
    else:
        email_sec.append({"check":"DMARC","status":"missing",
                          "message":"No DMARC record — phishing protection absent","severity":"medium"})

    results["email_security"] = email_sec
    return results
