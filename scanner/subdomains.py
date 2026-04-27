import socket
import concurrent.futures
import requests
import urllib3
urllib3.disable_warnings()

COMMON_SUBDOMAINS = [
    "www","mail","ftp","remote","blog","webmail","server","ns1","ns2",
    "smtp","secure","vpn","m","shop","api","dev","staging","test",
    "portal","admin","mx","email","cloud","cdn","media","app","beta",
    "static","assets","img","images","video","docs","help","support",
    "status","monitor","dashboard","login","auth","sso","git","gitlab",
    "jenkins","jira","confluence","wiki","forum","community","news",
    "store","payment","billing","account","accounts","my","id","search",
    "analytics","data","db","database","mysql","postgres","redis","mongo",
    "elastic","kibana","grafana","prometheus","backup","old","new","v1",
    "v2","internal","intranet","corp","office","files","download","upload",
    "s3","storage","cdn2","assets2",
]

def _check(sub, domain, timeout=3):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
    except (socket.gaierror, OSError):
        return None
    status = None
    title  = None
    for scheme in ("https","http"):
        try:
            r = requests.get(f"{scheme}://{fqdn}", timeout=timeout,
                             verify=False, allow_redirects=True)
            status = r.status_code
            txt = r.text
            if "<title>" in txt.lower():
                s = txt.lower().find("<title>") + 7
                e = txt.lower().find("</title>", s)
                title = txt[s:e].strip()[:60] if e > s else None
            break
        except Exception:
            pass
    return {"subdomain": fqdn, "ip": ip, "status": status,
            "title": title, "alive": True}

def enumerate_subdomains(domain, max_workers=30):
    found = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_check, sub, domain): sub for sub in COMMON_SUBDOMAINS}
            for f in concurrent.futures.as_completed(futs):
                try:
                    r = f.result()
                    if r:
                        found.append(r)
                except Exception:
                    pass
    except Exception:
        pass
    found.sort(key=lambda x: (x.get("status") != 200, x["subdomain"]))
    return found
