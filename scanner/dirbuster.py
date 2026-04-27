import requests, concurrent.futures
import urllib3
urllib3.disable_warnings()

PATHS = [
    "admin","admin/","admin/login","administrator","wp-admin","wp-login.php",
    "phpmyadmin","phpmyadmin/","pma","cpanel","webadmin","manager",
    ".env",".env.local",".env.production",".env.backup",
    "config.php","config.json","config.yml","configuration.php",
    "settings.php","database.php","wp-config.php","wp-config.php.bak",
    ".git/HEAD",".git/config",".gitignore",".htaccess",".htpasswd",
    "web.config","appsettings.json",
    "backup","backup.zip","backup.tar.gz","backup.sql","db.sql",
    "database.sql","dump.sql","site.zip","www.zip",
    "api","api/v1","api/v2","api/health","api/status","api/users",
    "api/admin","api/config","api/docs","swagger","swagger-ui",
    "swagger.json","openapi.json","graphql","graphiql",
    "logs","log","error.log","access.log","debug.log","logs/error.log",
    "debug","phpinfo.php","info.php","server-status","server-info",
    "login","signin","register","signup","dashboard","panel","portal",
    "account","profile","upload","uploads","files","downloads",
    "robots.txt","sitemap.xml","crossdomain.xml",
    "security.txt",".well-known/security.txt",
    "dev","staging","test","beta","old","temp",
    "console","telescope","horizon","actuator","actuator/health",
    "actuator/env","metrics","health","healthz","ping",
]

SENSITIVE = {".env","config","backup",".git","sql","password","admin","secret","key","token"}

def _check(base, path, timeout=4):
    url = f"{base.rstrip('/')}/{path}"
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=False,
                         headers={"User-Agent":"Mozilla/5.0 (Security Scanner)"})
        if r.status_code not in (200,201,301,302,401,403):
            return None
        size  = len(r.content)
        title = None
        if r.status_code == 200 and "<title>" in r.text.lower():
            s = r.text.lower().find("<title>") + 7
            e = r.text.lower().find("</title>", s)
            title = r.text[s:e].strip()[:50] if e > s else None

        sev = "medium"
        if r.status_code == 200:
            sev = "critical" if any(x in path.lower() for x in SENSITIVE) else "high"
        return {"url":url,"path":path,"status":r.status_code,
                "size":size,"title":title,"severity":sev}
    except Exception:
        return None

def bruteforce_dirs(base_url, max_workers=20):
    found = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_check, base_url, p): p for p in PATHS}
            for f in concurrent.futures.as_completed(futs):
                try:
                    r = f.result()
                    if r:
                        found.append(r)
                except Exception:
                    pass
    except Exception:
        pass
    found.sort(key=lambda x: ({"critical":0,"high":1,"medium":2}.get(x["severity"],3), -x.get("size",0)))
    return found
