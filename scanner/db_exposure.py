import socket, requests, concurrent.futures, json
import urllib3
urllib3.disable_warnings()

DB_SERVICES = [
    (3306,"MySQL"),(5432,"PostgreSQL"),(6379,"Redis"),(27017,"MongoDB"),
    (9200,"Elasticsearch"),(5984,"CouchDB"),(8086,"InfluxDB"),(7474,"Neo4j"),
    (11211,"Memcached"),(28017,"MongoDB Web Admin"),(8983,"Apache Solr"),
    (9042,"Cassandra"),(2181,"Zookeeper"),(5672,"RabbitMQ"),
    (15672,"RabbitMQ Mgmt"),(5601,"Kibana"),(3000,"Grafana"),
]

HTTP_PROBES = {
    9200: ("/","elasticsearch"),  5984: ("/","couchdb"),
    7474: ("/","neo4j"),          28017:("/",None),
    8983: ("/solr/admin/info/system?wt=json","solr"),
    15672:("/api/overview","rabbitmq"), 5601:("/api/status","kibana"),
    3000: ("/api/health",None),
}

def _probe(host, port, service, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        res = sock.connect_ex((host, port))
    except Exception:
        res = 1
    finally:
        sock.close()
    if res != 0:
        return None

    auth_required = None
    detail        = f"{service} port {port} is open"
    version       = None

    if port in HTTP_PROBES:
        path, kw = HTTP_PROBES[port]
        try:
            r = requests.get(f"http://{host}:{port}{path}", timeout=timeout, verify=False)
            if r.status_code == 200:
                auth_required = False
                detail = f"Unauthenticated HTTP access confirmed ({r.status_code})"
                if kw and kw in r.text.lower():
                    try:
                        j = r.json()
                        version = (j.get("version",{}).get("number") or
                                   j.get("version") or str(j)[:50])
                    except Exception:
                        pass
            elif r.status_code in (401,403):
                auth_required = True
                detail = f"Auth required (HTTP {r.status_code})"
        except Exception:
            pass

    if port in (6379,6380):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout); s.connect((host,port))
            s.send(b"PING\r\n")
            banner = s.recv(128).decode(errors="ignore"); s.close()
            if "+PONG" in banner:
                auth_required = False
                detail = "Redis responds to PING with no auth — fully exposed"
            elif "NOAUTH" in banner or "ERR" in banner:
                auth_required = True
                detail = "Redis open but requires AUTH"
        except Exception:
            pass

    if port == 3306:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout); s.connect((host,port))
            banner = s.recv(256); s.close()
            if banner:
                version = banner[5:].decode(errors="ignore").strip()[:40]
                detail = f"MySQL banner received — port exposed"
                auth_required = True
        except Exception:
            pass

    sev = "critical" if auth_required is False else "high" if auth_required is None else "medium"
    msg = (f"{service}:{port} EXPOSED — no authentication!"
           if auth_required is False else
           f"{service}:{port} open, auth status unknown" if auth_required is None else
           f"{service}:{port} open, authentication configured")
    return {"port":port,"service":service,"auth_required":auth_required,
            "detail":detail,"version":version,"severity":sev,"message":msg}

def check_exposed_databases(hostname, timeout=2):
    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(_probe, hostname, p, svc, timeout):(p,svc)
                    for p,svc in DB_SERVICES}
            for f in concurrent.futures.as_completed(futs):
                try:
                    r = f.result()
                    if r:
                        results.append(r)
                except Exception:
                    pass
    except Exception:
        pass
    results.sort(key=lambda x: {"critical":0,"high":1,"medium":2}.get(x["severity"],3))
    return results
