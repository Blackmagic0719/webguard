from flask import Flask, render_template, request, jsonify
import threading, time, requests
from urllib.parse import urlparse

from scanner.headers     import check_headers
from scanner.xss         import scan_xss
from scanner.sqli        import scan_sqli
from scanner.crawler     import get_links
from scanner.ssl_check   import check_ssl
from scanner.ports       import scan_ports
from scanner.tech_detect import detect_technologies
from scanner.csp         import check_csp
from scanner.osint       import run_osint
from scanner.subdomains  import enumerate_subdomains
from scanner.dirbuster   import bruteforce_dirs
from scanner.db_exposure import check_exposed_databases

app = Flask(__name__)
scan_results = {}
scan_status  = {}

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request — check your input"}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": f"Server error: {str(e)}"}), 500

def _step(sid, pct, msg):
    scan_status[sid]["progress"] = pct
    scan_status[sid]["current"]  = msg

def calculate_risk(results):
    score = 100
    weights = {"headers":5,"xss":20,"sqli":25,"ssl":15,"csp":10,"open_ports":5,"dirs":15,"db_exposure":20}
    findings = 0
    for cat, items in results.items():
        if isinstance(items, list) and items:
            bad = [i for i in items if isinstance(i,dict) and i.get("severity") not in ("ok","info",None)]
            findings += len(bad)
            score -= weights.get(cat,3) * min(len(bad),3)
    return max(0, score), findings

def risk_level(score):
    if score >= 80: return "LOW",      "#00ff9d"
    if score >= 60: return "MEDIUM",   "#f59e0b"
    if score >= 40: return "HIGH",     "#f97316"
    return              "CRITICAL", "#ef4444"

def run_full_scan(scan_id, url):
    scan_status[scan_id] = {"status":"running","progress":0,"current":"Initializing…"}
    results = {}
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
            parsed = urlparse(url)
        host = parsed.hostname
        resp = None

        _step(scan_id, 5,  "Fetching HTTP headers…")
        try:
            resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            results["headers"]       = check_headers(dict(resp.headers))
            results["status_code"]   = resp.status_code
            results["server"]        = resp.headers.get("Server","Unknown")
            results["response_time"] = round(resp.elapsed.total_seconds()*1000, 2)
        except Exception as e:
            results["headers"]       = [{"message":f"Connection failed: {e}","severity":"high"}]
            results["status_code"]   = None
            results["server"]        = "Unknown"
            results["response_time"] = None

        _step(scan_id, 12, "Inspecting SSL/TLS certificate…")
        results["ssl"] = check_ssl(host)

        _step(scan_id, 20, "Testing for XSS vulnerabilities…")
        results["xss"] = scan_xss(url)

        _step(scan_id, 28, "Testing for SQL injection…")
        results["sqli"] = scan_sqli(url)

        _step(scan_id, 35, "Evaluating Content Security Policy…")
        results["csp"] = check_csp(dict(resp.headers) if resp else {})

        _step(scan_id, 40, "Fingerprinting technologies…")
        results["technologies"] = detect_technologies(
            dict(resp.headers) if resp else {}, resp.text if resp else "")

        _step(scan_id, 46, "Crawling site links…")
        results["links"] = get_links(url)

        _step(scan_id, 52, "Scanning common ports…")
        results["open_ports"] = scan_ports(host)

        _step(scan_id, 58, "Running OSINT — DNS, WHOIS, breach data…")
        results["osint"] = run_osint(host)

        _step(scan_id, 67, "Enumerating subdomains…")
        results["subdomains"] = enumerate_subdomains(host)

        _step(scan_id, 78, "Bruteforcing hidden paths & files…")
        results["dirs"] = bruteforce_dirs(url)

        _step(scan_id, 90, "Checking for exposed databases & services…")
        results["db_exposure"] = check_exposed_databases(host)

        score, findings = calculate_risk(results)
        lvl, color = risk_level(score)
        results.update({"risk_score":score,"risk_level":lvl,"risk_color":color,
                         "total_findings":findings,"target":url,
                         "scan_time":time.strftime("%Y-%m-%d %H:%M:%S UTC",time.gmtime())})
        scan_results[scan_id] = results
        scan_status[scan_id]  = {"status":"complete","progress":100,"current":"Scan complete"}
    except Exception as e:
        scan_status[scan_id]  = {"status":"error","progress":0,"current":f"Error: {e}"}
        scan_results[scan_id] = {"error":str(e)}

@app.route("/")
def index(): return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    sid = str(int(time.time()*1000))
    threading.Thread(target=run_full_scan, args=(sid, url), daemon=True).start()
    return jsonify({"scan_id": sid})

@app.route("/status/<sid>")
def status(sid): return jsonify(scan_status.get(sid,{"status":"not_found"}))

@app.route("/results/<sid>")
def results(sid): return jsonify(scan_results.get(sid,{}))

if __name__ == "__main__":
    import urllib3; urllib3.disable_warnings()
    app.run(debug=True, port=5000)

# ── 403 Bypass endpoint ──────────────────────────────────────────────────────
from scanner.bypass403 import run_bypass_scan

bypass_results = {}
bypass_status  = {}

def run_bypass_job(job_id, base_url, paths):
    bypass_status[job_id] = {"status": "running", "progress": 0, "current": "Starting bypass tests…"}
    try:
        total = len(paths)
        results = {}
        for i, path in enumerate(paths):
            bypass_status[job_id]["current"] = f"Testing {path} ({i+1}/{total})…"
            bypass_status[job_id]["progress"] = int((i / total) * 100)
            from scanner.bypass403 import bypass_403
            results[path] = bypass_403(base_url, path)
        bypass_results[job_id] = results
        bypass_status[job_id]  = {"status": "complete", "progress": 100, "current": "Done"}
    except Exception as e:
        bypass_status[job_id]  = {"status": "error", "progress": 0, "current": str(e)}
        bypass_results[job_id] = {}

@app.route("/bypass", methods=["POST"])
def bypass():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    base  = (data.get("base_url") or "").strip()
    paths = data.get("paths", [])
    if not base or not paths:
        return jsonify({"error": "base_url and paths required"}), 400
    job_id = "bp_" + str(int(time.time() * 1000))
    threading.Thread(target=run_bypass_job, args=(job_id, base, paths), daemon=True).start()
    return jsonify({"job_id": job_id})

@app.route("/bypass/status/<job_id>")
def bypass_status_route(job_id):
    return jsonify(bypass_status.get(job_id, {"status": "not_found"}))

@app.route("/bypass/results/<job_id>")
def bypass_results_route(job_id):
    return jsonify(bypass_results.get(job_id, {}))
