#!/usr/bin/env python3
"""
Simple Vulnerability Scanner — Educational Tool
Made by Karanam Shrivasta
LinkedIn: linkedin.com/in/karanam-shrivasta
GitHub  : github.com/mrshrivasta

HOW TO RUN:
  pip install flask packaging
  python vuln_scanner.py            → http://localhost:5000
  python vuln_scanner.py --scan requirements.txt
  python vuln_scanner.py --installed
  python vuln_scanner.py --pkg requests 2.18.0

DATA SOURCES (free, no API keys):
  OSV.dev · PyPI JSON API · npm Registry · NVD CVE

⚠ Educational use only. Own systems only.
"""

import sys, os, re, json, csv, io, time, socket, threading, platform, subprocess
import urllib.request, urllib.parse, urllib.error
from datetime import datetime
from pathlib import Path

try:
    from packaging.version import Version
except ImportError:
    pass

try:
    from flask import Flask, jsonify, request, Response
except ImportError:
    print("pip install flask packaging"); sys.exit(1)

app = Flask(__name__)

# ── HTTP helper ───────────────────────────────────────────
UA = "vuln-scanner-edu/2.0 (github.com/mrshrivasta)"

def http_get(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def http_post(url, body, timeout=20):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
          headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

# ── parsers ───────────────────────────────────────────────
def parse_requirements(content):
    pkgs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = re.sub(r"\[.*?\]", "", line).split(";")[0].strip()
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*==\s*([^\s,]+)", line)
        if m:
            pkgs.append({"name": m.group(1).lower(), "version": m.group(2).strip(), "raw": line})
        else:
            m2 = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
            if m2:
                pkgs.append({"name": m2.group(1).lower(), "version": "", "raw": line})
    return pkgs

def parse_package_json(content):
    data = json.loads(content)
    pkgs = []
    for sec in ["dependencies", "devDependencies", "peerDependencies"]:
        for name, ver in data.get(sec, {}).items():
            ver_clean = re.sub(r"[^\d\.]", "", ver).strip(".")
            pkgs.append({"name": name, "version": ver_clean or ver, "raw": f"{name}@{ver}"})
    return pkgs

def parse_gemfile_lock(content):
    pkgs = []
    for line in content.splitlines():
        m = re.match(r"^\s{4}([a-z][a-z0-9_\-]+)\s+\(([\d\.]+)\)", line)
        if m:
            pkgs.append({"name": m.group(1), "version": m.group(2), "raw": line.strip()})
    return pkgs

def get_pip_installed():
    try:
        out = subprocess.check_output([sys.executable, "-m", "pip", "list", "--format=json"],
                                      stderr=subprocess.DEVNULL, timeout=15)
        return [{"name": p["name"].lower(), "version": p["version"], "raw": f"{p['name']}=={p['version']}"}
                for p in json.loads(out.decode())]
    except Exception:
        return []

# ── OSV.dev API ───────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

def osv_query_batch(packages, ecosystem):
    queries = [{"package": {"name": p["name"], "ecosystem": ecosystem},
                **({"version": p["version"]} if p.get("version") else {})}
               for p in packages]
    try:
        resp = http_post("https://api.osv.dev/v1/querybatch", {"queries": queries}, timeout=30)
        return {p["name"]: r.get("vulns", []) for p, r in zip(packages, resp.get("results", []))}
    except Exception as e:
        return {"_error": str(e)}

def osv_query_single(name, version, ecosystem):
    body = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    try:
        return http_post("https://api.osv.dev/v1/query", body, timeout=12).get("vulns", [])
    except Exception:
        return []

def severity_from_osv(vuln):
    # ── 1. CVSS numeric score (BEST SOURCE) ──
    for sev in vuln.get("severity", []):
        score = sev.get("score")

        try:
            score = float(score)
            if score >= 9.0:
                return "CRITICAL", score
            elif score >= 7.0:
                return "HIGH", score
            elif score >= 4.0:
                return "MEDIUM", score
            elif score > 0:
                return "LOW", score
        except:
            pass

    # ── 2. database_specific severity (OSV sometimes uses this) ──
    db_sev = vuln.get("database_specific", {}).get("severity")
    if db_sev:
        db_sev = db_sev.upper()
        if db_sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            return db_sev, None

    # ── 3. CVSS vector fallback (weak parsing) ──
    text = (vuln.get("summary", "") + " " + vuln.get("details", "")).lower()

    if "critical" in text:
        return "CRITICAL", None
    if "high" in text:
        return "HIGH", None
    if "medium" in text:
        return "MEDIUM", None
    if "low" in text:
        return "LOW", None

    return "UNKNOWN", None

def format_vuln(vuln, pkg_name, pkg_version):
    sev, score = severity_from_osv(vuln)
    fixed = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() == pkg_name.lower():
            for rng in affected.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed.append(ev["fixed"])
    cve_ids = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
    return {
        "id":          vuln.get("id", ""),
        "cve_ids":     cve_ids,
        "summary":     vuln.get("summary", "")[:200],
        "details":     vuln.get("details", "")[:400],
        "severity":    sev,
        "score":       score,
        "fixed_in":    fixed[:3],
        "published":   vuln.get("published", "")[:10],
        "modified":    vuln.get("modified", "")[:10],
        "references":  [r.get("url", "") for r in vuln.get("references", [])[:3]],
        "pkg_name":    pkg_name,
        "pkg_version": pkg_version,
    }

def calculate_risk_score(packages):
    """
    Returns a 0–10 security score (10 = safe, 0 = dangerous)
    """

    risk = 0
    total_vulns = 0

    for p in packages:
        for v in p.get("vulns", []):
            total_vulns += 1
            sev = v.get("severity", "UNKNOWN")

            if sev == "CRITICAL":
                risk += 5
            elif sev == "HIGH":
                risk += 3
            elif sev == "MEDIUM":
                risk += 2
            elif sev == "LOW":
                risk += 1
            else:
                risk += 0.5

    if len(packages) == 0:
        return 10.0

    # normalize risk
    score = 10 - (risk / max(len(packages), 1))
    return round(max(0, min(10, score)), 2)
    total = len(packages)
    osv_data = osv_query_batch(packages, ecosystem)
    if "_error" in osv_data:
        # fallback: one by one
        osv_data = {}
        for p in packages:
            osv_data[p["name"]] = osv_query_single(p["name"], p.get("version", ""), ecosystem)
            time.sleep(0.05)

    results = []
    all_vulns = []
    for p in packages:
        raw_vulns = osv_data.get(p["name"], [])
        fmt_vulns = sorted(
            [format_vuln(v, p["name"], p.get("version", "")) for v in raw_vulns],
            key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True
        )
        highest = fmt_vulns[0]["severity"] if fmt_vulns else "OK"
        results.append({"name": p["name"], "version": p.get("version", ""),
                         "raw": p.get("raw", ""), "vuln_count": len(fmt_vulns),
                         "highest": highest, "vulns": fmt_vulns, "ecosystem": ecosystem})
        all_vulns.extend(fmt_vulns)

    sc = {s: 0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]}
    for v in all_vulns:
        sc[v["severity"]] = sc.get(v["severity"], 0) + 1
    vuln_pkgs = [r for r in results if r["vuln_count"] > 0]
    return {"scanned_at": datetime.now().isoformat(), "ecosystem": ecosystem,
            "total_packages": total, "vulnerable": len(vuln_pkgs),
            "safe": total - len(vuln_pkgs), "total_vulns": len(all_vulns),
            "severity_counts": sc, "packages": results, "errors": []}

def pypi_info(name):
    try:
        d = http_get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json", timeout=8)
        info = d.get("info", {})
        return {"name": info.get("name", name), "latest": info.get("version", ""),
                "summary": info.get("summary", "")[:120], "license": info.get("license", ""),
                "home_page": info.get("home_page", "") or info.get("project_url", "")}
    except Exception:
        return {}

def npm_info(name):
    try:
        d = http_get(f"https://registry.npmjs.org/{urllib.parse.quote(name)}", timeout=8)
        latest = d.get("dist-tags", {}).get("latest", "")
        return {"name": d.get("name", name), "latest": latest,
                "summary": d.get("description", "")[:120],
                "license": d.get("license", ""), "home_page": d.get("homepage", "")}
    except Exception:
        return {}

def scan_port(host, port, timeout=0.8):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

COMMON_PORTS = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
                110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",
                3389:"RDP",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",
                8443:"HTTPS-Alt",27017:"MongoDB"}

def detect_eco(filename):
    fn = Path(filename).name.lower()
    if "package.json" in fn: return "npm"
    if "gemfile" in fn: return "RubyGems"
    return "PyPI"

# ── Flask routes ──────────────────────────────────────────
@app.route("/")
def index(): return HTML

@app.route("/api/scan/text", methods=["POST"])
def api_scan_text():
    d = request.get_json(force=True)
    content  = d.get("content", "").strip()
    filename = d.get("filename", "requirements.txt")
    if not content:
        return jsonify({"error": "No content provided"})
    eco = detect_eco(filename)
    try:
        fn = filename.lower()
        if "package.json" in fn:  pkgs = parse_package_json(content)
        elif "gemfile" in fn:     pkgs = parse_gemfile_lock(content)
        else:                     pkgs = parse_requirements(content)
    except Exception as e:
        return jsonify({"error": f"Parse error: {e}"})
    if not pkgs:
        return jsonify({"error": "No packages found in input"})
    return jsonify(scan_packages(pkgs[:150], eco))

@app.route("/api/scan/installed", methods=["POST"])
def api_scan_installed():
    pkgs = get_pip_installed()
    if not pkgs:
        return jsonify({"error": "Could not read installed packages"})
    return jsonify(scan_packages(pkgs[:200], "PyPI"))

@app.route("/api/scan/package", methods=["POST"])
def api_scan_single():
    d   = request.get_json(force=True)
    name    = d.get("name", "").strip()
    version = d.get("version", "").strip()
    eco     = d.get("ecosystem", "PyPI")
    if not name:
        return jsonify({"error": "Package name required"})
    raw   = osv_query_single(name, version, eco)
    vulns = sorted([format_vuln(v, name, version) for v in raw],
                   key=lambda x: SEVERITY_ORDER.get(x["severity"],0), reverse=True)
    info  = pypi_info(name) if eco == "PyPI" else npm_info(name)
    return jsonify({"package": name, "version": version,
                    "info": info, "vulns": vulns, "vuln_count": len(vulns)})

@app.route("/api/portscan", methods=["POST"])
def api_portscan():
    import concurrent.futures
    d    = request.get_json(force=True)
    host = d.get("host", "localhost")
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return jsonify({"error": "Cannot resolve host"})
    private = (ip.startswith("127.") or ip.startswith("192.168.") or
               ip.startswith("10.") or ip.startswith("172.") or ip == "::1"
               or host in ("localhost","127.0.0.1"))
    if not private:
        return jsonify({"error": "Only localhost and private IPs allowed"})
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(scan_port, host, p): p for p in COMMON_PORTS}
        for f, p in futs.items():
            if f.result():
                open_ports.append({"port": p, "service": COMMON_PORTS[p], "state": "open"})
    return jsonify({"host": host, "ip": ip,
                    "ports": sorted(open_ports, key=lambda x: x["port"])})

@app.route("/api/export/csv", methods=["POST"])
def api_export_csv():
    d = request.get_json(force=True)
    out = io.StringIO()
    w   = csv.writer(out)
    w.writerow(["package","version","vuln_id","cve_ids","severity","score","summary","fixed_in","published"])
    for p in d.get("packages", []):
        if not p.get("vulns"):
            w.writerow([p["name"], p["version"],"","","OK","","","",""])
        for v in p.get("vulns", []):
            w.writerow([p["name"], p["version"], v["id"], ";".join(v.get("cve_ids",[])),
                        v["severity"], v.get("score",""), v.get("summary","")[:100],
                        ";".join(v.get("fixed_in",[])), v.get("published","")])
    return Response(out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=vuln_scan.csv"})

@app.route("/api/export/json", methods=["POST"])
def api_export_json():
    return Response(json.dumps(request.get_json(force=True), indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=vuln_scan.json"})

# ══════════════════════════════════════════════════════════
# HTML — FULL DESKTOP + MOBILE UI
# ══════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="mobile-web-app-capable" content="yes">
<title>Vulnerability Scanner | Karanam Shrivasta</title>
<meta name="description" content="Free vulnerability scanner. Check Python, npm, Ruby packages against OSV, NVD CVE databases. No API key. By Karanam Shrivasta.">
<meta name="keywords" content="vulnerability scanner, CVE checker, OSV, NVD, dependency audit, pip audit, npm audit, Karanam Shrivasta">
<meta name="author" content="Karanam Shrivasta">
<meta name="robots" content="index,follow">
<meta name="geo.region" content="IN">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication","name":"Simple Vulnerability Scanner","applicationCategory":"SecurityApplication","author":{"@type":"Person","name":"Karanam Shrivasta","url":"https://www.linkedin.com/in/karanam-shrivasta/","sameAs":["https://github.com/mrshrivasta"]},"offers":{"@type":"Offer","price":"0"}}</script>
<style>
/* ── RESET + VARS ── */
:root{
  --bg:#0D1117;--bg2:#161B22;--bg3:#1C2128;--card:#21262D;
  --bdr:#30363D;--text:#E6EDF3;--muted:#8B949E;
  --blue:#58A6FF;--green:#3FB950;--red:#F85149;
  --amber:#D29922;--purple:#BC8CFF;
}
[data-theme="light"]{
  --bg:#F6F8FA;--bg2:#FFFFFF;--bg3:#F1F3F5;--card:#FFFFFF;
  --bdr:#D0D7DE;--text:#1F2328;--muted:#636C76;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:var(--bg);color:var(--text);font-size:14px;min-height:100vh}

/* ── SIDEBAR LAYOUT ── */
.layout{display:flex;min-height:100vh}
.sidebar{width:220px;background:var(--bg2);border-right:1px solid var(--bdr);
         position:fixed;top:0;left:0;height:100vh;display:flex;flex-direction:column;
         z-index:100;overflow-y:auto}
.sb-logo{padding:1.25rem 1rem;border-bottom:1px solid var(--bdr)}
.sb-logo .t{font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px}
.sb-logo .s{font-size:11px;color:var(--muted);margin-top:3px}
.sb-nav{padding:.5rem 0;flex:1}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:10px 1rem;
         border:none;border-left:3px solid transparent;background:none;
         color:var(--muted);font-size:13px;font-family:inherit;cursor:pointer;
         text-align:left;transition:all .12s}
.nav-btn:hover{color:var(--text);background:var(--bg3)}
.nav-btn.on{color:var(--blue);background:var(--bg3);border-left-color:var(--blue)}
.nav-btn .ico{font-size:16px;width:20px;text-align:center;flex-shrink:0}
.sb-foot{padding:1rem;border-top:1px solid var(--bdr)}
.sb-foot .by{font-size:11px;color:var(--muted);margin-bottom:6px;font-weight:600}
.sb-foot a{display:block;font-size:11px;color:var(--blue);text-decoration:none;margin-bottom:3px}

/* ── MAIN CONTENT ── */
.main-wrap{margin-left:220px;display:flex;flex-direction:column;min-height:100vh}
.topbar{background:var(--bg2);border-bottom:1px solid var(--bdr);
        padding:.75rem 1.5rem;display:flex;align-items:center;
        justify-content:space-between;position:sticky;top:0;z-index:99}
.topbar-title{font-size:15px;font-weight:700}
.topbar-right{display:flex;align-items:center;gap:10px}
.content{padding:1.5rem;max-width:1100px;width:100%}

/* ── PAGES ── */
.page{display:none}.page.on{display:block}

/* ── CARDS ── */
.card{background:var(--card);border:1px solid var(--bdr);border-radius:12px;
      padding:1.25rem;margin-bottom:1rem}
.card-title{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;
            letter-spacing:.5px;margin-bottom:1rem}

/* ── STAT GRID ── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:.75rem;margin-bottom:1rem}
.stat-card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;
           padding:1rem;border-top:3px solid var(--ac,var(--blue))}
.stat-val{font-size:28px;font-weight:700;color:var(--ac,var(--blue));line-height:1}
.stat-lbl{font-size:12px;color:var(--muted);margin-top:4px}

/* ── FORM ── */
.form-row{display:flex;gap:.75rem;margin-bottom:.875rem;align-items:flex-end;flex-wrap:wrap}
.form-group{display:flex;flex-direction:column;gap:5px;flex:1;min-width:0}
label.fl{font-size:12px;color:var(--muted);font-weight:500}
input[type=text],input[type=number],select,textarea{
  border:1px solid var(--bdr);border-radius:8px;padding:9px 12px;
  font-size:13px;background:var(--bg3);color:var(--text);
  font-family:inherit;width:100%}
input:focus,select:focus,textarea:focus{outline:2px solid var(--blue);border-color:transparent}
textarea{font-family:'Courier New',monospace;resize:vertical;min-height:160px}

/* ── BUTTONS ── */
.btn{padding:9px 20px;border-radius:8px;border:none;font-size:13px;font-weight:600;
     cursor:pointer;transition:opacity .12s;font-family:inherit;
     display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.btn:hover{opacity:.85}.btn:disabled{opacity:.5;cursor:not-allowed}
.bl{background:var(--blue);color:#fff}
.br{background:var(--red);color:#fff}
.bgr{background:var(--green);color:#000}
.bgray{background:var(--bg3);color:var(--text);border:1px solid var(--bdr)}
.bpurple{background:var(--purple);color:#fff}
.btn-full{width:100%;justify-content:center}

/* ── MODE TABS ── */
.mode-tabs{display:flex;gap:6px;margin-bottom:1rem;flex-wrap:wrap}
.mode-tab{padding:8px 16px;border-radius:8px;border:1px solid var(--bdr);font-size:13px;
          cursor:pointer;background:var(--bg3);color:var(--muted);
          transition:all .12s;font-family:inherit;font-weight:500}
.mode-tab:hover{background:var(--card)}
.mode-tab.on{background:var(--blue);color:#fff;border-color:var(--blue)}

/* ── PROGRESS ── */
.prog-wrap{height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;margin:.75rem 0;display:none}
.prog-bar{height:100%;border-radius:3px;background:var(--blue);transition:width .3s;width:0%}

/* ── BADGES ── */
.bd{display:inline-block;padding:3px 9px;border-radius:5px;font-size:11px;font-weight:700}
.sev-CRITICAL{background:rgba(248,81,73,.2);color:#F85149;border:1px solid rgba(248,81,73,.4)}
.sev-HIGH    {background:rgba(210,153,34,.2);color:#D29922;border:1px solid rgba(210,153,34,.4)}
.sev-MEDIUM  {background:rgba(88,166,255,.15);color:#58A6FF;border:1px solid rgba(88,166,255,.3)}
.sev-LOW     {background:rgba(63,185,80,.1);color:#3FB950;border:1px solid rgba(63,185,80,.3)}
.sev-OK      {background:rgba(63,185,80,.1);color:#3FB950;border:1px solid rgba(63,185,80,.3)}
.sev-UNKNOWN {background:var(--bg3);color:var(--muted);border:1px solid var(--bdr)}

/* ── TABLE ── */
.vtbl{width:100%;border-collapse:collapse;font-size:13px}
.vtbl th{background:var(--bg3);padding:10px 12px;text-align:left;font-size:11px;
         font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;
         border-bottom:1px solid var(--bdr)}
.vtbl td{padding:10px 12px;border-bottom:1px solid var(--bg3);vertical-align:middle}
.vtbl tr:hover td{background:var(--bg3)}
.vtbl tr.vuln-row td{cursor:pointer}

/* ── PACKAGE ROW ── */
.pkg-row{background:var(--card);border:1px solid var(--bdr);border-radius:10px;
         padding:1rem;margin-bottom:.625rem}
.pkg-row.has-vulns{border-color:rgba(248,81,73,.25)}
.pkg-header{display:flex;align-items:center;justify-content:space-between;
            margin-bottom:.5rem;cursor:pointer}
.pkg-name{font-weight:700;font-family:'Courier New',monospace;font-size:14px}
.pkg-meta{font-size:12px;color:var(--muted);margin-top:2px}
.vuln-list{padding-top:.5rem;border-top:1px solid var(--bg3);display:none}
.vuln-item{background:var(--bg3);border-radius:8px;padding:.875rem;margin-top:.5rem;cursor:pointer}
.vuln-item:hover{background:var(--bdr)}
.vuln-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:5px}
.vuln-id{font-family:'Courier New',monospace;font-size:13px;font-weight:700}
.vuln-summary{font-size:12px;color:var(--muted);line-height:1.6}
.vuln-meta-row{font-size:11px;color:var(--muted);margin-top:4px}

/* ── FILTER BAR ── */
.filter-bar{display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap;align-items:center}

/* ── MODAL ── */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;
               display:none;align-items:center;justify-content:center;
               backdrop-filter:blur(4px);padding:1rem}
.modal-overlay.on{display:flex}
.modal-box{background:var(--bg2);border:1px solid var(--bdr);border-radius:14px;
           padding:1.5rem;max-width:640px;width:100%;max-height:85vh;overflow-y:auto;
           box-shadow:0 20px 60px rgba(0,0,0,.5)}
.modal-close{float:right;background:none;border:none;color:var(--muted);
             cursor:pointer;font-size:20px;padding:2px 6px}
.kv-row{display:flex;padding:8px 0;border-bottom:1px solid var(--bg3);gap:1rem}
.kv-row:last-child{border:none}
.kv-k{font-size:12px;color:var(--muted);min-width:130px;flex-shrink:0}
.kv-v{font-size:12px;font-family:monospace;word-break:break-all;font-weight:500}

/* ── DISC ── */
.disc{background:#FEF2F2;border:1px solid #FECACA;border-radius:10px;
      padding:.875rem 1.25rem;margin-bottom:1rem}
.disc h3{font-size:13px;font-weight:700;color:#991B1B;margin-bottom:4px}
.disc p{font-size:12px;color:#B91C1C;line-height:1.7}

/* ── MISC ── */
.code-block{background:#010409;border:1px solid var(--bdr);border-radius:8px;
            padding:1rem;font-family:'Courier New',monospace;font-size:12px;
            line-height:1.9;overflow-x:auto;white-space:pre}
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--bdr);
      border-top-color:var(--blue);border-radius:50%;animation:sp .5s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.tag{background:var(--bg3);border:1px solid var(--bdr);border-radius:5px;
     padding:2px 8px;font-size:11px;font-family:monospace;display:inline-block;margin:2px}
.empty{text-align:center;padding:3rem 1rem;color:var(--muted)}
.empty .ei{font-size:48px;margin-bottom:.75rem}
.wm{text-align:center;padding:2rem 1rem;border-top:1px solid var(--bdr);margin-top:1rem}
.wm .n{font-size:14px;font-weight:700;margin-bottom:4px}
.wm .r{font-size:12px;color:var(--muted);margin-bottom:10px}
.wm a{font-size:13px;color:var(--blue);text-decoration:none;margin:0 8px;font-weight:600}

/* ── RESPONSIVE ── */
@media(max-width:768px){
  .sidebar{width:100%;height:auto;position:relative;flex-direction:row;flex-wrap:wrap}
  .sb-nav{display:flex;flex-wrap:wrap;padding:.25rem}
  .nav-btn{flex:1;min-width:80px;justify-content:center;border-left:none;border-bottom:3px solid transparent;padding:8px}
  .nav-btn.on{border-left:none;border-bottom-color:var(--blue)}
  .main-wrap{margin-left:0}
  .content{padding:1rem}
  .topbar{padding:.75rem 1rem}
}
@media(max-width:480px){
  .stat-grid{grid-template-columns:repeat(2,1fr)}
  .form-row{flex-direction:column}
}
</style>
</head>
<body>

<!-- MODAL -->
<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal-box">
    <button class="modal-close" onclick="closeModal()">✕</button>
    <div id="modal-body"></div>
  </div>
</div>

<div class="layout">
  <!-- SIDEBAR -->
  <nav class="sidebar">
    <div class="sb-logo">
      <div class="t">🔍 Vuln Scanner</div>
      <div class="s">Dependency Security Audit</div>
    </div>
    <div class="sb-nav">
      <button class="nav-btn on" data-p="p-scan" onclick="switchPage(this)">
        <span class="ico">🔍</span> Scanner
      </button>
      <button class="nav-btn" data-p="p-results" onclick="switchPage(this)">
        <span class="ico">📋</span> Results
      </button>
      <button class="nav-btn" data-p="p-lookup" onclick="switchPage(this)">
        <span class="ico">📦</span> Package Lookup
      </button>
      <button class="nav-btn" data-p="p-ports" onclick="switchPage(this)">
        <span class="ico">🔌</span> Port Scanner
      </button>
      <button class="nav-btn" data-p="p-about" onclick="switchPage(this)">
        <span class="ico">ℹ️</span> About / Help
      </button>
    </div>
    <div class="sb-foot">
      <div class="by">Made by Karanam Shrivasta</div>
      <a href="https://www.linkedin.com/in/karanam-shrivasta/" target="_blank">LinkedIn ↗</a>
      <a href="https://github.com/mrshrivasta" target="_blank">GitHub ↗</a>
    </div>
  </nav>

  <!-- MAIN -->
  <div class="main-wrap">
    <div class="topbar">
      <div class="topbar-title" id="topbar-title">🔍 Scanner</div>
      <div class="topbar-right">
        <span id="vuln-badge" style="display:none;background:rgba(248,81,73,.15);color:var(--red);
              border:1px solid rgba(248,81,73,.3);border-radius:6px;padding:4px 10px;font-size:12px;font-weight:600"></span>
        <button onclick="toggleTheme()" style="background:var(--bg3);border:1px solid var(--bdr);
                border-radius:8px;padding:7px 12px;cursor:pointer;font-size:14px;color:var(--muted)" id="theme-btn">🌙 Theme</button>
      </div>
    </div>

    <div class="content">

      <!-- ══ SCANNER PAGE ══════════════════════════════════════ -->
      <div id="p-scan" class="page on">
        <div class="disc">
          <h3>⚠️ Educational use only — legal disclaimer</h3>
          <p>This tool queries public CVE databases for packages you own or manage.
          Never use on production systems without authorization. Karanam Shrivasta assumes
          zero liability for misuse. May violate CFAA (US), CMA 1990 (UK), IT Act 2000 (India).</p>
        </div>

        <div class="card">
          <div class="card-title">Scan mode</div>
          <div class="mode-tabs">
            <button class="mode-tab on" onclick="setMode('file',this)">📄 Paste file</button>
            <button class="mode-tab" onclick="setMode('single',this)">📦 Single package</button>
            <button class="mode-tab" onclick="setMode('installed',this)">🐍 Installed packages</button>
          </div>

          <!-- FILE MODE -->
          <div id="mode-file">
            <div class="form-row">
              <div class="form-group" style="max-width:260px">
                <label class="fl">File type</label>
                <select id="file-type">
                  <option value="requirements.txt">requirements.txt (Python)</option>
                  <option value="package.json">package.json (npm)</option>
                  <option value="Gemfile.lock">Gemfile.lock (Ruby)</option>
                </select>
              </div>
            </div>
            <div class="form-group" style="margin-bottom:.875rem">
              <label class="fl">Paste file contents</label>
              <textarea id="file-content" placeholder="requests==2.28.0&#10;flask==2.0.0&#10;pillow==9.0.0&#10;..."></textarea>
            </div>
            <div style="margin-bottom:1rem">
              <div style="font-size:12px;color:var(--muted);margin-bottom:.5rem">Quick examples:</div>
              <div style="display:flex;gap:6px;flex-wrap:wrap">
                <button class="btn bgray" onclick="loadExample('py')">🐍 Python (vulnerable)</button>
                <button class="btn bgray" onclick="loadExample('npm')">📦 npm (vulnerable)</button>
                <button class="btn bgray" onclick="loadExample('safe')">✅ Python (safe)</button>
              </div>
            </div>
          </div>

          <!-- SINGLE MODE -->
          <div id="mode-single" style="display:none">
            <div class="form-row">
              <div class="form-group">
                <label class="fl">Package name</label>
                <input type="text" id="pkg-name" placeholder="e.g. requests, lodash, rails">
              </div>
              <div class="form-group" style="max-width:160px">
                <label class="fl">Version (optional)</label>
                <input type="text" id="pkg-version" placeholder="e.g. 2.18.0">
              </div>
              <div class="form-group" style="max-width:200px">
                <label class="fl">Ecosystem</label>
                <select id="pkg-eco">
                  <option value="PyPI">PyPI (Python)</option>
                  <option value="npm">npm (JavaScript)</option>
                  <option value="RubyGems">RubyGems (Ruby)</option>
                  <option value="Go">Go</option>
                  <option value="Maven">Maven (Java)</option>
                  <option value="NuGet">NuGet (.NET)</option>
                  <option value="crates.io">crates.io (Rust)</option>
                </select>
              </div>
            </div>
          </div>

          <!-- INSTALLED MODE -->
          <div id="mode-installed" style="display:none">
            <div style="background:var(--bg3);border-radius:8px;padding:1rem;
                        font-size:13px;color:var(--muted);line-height:1.8;margin-bottom:.875rem">
              Runs <code style="background:var(--bg2);padding:2px 6px;border-radius:4px">pip list</code>
              and queries all installed Python packages against the OSV database.
              This may take 30–90 seconds depending on how many packages are installed.
            </div>
          </div>

          <div style="display:flex;gap:.75rem;align-items:center;flex-wrap:wrap">
            <button class="btn bl" id="scan-btn" onclick="runScan()">🔍 Start scan</button>
            <div id="scan-status" style="font-size:13px;color:var(--muted);display:none"></div>
          </div>
          <div class="prog-wrap" id="prog-wrap">
            <div class="prog-bar" id="prog-bar"></div>
          </div>
        </div>
      </div>

      <!-- ══ RESULTS PAGE ══════════════════════════════════════ -->
      <div id="p-results" class="page">
        <div id="no-results" class="empty">
          <div class="ei">🔍</div>
          <p>No scan results yet.<br>Go to the Scanner tab and run a scan first.</p>
        </div>

        <div id="results-wrap" style="display:none">
          <div class="stat-grid" id="stat-grid"></div>

          <div class="filter-bar">
            <button class="btn bgray" onclick="filterPkgs('all')">All packages</button>
            <button class="btn br" onclick="filterPkgs('vuln')">⚠ Vulnerable only</button>
            <button class="btn bgr" onclick="filterPkgs('safe')">✅ Safe only</button>
            <div style="flex:1"></div>
            <button class="btn bgray" onclick="exportCSV()">⬇ Export CSV</button>
            <button class="btn bgray" onclick="exportJSON()">⬇ Export JSON</button>
          </div>

          <div class="card" style="padding:.5rem">
            <input type="text" id="pkg-search" placeholder="🔍  Search packages..."
              style="border:none;background:transparent;outline:none;padding:.5rem .75rem;
                     width:100%;font-size:14px;color:var(--text)"
              oninput="filterPkgs('search')">
          </div>

          <div id="pkg-list"></div>
        </div>
      </div>

      <!-- ══ LOOKUP PAGE ══════════════════════════════════════ -->
      <div id="p-lookup" class="page">
        <div class="card">
          <div class="card-title">Package vulnerability lookup</div>
          <div class="form-row">
            <div class="form-group">
              <label class="fl">Package name</label>
              <input type="text" id="l-name" placeholder="e.g. django, lodash, rails"
                onkeydown="if(event.key==='Enter')lookupPkg()">
            </div>
            <div class="form-group" style="max-width:160px">
              <label class="fl">Version</label>
              <input type="text" id="l-version" placeholder="e.g. 3.2.0"
                onkeydown="if(event.key==='Enter')lookupPkg()">
            </div>
            <div class="form-group" style="max-width:200px">
              <label class="fl">Ecosystem</label>
              <select id="l-eco">
                <option value="PyPI">PyPI (Python)</option>
                <option value="npm">npm (JavaScript)</option>
                <option value="RubyGems">RubyGems (Ruby)</option>
                <option value="Go">Go</option>
                <option value="Maven">Maven (Java)</option>
                <option value="NuGet">NuGet (.NET)</option>
                <option value="crates.io">crates.io (Rust)</option>
              </select>
            </div>
            <div class="form-group" style="max-width:140px;justify-content:flex-end">
              <button class="btn bl btn-full" onclick="lookupPkg()">🔍 Lookup</button>
            </div>
          </div>
        </div>
        <div id="lookup-result"></div>
      </div>

      <!-- ══ PORT SCANNER PAGE ══════════════════════════════════ -->
      <div id="p-ports" class="page">
        <div class="disc">
          <h3>⚠️ localhost and private IPs only</h3>
          <p>Port scanning is restricted to 127.0.0.1, localhost, and RFC 1918 private addresses
          (192.168.x, 10.x, 172.16–31.x). Karanam Shrivasta assumes zero liability for misuse.</p>
        </div>
        <div class="card">
          <div class="card-title">Scan open ports</div>
          <div class="form-row">
            <div class="form-group">
              <label class="fl">Host (localhost or private IP)</label>
              <input type="text" id="port-host" value="localhost"
                onkeydown="if(event.key==='Enter')runPortScan()">
            </div>
            <div class="form-group" style="max-width:140px;justify-content:flex-end">
              <button class="btn bl btn-full" onclick="runPortScan()" id="port-btn">▶ Scan</button>
            </div>
          </div>
          <div id="port-status" style="font-size:13px;color:var(--muted);margin-top:.5rem"></div>
        </div>
        <div id="port-results" style="display:none" class="card">
          <div class="card-title" id="port-title">Open ports</div>
          <table class="vtbl">
            <thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Risk</th></tr></thead>
            <tbody id="port-tbody"></tbody>
          </table>
        </div>
      </div>

      <!-- ══ ABOUT PAGE ══════════════════════════════════════ -->
      <div id="p-about" class="page">
        <div class="card">
          <div class="card-title">Data sources — no API keys required</div>
          <table class="vtbl">
            <thead><tr><th>Source</th><th>URL</th><th>Coverage</th></tr></thead>
            <tbody>
              <tr><td><strong>OSV.dev</strong></td><td><a href="https://osv.dev" target="_blank" style="color:var(--blue)">osv.dev</a></td><td style="color:var(--muted)">PyPI, npm, RubyGems, Go, Maven, NuGet, Rust, GitHub Actions</td></tr>
              <tr><td><strong>PyPI JSON API</strong></td><td><a href="https://pypi.org/pypi" target="_blank" style="color:var(--blue)">pypi.org/pypi</a></td><td style="color:var(--muted)">Python package metadata, latest version</td></tr>
              <tr><td><strong>npm Registry</strong></td><td><a href="https://registry.npmjs.org" target="_blank" style="color:var(--blue)">registry.npmjs.org</a></td><td style="color:var(--muted)">Node.js package info</td></tr>
              <tr><td><strong>NVD NIST</strong></td><td><a href="https://nvd.nist.gov" target="_blank" style="color:var(--blue)">nvd.nist.gov</a></td><td style="color:var(--muted)">CVSS scores, CVE details</td></tr>
            </tbody>
          </table>
        </div>
        <div class="card">
          <div class="card-title">Supported file formats</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.75rem">
            <div style="background:var(--bg3);border-radius:8px;padding:.875rem">
              <div style="font-weight:700;margin-bottom:4px">requirements.txt</div>
              <div style="font-size:12px;color:var(--muted)">Python pinned & range deps</div>
            </div>
            <div style="background:var(--bg3);border-radius:8px;padding:.875rem">
              <div style="font-weight:700;margin-bottom:4px">package.json</div>
              <div style="font-size:12px;color:var(--muted)">npm/Yarn dependencies</div>
            </div>
            <div style="background:var(--bg3);border-radius:8px;padding:.875rem">
              <div style="font-weight:700;margin-bottom:4px">Gemfile.lock</div>
              <div style="font-size:12px;color:var(--muted)">Ruby Bundler lockfile</div>
            </div>
            <div style="background:var(--bg3);border-radius:8px;padding:.875rem">
              <div style="font-weight:700;margin-bottom:4px">pip freeze</div>
              <div style="font-size:12px;color:var(--muted)">Output of pip freeze</div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-title">CLI reference</div>
          <div class="code-block"><span style="color:#4ADE80">python vuln_scanner.py</span>                      <span style="color:#555">  # web UI</span>
<span style="color:#4ADE80">python vuln_scanner.py</span> <span style="color:#60A5FA">--scan requirements.txt</span>
<span style="color:#4ADE80">python vuln_scanner.py</span> <span style="color:#60A5FA">--scan package.json</span>
<span style="color:#4ADE80">python vuln_scanner.py</span> <span style="color:#60A5FA">--scan Gemfile.lock</span>
<span style="color:#4ADE80">python vuln_scanner.py</span> <span style="color:#60A5FA">--installed</span>            <span style="color:#555">  # scan all pip pkgs</span>
<span style="color:#4ADE80">python vuln_scanner.py</span> <span style="color:#60A5FA">--pkg requests 2.18.0</span>
<span style="color:#4ADE80">python vuln_scanner.py</span> <span style="color:#60A5FA">--scan reqs.txt --csv out.csv</span>

<span style="color:#FCD34D">pip install flask packaging</span></div>
        </div>
        <div class="disc">
          <h3>⚠️ Legal disclaimer</h3>
          <p>Use only on your own projects and systems. Never scan packages or systems you don't own.
          Karanam Shrivasta assumes zero liability for misuse. May violate CFAA (US),
          Computer Misuse Act 1990 (UK), IT Act 2000 (India).</p>
        </div>
        <div class="wm">
          <div class="n">Made by Karanam Shrivasta</div>
          <div class="r">Network Security Educator · Ethical Hacking Researcher · Open Source Developer</div>
          <div>
            <a href="https://www.linkedin.com/in/karanam-shrivasta/" target="_blank">LinkedIn ↗</a>
            <a href="https://github.com/mrshrivasta" target="_blank">GitHub ↗</a>
          </div>
        </div>
      </div>

    </div><!-- /content -->
  </div><!-- /main-wrap -->
</div><!-- /layout -->

<script>
// ── navigation ───────────────────────────────────────────
const PAGE_TITLES = {
  "p-scan":"🔍 Scanner","p-results":"📋 Results",
  "p-lookup":"📦 Package Lookup","p-ports":"🔌 Port Scanner","p-about":"ℹ️ About"
};
function switchPage(btn){
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('on'));
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('on'));
  btn.classList.add('on');
  document.getElementById(btn.dataset.p).classList.add('on');
  document.getElementById('topbar-title').textContent = PAGE_TITLES[btn.dataset.p]||'';
}

// ── theme ────────────────────────────────────────────────
let DARK = true;
function toggleTheme(){
  DARK=!DARK;
  document.documentElement.setAttribute('data-theme',DARK?'dark':'light');
  document.getElementById('theme-btn').textContent = DARK?'🌙 Theme':'☀️ Theme';
}

// ── scan mode ─────────────────────────────────────────────
function setMode(m,btn){
  ['file','single','installed'].forEach(k=>{
    document.getElementById('mode-'+k).style.display = k===m?'block':'none';
  });
  document.querySelectorAll('.mode-tab').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
}

// ── examples ──────────────────────────────────────────────
const EXAMPLES = {
  py:  "requests==2.18.0\nflask==0.12.0\npillow==9.0.0\ndjango==2.2.0\npyyaml==5.1\ncryptography==3.2.0",
  npm: '{\n  "dependencies": {\n    "lodash": "4.17.4",\n    "express": "4.16.0",\n    "axios": "0.18.0",\n    "minimist": "1.2.0"\n  }\n}',
  safe:"requests==2.31.0\nflask==3.0.0\ndjango==4.2.0\npillow==10.0.0\ncryptography==41.0.0"
};
function loadExample(k){
  if(k==='npm') document.getElementById('file-type').value='package.json';
  else document.getElementById('file-type').value='requirements.txt';
  document.getElementById('file-content').value = EXAMPLES[k];
}

// ── scan ─────────────────────────────────────────────────
let scanData = null;

function setScanUI(loading, msg){
  const btn = document.getElementById('scan-btn');
  const st  = document.getElementById('scan-status');
  const pw  = document.getElementById('prog-wrap');
  btn.disabled = loading;
  btn.textContent = loading ? 'Scanning...' : '🔍 Start scan';
  if(msg){ st.style.display='block'; st.innerHTML=loading?`<span class="spin"></span> ${msg}`:msg; }
  else st.style.display='none';
  pw.style.display = loading ? 'block' : 'none';
  if(loading){ let pct=10; const t=setInterval(()=>{ pct=Math.min(90,pct+5); document.getElementById('prog-bar').style.width=pct+'%'; },600); btn._timer=t; }
  else{ if(btn._timer) clearInterval(btn._timer); document.getElementById('prog-bar').style.width='100%'; setTimeout(()=>{ pw.style.display='none'; document.getElementById('prog-bar').style.width='0%'; },500); }
}

async function runScan(){
  const fileVis  = document.getElementById('mode-file').style.display!=='none';
  const singleVis= document.getElementById('mode-single').style.display!=='none';
  setScanUI(true,'Scanning...');
  try{
    let data;
    if(fileVis){
      const content  = document.getElementById('file-content').value.trim();
      const filename = document.getElementById('file-type').value;
      if(!content){alert('Paste file contents first.');setScanUI(false);return;}
      const r = await fetch('/api/scan/text',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content,filename})});
      data = await r.json();
    } else if(singleVis){
      const name = document.getElementById('pkg-name').value.trim();
      const ver  = document.getElementById('pkg-version').value.trim();
      const eco  = document.getElementById('pkg-eco').value;
      if(!name){alert('Enter a package name.');setScanUI(false);return;}
      setScanUI(true,'Looking up '+name+'...');
      const r = await fetch('/api/scan/package',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,version:ver,ecosystem:eco})});
      const d = await r.json();
      if(d.error){setScanUI(false,'Error: '+d.error);return;}
      data = {
        scanned_at: new Date().toISOString(), ecosystem: eco,
        total_packages:1, vulnerable:d.vuln_count>0?1:0, safe:d.vuln_count===0?1:0,
        total_vulns:d.vuln_count, severity_counts:countSev(d.vulns),
        packages:[{name:d.package,version:d.version,raw:name+'=='+ver,
                   vuln_count:d.vuln_count,highest:d.vuln_count?d.vulns[0].severity:'OK',
                   vulns:d.vulns,ecosystem:eco}], errors:[]
      };
    } else {
      setScanUI(true,'Running pip list and querying OSV (30–60s)...');
      const r = await fetch('/api/scan/installed',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
      data = await r.json();
    }
    if(data.error){setScanUI(false,'❌ '+data.error);return;}
    scanData = data;
    setScanUI(false,'✅ Done — '+data.total_packages+' packages scanned');
    const vb = document.getElementById('vuln-badge');
    if(data.vulnerable>0){ vb.style.display='block'; vb.textContent=data.vulnerable+' vulnerable'; }
    else vb.style.display='none';
    renderResults(data);
    // switch to results tab
    document.querySelector('.nav-btn[data-p="p-results"]').click();
  }catch(e){
    setScanUI(false,'❌ Error: '+e.message);
  }
}

function countSev(vulns){
  const c={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};
  (vulns||[]).forEach(v=>{c[v.severity]=(c[v.severity]||0)+1;});
  return c;
}

// ── render results ─────────────────────────────────────────
function renderResults(data){
  document.getElementById('no-results').style.display='none';
  document.getElementById('results-wrap').style.display='block';
  const sc = data.severity_counts||{};
  document.getElementById('stat-grid').innerHTML=[
    {v:data.total_packages,l:'Total packages',ac:'var(--blue)'},
    {v:data.vulnerable,l:'Vulnerable',ac:'var(--red)'},
    {v:data.safe,l:'Safe',ac:'var(--green)'},
    {v:sc.CRITICAL||0,l:'Critical',ac:'var(--red)'},
    {v:sc.HIGH||0,l:'High',ac:'var(--amber)'},
    {v:sc.MEDIUM||0,l:'Medium',ac:'var(--blue)'},
  ].map(w=>`<div class="stat-card" style="--ac:${w.ac}">
    <div class="stat-val">${w.v}</div>
    <div class="stat-lbl">${w.l}</div>
  </div>`).join('');
  renderPkgList(data.packages);
}

let currentFilter='all';
function filterPkgs(f){
  currentFilter=f;
  if(!scanData) return;
  let pkgs=[...scanData.packages];
  const q=(document.getElementById('pkg-search')?.value||'').toLowerCase();
  if(f==='vuln')  pkgs=pkgs.filter(p=>p.vuln_count>0);
  if(f==='safe')  pkgs=pkgs.filter(p=>p.vuln_count===0);
  if(f==='search'&&q) pkgs=pkgs.filter(p=>p.name.includes(q)||p.version.includes(q));
  renderPkgList(pkgs);
}

function renderPkgList(pkgs){
  const el=document.getElementById('pkg-list');
  if(!pkgs.length){el.innerHTML='<div class="empty"><div class="ei">✅</div><p>No packages match this filter.</p></div>';return;}
  el.innerHTML=pkgs.map((p,i)=>`
    <div class="pkg-row ${p.vuln_count>0?'has-vulns':''}">
      <div class="pkg-header" onclick="toggleVulns(${i})">
        <div>
          <div class="pkg-name">${p.name}</div>
          <div class="pkg-meta">${p.version||'no version'} · ${p.ecosystem} · ${p.vuln_count} vulnerability${p.vuln_count!==1?'ies':'y'}</div>
        </div>
        <div style="display:flex;align-items:center;gap:.75rem">
          <span class="bd sev-${p.highest||'OK'}">${p.highest||'OK'}</span>
          ${p.vuln_count>0?`<span style="color:var(--muted);font-size:12px" id="toggle-${i}">▼ show</span>`:''}
        </div>
      </div>
      ${p.vuln_count>0?`<div class="vuln-list" id="vlist-${i}">
        ${p.vulns.map((v,j)=>`
          <div class="vuln-item" onclick='openVuln(${JSON.stringify(v).replace(/"/g,"&quot;")})'>
            <div class="vuln-header">
              <span class="vuln-id">${v.id}</span>
              <span class="bd sev-${v.severity}">${v.severity}${v.score?' '+v.score:''}</span>
            </div>
            <div class="vuln-summary">${v.summary||v.details||'No description available'}</div>
            <div class="vuln-meta-row">
              ${v.cve_ids&&v.cve_ids.length?v.cve_ids.join(' · '):''}
              ${v.fixed_in&&v.fixed_in.length?' · Fix: '+v.fixed_in.join(', '):''}
              ${v.published?' · '+v.published:''}
            </div>
          </div>`).join('')}
      </div>`:''}
    </div>`).join('');
}

function toggleVulns(i){
  const el=document.getElementById('vlist-'+i);
  const tog=document.getElementById('toggle-'+i);
  if(!el) return;
  const open=el.style.display==='block';
  el.style.display=open?'none':'block';
  if(tog) tog.textContent=open?'▼ show':'▲ hide';
}

// ── vuln detail modal ─────────────────────────────────────
function openVuln(v){
  if(typeof v==='string') v=JSON.parse(v);
  document.getElementById('modal-body').innerHTML=`
    <div style="display:flex;align-items:flex-start;justify-content:space-between;
                gap:1rem;margin-bottom:1rem">
      <div>
        <div style="font-family:monospace;font-size:16px;font-weight:700;margin-bottom:4px">${v.id}</div>
        <span class="bd sev-${v.severity}">${v.severity}${v.score?' · CVSS '+v.score:''}</span>
      </div>
    </div>
    <div style="font-size:14px;line-height:1.8;color:var(--muted);margin-bottom:1.25rem">
      ${v.summary||v.details||'No description available'}
    </div>
    ${v.details&&v.summary&&v.details!==v.summary?`<div style="font-size:12px;line-height:1.8;color:var(--muted);margin-bottom:1.25rem">${v.details}</div>`:''}
    ${[
      ['Package',        `${v.pkg_name} ${v.pkg_version}`],
      ['CVE IDs',        (v.cve_ids||[]).join(', ')||'—'],
      ['Fixed in',       (v.fixed_in||[]).join(', ')||'No fix available'],
      ['Published',      v.published||'—'],
      ['Last modified',  v.modified||'—'],
    ].map(([k,val])=>`<div class="kv-row"><div class="kv-k">${k}</div><div class="kv-v">${val}</div></div>`).join('')}
    ${(v.references||[]).length?`
      <div class="kv-row" style="flex-direction:column;gap:.5rem">
        <div class="kv-k">References</div>
        <div>${(v.references||[]).map(r=>`<a href="${r}" target="_blank" rel="noopener"
          style="display:block;font-size:12px;color:var(--blue);margin-bottom:4px;
                 word-break:break-all">${r}</a>`).join('')}</div>
      </div>`:''}`;
  document.getElementById('modal').classList.add('on');
}

function closeModal(){
  document.getElementById('modal').classList.remove('on');
}
document.addEventListener('keydown',e=>{ if(e.key==='Escape') closeModal(); });

// ── package lookup ────────────────────────────────────────
async function lookupPkg(){
  const name = document.getElementById('l-name').value.trim();
  const ver  = document.getElementById('l-version').value.trim();
  const eco  = document.getElementById('l-eco').value;
  if(!name){alert('Enter a package name.');return;}
  const el = document.getElementById('lookup-result');
  el.innerHTML='<div style="padding:1rem;color:var(--muted)"><span class="spin"></span> Looking up '+name+'...</div>';
  const r = await fetch('/api/scan/package',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,version:ver,ecosystem:eco})});
  const d = await r.json();
  if(d.error){el.innerHTML=`<div class="card" style="color:var(--red)">Error: ${d.error}</div>`;return;}
  const info=d.info||{};
  el.innerHTML=`
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.875rem">
        <div>
          <div style="font-size:18px;font-weight:700">${info.name||name}</div>
          <div style="font-size:13px;color:var(--muted);margin-top:3px">${info.summary||''}</div>
        </div>
        <span class="bd sev-${d.vuln_count>0?(d.vulns[0]?.severity||'HIGH'):'OK'}" style="font-size:13px">
          ${d.vuln_count} vuln${d.vuln_count!==1?'s':''}
        </span>
      </div>
      ${[['Latest version',info.latest||'—'],['License',info.license||'—'],
         ['Ecosystem',eco],['Queried version',ver||'latest']].map(([k,v])=>
        `<div class="kv-row"><div class="kv-k">${k}</div><div class="kv-v">${v}</div></div>`).join('')}
      ${info.home_page?`<div class="kv-row"><div class="kv-k">Homepage</div><div class="kv-v"><a href="${info.home_page}" target="_blank" style="color:var(--blue)">${info.home_page.substring(0,60)}</a></div></div>`:''}
    </div>
    ${d.vulns.length===0?`<div class="card" style="text-align:center;color:var(--green);padding:2rem">✅ No known vulnerabilities found for this version.</div>`:''}
    ${d.vulns.map(v=>`
      <div class="vuln-item card" onclick='openVuln(${JSON.stringify(v).replace(/"/g,"&quot;")})'>
        <div class="vuln-header">
          <span class="vuln-id">${v.id}</span>
          <span class="bd sev-${v.severity}">${v.severity}${v.score?' '+v.score:''}</span>
        </div>
        <div class="vuln-summary">${v.summary||'No description'}</div>
        <div class="vuln-meta-row">${v.cve_ids.join(' · ')}${v.fixed_in.length?' · Fix: '+v.fixed_in.join(', '):''}${v.published?' · '+v.published:''}</div>
      </div>`).join('')}`;
}

// ── port scanner ──────────────────────────────────────────
async function runPortScan(){
  const host = document.getElementById('port-host').value.trim();
  document.getElementById('port-status').innerHTML='<span class="spin"></span> Scanning '+host+'...';
  document.getElementById('port-results').style.display='none';
  document.getElementById('port-btn').disabled=true;
  const r = await fetch('/api/portscan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host})});
  const d = await r.json();
  document.getElementById('port-btn').disabled=false;
  document.getElementById('port-status').textContent='';
  if(d.error){document.getElementById('port-status').textContent='❌ '+d.error;return;}
  document.getElementById('port-results').style.display='block';
  document.getElementById('port-title').textContent=`Open ports on ${d.host} (${d.ip})`;
  const RISK={22:'LOW',23:'HIGH',21:'MEDIUM',3389:'HIGH',445:'HIGH',3306:'HIGH',27017:'HIGH',6379:'HIGH'};
  if(!d.ports.length){
    document.getElementById('port-tbody').innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:1.5rem">No open ports found</td></tr>';
    return;
  }
  document.getElementById('port-tbody').innerHTML=d.ports.map(p=>`
    <tr>
      <td><strong style="font-family:monospace">${p.port}</strong></td>
      <td style="color:var(--purple)">${p.service}</td>
      <td><span class="bd sev-OK">open</span></td>
      <td><span class="bd sev-${RISK[p.port]||'LOW'}">${RISK[p.port]||'LOW'}</span></td>
    </tr>`).join('');
}

// ── export ────────────────────────────────────────────────
async function exportCSV(){
  if(!scanData){alert('No scan data. Run a scan first.');return;}
  const r=await fetch('/api/export/csv',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(scanData)});
  const blob=await r.blob();
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='vuln_scan.csv';a.click();
}
async function exportJSON(){
  if(!scanData){alert('No scan data. Run a scan first.');return;}
  const r=await fetch('/api/export/json',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(scanData)});
  const blob=await r.blob();
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='vuln_scan.json';a.click();
}
</script>
</body>
</html>"""

# ── CLI ───────────────────────────────────────────────────
def cli_main():
    import argparse

    ap = argparse.ArgumentParser(description="Vulnerability Scanner")
    ap.add_argument("--scan", default=None)
    ap.add_argument("--installed", action="store_true")
    ap.add_argument("--pkg", nargs=2)
    ap.add_argument("--eco", default="PyPI")
    ap.add_argument("--port", type=int, default=5000)

    args = ap.parse_args()

    if args.pkg:
        name, ver = args.pkg
        raw = osv_query_single(name, ver, args.eco)
        vulns = [format_vuln(v, name, ver) for v in raw]
        print(f"{name}: {len(vulns)} vulnerabilities")
        return

    if args.installed:
        pkgs = get_pip_installed()
        print(scan_packages(pkgs, "PyPI"))
        return

    if args.scan:
        content = Path(args.scan).read_text()
        pkgs = parse_requirements(content)
        print(scan_packages(pkgs, "PyPI"))
        return

    app.run(host="0.0.0.0", port=args.port, debug=False)

    if args.pkg:
        name, ver = args.pkg
        print(f"\n  Querying {name} {ver} ({args.eco})...")
        raw   = osv_query_single(name, ver, args.eco)
        vulns = [format_vuln(v, name, ver) for v in raw]
        vulns.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"],0), reverse=True)
        if not vulns:
            print(f"  ✅ No vulnerabilities found for {name} {ver}")
        else:
            print(f"  ⚠ {len(vulns)} vulnerabilities:")
            for v in vulns:
                print(f"  [{v['severity']:8}] {v['id']}: {v['summary'][:70]}")
                if v['fixed_in']: print(f"            Fixed: {v['fixed_in']}")
        return

    if args.installed:
        pkgs = get_pip_installed()
        eco  = "PyPI"
    elif args.scan:
        content = Path(args.scan).read_text()
        fn = args.scan.lower()
        if "package.json" in fn:  pkgs = parse_package_json(content)
        elif "gemfile"    in fn:  pkgs = parse_gemfile_lock(content)
        else:                     pkgs = parse_requirements(content)
        eco = detect_eco(args.scan)
    else:
        print(__doc__)
        print(f"  Web UI → http://localhost:{args.port}\n")
        app.run(debug=False, host="0.0.0.0", port=args.port, threaded=True)
        return

    print(f"\n  {len(pkgs)} packages found. Querying OSV.dev...")
    result = scan_packages(pkgs[:200], eco)
    sc     = result["severity_counts"]
    print(f"\n  ━━━ Results ━━━")
    print(f"  Packages  : {result['total_packages']}")
    print(f"  Vulnerable: {result['vulnerable']}")
    print(f"  Critical  : {sc.get('CRITICAL',0)}  High: {sc.get('HIGH',0)}  Medium: {sc.get('MEDIUM',0)}")
    for p in sorted([x for x in result['packages'] if x['vuln_count']>0],
                    key=lambda x: SEVERITY_ORDER.get(x["highest"],0), reverse=True):
        print(f"\n  ⚠ {p['name']} {p['version']} [{p['highest']}] — {p['vuln_count']} vulns")
        for v in p['vulns'][:2]:
            print(f"      {v['id']}: {v['summary'][:70]}")
            if v['fixed_in']: print(f"      Fixed: {v['fixed_in']}")
    if not any(p['vuln_count']>0 for p in result['packages']):
        print("  ✅ No known vulnerabilities found!")
    if args.csv:
        out = io.StringIO()
        w   = csv.writer(out)
        w.writerow(["package","version","vuln_id","cve_ids","severity","score","summary","fixed_in"])
        for p in result['packages']:
            for v in p.get('vulns',[]):
                w.writerow([p['name'],p['version'],v['id'],";".join(v.get('cve_ids',[])),
                            v['severity'],v.get('score',''),v.get('summary','')[:100],
                            ";".join(v.get('fixed_in',[]))])
        Path(args.csv).write_text(out.getvalue())
        print(f"\n  CSV → {args.csv}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2))
        print(f"  JSON → {args.json_out}")

if __name__ == "__main__":
    cli_main()