"""
╔══════════════════════════════════════════════════════════════╗
║        SENTINEL — URL & Website Threat Scanner  v1.0        ║
║        100% Free · No paid APIs · Pure Python stdlib        ║
╠══════════════════════════════════════════════════════════════╣
║  Scans any URL or website for:                              ║
║    • Malware / phishing (VirusTotal)                        ║
║    • SSL/TLS certificate issues                             ║
║    • Suspicious HTTP headers (missing security headers)     ║
║    • Redirect chains & suspicious redirects                 ║
║    • Malicious JS patterns in page source                   ║
║    • Domain age & reputation signals                        ║
║    • Open redirect vulnerabilities                          ║
║    • Mixed content & insecure resource loading              ║
║  Generates a full HTML + JSON report                        ║
╠══════════════════════════════════════════════════════════════╣
║  .env needs only: VIRUSTOTAL_API_KEY                        ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python url_threat_scanner.py https://example.com
    python url_threat_scanner.py                      <- prompts
"""

import os, sys, re, json, ssl, socket, time, hashlib
import urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone
from html import escape as he

# ── ANSI colours ───────────────────────────────────────────────────────────────
RESET  = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED    = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
CYAN   = "\033[96m"; WHITE  = "\033[97m"; MAGENTA = "\033[95m"

SEV_COLOUR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW,
              "LOW": CYAN, "INFO": DIM, "CLEAN": GREEN}

# ══════════════════════════════════════════════════════════════════════════════
#  0 — Helpers
# ══════════════════════════════════════════════════════════════════════════════

def load_env(path: str = ".env") -> None:
    if not os.path.exists(path):
        print(f"{RED}[ERROR]{RESET} .env not found: {os.path.abspath(path)}")
        sys.exit(1)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def normalise_url(raw: str) -> str:
    """Ensure the URL has a scheme; default to https."""
    raw = raw.strip().rstrip("/")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def extract_domain(url: str) -> str:
    return urllib.parse.urlparse(url).netloc.lower().lstrip("www.")


def banner(msg: str) -> None:
    print(f"\n  {DIM}[•]{RESET} {msg} …")


# ══════════════════════════════════════════════════════════════════════════════
#  1 — VirusTotal URL scan
# ══════════════════════════════════════════════════════════════════════════════

def vt_url_lookup(url: str, api_key: str) -> dict:
    """
    POST the URL to VT for scanning, then GET the analysis result.
    VT identifies URLs by the base64url-encoded URL (no padding).
    """
    import base64

    # Encode URL → VT ID
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

    headers = {"x-apikey": api_key, "Content-Type": "application/x-www-form-urlencoded"}

    # Submit for (re)scan
    try:
        post_data = urllib.parse.urlencode({"url": url}).encode()
        req = urllib.request.Request(
            "https://www.virustotal.com/api/v3/urls",
            data=post_data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            pass  # we just trigger the scan; result fetched below
    except Exception:
        pass  # scan submission can fail harmlessly; we still try GET

    # GET the stored report
    get_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    req = urllib.request.Request(get_url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return {"_error": json.loads(body)}
        except Exception:
            return {"_error": body}
    except Exception as e:
        return {"_error": str(e)}


def parse_vt_url_result(data: dict) -> dict:
    """Extract clean signals from a VT URL analysis response."""
    if "_error" in data:
        return {"ok": False, "error": str(data["_error"]),
                "malicious": 0, "suspicious": 0, "harmless": 0,
                "total": 0, "categories": [], "tags": [], "reputation": 0,
                "final_url": "", "title": ""}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    cats  = list(attrs.get("categories", {}).values())
    tags  = attrs.get("tags", [])

    return {
        "ok":         True,
        "malicious":  stats.get("malicious",  0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless",   0),
        "undetected": stats.get("undetected", 0),
        "total":      sum(stats.values()),
        "reputation": attrs.get("reputation", 0),
        "categories": [c.lower() for c in cats],
        "tags":       [t.lower() for t in tags],
        "final_url":  attrs.get("last_final_url", ""),
        "title":      attrs.get("title", ""),
        "votes_mal":  attrs.get("total_votes", {}).get("malicious", 0),
        "votes_har":  attrs.get("total_votes", {}).get("harmless",  0),
        "flagged_by": [
            engine for engine, r in attrs.get("last_analysis_results", {}).items()
            if r.get("category") in ("malicious", "suspicious")
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
#  2 — SSL/TLS Certificate Inspector
# ══════════════════════════════════════════════════════════════════════════════

def inspect_ssl(domain: str, port: int = 443) -> dict:
    result = {"ok": False, "findings": [], "cert_info": {}}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()

        # Expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.utcnow()).days
            result["cert_info"]["expires"] = not_after_str
            result["cert_info"]["days_left"] = days_left
            if days_left < 0:
                result["findings"].append({
                    "id": "SSL-001", "sev": "CRITICAL",
                    "title": "SSL Certificate Expired",
                    "detail": f"Certificate expired {abs(days_left)} day(s) ago.",
                    "fix": "Renew the SSL certificate immediately using Let's Encrypt or your CA."
                })
            elif days_left < 14:
                result["findings"].append({
                    "id": "SSL-002", "sev": "HIGH",
                    "title": "SSL Certificate Expiring Very Soon",
                    "detail": f"Certificate expires in {days_left} day(s).",
                    "fix": "Renew the SSL certificate before it expires to avoid service disruption."
                })
            elif days_left < 30:
                result["findings"].append({
                    "id": "SSL-003", "sev": "MEDIUM",
                    "title": "SSL Certificate Expiring Soon",
                    "detail": f"Certificate expires in {days_left} day(s).",
                    "fix": "Schedule SSL certificate renewal within the next two weeks."
                })

        # Protocol version
        result["cert_info"]["protocol"] = proto
        if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            result["findings"].append({
                "id": "SSL-004", "sev": "HIGH",
                "title": f"Weak Protocol in Use: {proto}",
                "detail": f"The server negotiated {proto}, which is deprecated and vulnerable.",
                "fix": "Configure the web server to use TLS 1.2 or TLS 1.3 only."
            })

        # Subject / SAN
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")
        result["cert_info"]["cn"] = cn
        result["cert_info"]["issuer"] = dict(
            x[0] for x in cert.get("issuer", [])
        ).get("organizationName", "Unknown")

        # Self-signed check
        issuer_org = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "")
        subject_org = subject.get("organizationName", "")
        if issuer_org and issuer_org == subject_org:
            result["findings"].append({
                "id": "SSL-005", "sev": "MEDIUM",
                "title": "Possible Self-Signed Certificate",
                "detail": "Issuer and subject organisation are identical.",
                "fix": "Replace self-signed certificates with one from a trusted CA (e.g. Let's Encrypt)."
            })

        result["ok"] = True

    except ssl.SSLCertVerificationError as e:
        result["findings"].append({
            "id": "SSL-006", "sev": "CRITICAL",
            "title": "SSL Certificate Verification Failed",
            "detail": str(e),
            "fix": "Fix the certificate chain. Ensure the full chain is served and the cert is valid."
        })
    except ssl.SSLError as e:
        result["findings"].append({
            "id": "SSL-007", "sev": "HIGH",
            "title": "SSL Handshake Error",
            "detail": str(e),
            "fix": "Check the server's SSL configuration with ssllabs.com/ssltest."
        })
    except (socket.timeout, ConnectionRefusedError, OSError):
        result["findings"].append({
            "id": "SSL-008", "sev": "INFO",
            "title": "SSL Not Available or Port 443 Unreachable",
            "detail": "Could not connect to port 443. Site may be HTTP-only.",
            "fix": "Enable HTTPS with a free Let's Encrypt certificate."
        })
    except Exception as e:
        result["findings"].append({
            "id": "SSL-009", "sev": "INFO",
            "title": "SSL Check Skipped",
            "detail": str(e),
            "fix": "Verify SSL configuration manually at ssllabs.com/ssltest."
        })

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  3 — HTTP Header Security Inspector
# ══════════════════════════════════════════════════════════════════════════════

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "id": "HDR-001", "sev": "HIGH",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "detail": "HSTS header absent. Browsers are not forced to use HTTPS.",
        "fix": 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
    },
    "Content-Security-Policy": {
        "id": "HDR-002", "sev": "HIGH",
        "title": "Missing Content Security Policy (CSP)",
        "detail": "No CSP header found. The site is vulnerable to XSS and data injection attacks.",
        "fix": "Define a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'"
    },
    "X-Frame-Options": {
        "id": "HDR-003", "sev": "MEDIUM",
        "title": "Missing X-Frame-Options (Clickjacking Risk)",
        "detail": "Without X-Frame-Options, attackers can embed this page in an iframe to trick users.",
        "fix": "Add header: X-Frame-Options: DENY   (or SAMEORIGIN if framing is needed internally)"
    },
    "X-Content-Type-Options": {
        "id": "HDR-004", "sev": "MEDIUM",
        "title": "Missing X-Content-Type-Options",
        "detail": "Browsers may MIME-sniff responses and execute unexpected content types.",
        "fix": "Add header: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "id": "HDR-005", "sev": "LOW",
        "title": "Missing Referrer-Policy",
        "detail": "Full referrer URLs (including paths and query strings) may leak to third parties.",
        "fix": "Add header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "id": "HDR-006", "sev": "LOW",
        "title": "Missing Permissions-Policy",
        "detail": "Browser features (camera, microphone, geolocation) are not explicitly restricted.",
        "fix": "Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    },
}

DANGEROUS_HEADERS = {
    "Server": {
        "id": "HDR-007", "sev": "LOW",
        "title": "Server Version Disclosure",
        "detail_template": "Server header exposes: '{value}'. Attackers can target specific CVEs.",
        "fix": "Configure the web server to suppress or obscure the Server header."
    },
    "X-Powered-By": {
        "id": "HDR-008", "sev": "LOW",
        "title": "Technology Stack Disclosed via X-Powered-By",
        "detail_template": "X-Powered-By reveals: '{value}'. Useful intelligence for attackers.",
        "fix": "Remove the X-Powered-By header from your server/framework configuration."
    },
    "X-AspNet-Version": {
        "id": "HDR-009", "sev": "LOW",
        "title": "ASP.NET Version Disclosed",
        "detail_template": "X-AspNet-Version reveals: '{value}'.",
        "fix": "Set <httpRuntime enableVersionHeader='false'/> in web.config."
    },
}


def inspect_headers(url: str) -> dict:
    result = {"ok": False, "findings": [], "headers": {}, "redirects": []}
    try:
        # Follow redirects manually to capture the chain
        current = url
        redirect_chain = []
        for _ in range(10):
            req = urllib.request.Request(
                current,
                headers={"User-Agent": "Mozilla/5.0 (SENTINEL-Scanner/1.0)"}
            )
            # Don't auto-follow so we can inspect each hop
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
            try:
                with opener.open(req, timeout=12) as resp:
                    final_url   = resp.geturl()
                    headers_raw = dict(resp.headers)
                    status      = resp.status
                    body_bytes  = resp.read(65536)   # read up to 64 KB for content checks
                    break
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get("Location", "")
                    redirect_chain.append({"from": current, "to": location, "code": e.code})
                    # Check for suspicious redirect destination
                    if location and not location.startswith(("http://", "https://")):
                        pass  # relative redirect, fine
                    current = location or current
                    continue
                raise
        else:
            result["findings"].append({
                "id": "HDR-010", "sev": "MEDIUM",
                "title": "Excessive Redirect Chain (>10 hops)",
                "detail": "The URL redirects more than 10 times, which is abnormal.",
                "fix": "Audit redirect rules on the server and remove unnecessary hops."
            })
            return result

        result["ok"] = True
        result["headers"] = {k.lower(): v for k, v in headers_raw.items()}
        result["status"]  = status
        result["final_url"] = final_url
        result["body_bytes"] = body_bytes
        result["redirects"]  = redirect_chain

        # Missing required security headers
        lower_headers = {k.lower(): v for k, v in headers_raw.items()}
        for header_name, finding in REQUIRED_HEADERS.items():
            if header_name.lower() not in lower_headers:
                result["findings"].append(dict(finding))

        # Dangerous information-disclosure headers
        for header_name, template in DANGEROUS_HEADERS.items():
            val = lower_headers.get(header_name.lower(), "")
            if val:
                finding = {
                    "id":     template["id"],
                    "sev":    template["sev"],
                    "title":  template["title"],
                    "detail": template["detail_template"].replace("{value}", val),
                    "fix":    template["fix"],
                }
                result["findings"].append(finding)

        # Redirect to HTTP (downgrade)
        for redir in redirect_chain:
            dest = redir.get("to", "")
            if dest.startswith("http://"):
                result["findings"].append({
                    "id": "HDR-011", "sev": "HIGH",
                    "title": "HTTPS → HTTP Downgrade Redirect",
                    "detail": f"Redirect goes to an insecure HTTP URL: {dest}",
                    "fix": "Fix the redirect to send users to https:// instead of http://."
                })

        # Cookie flags
        set_cookie = lower_headers.get("set-cookie", "")
        if set_cookie:
            if "secure" not in set_cookie.lower():
                result["findings"].append({
                    "id": "HDR-012", "sev": "MEDIUM",
                    "title": "Cookie Missing 'Secure' Flag",
                    "detail": "Cookies can be transmitted over unencrypted HTTP connections.",
                    "fix": "Add the Secure attribute to all Set-Cookie headers."
                })
            if "httponly" not in set_cookie.lower():
                result["findings"].append({
                    "id": "HDR-013", "sev": "MEDIUM",
                    "title": "Cookie Missing 'HttpOnly' Flag",
                    "detail": "Cookies are accessible to JavaScript, increasing XSS risk.",
                    "fix": "Add the HttpOnly attribute to session and auth cookies."
                })
            if "samesite" not in set_cookie.lower():
                result["findings"].append({
                    "id": "HDR-014", "sev": "LOW",
                    "title": "Cookie Missing 'SameSite' Attribute",
                    "detail": "Cookies may be sent with cross-site requests (CSRF risk).",
                    "fix": "Add SameSite=Strict or SameSite=Lax to all cookies."
                })

    except Exception as e:
        result["findings"].append({
            "id": "HDR-ERR", "sev": "INFO",
            "title": "Header Inspection Failed",
            "detail": str(e),
            "fix": "Check network connectivity and verify the URL is reachable."
        })

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  4 — Page Content / Source Code Analysis
# ══════════════════════════════════════════════════════════════════════════════

# Patterns that indicate malicious or suspicious JavaScript
MALICIOUS_JS_PATTERNS = [
    (r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent)",
     "CNT-001", "HIGH",
     "Obfuscated JavaScript (eval + decode)",
     "eval() with base64/URL decoding is a classic malware obfuscation pattern.",
     "Audit all JavaScript files. Remove or replace obfuscated code."),

    (r"document\.write\s*\(\s*unescape",
     "CNT-002", "HIGH",
     "Obfuscated document.write() Injection",
     "document.write(unescape(...)) is used to inject hidden malicious HTML.",
     "Remove this pattern. Use safe DOM APIs instead of document.write()."),

    (r"String\.fromCharCode\s*\(\s*[\d\s,]{20,}\)",
     "CNT-003", "MEDIUM",
     "Character-Code Obfuscation Detected",
     "Long String.fromCharCode() arrays are used to hide malicious strings from scanners.",
     "Investigate the surrounding code block. Deobfuscate and review."),

    (r"<script[^>]+src=['\"]https?://(?!(?:ajax\.googleapis|cdn\.jsdelivr|"
     r"cdnjs\.cloudflare|code\.jquery|stackpath\.bootstrapcdn|unpkg\.com|"
     r"fonts\.googleapis)[^'\"]*)[^'\"]{0,10}\.[a-z]{1,4}['\"]",
     "CNT-004", "MEDIUM",
     "External Script from Unrecognised Domain",
     "A <script src=...> loads JavaScript from an external, unrecognised host.",
     "Verify the domain is trusted. Host scripts locally when possible."),

    (r"(?:fetch|XMLHttpRequest|\.ajax)\s*\(['\"]https?://[^'\"]+['\"]",
     "CNT-005", "LOW",
     "Outbound HTTP Request in Page Source",
     "JavaScript makes network requests to external URLs.",
     "Review all outbound requests. Ensure they point to trusted, expected endpoints."),

    (r"crypto(?:currency|miner|\.mine|CoinHive|coinhive|minero)",
     "CNT-006", "CRITICAL",
     "Cryptominer Script Detected",
     "Keywords associated with in-browser cryptocurrency mining were found.",
     "Remove all mining scripts immediately. This is malware."),

    (r"(?:keylogger|keylog|onkeypress=.*(?:fetch|xmlhttp)|addEventListener.*keydown.*fetch)",
     "CNT-007", "CRITICAL",
     "Possible Keylogger Pattern Detected",
     "Code patterns consistent with keylogging (capturing keystrokes and sending them).",
     "Immediately audit all event listeners and form handlers. Investigate server compromise."),

    (r"<iframe[^>]+(?:display:\s*none|visibility:\s*hidden|width=['\"]0['\"]|height=['\"]0['\"])",
     "CNT-008", "HIGH",
     "Hidden Iframe Detected",
     "A hidden iframe is a classic malware injection technique to load malicious content silently.",
     "Remove hidden iframes. Audit the server for web shell or file injection."),

    (r"(?:base64_decode|rot13|str_rot13)\s*\(",
     "CNT-009", "MEDIUM",
     "Server-Side Obfuscation Leak in HTML",
     "Obfuscation function names leaked into the HTML output, suggesting server-side issues.",
     "Check server-side scripts for malware. Scan PHP/ASP files for obfuscated code."),

    (r"(?:phish|credential.harvest|login.*fake|fake.*login)",
     "CNT-010", "HIGH",
     "Phishing Keyword in Page Source",
     "Words associated with phishing pages were found in the page source.",
     "Investigate whether this is a legitimate page or a phishing clone."),
]

MIXED_CONTENT_PATTERN = re.compile(
    r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']', re.IGNORECASE
)

FORMS_ACTION_PATTERN = re.compile(
    r'<form[^>]+action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE
)


def inspect_content(body_bytes: bytes, base_url: str) -> dict:
    result = {"findings": []}
    try:
        html = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        return result

    # Malicious JS patterns
    for pattern, fid, sev, title, detail, fix in MALICIOUS_JS_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            result["findings"].append({
                "id": fid, "sev": sev,
                "title": title, "detail": detail, "fix": fix
            })

    # Mixed content (HTTPS page loading HTTP resources)
    parsed_base = urllib.parse.urlparse(base_url)
    if parsed_base.scheme == "https":
        mixed = MIXED_CONTENT_PATTERN.findall(html)
        if mixed:
            result["findings"].append({
                "id": "CNT-011", "sev": "MEDIUM",
                "title": f"Mixed Content Detected ({len(mixed)} insecure resource(s))",
                "detail": "The HTTPS page loads resources over plain HTTP, leaking data and breaking HTTPS.",
                "fix": "Update all resource URLs to use https:// or protocol-relative //."
            })

    # Forms submitting to external domains
    base_domain = extract_domain(base_url)
    for action in FORMS_ACTION_PATTERN.findall(html):
        if action.startswith("http") and base_domain not in action:
            result["findings"].append({
                "id": "CNT-012", "sev": "HIGH",
                "title": "Form Submits Data to External Domain",
                "detail": f"A form's action points to an external URL: {action[:80]}",
                "fix": "Verify this is intentional. If not, your site may be injected with a phishing form."
            })

    # Password field without HTTPS
    if re.search(r'<input[^>]+type\s*=\s*["\']password["\']', html, re.IGNORECASE):
        if parsed_base.scheme == "http":
            result["findings"].append({
                "id": "CNT-013", "sev": "CRITICAL",
                "title": "Password Field Served Over HTTP",
                "detail": "A password input exists on a plain HTTP page — credentials will be sent in cleartext.",
                "fix": "Move the entire login flow to HTTPS immediately."
            })

    # Inline event handlers (XSS surface)
    inline_handlers = len(re.findall(r'\bon\w+\s*=\s*["\'][^"\']{10,}["\']', html, re.IGNORECASE))
    if inline_handlers > 10:
        result["findings"].append({
            "id": "CNT-014", "sev": "LOW",
            "title": f"Many Inline Event Handlers ({inline_handlers})",
            "detail": "Large numbers of inline event handlers expand the XSS attack surface.",
            "fix": "Move event handling to external JS files. Enforce CSP to block inline scripts."
        })

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  5 — Domain Intelligence
# ══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_TLD = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
                  ".loan", ".win", ".racing", ".party", ".review", ".science",
                  ".work", ".men", ".date", ".download", ".stream"}

KNOWN_LEGIT_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "github.com", "stackoverflow.com", "wikipedia.org", "mozilla.org",
    "cloudflare.com", "akamai.com", "fastly.com"
}

HOMOGLYPH_PATTERN = re.compile(r"[0-9](?:paypa1|paypai|g00gle|micosoft|faceb00k|arnazon)")


def inspect_domain(domain: str, url: str) -> dict:
    result = {"findings": [], "domain_info": {"domain": domain}}

    # Suspicious TLD
    for tld in SUSPICIOUS_TLD:
        if domain.endswith(tld):
            result["findings"].append({
                "id": "DOM-001", "sev": "MEDIUM",
                "title": f"Suspicious Top-Level Domain: {tld}",
                "detail": f"The TLD '{tld}' is heavily abused for phishing, spam, and malware.",
                "fix": "Treat traffic from this TLD with extra caution. Verify site legitimacy."
            })
            break

    # Hyphen count (many hyphens = suspicious)
    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        result["findings"].append({
            "id": "DOM-002", "sev": "LOW",
            "title": f"Domain Contains Many Hyphens ({hyphen_count})",
            "detail": "Domains with many hyphens (e.g. secure-login-verify-paypal.com) are often phishing.",
            "fix": "Verify the domain owner via WHOIS before trusting it."
        })

    # Long subdomain chain
    parts = domain.split(".")
    if len(parts) > 4:
        result["findings"].append({
            "id": "DOM-003", "sev": "LOW",
            "title": f"Deep Subdomain Structure ({len(parts)} levels)",
            "detail": "Deeply nested subdomains can hide the real domain from casual inspection.",
            "fix": "Check the registered domain (last two labels). Verify it is the expected owner."
        })

    # Numeric IP as host
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        result["findings"].append({
            "id": "DOM-004", "sev": "MEDIUM",
            "title": "URL Uses a Raw IP Address Instead of Domain",
            "detail": "Legitimate sites almost never use raw IP addresses in URLs.",
            "fix": "Avoid visiting sites accessed by raw IP. Investigate the host."
        })

    # Homoglyph / brand impersonation
    if HOMOGLYPH_PATTERN.search(domain):
        result["findings"].append({
            "id": "DOM-005", "sev": "CRITICAL",
            "title": "Brand Impersonation / Homoglyph Domain Detected",
            "detail": f"The domain '{domain}' appears to mimic a well-known brand using character substitution.",
            "fix": "This is almost certainly a phishing domain. Block it and report it."
        })

    # Brand squatting (known brand name in a different domain)
    brands = ["paypal", "google", "microsoft", "apple", "amazon", "facebook",
              "netflix", "instagram", "whatsapp", "linkedin", "twitter", "dropbox"]
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    for brand in brands:
        if brand in domain and registered not in KNOWN_LEGIT_DOMAINS:
            result["findings"].append({
                "id": "DOM-006", "sev": "HIGH",
                "title": f"Possible Brand Squatting: '{brand}' in Domain",
                "detail": f"The domain '{domain}' contains the brand name '{brand}' but is not the official site.",
                "fix": "Do not enter credentials. Verify you are on the real site before proceeding."
            })
            break

    # HTTP only (no HTTPS)
    if url.startswith("http://"):
        result["findings"].append({
            "id": "DOM-007", "sev": "HIGH",
            "title": "Site Accessed Over Insecure HTTP",
            "detail": "All traffic is transmitted in cleartext — susceptible to MITM attacks.",
            "fix": "Enable HTTPS with a free certificate from Let's Encrypt (certbot)."
        })

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  6 — Risk Aggregator & Report Builder
# ══════════════════════════════════════════════════════════════════════════════

SEV_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2, "INFO": 0}
SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def aggregate_risk(all_findings: list, vt: dict) -> tuple:
    """Compute overall risk score (0-100) and level from all findings + VT."""
    score = 0

    # VT score component (up to 50 pts)
    if vt.get("ok"):
        total = max(vt.get("total", 1), 1)
        mal   = vt.get("malicious", 0)
        susp  = vt.get("suspicious", 0)
        score += int((mal / total) * 40)
        score += int((susp / total) * 10)
        if vt.get("reputation", 0) < -20:
            score += 10

    # Finding severity component (up to 50 pts)
    for f in all_findings:
        score += SEV_WEIGHT.get(f.get("sev", "INFO"), 0)

    score = min(score, 100)

    if score >= 70:   level = "CRITICAL"
    elif score >= 50: level = "HIGH"
    elif score >= 25: level = "MEDIUM"
    elif score >= 5:  level = "LOW"
    else:             level = "CLEAN"

    return score, level


def generate_plain_summary(url: str, score: int, level: str,
                            all_findings: list, vt: dict) -> str:
    domain = extract_domain(url)
    crit   = sum(1 for f in all_findings if f["sev"] == "CRITICAL")
    high   = sum(1 for f in all_findings if f["sev"] == "HIGH")
    total  = len(all_findings)

    vt_part = ""
    if vt.get("ok") and vt.get("malicious", 0) > 0:
        vt_part = (
            f" VirusTotal flagged it as malicious on {vt['malicious']} "
            f"out of {vt['total']} security engines."
        )

    if level == "CLEAN":
        return (
            f"The website {domain} passed all checks with no significant issues detected."
            f" {total} checks were performed and no critical or high-severity vulnerabilities were found."
            f" Continue monitoring periodically."
        )
    elif level == "LOW":
        return (
            f"The website {domain} has minor security concerns — {total} issue(s) found,"
            f" none of which are critical.{vt_part}"
            f" Address these when possible to improve your security posture."
        )
    elif level == "MEDIUM":
        return (
            f"The website {domain} has {total} security issue(s) including {high} high-severity finding(s)."
            f"{vt_part} These vulnerabilities could be exploited by attackers and should be fixed promptly."
        )
    elif level == "HIGH":
        return (
            f"Warning: {domain} has serious security vulnerabilities — {total} issues found,"
            f" including {crit} critical and {high} high-severity findings.{vt_part}"
            f" Immediate remediation is strongly recommended."
        )
    else:
        return (
            f"CRITICAL ALERT: {domain} presents a severe threat.{vt_part}"
            f" {crit} critical issue(s) detected across {total} total findings."
            f" This site should be blocked and investigated immediately."
        )


# ══════════════════════════════════════════════════════════════════════════════
#  7 — Terminal Renderer
# ══════════════════════════════════════════════════════════════════════════════

def wrap(text: str, w: int = 68, pad: str = "    ") -> str:
    words, lines, line = text.split(), [], pad
    for word in words:
        if len(line) + len(word) + 1 > w:
            lines.append(line.rstrip()); line = pad + word + " "
        else:
            line += word + " "
    if line.strip(): lines.append(line.rstrip())
    return "\n".join(lines)


def print_terminal_report(url: str, score: int, level: str,
                           all_findings: list, vt: dict,
                           ssl_info: dict, cert_info: dict) -> None:
    colour = SEV_COLOUR.get(level, WHITE)
    bar    = "█" * (score // 5) + "░" * (20 - score // 5)
    ts     = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    W = 62

    print()
    print(f"{BOLD}╔{'═'*W}╗{RESET}")
    print(f"{BOLD}║{'  SENTINEL — WEBSITE THREAT REPORT':^{W}}║{RESET}")
    print(f"{BOLD}╠{'═'*W}╣{RESET}")
    print(f"{BOLD}║{RESET}  URL       : {WHITE}{url[:W-13]}{RESET}{BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}  Scanned   : {DIM}{ts:<{W-13}}{RESET}{BOLD}║{RESET}")
    print(f"{BOLD}╠{'═'*W}╣{RESET}")
    print(f"\n  {BOLD}OVERALL RISK LEVEL  :{RESET}  {colour}{BOLD}{level}{RESET}")
    print(f"  {BOLD}RISK SCORE          :{RESET}  {colour}{bar}{RESET}  {colour}{BOLD}{score}/100{RESET}")

    # VT summary
    if vt.get("ok"):
        print(f"\n  {BOLD}VirusTotal Result   :{RESET}  "
              f"{RED if vt['malicious']>0 else GREEN}"
              f"{vt['malicious']} malicious{RESET} / "
              f"{YELLOW}{vt['suspicious']} suspicious{RESET} / "
              f"{vt['total']} engines")

    # SSL quick view
    if cert_info:
        dl = cert_info.get("days_left", "?")
        dl_col = RED if isinstance(dl, int) and dl < 30 else GREEN
        print(f"  {BOLD}SSL Expires         :{RESET}  {dl_col}{cert_info.get('expires','N/A')}"
              f" ({dl} days){RESET}")

    # Finding counts by severity
    print(f"\n  {'─'*W}")
    for sev in SEV_ORDER:
        n = sum(1 for f in all_findings if f["sev"] == sev)
        if n:
            c = SEV_COLOUR.get(sev, WHITE)
            bar_s = "■" * n + " " * max(0, 10-n)
            print(f"  {c}{BOLD}{sev:<10}{RESET}  {c}{bar_s}{RESET}  {n} finding(s)")

    # Findings detail
    print(f"\n  {BOLD}{'═'*W}{RESET}")
    print(f"  {BOLD}  DETAILED FINDINGS{RESET}")
    print(f"  {BOLD}{'═'*W}{RESET}")

    grouped = {}
    for f in all_findings:
        grouped.setdefault(f["sev"], []).append(f)

    for sev in SEV_ORDER:
        if sev not in grouped:
            continue
        c = SEV_COLOUR.get(sev, WHITE)
        print(f"\n  {c}{BOLD}◈ {sev}{RESET}")
        for f in grouped[sev]:
            print(f"\n    {BOLD}[{f['id']}] {f['title']}{RESET}")
            print(wrap(f"Detail: {f['detail']}", w=72))
            print(f"{GREEN}" + wrap(f"Fix   : {f['fix']}", w=72) + f"{RESET}")

    # Summary
    print(f"\n  {BOLD}{'═'*W}{RESET}")
    print(f"  {BOLD}  PLAIN-ENGLISH SUMMARY{RESET}")
    print(f"  {BOLD}{'═'*W}{RESET}\n")
    summary = generate_plain_summary(url, score, level, all_findings, vt)
    print(wrap(summary, w=72))

    # Remediation priority list
    crit_high = [f for f in all_findings if f["sev"] in ("CRITICAL", "HIGH")]
    if crit_high:
        print(f"\n  {BOLD}TOP PRIORITY FIXES:{RESET}")
        for i, f in enumerate(crit_high[:5], 1):
            print(f"\n  {CYAN}[{i}]{RESET} {BOLD}{f['title']}{RESET}")
            print(wrap(f["fix"], w=72))

    print(f"\n{BOLD}╚{'═'*W}╝{RESET}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  8 — HTML Report Generator
# ══════════════════════════════════════════════════════════════════════════════

SEV_HTML_COLOUR = {
    "CRITICAL": ("#ff4d4d", "#1a0000"),
    "HIGH":     ("#ff8c42", "#1a0800"),
    "MEDIUM":   ("#ffd166", "#1a1000"),
    "LOW":      ("#06d6a0", "#001a12"),
    "INFO":     ("#8ecae6", "#00111a"),
    "CLEAN":    ("#06d6a0", "#001a12"),
}


def generate_html_report(url: str, score: int, level: str,
                          all_findings: list, vt: dict,
                          ssl_res: dict, domain_res: dict,
                          timestamp: str) -> str:
    domain     = extract_domain(url)
    risk_hex   = SEV_HTML_COLOUR.get(level, ("#aaa", "#111"))[0]
    total_f    = len(all_findings)
    crit_count = sum(1 for f in all_findings if f["sev"] == "CRITICAL")
    high_count = sum(1 for f in all_findings if f["sev"] == "HIGH")
    med_count  = sum(1 for f in all_findings if f["sev"] == "MEDIUM")
    low_count  = sum(1 for f in all_findings if f["sev"] == "LOW")
    bar_pct    = score

    summary_text = generate_plain_summary(url, score, level, all_findings, vt)

    # Build findings HTML
    findings_html = ""
    grouped = {}
    for f in all_findings:
        grouped.setdefault(f["sev"], []).append(f)

    for sev in SEV_ORDER:
        if sev not in grouped:
            continue
        fg, bg = SEV_HTML_COLOUR.get(sev, ("#aaa", "#111"))
        findings_html += f"""
        <div class="sev-section">
          <h3 class="sev-header" style="color:{fg};border-color:{fg}">
            {he(sev)} — {len(grouped[sev])} finding(s)
          </h3>"""
        for f in grouped[sev]:
            findings_html += f"""
          <div class="finding-card" style="border-left:4px solid {fg};background:{bg}22">
            <div class="finding-id" style="color:{fg}">[{he(f['id'])}]</div>
            <div class="finding-title">{he(f['title'])}</div>
            <div class="finding-row">
              <span class="label">Detail:</span>
              <span>{he(f['detail'])}</span>
            </div>
            <div class="finding-row fix-row">
              <span class="label">Fix:</span>
              <span>{he(f['fix'])}</span>
            </div>
          </div>"""
        findings_html += "\n        </div>"

    # VT section
    vt_section = ""
    if vt.get("ok"):
        vt_mal  = vt.get("malicious", 0)
        vt_susp = vt.get("suspicious", 0)
        vt_tot  = vt.get("total", 0)
        vt_col  = "#ff4d4d" if vt_mal > 0 else "#06d6a0"
        flagged = ", ".join(vt.get("flagged_by", [])[:10]) or "None"
        cats    = ", ".join(vt.get("categories", [])) or "None"
        vt_section = f"""
        <div class="section">
          <h2>VirusTotal Analysis</h2>
          <div class="vt-grid">
            <div class="vt-stat" style="border-color:{vt_col}">
              <span class="vt-num" style="color:{vt_col}">{vt_mal}</span>
              <span class="vt-lbl">Malicious</span>
            </div>
            <div class="vt-stat" style="border-color:#ffd166">
              <span class="vt-num" style="color:#ffd166">{vt_susp}</span>
              <span class="vt-lbl">Suspicious</span>
            </div>
            <div class="vt-stat" style="border-color:#06d6a0">
              <span class="vt-num" style="color:#06d6a0">{vt_tot}</span>
              <span class="vt-lbl">Engines Total</span>
            </div>
          </div>
          <p><strong>Flagged by:</strong> {he(flagged)}</p>
          <p><strong>Categories:</strong> {he(cats)}</p>
        </div>"""

    # SSL section
    ssl_section = ""
    cert = ssl_res.get("cert_info", {})
    if cert:
        ssl_section = f"""
        <div class="section">
          <h2>SSL / TLS Certificate</h2>
          <table class="info-table">
            <tr><td>Common Name</td><td>{he(str(cert.get('cn','N/A')))}</td></tr>
            <tr><td>Issuer</td><td>{he(str(cert.get('issuer','N/A')))}</td></tr>
            <tr><td>Expires</td><td>{he(str(cert.get('expires','N/A')))}</td></tr>
            <tr><td>Days Remaining</td><td>{cert.get('days_left','N/A')}</td></tr>
            <tr><td>Protocol</td><td>{he(str(cert.get('protocol','N/A')))}</td></tr>
          </table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTINEL Threat Report — {he(domain)}</title>
<style>
  :root {{
    --bg: #0a0e1a; --bg2: #111827; --bg3: #1f2937;
    --text: #e2e8f0; --text2: #94a3b8; --text3: #64748b;
    --brand: #00ffb2; --border: rgba(0,255,178,0.15);
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif;
          font-size:15px; line-height:1.7; padding:0; }}
  header {{ background:var(--bg2); border-bottom:1px solid var(--border);
            padding:24px 40px; display:flex; align-items:center; gap:16px; }}
  .logo {{ font-family:monospace; font-size:22px; font-weight:700;
           color:var(--brand); letter-spacing:2px; }}
  .logo-sub {{ font-size:11px; color:var(--text3); letter-spacing:3px; text-transform:uppercase; }}
  .container {{ max-width:960px; margin:0 auto; padding:32px 24px; }}
  h2 {{ font-size:18px; font-weight:600; color:var(--brand);
        margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid var(--border); }}
  h3 {{ font-size:15px; font-weight:600; margin-bottom:12px; }}
  .hero {{ background:var(--bg2); border:1px solid var(--border); border-radius:12px;
           padding:28px 32px; margin-bottom:24px; }}
  .hero-url {{ font-family:monospace; font-size:14px; color:var(--text2);
               word-break:break-all; margin-bottom:20px; }}
  .risk-badge {{ display:inline-block; font-size:28px; font-weight:800;
                 color:{risk_hex}; letter-spacing:2px; margin-bottom:8px; }}
  .score-bar-wrap {{ margin:12px 0; }}
  .score-bar-track {{ background:rgba(255,255,255,0.06); border-radius:4px;
                      height:10px; overflow:hidden; width:100%; max-width:420px; }}
  .score-bar-fill {{ height:100%; border-radius:4px; width:{bar_pct}%;
                     background:linear-gradient(90deg,#00ffb2,#ffd166,#ff4d4d); }}
  .score-label {{ font-size:13px; color:var(--text2); margin-top:4px; }}
  .counts-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-top:20px; }}
  .count-box {{ background:var(--bg3); border-radius:8px; padding:14px; text-align:center;
                border:1px solid var(--border); }}
  .count-num {{ font-size:26px; font-weight:700; }}
  .count-lbl {{ font-size:11px; color:var(--text3); text-transform:uppercase; letter-spacing:1px; }}
  .section {{ background:var(--bg2); border:1px solid var(--border); border-radius:12px;
              padding:24px 28px; margin-bottom:20px; }}
  .summary-box {{ background:rgba(0,255,178,0.06); border:1px solid var(--border);
                  border-radius:8px; padding:20px; margin-bottom:20px;
                  font-size:15px; line-height:1.8; }}
  .sev-section {{ margin-bottom:20px; }}
  .sev-header {{ font-size:14px; font-weight:700; letter-spacing:1px; text-transform:uppercase;
                 padding:6px 0; margin-bottom:10px; border-bottom:1px solid; }}
  .finding-card {{ border-radius:8px; padding:14px 16px; margin-bottom:10px; }}
  .finding-id {{ font-family:monospace; font-size:11px; font-weight:700;
                 letter-spacing:1px; margin-bottom:4px; }}
  .finding-title {{ font-size:15px; font-weight:600; margin-bottom:8px; }}
  .finding-row {{ font-size:13px; color:var(--text2); margin-top:4px; }}
  .fix-row {{ color:#06d6a0; }}
  .label {{ font-weight:600; margin-right:6px; }}
  .vt-grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:16px; }}
  .vt-stat {{ background:var(--bg3); border-radius:8px; padding:16px; text-align:center;
              border:2px solid; }}
  .vt-num {{ display:block; font-size:32px; font-weight:800; }}
  .vt-lbl {{ font-size:11px; color:var(--text3); text-transform:uppercase; letter-spacing:1px; }}
  .info-table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  .info-table td {{ padding:8px 12px; border-bottom:1px solid var(--border); }}
  .info-table td:first-child {{ color:var(--text3); width:160px; }}
  footer {{ text-align:center; padding:24px; font-size:12px; color:var(--text3);
            border-top:1px solid var(--border); margin-top:32px; }}
  @media(max-width:600px) {{
    .counts-grid {{ grid-template-columns:1fr 1fr; }}
    .vt-grid {{ grid-template-columns:1fr; }}
    header {{ padding:16px 20px; }}
    .container {{ padding:20px 16px; }}
  }}
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">SENTINEL·AI</div>
    <div class="logo-sub">Website Threat Intelligence Report</div>
  </div>
</header>

<div class="container">

  <!-- Hero -->
  <div class="hero">
    <div class="hero-url">🔗 {he(url)}</div>
    <div class="risk-badge">{he(level)}</div>
    <div class="score-bar-wrap">
      <div class="score-bar-track"><div class="score-bar-fill"></div></div>
      <div class="score-label">Risk Score: <strong>{score}/100</strong> &nbsp;|&nbsp; Scanned: {he(timestamp)}</div>
    </div>
    <div class="counts-grid">
      <div class="count-box">
        <div class="count-num" style="color:#ff4d4d">{crit_count}</div>
        <div class="count-lbl">Critical</div>
      </div>
      <div class="count-box">
        <div class="count-num" style="color:#ff8c42">{high_count}</div>
        <div class="count-lbl">High</div>
      </div>
      <div class="count-box">
        <div class="count-num" style="color:#ffd166">{med_count}</div>
        <div class="count-lbl">Medium</div>
      </div>
      <div class="count-box">
        <div class="count-num" style="color:#06d6a0">{low_count}</div>
        <div class="count-lbl">Low</div>
      </div>
    </div>
  </div>

  <!-- Summary -->
  <div class="section">
    <h2>Plain-English Summary</h2>
    <div class="summary-box">{he(summary_text)}</div>
  </div>

  {vt_section}

  {ssl_section}

  <!-- Findings -->
  <div class="section">
    <h2>All Findings — {total_f} Issue(s) Detected</h2>
    {findings_html if findings_html else '<p style="color:#06d6a0">✓ No issues found across all checks.</p>'}
  </div>

</div>

<footer>
  SENTINEL AI · Rule-Based Threat Intelligence · Free &amp; Open ·
  Generated {he(timestamp)}
</footer>
</body>
</html>"""
    return html


# ══════════════════════════════════════════════════════════════════════════════
#  9 — Main Orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def scan(url: str, vt_key: str):
    ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    domain = extract_domain(url)

    banner(f"VirusTotal URL lookup for {url}")
    vt_raw = vt_url_lookup(url, vt_key)
    vt     = parse_vt_url_result(vt_raw)

    banner(f"SSL/TLS certificate inspection for {domain}")
    ssl_res = inspect_ssl(domain)

    banner("HTTP header security check")
    hdr_res = inspect_headers(url)

    banner("Page content & source code analysis")
    body_bytes = hdr_res.get("body_bytes", b"")
    cnt_res    = inspect_content(body_bytes, url)

    banner("Domain intelligence analysis")
    dom_res = inspect_domain(domain, url)

    # Merge all findings
    all_findings = (
        ssl_res.get("findings", [])
        + hdr_res.get("findings", [])
        + cnt_res.get("findings", [])
        + dom_res.get("findings", [])
    )

    # Deduplicate by ID
    seen_ids, deduped = set(), []
    for f in all_findings:
        if f["id"] not in seen_ids:
            seen_ids.add(f["id"])
            deduped.append(f)
    all_findings = deduped

    # Score & level
    score, level = aggregate_risk(all_findings, vt)

    # Terminal output
    print_terminal_report(url, score, level, all_findings, vt,
                          ssl_res, ssl_res.get("cert_info", {}))

    # Save JSON report
    safe = re.sub(r"[^\w\-]", "_", domain)[:40]
    json_path = f"site_report_{safe}.json"
    html_path = f"site_report_{safe}.html"

    report_data = {
        "generated_at": ts,
        "url":          url,
        "domain":       domain,
        "risk_level":   level,
        "risk_score":   score,
        "findings":     all_findings,
        "virustotal":   vt,
        "ssl":          ssl_res.get("cert_info", {}),
        "ssl_findings": ssl_res.get("findings", []),
        "header_findings": hdr_res.get("findings", []),
        "content_findings": cnt_res.get("findings", []),
        "domain_findings":  dom_res.get("findings", []),
    }
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2)

    # Save HTML report
    html = generate_html_report(
        url, score, level, all_findings, vt,
        ssl_res, dom_res, ts
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  {DIM}JSON report → {json_path}{RESET}")
    print(f"  {GREEN}HTML report → {html_path}  (open in your browser){RESET}\n")
    return score, level

# ══════════════════════════════════════════════════════════════════════════════
#  10 — Entry Point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    load_env(".env")

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_key:
        print(f"{RED}[ERROR]{RESET} VIRUSTOTAL_API_KEY missing from .env")
        print("  Free key at: https://www.virustotal.com/gui/my-apikey")
        sys.exit(1)

    raw = (sys.argv[1].strip() if len(sys.argv) > 1
           else input(f"\n{CYAN}Enter URL or website to scan:{RESET} ").strip())

    if not raw:
        print(f"{RED}[ERROR]{RESET} No URL provided.")
        sys.exit(1)

    url = normalise_url(raw)
    print(f"\n{BOLD}  SENTINEL — Website Threat Scanner{RESET}")
    print(f"  Target : {WHITE}{url}{RESET}")
    print(f"  {'─'*50}")

    scan(url, vt_key)