"""
╔══════════════════════════════════════════════════════════╗
║         SENTINEL — AI Threat Analyzer  v2.0             ║
║         100% Free · No paid APIs · Pure Python          ║
╠══════════════════════════════════════════════════════════╣
║  Only requirement: VIRUSTOTAL_API_KEY in your .env      ║
║  Python standard library only — nothing to install      ║
╚══════════════════════════════════════════════════════════╝

What it does:
  1. Queries VirusTotal for any IP address (free API key)
  2. Runs a rule-based intelligence engine on the raw JSON
  3. Returns:
       - Risk Level     (CRITICAL / HIGH / MEDIUM / LOW / CLEAN)
       - Risk Score     (0-100 with visual bar)
       - Threat Types   (C2 Server, Botnet, Scanner, etc.)
       - Plain-English  (anyone can understand it)
       - Technical Info (for engineers)
       - Remediation    (concrete steps to fix it)
  4. Saves full JSON report to disk

Usage:
    python ai_threat_analyzer.py 8.8.8.8
    python ai_threat_analyzer.py          <- prompts for IP
"""

import os
import sys
import json
import urllib.request
import urllib.error
from datetime import datetime
from url_threat_scanner import scan as scan_url
# ── ANSI terminal colours ──────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
DIM     = "\033[2m"

RISK_COLOUR = {
    "CRITICAL": RED,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "CLEAN":    GREEN,
}

# ══════════════════════════════════════════════════════════════════════════════
#  1 — Environment & VirusTotal
# ══════════════════════════════════════════════════════════════════════════════

def load_env(path: str = ".env") -> None:
    if not os.path.exists(path):
        print(f"{RED}[ERROR]{RESET} .env not found at: {os.path.abspath(path)}")
        sys.exit(1)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(
                    key.strip(),
                    val.strip().strip('"').strip("'")
                )


def virustotal_lookup(ip: str, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"{RED}[HTTP {e.code}]{RESET} {e.reason}")
        try:
            err = json.loads(body)
            print(f"  {err.get('error', {}).get('message', body)}")
        except Exception:
            print(body)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"{RED}[ERROR]{RESET} Network error: {e.reason}")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  2 — Signal Extraction
# ══════════════════════════════════════════════════════════════════════════════

def extract_signals(data: dict) -> dict:
    """Pull every useful field from raw VT JSON into a clean flat dict."""
    attrs   = data.get("data", {}).get("attributes", {})
    stats   = attrs.get("last_analysis_stats", {})
    votes   = attrs.get("total_votes", {})
    results = attrs.get("last_analysis_results", {})

    flagged_engines    = {}
    suspicious_engines = {}
    for engine, r in results.items():
        cat   = r.get("category", "")
        label = (r.get("result") or "").lower()
        if cat == "malicious":
            flagged_engines[engine] = label
        elif cat == "suspicious":
            suspicious_engines[engine] = label

    vendor_categories = [v.lower() for v in attrs.get("categories", {}).values()]
    tags = [t.lower() for t in attrs.get("tags", [])]

    return {
        "ip":         data.get("data", {}).get("id", "N/A"),
        "country":    attrs.get("country", "N/A"),
        "asn":        attrs.get("asn", "N/A"),
        "as_owner":   attrs.get("as_owner", "N/A"),
        "network":    attrs.get("network", "N/A"),
        "reputation": attrs.get("reputation", 0),
        "malicious":  stats.get("malicious",  0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless",   0),
        "undetected": stats.get("undetected", 0),
        "total_engines":   sum(stats.values()),
        "votes_malicious": votes.get("malicious", 0),
        "votes_harmless":  votes.get("harmless",  0),
        "flagged_engines":    flagged_engines,
        "suspicious_engines": suspicious_engines,
        "vendor_categories":  vendor_categories,
        "tags":               tags,
        "all_labels": list(flagged_engines.values()) + list(suspicious_engines.values()),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  3 — Rule-Based Intelligence Engine
# ══════════════════════════════════════════════════════════════════════════════

THREAT_KEYWORD_MAP = [
    (["c2", "command", "control", "botnet", "bot"],        "C2 / Botnet Controller"),
    (["ransomware", "ransom"],                             "Ransomware Infrastructure"),
    (["phish", "phishing"],                                "Phishing Host"),
    (["spam", "spammer", "bulk mail", "mass mail"],        "Spam / Email Abuse"),
    (["scanner", "scanning", "bruteforce",
      "brute-force", "brute force", "credential"],         "Port Scanner / Brute-Force"),
    (["miner", "mining", "cryptominer", "crypto"],         "Crypto Miner"),
    (["malware", "trojan", "virus", "worm",
      "backdoor", "rat", "rootkit", "dropper"],            "Malware Distribution"),
    (["exploit", "shellcode", "payload", "rce"],           "Exploit / Attack Tool"),
    (["proxy", "proxies"],                                 "Open Proxy / Relay"),
    (["tor", "exit node"],                                 "Tor Exit Node"),
    (["vpn"],                                              "VPN / Anonymiser"),
    (["ddos", "dos", "flood"],                             "DDoS Infrastructure"),
    (["adware", "unwanted"],                               "Adware / PUA"),
]

TAG_MAP = {
    "tor":      "Tor Exit Node",
    "vpn":      "VPN / Anonymiser",
    "proxy":    "Open Proxy / Relay",
    "scanner":  "Port Scanner / Brute-Force",
    "botnet":   "C2 / Botnet Controller",
    "c2":       "C2 / Botnet Controller",
    "spam":     "Spam / Email Abuse",
    "phishing": "Phishing Host",
    "malware":  "Malware Distribution",
    "mining":   "Crypto Miner",
    "ddos":     "DDoS Infrastructure",
}


def detect_threat_types(sig: dict) -> list:
    found    = set()
    haystack = sig["all_labels"] + sig["vendor_categories"] + sig["tags"]
    combined = " ".join(haystack).lower()

    for keywords, label in THREAT_KEYWORD_MAP:
        if any(kw in combined for kw in keywords):
            found.add(label)

    for tag in sig["tags"]:
        if tag in TAG_MAP:
            found.add(TAG_MAP[tag])

    return sorted(found) if found else ["No specific threat type identified"]


def calculate_risk_score(sig: dict) -> int:
    """Weighted 0-100 score from malicious ratio, reputation, votes, tags."""
    score = 0
    total = max(sig["total_engines"], 1)

    # Malicious engine ratio — up to 55 pts
    mal_ratio = sig["malicious"] / total
    score += int(mal_ratio * 55)
    if sig["malicious"] >= 20:   score += 10
    elif sig["malicious"] >= 10: score += 5
    elif sig["malicious"] >= 5:  score += 2

    # Reputation score — up to 20 pts
    rep = sig["reputation"]
    if rep < -50:   score += 20
    elif rep < -20: score += 14
    elif rep < -5:  score += 8
    elif rep < 0:   score += 3

    # Community votes — up to 10 pts
    total_votes = sig["votes_malicious"] + sig["votes_harmless"]
    if total_votes > 0:
        score += int((sig["votes_malicious"] / total_votes) * 10)

    # Suspicious engines — up to 10 pts
    score += int((sig["suspicious"] / total) * 10)

    # High-risk tag bonus — up to 5 pts
    HIGH_RISK_TAGS = {"tor", "botnet", "c2", "malware", "ransomware", "ddos"}
    if any(t in HIGH_RISK_TAGS for t in sig["tags"]):
        score += 5

    return min(score, 100)


def determine_risk_level(score: int, sig: dict) -> str:
    if (
        sig["malicious"] >= 20
        or sig["reputation"] <= -75
        or any(t in sig["tags"] for t in ["botnet", "c2", "ransomware"])
    ):
        return "CRITICAL"
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    if score >= 10: return "LOW"
    return "CLEAN"


def assess_confidence(sig: dict) -> str:
    pts = 0
    if sig["total_engines"] >= 50:   pts += 2
    elif sig["total_engines"] >= 20: pts += 1
    if sig["malicious"] + sig["suspicious"] > 5:  pts += 2
    elif sig["malicious"] + sig["suspicious"] > 0: pts += 1
    if sig["votes_malicious"] + sig["votes_harmless"] > 10: pts += 1
    if sig["vendor_categories"]: pts += 1
    if sig["tags"]:              pts += 1
    if pts >= 5: return "HIGH"
    if pts >= 3: return "MEDIUM"
    return "LOW"


# ══════════════════════════════════════════════════════════════════════════════
#  4 — Plain-English Summary Generator
# ══════════════════════════════════════════════════════════════════════════════

def generate_summary(sig: dict, risk_level: str, threat_types: list) -> str:
    ip      = sig["ip"]
    country = sig["country"]
    owner   = sig["as_owner"] or "an unknown organisation"
    mal     = sig["malicious"]
    total   = sig["total_engines"]
    rep     = sig["reputation"]

    if risk_level == "CLEAN":
        opening = (
            f"The IP address {ip} (registered to {owner} in {country}) "
            f"appears clean — none of the {total} security engines flagged it as a threat."
        )
    elif risk_level == "LOW":
        opening = (
            f"The IP address {ip} ({owner}, {country}) raised minor concern — "
            f"{mal} out of {total} security engines reported suspicious activity, "
            f"which may be a false positive or low-level risk."
        )
    elif risk_level == "MEDIUM":
        opening = (
            f"The IP address {ip} ({owner}, {country}) has been flagged by "
            f"{mal} out of {total} security vendors, suggesting a real but moderate threat."
        )
    elif risk_level == "HIGH":
        opening = (
            f"Warning: the IP address {ip} ({owner}, {country}) is considered dangerous — "
            f"{mal} out of {total} security engines have confirmed it as malicious."
        )
    else:
        opening = (
            f"Critical threat: {ip} ({owner}, {country}) is widely confirmed as highly "
            f"malicious by {mal} out of {total} security engines and should be blocked immediately."
        )

    known = [t for t in threat_types if t != "No specific threat type identified"]
    if known:
        middle = f"It has been associated with: {', '.join(known[:3])}."
    else:
        middle = "No specific attack category has been confirmed, but general malicious behaviour was detected."

    if rep < -50:
        closing = "Its reputation score is severely negative, indicating a long history of abuse."
    elif rep < 0:
        closing = "Its reputation score is negative, suggesting a history of reported abuse."
    elif rep > 0:
        closing = "Its reputation score is positive, which slightly reduces concern."
    else:
        closing = "No strong reputation history exists for this IP."

    return f"{opening} {middle} {closing}"


def generate_technical_detail(sig: dict) -> str:
    engine_list = list(sig["flagged_engines"].keys())[:5]
    engines_str = ", ".join(engine_list) if engine_list else "none"
    rep_note    = f"VT reputation: {sig['reputation']}. " if sig["reputation"] != 0 else "VT reputation score is neutral (0). "
    vote_note   = ""
    if sig["votes_malicious"] or sig["votes_harmless"]:
        vote_note = (
            f"Community votes — malicious: {sig['votes_malicious']}, "
            f"harmless: {sig['votes_harmless']}. "
        )
    engine_note = (
        f"Flagging engines include: {engines_str}."
        if engine_list else
        "No engines returned positive malicious flags."
    )
    tags_note = f" VT tags: {', '.join(sig['tags'])}." if sig["tags"] else ""
    return f"{rep_note}{vote_note}{engine_note}{tags_note}"


# ══════════════════════════════════════════════════════════════════════════════
#  5 — Remediation Playbooks
# ══════════════════════════════════════════════════════════════════════════════

THREAT_PLAYBOOKS = {
    "C2 / Botnet Controller": [
        "Block this IP immediately at your perimeter firewall (ingress + egress).",
        "Search all endpoint and DNS logs for any past connections to this IP.",
        "Isolate any internal host that contacted it and run a full malware scan.",
        "Check running processes and scheduled tasks on affected hosts for persistence.",
        "Reset credentials for any accounts active on potentially compromised machines.",
    ],
    "Ransomware Infrastructure": [
        "Block this IP at the firewall immediately — do not delay.",
        "Scan all hosts for ransomware indicators (encrypted files, ransom notes).",
        "Disconnect any host that contacted this IP until it is confirmed clean.",
        "Verify backups are intact before attempting any recovery.",
        "Report to your national CERT and check for available decryption tools.",
    ],
    "Phishing Host": [
        "Block this IP and associated domains at your DNS resolver and web proxy.",
        "Search email logs for messages containing links pointing to this IP.",
        "Notify affected users to reset passwords immediately.",
        "Enable DMARC, DKIM, and SPF on your mail domain if not already active.",
        "Submit the phishing URL to Google Safe Browsing and Microsoft SmartScreen.",
    ],
    "Spam / Email Abuse": [
        "Add this IP to your mail server block list (Postfix, Exchange, etc.).",
        "Verify it against public blacklists: MXToolbox, Spamhaus, Barracuda.",
        "If this is your own IP range: contact your hosting provider about the abuse.",
        "Check for open mail relays or compromised SMTP accounts on your network.",
        "Ensure SPF records are correctly configured to prevent domain spoofing.",
    ],
    "Port Scanner / Brute-Force": [
        "Block this IP at the firewall and add it to your deny list.",
        "Enable rate-limiting and account lockout on SSH, RDP, and login pages.",
        "Review auth logs for successful logins coinciding with this IP's activity.",
        "Deploy fail2ban or equivalent to auto-block repeated login failures.",
        "Disable password-based SSH login; enforce key-based authentication only.",
    ],
    "Crypto Miner": [
        "Block outbound connections to this IP to stop active mining sessions.",
        "Scan all servers for unauthorised processes with abnormally high CPU usage.",
        "Audit cron jobs, startup scripts, and web files for mining implants.",
        "Patch the initial access vector — check for unpatched web apps or weak SSH.",
        "Review cloud billing for unexpected compute cost spikes from hidden miners.",
    ],
    "Malware Distribution": [
        "Block this IP at both firewall and DNS layers immediately.",
        "Scan all hosts for recently downloaded files originating from this IP.",
        "Check web proxy and DNS logs for hosts that resolved or contacted this IP.",
        "Quarantine any host found to have downloaded content from this address.",
        "Run memory forensics on suspected hosts to detect in-memory payloads.",
    ],
    "Exploit / Attack Tool": [
        "Block this IP and flag it in your SIEM as a confirmed attack source.",
        "Review WAF and IDS/IPS logs for exploit attempts from this IP.",
        "Patch all systems — check CVE advisories matching the signatures seen.",
        "Enable detailed logging on all exposed services (SSH, HTTP, RDP).",
        "Run a vulnerability scan on your external attack surface without delay.",
    ],
    "Open Proxy / Relay": [
        "Block this IP to prevent abuse of your services via proxy anonymisation.",
        "Review access logs for suspicious requests routed through this proxy.",
        "Implement CAPTCHA or geo-blocking if proxy abuse is ongoing.",
        "Use a proxy/VPN detection API to filter similar traffic proactively.",
    ],
    "Tor Exit Node": [
        "Block this Tor exit node IP if your service does not need Tor access.",
        "Use the Tor Project's official exit node list to build a comprehensive block list.",
        "Monitor for credential stuffing or scraping patterns in your access logs.",
        "Consider deploying a Tor-aware WAF rule set for services that must allow Tor.",
    ],
    "DDoS Infrastructure": [
        "Enable DDoS protection on your upstream provider or CDN (e.g. Cloudflare).",
        "Block this IP and null-route it at your upstream BGP peer if possible.",
        "Configure rate-limiting and connection throttling on all exposed services.",
        "Set traffic volume alerts to detect sudden inbound spikes early.",
        "Contact your ISP to apply upstream filtering during any active DDoS event.",
    ],
}

GENERIC_REMEDIATION = [
    "Block this IP at your perimeter firewall for both inbound and outbound traffic.",
    "Add this IP to your SIEM watchlist and alert on any future connections to it.",
    "Search historical logs (firewall, DNS, proxy) for past activity from this IP.",
    "Update your threat intelligence feeds to include this indicator of compromise.",
    "Review internet-exposed services and reduce unnecessary attack surface.",
]

CLEAN_REMEDIATION = [
    "No immediate action required — this IP appears safe based on current data.",
    "Threat intelligence changes frequently; re-check if this IP appears in your logs.",
    "Continue routine monitoring and log review as a baseline best practice.",
]


def generate_remediation(threat_types: list, risk_level: str) -> list:
    if risk_level == "CLEAN":
        return CLEAN_REMEDIATION

    actions = []
    seen    = set()

    for threat in threat_types:
        if threat in THREAT_PLAYBOOKS:
            for action in THREAT_PLAYBOOKS[threat]:
                if action not in seen:
                    seen.add(action)
                    actions.append(action)

    for action in GENERIC_REMEDIATION:
        if action not in seen:
            seen.add(action)
            actions.append(action)

    return actions[:8]


# ══════════════════════════════════════════════════════════════════════════════
#  6 — Analysis Orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def analyze(vt_data: dict) -> dict:
    sig          = extract_signals(vt_data)
    score        = calculate_risk_score(sig)
    risk_level   = determine_risk_level(score, sig)
    threat_types = detect_threat_types(sig)
    confidence   = assess_confidence(sig)
    summary      = generate_summary(sig, risk_level, threat_types)
    tech_detail  = generate_technical_detail(sig)
    actions      = generate_remediation(threat_types, risk_level)

    return {
        "risk_level":          risk_level,
        "risk_score":          score,
        "threat_types":        threat_types,
        "summary":             summary,
        "technical_detail":    tech_detail,
        "recommended_actions": actions,
        "confidence":          confidence,
        "_engine":             "rule-based intelligence (no external AI API required)",
        "_signals": {
            "malicious_engines":  sig["malicious"],
            "suspicious_engines": sig["suspicious"],
            "total_engines":      sig["total_engines"],
            "reputation":         sig["reputation"],
            "tags":               sig["tags"],
            "flagged_by":         list(sig["flagged_engines"].keys()),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
#  7 — Terminal Renderer
# ══════════════════════════════════════════════════════════════════════════════

def wrap(text: str, width: int = 70, indent: str = "    ") -> str:
    """Simple word-wrapper that respects a maximum line width."""
    words  = text.split()
    lines  = []
    line   = indent
    for word in words:
        if len(line) + len(word) + 1 > width:
            lines.append(line.rstrip())
            line = indent + word + " "
        else:
            line += word + " "
    if line.strip():
        lines.append(line.rstrip())
    return "\n".join(lines)


def print_report(ip: str, report: dict) -> None:
    risk   = report["risk_level"]
    colour = RISK_COLOUR.get(risk, WHITE)
    score  = report["risk_score"]
    conf   = report["confidence"]

    bar_fill  = "█" * (score // 5)
    bar_empty = "░" * (20 - score // 5)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    W = 58   # box width

    print()
    print(f"{BOLD}╔{'═'*W}╗{RESET}")
    print(f"{BOLD}║{'  SENTINEL — AI THREAT ANALYSIS REPORT':^{W}}║{RESET}")
    print(f"{BOLD}╠{'═'*W}╣{RESET}")
    print(f"{BOLD}║{RESET}  IP         : {WHITE}{BOLD}{ip:<{W-15}}{RESET}{BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}  Timestamp  : {DIM}{timestamp:<{W-15}}{RESET}{BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}  Engine     : {DIM}{'Rule-Based Intelligence (Free)':<{W-15}}{RESET}{BOLD}║{RESET}")
    print(f"{BOLD}╠{'═'*W}╣{RESET}")
    print(f"{BOLD}║{RESET}")
    print(f"  Risk Level  :  {colour}{BOLD}{risk}{RESET}")
    print(f"  Risk Score  :  {colour}{bar_fill}{DIM}{bar_empty}{RESET}  {colour}{BOLD}{score}/100{RESET}")
    print(f"  Confidence  :  {conf}")
    print()

    # Threat types
    threats = report["threat_types"]
    print(f"  {BOLD}◈  THREAT TYPES DETECTED{RESET}")
    for t in threats:
        marker = f"{RED}▸{RESET}" if "No specific" not in t else f"{GREEN}✓{RESET}"
        print(f"     {marker}  {t}")

    # Plain-English summary
    print(f"\n  {BOLD}◈  PLAIN-ENGLISH SUMMARY{RESET}")
    print(wrap(report["summary"], width=72))

    # Technical detail
    tech = report.get("technical_detail", "")
    if tech:
        print(f"\n  {BOLD}◈  TECHNICAL DETAIL{RESET}")
        print(DIM + wrap(tech, width=72) + RESET)

    # Remediation
    actions = report.get("recommended_actions", [])
    if actions:
        print(f"\n  {BOLD}◈  RECOMMENDED ACTIONS{RESET}")
        for i, action in enumerate(actions, 1):
            first_line = True
            words = action.split()
            line  = f"    {CYAN}[{i}]{RESET} "
            for word in words:
                if len(line.replace(CYAN, "").replace(RESET, "")) + len(word) > 72:
                    print(line.rstrip())
                    line = "         " + word + " "
                    first_line = False
                else:
                    line += word + " "
            if line.strip():
                print(line.rstrip())

    # Signal footer
    sig = report.get("_signals", {})
    if sig:
        print(f"\n  {BOLD}◈  RAW SIGNAL SUMMARY{RESET}")
        print(f"  {DIM}  Engines scanned  : {sig.get('total_engines', '?')}")
        print(f"    Malicious flags   : {sig.get('malicious_engines', 0)}")
        print(f"    Suspicious flags  : {sig.get('suspicious_engines', 0)}")
        print(f"    VT Reputation     : {sig.get('reputation', 0)}")
        tags = sig.get("tags", [])
        print(f"    VT Tags           : {', '.join(tags) if tags else 'none'}{RESET}")

    print()
    print(f"{BOLD}╚{'═'*W}╝{RESET}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  8 — Entry Point
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    load_env(".env")

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_key:
        print(f"{RED}[ERROR]{RESET} VIRUSTOTAL_API_KEY is missing from .env")
        sys.exit(1)

    print("\n========== SENTINEL MENU ==========")
    print("1. IP Threat Analysis")
    print("2. Website URL Scan")
    choice = input("Enter choice: ").strip()

    # -------------------------------
    # OPTION 1: IP ANALYSIS (existing)
    # -------------------------------
    if choice == "1":
        ip = input(f"\n{CYAN}Enter IP address:{RESET} ").strip()
        if not ip:
            print(f"{RED}[ERROR]{RESET} No IP provided.")
            sys.exit(1)

        print(f"\n  {DIM}[1/3] Querying VirusTotal for {ip} …{RESET}")
        vt_data = virustotal_lookup(ip, vt_key)

        print(f"  {DIM}[2/3] Extracting threat signals …{RESET}")
        print(f"  {DIM}[3/3] Running intelligence engine …{RESET}")
        report = analyze(vt_data)

        print_report(ip, report)
    # Save report ONLY for IP scan
    
        out_file = f"threat_report_{ip.replace('.', '_')}.json"
        with open(out_file, "w") as f:
            json.dump(
            {
                "generated_at": datetime.now().isoformat(),
                "ip": ip,
                "virustotal": vt_data,
                "ai_analysis": report,
            },
            f, indent=2
        )
        print(f"  {DIM}Full report saved → {out_file}{RESET}\n")

    # -------------------------------
    # OPTION 2: WEBSITE SCAN (NEW)
    # -------------------------------
    elif choice == "2":
        url = input("\nEnter website URL: ").strip()
        if not url:
            print(f"{RED}[ERROR]{RESET} No URL provided.")
            sys.exit(1)

        score, level = scan_url(url, vt_key)

        print("\n[WEBSITE SCAN RESULT]")
        print("Risk Level:", level)
        print("Risk Score:", score)
    # Save URL report
        out_file = f"url_report.json"
        with open(out_file, "w") as f:
            json.dump(
            {
                "generated_at": datetime.now().isoformat(),
                "url": url,
                "risk_level": level,
                "risk_score": score
            },
            f, indent=2
        )
        print(f"{DIM}Saved → {out_file}{RESET}")
    else:
        print(f"{RED}[ERROR]{RESET} Invalid choice.")    


    # Save full JSON report to disk
    out_file = f"threat_report_{ip.replace('.', '_')}.json"
    with open(out_file, "w") as f:
        json.dump(
            {
                "generated_at": datetime.now().isoformat(),
                "ip": ip,
                "virustotal":  vt_data,
                "ai_analysis": report,
            },
            f, indent=2
        )
    print(f"  {DIM}Full report saved → {out_file}{RESET}\n")