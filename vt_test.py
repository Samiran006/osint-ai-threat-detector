"""
VirusTotal IP Lookup — Simple Test Script
Reads API key from .env, queries VirusTotal for a given IP address.
"""

import os
import json
import sys
import urllib.request
import urllib.error

# ── Load .env manually (no third-party libs required) ──────────────────────────
def load_env(path=".env"):
    if not os.path.exists(path):
        print(f"[ERROR] .env file not found at: {os.path.abspath(path)}")
        sys.exit(1)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

# ── Query VirusTotal ────────────────────────────────────────────────────────────
def lookup_ip(ip: str, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[HTTP {e.code}] {e.reason}")
        try:
            print(json.dumps(json.loads(body), indent=2))
        except Exception:
            print(body)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[ERROR] Network error: {e.reason}")
        sys.exit(1)

# ── Pretty-print key fields ─────────────────────────────────────────────────────
def print_summary(data: dict):
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    print("\n" + "="*52)
    print("  VIRUSTOTAL IP REPORT")
    print("="*52)
    print(f"  IP Address  : {data.get('data', {}).get('id', 'N/A')}")
    print(f"  Country     : {attrs.get('country', 'N/A')}")
    print(f"  ASN         : {attrs.get('asn', 'N/A')}")
    print(f"  AS Owner    : {attrs.get('as_owner', 'N/A')}")
    print(f"  Network     : {attrs.get('network', 'N/A')}")
    print(f"  Reputation  : {attrs.get('reputation', 'N/A')}")
    print("-"*52)
    print("  Last Analysis Stats:")
    print(f"    Malicious   : {stats.get('malicious', 0)}")
    print(f"    Suspicious  : {stats.get('suspicious', 0)}")
    print(f"    Undetected  : {stats.get('undetected', 0)}")
    print(f"    Harmless    : {stats.get('harmless', 0)}")
    print("="*52)

    # Full raw JSON
    print("\n--- Full JSON Response ---\n")
    print(json.dumps(data, indent=2))

# ── Main ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    load_env(".env")

    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("[ERROR] VIRUSTOTAL_API_KEY not found in .env")
        sys.exit(1)

    if len(sys.argv) > 1:
        ip = sys.argv[1]
    else:
        ip = input("Enter IP address to look up: ").strip()

    if not ip:
        print("[ERROR] No IP address provided.")
        sys.exit(1)

    print(f"\n[*] Looking up: {ip}")
    data = lookup_ip(ip, api_key)
    print_summary(data)