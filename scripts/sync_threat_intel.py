#!/usr/bin/env python3
"""
sync_threat_intel.py — Threat Intel IP Blocklist Sync
======================================================
Fetches IP blocklists from configured feeds, writes Nginx deny directives
to config/threat-intel/ip_rules.conf, then reloads Nginx.

Usage (from project root):
    python3 scripts/sync_threat_intel.py [--dry-run] [--config PATH] [--reload-cmd CMD]

Cron (host):
    0 */6 * * * cd /path/to/nginx-coroza-crs-docker && python3 scripts/sync_threat_intel.py >> logs/threat_intel.log 2>&1

Cron (inside container via docker exec):
    0 */6 * * * docker exec nginx-coroza-crs python3 /scripts/sync_threat_intel.py
"""

import json
import sys
import os
import re
import argparse
import subprocess
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

# ── Paths (relative to project root, or override via CLI args) ───────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_CONFIG   = os.path.join(PROJECT_ROOT, "config", "threat-intel", "threat_intel.json")
DEFAULT_OUTPUT   = os.path.join(PROJECT_ROOT, "config", "threat-intel", "ip_rules.conf")
# Docker exec reload — adjust container name if different
DEFAULT_RELOAD   = "docker exec nginx-coroza-crs nginx -s reload"


# ── Feed parsers ─────────────────────────────────────────────────────────────

def _parse_spamhaus_drop(text: str) -> list[str]:
    """Spamhaus DROP/EDROP: lines like '1.10.16.0/20 ; SBL...' → CIDR"""
    ips = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        cidr = line.split(";")[0].strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$", cidr):
            ips.append(cidr)
    return ips


def _parse_emerging_threats(text: str) -> list[str]:
    """Emerging Threats: plain IP list, one per line, # = comment"""
    ips = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$", line):
            ips.append(line)
    return ips


def _parse_abuseipdb(text: str, block_score: int) -> list[str]:
    """AbuseIPDB JSON: filter by abuseConfidenceScore >= block_score"""
    try:
        data = json.loads(text)
        return [
            entry["ipAddress"]
            for entry in data.get("data", [])
            if entry.get("abuseConfidenceScore", 0) >= block_score
        ]
    except json.JSONDecodeError as exc:
        print(f"  [!] AbuseIPDB JSON parse error: {exc}", file=sys.stderr)
        return []


PARSERS = {
    "spamhaus_drop":    _parse_spamhaus_drop,
    "emerging_threats": _parse_emerging_threats,
    "abuseipdb":        _parse_abuseipdb,
}


# ── HTTP fetch ────────────────────────────────────────────────────────────────

def fetch_url(url: str, headers: dict | None = None, timeout: int = 30) -> str | None:
    req = Request(url, headers=headers or {})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except URLError as exc:
        print(f"  [!] Fetch failed: {exc}", file=sys.stderr)
        return None


# ── Core sync logic ───────────────────────────────────────────────────────────

def sync(config_path: str, output_path: str, dry_run: bool, reload_cmd: str) -> None:
    print(f"[sync_threat_intel] {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")

    with open(config_path, encoding="utf-8") as f:
        cfg = json.load(f)

    if not cfg.get("enabled", True):
        print("[*] Threat intel disabled in config — nothing to do.")
        return

    whitelist  = set(cfg.get("whitelist_ips", []))
    manual_ips = list(cfg.get("blocked_ips", []))
    block_score = cfg.get("block_score", 90)
    action      = cfg.get("action", "block")

    all_ips: set[str] = set(manual_ips)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    for feed in cfg.get("feeds", []):
        if not feed.get("enabled", False):
            print(f"[skip] {feed['name']} (disabled)")
            feed["last_sync"] = "skipped"
            continue

        print(f"[feed] {feed['name']} — {feed['url']}")

        extra_headers = {}
        feed_type = feed.get("type", "")

        if feed_type == "abuseipdb":
            api_key = feed.get("api_key", "")
            if not api_key:
                print("  [!] AbuseIPDB api_key is empty — skipping.")
                feed["last_sync"] = "skipped (no api_key)"
                continue
            extra_headers = {
                "Key": api_key,
                "Accept": "application/json",
            }

        raw = fetch_url(feed["url"], headers=extra_headers)
        if raw is None:
            feed["last_sync"] = f"error ({now_str})"
            continue

        parser = PARSERS.get(feed_type)
        if parser is None:
            print(f"  [!] Unknown feed type: {feed_type}")
            feed["last_sync"] = "error (unknown type)"
            continue

        if feed_type == "abuseipdb":
            parsed = parser(raw, block_score)
        else:
            parsed = parser(raw)

        filtered = [ip for ip in parsed if ip not in whitelist]
        all_ips.update(filtered)

        feed["ip_count"] = len(filtered)
        feed["last_sync"] = now_str
        print(f"  → {len(filtered)} IPs loaded")

    sorted_ips = sorted(all_ips)
    print(f"[total] {len(sorted_ips)} unique IPs/CIDRs to block")

    # Build nginx deny block
    nginx_action = "deny" if action == "block" else "allow"  # future: allow action
    lines = [
        "# Threat Intel IP Rules",
        "# Managed by: scripts/sync_threat_intel.py — DO NOT EDIT MANUALLY",
        f"# Last sync:  {now_str}",
        f"# Total IPs:  {len(sorted_ips)}",
        "",
    ]
    for ip in sorted_ips:
        lines.append(f"{nginx_action} {ip};")

    output = "\n".join(lines) + "\n"

    if dry_run:
        print("[dry-run] Would write:\n" + output[:500] + ("..." if len(output) > 500 else ""))
    else:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"[write] {output_path}")

        # Persist updated counts/timestamps back to JSON
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")

        # Reload nginx
        if reload_cmd:
            print(f"[reload] {reload_cmd}")
            result = subprocess.run(reload_cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print("[reload] OK")
            else:
                print(f"[reload] FAILED: {result.stderr.strip()}", file=sys.stderr)

    print("[done]")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Sync threat intel IP blocklist for Nginx.")
    parser.add_argument("--config",     default=DEFAULT_CONFIG,  help="Path to threat_intel.json")
    parser.add_argument("--output",     default=DEFAULT_OUTPUT,  help="Path to output ip_rules.conf")
    parser.add_argument("--reload-cmd", default=DEFAULT_RELOAD,  help="Command to reload Nginx")
    parser.add_argument("--dry-run",    action="store_true",     help="Fetch and parse but don't write or reload")
    args = parser.parse_args()

    if not os.path.isfile(args.config):
        print(f"[!] Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    sync(
        config_path=args.config,
        output_path=args.output,
        dry_run=args.dry_run,
        reload_cmd="" if args.dry_run else args.reload_cmd,
    )


if __name__ == "__main__":
    main()
