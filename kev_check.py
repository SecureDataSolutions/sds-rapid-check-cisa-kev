#!/usr/bin/env python3
# Eddie Espino, Secure Data Solutions. MIT License. No warranty; run only on systems you own or are authorized to check.
"""List recent CISA Known Exploited Vulnerabilities (KEV) and flag the vendors you run.

Usage:
  python3 kev_check.py                       # last 7 days, all vendors
  python3 kev_check.py --days 14 --vendors vmware synology cisco litellm
  python3 kev_check.py --file kev.json       # use a KEV catalog saved locally

Read-only. Downloads CISA's public KEV JSON feed, with CISA's GitHub mirror as a fallback.
With --file it reads only that local JSON file and makes no network requests. It does not
look at your systems. Python 3 standard library only.

Limits: it matches the words you give against CISA's vendor and product names only.
A product filed under another name (a parent company, an old brand) is missed, so read
the whole list too. It shows only entries added in the --days window.
"""
import argparse, json, re, sys, urllib.request
from datetime import date, timedelta

LAST_CHECKED = "2026-11-23"  # date this script was last tested against the live feed
FEEDS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's own mirror, used only if cisa.gov does not answer.
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
ROW_FIELDS = ("dateAdded", "cveID", "vendorProject", "product", "dueDate", "requiredAction")


class FeedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl not in FEEDS:
            raise ValueError("redirect outside CISA's published feed URLs")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch():
    opener = urllib.request.build_opener(FeedRedirect())
    errors = []
    for url in FEEDS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "kev-check/1.1"})
            with opener.open(req, timeout=30) as r:
                data, source = json.load(r), r.geturl()
            return validate_catalog(data, source)
        except Exception as e:  # network, HTTP or JSON error: try the next source
            errors.append(f"  {url}\n    {e}")
    sys.exit("Could not read the KEV feed. Nothing was checked.\n" + "\n".join(errors))


def validate_catalog(data, source):
    if not isinstance(data, dict) or not isinstance(data.get("catalogVersion"), str):
        raise ValueError("invalid KEV catalog version")
    if not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("missing or invalid KEV vulnerabilities list")
    rows = []
    for row in data["vulnerabilities"]:
        if not isinstance(row, dict) or not all(isinstance(row.get(key), str) for key in ROW_FIELDS):
            raise ValueError("invalid KEV vulnerability entry")
        rows.append((date.fromisoformat(row["dateAdded"]), row))
    return data["catalogVersion"], source, rows


def read_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return validate_catalog(data, "local file: " + path)
    except (OSError, ValueError, RecursionError) as e:
        sys.exit(f"Could not read KEV catalog from {path}. Nothing was checked.\n  {e}")


def main():
    p = argparse.ArgumentParser(description="List recent CISA KEV entries and flag your vendors.")
    p.add_argument("--file", help="read a KEV JSON catalog saved locally (no network access)")
    p.add_argument("--days", type=int, default=7, help="calendar days including today (default 7, 0 for today)")
    p.add_argument("--vendors", nargs="*", default=[],
                   help="vendor or product words to flag, e.g. vmware synology (matches the start of a word)")
    a = p.parse_args()
    if a.days < 0:
        p.error("--days must be 0 or more")
    today = date.today()
    try:
        since = today - timedelta(days=max(a.days - 1, 0))
    except OverflowError:
        p.error("--days is too large")

    version, source, catalog = read_file(a.file) if a.file is not None else fetch()
    words = [w.strip().lower() for w in a.vendors if w.strip()]
    # Match at the start of a word, so "hp" does not hit "PHP" but "forti" hits "FortiOS".
    patterns = [re.compile(r"(?<![a-z0-9])" + re.escape(w)) for w in words]

    def is_hit(v):
        text = f'{v.get("vendorProject", "")} {v.get("product", "")}'.lower()
        return any(rx.search(text) for rx in patterns)

    rows = [(added, row) for added, row in catalog if since <= added <= today]
    rows.sort(key=lambda entry: entry[0], reverse=True)

    print(f"KEV catalog {version}: {len(rows)} added {since} through {today}")
    print(f"Source: {source}\n")
    hits = 0
    for _, v in rows:
        hit = is_hit(v)
        hits += hit
        mark = ">>" if hit else "  "
        ransom = " [ransomware use known]" if v.get("knownRansomwareCampaignUse") == "Known" else ""
        print(f'{mark} {v["dateAdded"]}  {v.get("cveID", "?"):<18} {v.get("vendorProject", "")} {v.get("product", "")}{ransom}')
        print(f'     Fix due (US federal): {v.get("dueDate", "?")}  Action: {v.get("requiredAction", "")[:110]}')
    if words:
        print(f"\n{hits} match(es) for: {', '.join(words)}")
        if any(len(w) < 3 for w in words):
            print("Note: very short words match many names. Check each '>>' line.")
    print("\nNo finding is not proof of no compromise. No match means only that CISA's vendor and\n"
          "product names for this period did not start with your words. This script does not look\n"
          "at your systems. Patching a listed flaw does not show whether someone got in before the patch.")
    print(f"Script last checked: {LAST_CHECKED}. Data: CISA KEV catalog (public domain, CC0).")


if __name__ == "__main__":
    main()
