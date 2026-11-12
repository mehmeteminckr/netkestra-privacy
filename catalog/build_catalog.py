#!/usr/bin/env python3
"""Builds catalog.json, the downloadable known-issue list of the Netkestra app.

For every product in products.json it asks the US National Vulnerability Database (NVD) for the CVEs that
(a) are in CISA's Known Exploited Vulnerabilities catalog, or (b) are rated CRITICAL or HIGH (the newest ones, capped),
and writes which versions each one affects. The app downloads the result (only when the person allowed updates), checks every
field, and shows it next to the issues built into the app.

Usage:   python3 build_catalog.py [--out catalog.json] [--products products.json] [--only key1,key2]
Key:     set NVD_API_KEY (free at https://nvd.nist.gov/developers/request-an-api-key) to run about ten times faster.
         Without a key NVD allows 5 requests per 30 seconds; the script waits between requests.
Python 3.8+, standard library only.
"""
import argparse
import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEY = os.environ.get("NVD_API_KEY", "").strip() or None
DELAY = 0.8 if KEY else 6.5
NEWEST_PER_SEVERITY = 15      # besides every exploited issue
MAX_PER_PRODUCT = 45
MAX_SPANS = 12
SUMMARY_LENGTH = 220


def get(params):
    """One paced NVD request with retries. Returns the parsed JSON."""
    url = API + "?" + urllib.parse.urlencode(params, safe=":*")
    headers = {"User-Agent": "Netkestra-catalog-builder"}
    if KEY:
        headers["apiKey"] = KEY
    for attempt in range(6):
        time.sleep(DELAY)
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code in (403, 429, 503, 502, 500):
                wait = 35 + attempt * 10
                print(f"  NVD answered {error.code}, waiting {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            time.sleep(10 + attempt * 10)
    raise RuntimeError("NVD did not answer: " + url)


def score_of(cve):
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(name)
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    return None


def severity_of(score):
    if score is None:
        return "medium"
    return "high" if score >= 7 else "medium" if score >= 4 else "low"


def summary_of(cve):
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            text = re.sub(r"\s+", " ", description["value"]).strip()
            return text if len(text) <= SUMMARY_LENGTH else text[: SUMMARY_LENGTH - 1].rstrip() + "…"
    return ""


def version_of(parts):
    """The version text of a CPE (parts[5]), with an update such as p1 appended when it looks like a letter-number suffix."""
    version, update = parts[5], parts[6]
    if version in ("*", "-"):
        return None
    if update not in ("*", "-") and re.fullmatch(r"[a-z][0-9a-z]*", update):
        return version + update
    return version


def spans_for(cve, pairs):
    """Affected version spans of this CVE for one product (vendor:product pairs)."""
    spans = []

    def add(span):
        if span not in spans:
            spans.append(span)

    def walk(nodes):
        for node in nodes:
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = match["criteria"].split(":")
                if len(parts) < 7 or parts[2] != "a" or f"{parts[3]}:{parts[4]}" not in pairs:
                    continue
                start_in, start_ex = match.get("versionStartIncluding"), match.get("versionStartExcluding")
                end_in, end_ex = match.get("versionEndIncluding"), match.get("versionEndExcluding")
                if start_in or start_ex or end_in or end_ex:
                    span = {"from": start_in or start_ex, "fromInclusive": bool(start_in) or not start_ex,
                            "to": end_in or end_ex, "toInclusive": bool(end_in)}
                    add({k: v for k, v in span.items() if v is not None})
                else:
                    exact = version_of(parts)
                    if exact:
                        add({"from": exact, "fromInclusive": True, "to": exact, "toInclusive": True})
            walk(node.get("children", []))

    for configuration in cve.get("configurations", []):
        walk(configuration.get("nodes", []))
    return spans[:MAX_SPANS]


def clean_span_text(span):
    for key in ("from", "to"):
        if key in span and not re.fullmatch(r"[A-Za-z0-9._+\-]{1,40}", span[key]):
            return False
    return "from" in span or "to" in span


def fetch_product(product):
    pairs = product["cpe"]
    found = {}
    for pair in pairs:
        base = {"virtualMatchString": f"cpe:2.3:a:{pair}", "resultsPerPage": 2000}
        for label, extra in (("exploited", {"hasKev": ""}), ("critical", {"cvssV3Severity": "CRITICAL"}), ("high", {"cvssV3Severity": "HIGH"})):
            data = get(dict(base, **extra))
            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                found.setdefault(cve["id"], cve)
    issues = []
    for cve_id, cve in found.items():
        spans = [s for s in spans_for(cve, set(pairs)) if clean_span_text(s)]
        summary = summary_of(cve)
        if not spans or not summary:
            continue
        score = score_of(cve)
        issues.append({"id": cve_id, "product": product["key"], "kind": "vulnerability", "severity": severity_of(score),
                       "summary": summary, "kev": "cisaExploitAdd" in cve, "spans": spans,
                       "_score": score or 0, "_published": cve.get("published", "")})
    exploited = [i for i in issues if i["kev"]]
    rest = sorted((i for i in issues if not i["kev"]), key=lambda i: (i["_published"], i["_score"]), reverse=True)
    chosen = sorted(exploited, key=lambda i: i["_published"], reverse=True) + rest
    chosen = chosen[:MAX_PER_PRODUCT]
    for issue in chosen:
        del issue["_score"], issue["_published"]
    return sorted(chosen, key=lambda i: i["id"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--products", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "products.json"))
    parser.add_argument("--out", default="catalog.json")
    parser.add_argument("--only", default="")
    args = parser.parse_args()

    with open(args.products, encoding="utf-8") as handle:
        products = json.load(handle)["products"]
    only = {k for k in args.only.split(",") if k}
    issues, listed = [], []
    for index, product in enumerate(products, 1):
        if only and product["key"] not in only:
            continue
        if not product["cpe"]:
            continue
        print(f"[{index}/{len(products)}] {product['key']}", file=sys.stderr)
        found = fetch_product(product)
        print(f"   {len(found)} issues", file=sys.stderr)
        issues.extend(found)
        if not product.get("builtin"):
            listed.append({k: product[k] for k in ("key", "name", "synonyms", "banner", "aliases", "cpe")})

    now = datetime.datetime.now(datetime.timezone.utc)
    catalog = {"schema": 1, "edition": now.strftime("%Y-%m-%d"), "generated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "products": listed, "issues": issues}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(catalog, handle, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    print(f"Wrote {args.out}: {len(listed)} products, {len(issues)} issues, {os.path.getsize(args.out) // 1024} KB", file=sys.stderr)


if __name__ == "__main__":
    main()

