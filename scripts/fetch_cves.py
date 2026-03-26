"""Fetch CVEs from NVD, CISA KEV, and CERT-Bund and generate Hugo markdown posts."""
import json, os, urllib.request, xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CERT_BUND_RSS = "https://wid.cert-bund.de/content/public/securityAdvisory/rss"
OUT = os.path.join(os.path.dirname(__file__), "..", "content", "posts")
UA = {"User-Agent": "cve-blog/1.0"}


def http_get(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def fetch_kev():
    """Return set of CVE IDs that are actively exploited."""
    try:
        data = json.loads(http_get(KEV_URL))
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"CISA KEV fetch failed: {e}")
        return set()


def fetch_cert_bund():
    """Fetch CERT-Bund advisories from RSS and return list of dicts."""
    # Map German severity tags to English
    sev_map = {
        "kritisch": ("CRITICAL", 9.0),
        "hoch": ("HIGH", 7.5),
        "mittel": ("MEDIUM", 5.0),
        "niedrig": ("LOW", 2.5),
    }
    advisories = []
    try:
        root = ET.fromstring(http_get(CERT_BUND_RSS))
        for item in root.findall(".//item"):
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            desc = item.findtext("description", "")
            pub = item.findtext("pubDate", "")
            if not title:
                continue
            # Extract severity and status from title like "[NEU] [hoch] Product: ..."
            severity, cvss = "UNKNOWN", 0.0
            is_update = False
            clean_title = title
            is_update = False
            for tag in ("NEU", "UPDATE"):
                if f"[{tag}]" in title:
                    if tag == "UPDATE":
                        is_update = True
                    clean_title = clean_title.replace(f"[{tag}]", "")
            for de, (en, score) in sev_map.items():
                if f"[{de}]" in clean_title.lower():
                    severity, cvss = en, score
                    import re
                    clean_title = re.sub(r'\[' + de + r'\]', '', clean_title, flags=re.IGNORECASE)
                    break
            clean_title = clean_title.strip().strip("-").strip()

            # Extract vendor from title (text before first colon, simplified)
            vendor = "unknown"
            if ":" in clean_title:
                raw_vendor = clean_title.split(":")[0].strip()
                # Take first meaningful word(s), drop "und", version info etc.
                parts = raw_vendor.split()
                short = []
                for p in parts:
                    if p.lower() in ("und", "for", "mit", "-"):
                        break
                    short.append(p)
                    if len(short) >= 2:
                        break
                vendor = "-".join(short).lower().rstrip(",-") if short else "unknown"

            try:
                dt = datetime.strptime(pub[:25], "%a, %d %b %Y %H:%M:%S")
                date_str = dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            except Exception:
                date_str = datetime.now(timezone.utc).isoformat()
            advisories.append({
                "title": clean_title, "link": link, "desc": desc,
                "date": date_str, "severity": severity, "cvss": cvss,
                "is_update": is_update, "vendor": vendor,
            })
    except Exception as e:
        print(f"CERT-Bund fetch failed: {e}")
    return advisories


def safe_yaml(text):
    return text.replace("{{", "{ {").replace("}}", "} }").replace("\n", " ").replace("\r", "")


def write_post(path, frontmatter):
    if os.path.exists(path):
        return False
    with open(path, "w") as f:
        f.write(frontmatter)
    return True


def fetch_nvd(kev_ids):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    start_idx = 0
    count = 0
    while True:
        params = (
            f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
            f"&resultsPerPage=200&startIndex={start_idx}"
        )
        data = json.loads(http_get(API + params))
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        for v in vulns:
            cve = v["cve"]
            cve_id = cve["id"]
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description.")
            metrics = cve.get("metrics", {})
            cvss, severity = 0.0, "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    m = metrics[key][0]["cvssData"]
                    cvss = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", "UNKNOWN")
                    break
            all_refs = cve.get("references", [])
            refs = [r["url"] for r in all_refs[:5]]
            patches = [r["url"] for r in all_refs if "Patch" in r.get("tags", [])][:3]
            advisories = [r["url"] for r in all_refs if "Vendor Advisory" in r.get("tags", [])][:3]
            vendors = set()
            for conf in cve.get("configurations", []):
                for node in conf.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        parts = match.get("criteria", "").split(":")
                        if len(parts) >= 5:
                            vendors.add(parts[3])
            vendor = ", ".join(sorted(vendors)) if vendors else "unknown"
            date = cve.get("published", datetime.now(timezone.utc).isoformat())
            exploited = cve_id in kev_ids
            sources = ["NVD"]
            if exploited:
                sources.append("CISA KEV")
            front = (
                f'---\ntitle: "{cve_id}"\ndate: {date}\n'
                f'cvss: {cvss}\nseverity: "{severity}"\nvendor: "{vendor}"\n'
                f'exploited: {str(exploited).lower()}\n'
                f'sources: {json.dumps(sources)}\n'
                f'description: "{cve_id} - {severity} vulnerability with CVSS score {cvss}"\n'
                f'summary: |\n  {safe_yaml(desc)}\n'
                f'patches: {json.dumps(patches)}\n'
                f'advisories: {json.dumps(advisories)}\n'
                f'references: {json.dumps(refs)}\n---\n'
            )
            if write_post(os.path.join(OUT, f"{cve_id.lower()}.md"), front):
                count += 1
        total = data.get("totalResults", 0)
        start_idx += 200
        if start_idx >= total:
            break
    return count


def process_cert_bund(advisories):
    count = 0
    for adv in advisories:
        import re as _re
        raw = adv["title"].split(":")[0].strip() if ":" in adv["title"] else adv["title"].split()[0]
        slug = "cb-" + _re.sub(r'[^a-z0-9]+', '-', raw.lower()).strip('-')
        desc = safe_yaml(adv["desc"]) if adv["desc"] else "No description available."
        title = adv["title"].replace('"', '\\"')
        severity = adv.get("severity", "UNKNOWN")
        cvss = adv.get("cvss", 0.0)
        is_update = str(adv.get("is_update", False)).lower()
        vendor = adv.get("vendor", "unknown")
        front = (
            f'---\ntitle: "{title}"\ndate: {adv["date"]}\n'
            f'cvss: {cvss}\nseverity: "{severity}"\nvendor: "{vendor}"\n'
            f'exploited: false\nupdate: {is_update}\n'
            f'sources: ["CERT-Bund"]\n'
            f'description: "{title}"\n'
            f'summary: |\n  {desc}\n'
            f'references: ["{adv["link"]}"]\n---\n'
        )
        if write_post(os.path.join(OUT, f"{slug}.md"), front):
            count += 1
    return count


def main():
    os.makedirs(OUT, exist_ok=True)
    kev_ids = fetch_kev()
    print(f"CISA KEV: {len(kev_ids)} known exploited CVEs loaded")
    nvd_count = fetch_nvd(kev_ids)
    print(f"NVD: {nvd_count} new posts")
    cb_advisories = fetch_cert_bund()
    cb_count = process_cert_bund(cb_advisories)
    print(f"CERT-Bund: {cb_count} new posts")


if __name__ == "__main__":
    main()
