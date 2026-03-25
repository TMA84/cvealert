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
            # Parse date like "Thu, 20 Mar 2026 10:00:00 +0100"
            try:
                dt = datetime.strptime(pub[:25], "%a, %d %b %Y %H:%M:%S")
                date_str = dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            except Exception:
                date_str = datetime.now(timezone.utc).isoformat()
            advisories.append({"title": title, "link": link, "desc": desc, "date": date_str})
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
            refs = [r["url"] for r in cve.get("references", [])[:5]]
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
        slug = adv["title"].split()[0].replace("[", "").replace("]", "").lower()
        if not slug:
            continue
        slug = f"cb-{slug}"
        desc = safe_yaml(adv["desc"]) if adv["desc"] else "No description available."
        title = adv["title"].replace('"', '\\"')
        front = (
            f'---\ntitle: "{title}"\ndate: {adv["date"]}\n'
            f'cvss: 0.0\nseverity: "UNKNOWN"\nvendor: "unknown"\n'
            f'exploited: false\n'
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
