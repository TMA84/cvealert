"""Fetch recent high/critical CVEs from NVD API and generate Hugo markdown posts."""
import json, os, urllib.request
from datetime import datetime, timedelta, timezone

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUT = os.path.join(os.path.dirname(__file__), "..", "content", "posts")

def fetch_cves():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=1)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = (
        f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
        f"&resultsPerPage=200"
    )
    req = urllib.request.Request(API + params, headers={"User-Agent": "cve-blog/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def make_post(cve):
    cve_id = cve["cve"]["id"]
    desc_list = cve["cve"].get("descriptions", [])
    desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description.")
    desc = desc.replace("{{", "{ {").replace("}}", "} }")
    metrics = cve["cve"].get("metrics", {})
    cvss = 0.0
    severity = "UNKNOWN"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            m = metrics[key][0]["cvssData"]
            cvss = m.get("baseScore", 0.0)
            severity = m.get("baseSeverity", "UNKNOWN")
            break
    refs = [r["url"] for r in cve["cve"].get("references", [])[:5]]
    # Extract vendor/product from CPE configurations
    vendors = set()
    for conf in cve["cve"].get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5:
                    vendors.add(parts[3])
    vendor = ", ".join(sorted(vendors)) if vendors else "unknown"
    date = cve["cve"].get("published", datetime.now(timezone.utc).isoformat())
    slug = cve_id.lower()
    path = os.path.join(OUT, f"{slug}.md")
    if os.path.exists(path):
        return False
    front = (
        f'---\ntitle: "{cve_id}"\ndate: {date}\n'
        f'cvss: {cvss}\nseverity: "{severity}"\nvendor: "{vendor}"\n'
        f'description: "{cve_id} - {severity} vulnerability with CVSS score {cvss}"\n'
        f'references: {json.dumps(refs)}\n---\n\n{desc}\n'
    )
    with open(path, "w") as f:
        f.write(front)
    return True

def main():
    os.makedirs(OUT, exist_ok=True)
    data = fetch_cves()
    total = sum(1 for v in data.get("vulnerabilities", []) if make_post(v))
    print(f"Created {total} new posts")

if __name__ == "__main__":
    main()
