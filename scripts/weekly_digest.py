"""Generate a weekly digest post summarizing the past week's CVEs."""
import json, os, glob
from datetime import datetime, timedelta, timezone
from collections import Counter

OUT = os.path.join(os.path.dirname(__file__), "..", "content", "posts")

def main():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    week_str = start.strftime("%Y-%m-%d")
    slug = f"weekly-digest-{week_str}"
    path = os.path.join(OUT, f"{slug}.md")
    if os.path.exists(path):
        print(f"Digest {slug} already exists")
        return

    # Scan existing posts
    total = critical = high = medium = low = 0
    vendors = Counter()
    exploited = []
    top_cvss = []

    for f in glob.glob(os.path.join(OUT, "*.md")):
        with open(f) as fh:
            content = fh.read()
        # Quick frontmatter parse
        if not content.startswith("---"):
            continue
        fm = content.split("---")[1]
        date_line = [l for l in fm.split("\n") if l.startswith("date:")]
        if not date_line:
            continue
        date_str = date_line[0].replace("date:", "").strip()
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            continue
        if dt < start or dt > end:
            continue

        total += 1
        sev = ""
        cvss = 0.0
        title = ""
        vendor = "unknown"
        is_exploited = False

        for line in fm.split("\n"):
            if line.startswith("severity:"):
                sev = line.split('"')[1] if '"' in line else ""
            elif line.startswith("cvss:"):
                try:
                    cvss = float(line.split(":")[1].strip())
                except Exception:
                    pass
            elif line.startswith("title:"):
                title = line.split('"')[1] if '"' in line else ""
            elif line.startswith("vendor:"):
                vendor = line.split('"')[1] if '"' in line else "unknown"
            elif line.startswith("exploited: true"):
                is_exploited = True

        if sev == "CRITICAL":
            critical += 1
        elif sev == "HIGH":
            high += 1
        elif sev == "MEDIUM":
            medium += 1
        elif sev == "LOW":
            low += 1

        if vendor != "unknown":
            vendors[vendor] += 1
        if is_exploited:
            exploited.append(title)
        if cvss >= 9.0:
            top_cvss.append((title, cvss, sev, vendor))

    if total == 0:
        print("No CVEs found for this week")
        return

    top_cvss.sort(key=lambda x: -x[1])
    top_vendors = vendors.most_common(10)

    # Build digest content
    lines = []
    lines.append(f"This week **{total}** new vulnerabilities were published:")
    lines.append(f"**{critical}** Critical, **{high}** High, **{medium}** Medium, **{low}** Low.")
    lines.append("")

    if exploited:
        lines.append("## Actively Exploited")
        for e in exploited:
            lines.append(f"- [{e}](../{ e.lower()}/)")
        lines.append("")

    if top_cvss:
        lines.append("## Highest Severity (CVSS ≥ 9.0)")
        for t, c, s, v in top_cvss[:10]:
            vstr = f" ({v})" if v != "unknown" else ""
            lines.append(f"- [{t}](../{t.lower()}/) — **{c}** {s}{vstr}")
        lines.append("")

    if top_vendors:
        lines.append("## Top Affected Vendors")
        for v, c in top_vendors:
            lines.append(f"- **{v}**: {c} CVEs")
        lines.append("")

    desc = f"Weekly security digest: {total} CVEs ({critical} Critical, {high} High) from {start.strftime('%b %d')} to {end.strftime('%b %d, %Y')}."
    body = "\n".join(lines)

    front = (
        f'---\ntitle: "Weekly Digest: {start.strftime("%b %d")} – {end.strftime("%b %d, %Y")}"\n'
        f'date: {end.isoformat()}\n'
        f'cvss: 0.0\nseverity: "UNKNOWN"\nvendor: "unknown"\n'
        f'exploited: false\n'
        f'sources: ["Digest"]\n'
        f'description: "{desc}"\n'
        f'summary: |\n  {desc}\n'
        f'references: []\npatches: []\nadvisories: []\n---\n\n{body}\n'
    )

    with open(path, "w") as fh:
        fh.write(front)
    print(f"Created digest: {slug}")

if __name__ == "__main__":
    main()
