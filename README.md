# CVE Security Feed

Auto-generated blog that posts daily HIGH/CRITICAL CVEs from the [NVD API](https://nvd.nist.gov/).

## Setup

1. Fork/clone this repo
2. In GitHub: **Settings → Pages → Source → GitHub Actions**
3. Edit `hugo.toml` and set your `baseURL`
4. Push — the Action runs daily at 08:00 CET or trigger manually via **Actions → Run workflow**

## How it works

- GitHub Actions runs daily on schedule
- Python script fetches CVEs (CVSS ≥ 7.0) from the last 24h
- Generates Hugo markdown posts
- Commits new posts and deploys to GitHub Pages
