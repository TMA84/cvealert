---
title: "RSS Feeds Documentation"
layout: "single"
---

## RSS Feeds

CVE Alert provides RSS feeds so you can subscribe to vulnerability updates using your favorite RSS reader (Feedly, Thunderbird, Outlook, etc.).

### Global Feed

Subscribe to all CVEs:

```
https://cvealert.net/index.xml
```

### Per-Vendor Feeds

Get notified only about vulnerabilities from specific vendors:

```
https://cvealert.net/vendors/<vendor-name>/index.xml
```

**Examples:**
- Mozilla: `https://cvealert.net/vendors/mozilla/index.xml`
- Linux: `https://cvealert.net/vendors/linux/index.xml`
- Apple: `https://cvealert.net/vendors/apple/index.xml`
- Google: `https://cvealert.net/vendors/google/index.xml`
- Microsoft: `https://cvealert.net/vendors/microsoft/index.xml`
- Red Hat: `https://cvealert.net/vendors/red-hat/index.xml`

Browse all available vendors: [/vendors/](/vendors/)

### Per-Product Feeds

Get notified only about vulnerabilities in specific products:

```
https://cvealert.net/products/<product-name>/index.xml
```

**Examples:**
- Firefox: `https://cvealert.net/products/firefox/index.xml`
- Kernel: `https://cvealert.net/products/kernel/index.xml`
- Chrome: `https://cvealert.net/products/chrome/index.xml`
- Tomcat: `https://cvealert.net/products/tomcat/index.xml`
- OpenSSH: `https://cvealert.net/products/openssh/index.xml`

Browse all available products: [/products/](/products/)

### How to Subscribe

1. Copy the RSS feed URL for the vendor or product you want to monitor
2. Open your RSS reader application
3. Add a new feed and paste the URL
4. You will receive updates every time new CVEs are published for that vendor/product

### Update Frequency

Feeds are updated every 3 hours with new CVEs from:
- **NVD** (National Vulnerability Database)
- **CISA KEV** (Known Exploited Vulnerabilities)
- **CERT-Bund** (German Federal Office for Information Security)
