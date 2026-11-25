# threat-feed

A daily digest of vulnerabilities newly added to CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
ranked by [EPSS](https://www.first.org/epss/) exploit-probability score.

A GitHub Action runs `digest.py` every morning. When CISA has added
entries since the last run, it writes a digest to `digests/YYYY/` and
updates the table below. Days with nothing new produce no commit.

## Latest

<!-- latest:start -->
**2026-11-25**: 10 new, full digest in [`digests/2026/2026-11-25.md`](digests/2026/2026-11-25.md)

| CVE | Vendor / product | EPSS |
|---|---|---|
| CVE-2026-133323 | Mitel MiCollab | 2.5% (p86) |
| CVE-2023-25915 | Danfoss AK-SM 800A Series | 1.4% (p73) |
| CVE-2026-133469 | Vates Xen Orchestra | 1.1% (p65) |
| CVE-2023-25914 | Danfoss AK-SM 800A Series | 1.1% (p65) |
| CVE-2026-103406 | Hewlett Packard Enterprise (HPE) Juniper Session Smart Conductor and Session Smart Router | 0.9% (p56) |
| CVE-2026-133303 | Mitel MiCollab | 0.5% (p37) |
| CVE-2025-41450 | Danfoss AK-SM 800A Series | 0.5% (p37) |
| CVE-2026-133324 | Mitel MiCollab | 0.4% (p27) |
| CVE-2026-133311 | Mitel MiCollab | 0.4% (p25) |
| CVE-2026-133275 | Mitel MiCollab | 0.3% (p17) |
<!-- latest:end -->

## How it works

- **Source:** CISA KEV JSON feed: vendor, product, required action, remediation due date, ransomware use
- **Enrichment:** FIRST EPSS API: probability of exploitation in the next 30 days, plus percentile
- **State:** `state/seen.json` tracks CVE IDs already reported, so each entry appears once
- **No dependencies:** Python standard library only

Run it locally:

```sh
python3 digest.py
```
