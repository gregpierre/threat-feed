"""Daily digest of new CISA KEV entries, enriched with EPSS scores.

Writes digests/YYYY/YYYY-MM-DD.md for each run that finds new KEV entries
and refreshes the "Latest" table in README.md. Runs with no new entries
change nothing, so there is nothing to commit.
"""

import json
import re
import sys
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"
NVD_LINK = "https://nvd.nist.gov/vuln/detail/{}"

ROOT = Path(__file__).parent
SEEN_FILE = ROOT / "state" / "seen.json"
README = ROOT / "README.md"
LATEST_START = "<!-- latest:start -->"
LATEST_END = "<!-- latest:end -->"


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "threat-feed-digest/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def epss_scores(cve_ids):
    scores = {}
    # The EPSS API accepts comma-separated batches; keep URLs short.
    for i in range(0, len(cve_ids), 50):
        batch = cve_ids[i : i + 50]
        try:
            data = fetch_json(EPSS_URL.format(",".join(batch)))
        except Exception as exc:
            print(f"EPSS lookup failed: {exc}", file=sys.stderr)
            continue
        for row in data.get("data", []):
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return scores


def load_seen():
    if SEEN_FILE.exists():
        return set(json.loads(SEEN_FILE.read_text()))
    return None


def save_seen(seen):
    SEEN_FILE.parent.mkdir(exist_ok=True)
    SEEN_FILE.write_text(json.dumps(sorted(seen), indent=0) + "\n")


def fmt_epss(score):
    if score is None:
        return "n/a"
    epss, pct = score
    return f"{epss:.1%} (p{pct * 100:.0f})"


def render_digest(day, entries, scores, catalog_version):
    ransomware = sum(1 for e in entries if e.get("knownRansomwareCampaignUse") == "Known")
    lines = [
        f"# KEV digest: {day}",
        "",
        f"{len(entries)} new known-exploited "
        f"{'vulnerability' if len(entries) == 1 else 'vulnerabilities'} "
        f"added to the CISA KEV catalog (version {catalog_version}).",
    ]
    if ransomware:
        lines.append(f"**{ransomware} linked to known ransomware campaigns.**")
    lines += [
        "",
        "| CVE | Vendor / product | EPSS | Ransomware | Fix due |",
        "|---|---|---|---|---|",
    ]
    for e in entries:
        cve = e["cveID"]
        lines.append(
            f"| [{cve}]({NVD_LINK.format(cve)}) | {e['vendorProject']} {e['product']} "
            f"| {fmt_epss(scores.get(cve))} | {e.get('knownRansomwareCampaignUse', 'Unknown')} "
            f"| {e.get('dueDate', '')} |"
        )
    lines.append("")
    for e in entries:
        cve = e["cveID"]
        lines += [
            f"## {cve}: {e['vulnerabilityName']}",
            "",
            e.get("shortDescription", "").strip(),
            "",
            f"- **Added to KEV:** {e['dateAdded']}",
            f"- **CWE:** {', '.join(e.get('cwes') or []) or 'n/a'}",
            f"- **Required action:** {e.get('requiredAction', '').strip()}",
            "",
        ]
    return "\n".join(lines)


def update_readme(day, entries, scores, digest_path):
    rows = [
        "| CVE | Vendor / product | EPSS |",
        "|---|---|---|",
    ]
    ranked = sorted(entries, key=lambda e: -(scores.get(e["cveID"], (0, 0))[0]))
    for e in ranked[:10]:
        rows.append(
            f"| {e['cveID']} | {e['vendorProject']} {e['product']} | {fmt_epss(scores.get(e['cveID']))} |"
        )
    block = "\n".join(
        [
            LATEST_START,
            f"**{day}**: {len(entries)} new, full digest in [`{digest_path}`]({digest_path})",
            "",
            *rows,
            LATEST_END,
        ]
    )
    text = README.read_text()
    text = re.sub(
        re.escape(LATEST_START) + ".*?" + re.escape(LATEST_END), block, text, flags=re.S
    )
    README.write_text(text)


def main():
    kev = fetch_json(KEV_URL)
    vulns = kev["vulnerabilities"]
    seen = load_seen()

    if seen is None:
        # First run: report only the most recent batch rather than the whole catalog.
        latest = max(v["dateAdded"] for v in vulns)
        new = [v for v in vulns if v["dateAdded"] == latest]
        seen = {v["cveID"] for v in vulns}
    else:
        new = [v for v in vulns if v["cveID"] not in seen]
        seen |= {v["cveID"] for v in new}

    if not new:
        print("No new KEV entries.")
        save_seen(seen)
        return

    new.sort(key=lambda v: (v["dateAdded"], v["cveID"]))
    scores = epss_scores([v["cveID"] for v in new])
    day = datetime.now(timezone.utc).date().isoformat()

    digest_path = Path("digests") / day[:4] / f"{day}.md"
    out = ROOT / digest_path
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_digest(day, new, scores, kev.get("catalogVersion", "?")))

    update_readme(day, new, scores, digest_path.as_posix())
    save_seen(seen)
    print(f"Wrote {digest_path} with {len(new)} entries.")


if __name__ == "__main__":
    main()
