# CISA KEV history

This repository preserves the best observable history of the CISA Known
Exploited Vulnerabilities catalog. It tracks one deterministic JSON snapshot.
Git commits and diffs are the history.

The reconstruction begins with an Internet Archive capture from the catalog's
2021-11-03 launch day. It then combines daily public snapshots through
2025-01-26 with the official CISA Git history from 2025-01-27 onward. Scheduled
polling records future catalog states.

This is not an authoritative lossless event log. Public daily snapshots can
miss a vulnerability added and removed within the same day. Commit timestamps
record when a source observed a catalog state. They do not prove when CISA
published it.

## Data model

`known_exploited_vulnerabilities.json` contains the current canonical snapshot.
Records are sorted by `cveID`, object keys are sorted and set-like `cwes` values
are sorted and deduplicated. Historical duplicate CVE rows are preserved and
identified in commit trailers. Future source snapshots must have unique CVE
IDs. Volatile fetch timestamps are not stored in the file, so an unchanged
catalog creates no commit.

Every data commit records provenance in its message:

```text
KEV snapshot: 287 CVEs, 291 records (+287 -0 ~0)

Observed-At: 2021-11-03T20:33:03Z
Source-Type: wayback-cisa-payload
Source-URL: https://...
Source-SHA256: ...
Canonical-SHA256: ...
Method: observed
Confidence: high
```

Use normal Git commands to inspect the catalog:

```bash
git log -- known_exploited_vulnerabilities.json
git diff HEAD^ HEAD -- known_exploited_vulnerabilities.json
git show <commit>:known_exploited_vulnerabilities.json
```

## Updating

The GitHub Actions workflow polls CISA every 15 minutes. It validates the JSON,
requires unique valid CVE IDs, verifies the declared count and rejects empty or
implausibly collapsed catalogs before committing.

Run the same updater locally:

```bash
python3 kev_archive.py update --repo . --commit
```

Rebuild the historical commits in a new empty Git repository:

```bash
python3 kev_archive.py backfill \
  --repo /path/to/empty/archive \
  --mirror-repo /path/to/hrbrmstr/cisa-known-exploited-vulns \
  --official-repo /path/to/cisagov/kev-data
```

Add `--resume` after an interrupted import. The importer continues after the
observation timestamp stored in the current `HEAD` commit.

The backfill accepts only observed full snapshots. NVD events and CISA alerts
can corroborate changes, but the importer does not synthesize catalog states
from partial event descriptions.

## Sources

- CISA live JSON: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- Official CISA Git mirror: <https://github.com/cisagov/kev-data>
- Daily public archive: <https://github.com/hrbrmstr/cisa-known-exploited-vulns>
- Internet Archive CDX: <https://web.archive.org/cdx/search/cdx?url=www.cisa.gov%2Fsites%2Fdefault%2Ffiles%2Fcsv%2Fknown_exploited_vulnerabilities.csv&output=json&filter=statuscode%3A200&collapse=digest>

This repository follows Simon Willison's
[Git scraping](https://simonwillison.net/2020/Oct/9/git-scraping/) pattern.

## License and attribution

CISA distributes the KEV database under CC0 1.0. Third-party links included in
the catalog remain subject to their own policies and licenses. This repository
does not imply endorsement by CISA or DHS and does not authorize use of their
marks.
