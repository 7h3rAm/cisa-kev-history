#!/usr/bin/env python3
"""Maintain a Git-native history of the CISA KEV catalog."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import time
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


CATALOG_PATH = "known_exploited_vulnerabilities.json"
LIVE_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
WAYBACK_CDX_URL = (
    "https://web.archive.org/cdx/search/cdx?"
    "url=www.cisa.gov%2Fsites%2Fdefault%2Ffiles%2Fcsv%2F"
    "known_exploited_vulnerabilities.csv&output=json&"
    "fl=timestamp%2Coriginal%2Cstatuscode%2Cmimetype%2Cdigest%2Clength&"
    "filter=statuscode%3A200&collapse=digest"
)
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MIN_CATALOG_ENTRIES = 200
MAX_REMOVAL_FRACTION = 0.10
USER_AGENT = "cisa-kev-history/1.0 (+https://github.com/7h3rAm/cisa-kev-history)"

CSV_FIELD_MAP = {
    "CVE": "cveID",
    "Vendor/Project": "vendorProject",
    "Product": "product",
    "Vulnerability Name": "vulnerabilityName",
    "Date Added to Catalog": "dateAdded",
    "Short Description": "shortDescription",
    "Action": "requiredAction",
    "Due Date": "dueDate",
    "Known Ransomware Campaign Use": "knownRansomwareCampaignUse",
    "Forensic Triage": "forensicTriage",
    "Notes": "notes",
    "CWEs": "cwes",
}


class SnapshotError(ValueError):
    """A source payload cannot safely become an archive snapshot."""


@dataclass(frozen=True)
class Observation:
    observed_at: str
    source_type: str
    source_url: str
    format: str
    repo: Path | None = None
    commit: str | None = None
    path: str | None = None


def git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=text,
    )
    return result.stdout


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean_cve_id(value: Any) -> str:
    text = "".join(
        character
        for character in str(value or "")
        if unicodedata.category(character) != "Cf"
    )
    return text.strip().upper()


def normalize_date(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    for format_string in (
        "%Y-%m-%d",
        "%d-%b-%y",
        "%d-%b-%Y",
        "%m/%d/%Y",
        "%m/%d/%y",
    ):
        try:
            return datetime.strptime(text, format_string).date().isoformat()
        except ValueError:
            continue
    raise SnapshotError(f"unsupported date value: {text!r}")


def parse_csv_payload(data: bytes) -> list[dict[str, Any]]:
    if data.startswith(b"\x1f\x8b"):
        try:
            data = gzip.decompress(data)
        except OSError as exc:
            raise SnapshotError(f"invalid gzip-compressed CSV: {exc}") from exc
    try:
        decoded = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SnapshotError(f"CSV is not UTF-8: {exc}") from exc
    reader = csv.DictReader(io.StringIO(decoded))
    if not reader.fieldnames:
        raise SnapshotError("CSV has no header")
    entries = []
    for source_row in reader:
        row: dict[str, Any] = {}
        for source_field, value in source_row.items():
            if source_field is None:
                continue
            field = CSV_FIELD_MAP.get(source_field.strip(), source_field.strip())
            if field == "cwes":
                row[field] = [
                    item.strip() for item in (value or "").split(",") if item.strip()
                ]
            else:
                row[field] = value or ""
        entries.append(row)
    return entries


def parse_json_payload(data: bytes) -> tuple[list[dict[str, Any]], int | None]:
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"invalid JSON: {exc}") from exc
    declared_count = None
    if isinstance(payload, dict):
        entries = payload.get("vulnerabilities")
        if payload.get("count") is not None:
            try:
                declared_count = int(payload["count"])
            except (TypeError, ValueError) as exc:
                raise SnapshotError("JSON count is not an integer") from exc
    else:
        entries = payload
    if not isinstance(entries, list):
        raise SnapshotError("JSON must contain a vulnerabilities array")
    return entries, declared_count


def normalize_entries(
    entries: Iterable[dict[str, Any]],
    declared_count: int | None = None,
    allow_duplicate_ids: bool = False,
) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicate_count = 0
    source_count = 0
    for source in entries:
        source_count += 1
        if not isinstance(source, dict):
            raise SnapshotError("catalog entries must be objects")
        record = dict(source)
        cve = clean_cve_id(record.get("cveID"))
        if not CVE_PATTERN.fullmatch(cve):
            raise SnapshotError(f"invalid CVE ID: {record.get('cveID')!r}")
        record["cveID"] = cve
        for field in ("dateAdded", "dueDate"):
            if field in record:
                record[field] = normalize_date(record[field])
        if "cwes" in record:
            cwes = record["cwes"]
            if isinstance(cwes, str):
                cwes = cwes.split(",")
            if not isinstance(cwes, list):
                raise SnapshotError(f"{cve} cwes must be a list or string")
            record["cwes"] = sorted(
                {str(value).strip() for value in cwes if str(value).strip()}
            )
        if cve in seen:
            duplicate_count += 1
            if not allow_duplicate_ids:
                raise SnapshotError(f"duplicate CVE ID: {cve}")
        seen.add(cve)
        records.append(record)
    if declared_count is not None and declared_count != source_count:
        raise SnapshotError(
            f"declared count {declared_count} does not match {source_count} entries"
        )
    if len(seen) < MIN_CATALOG_ENTRIES:
        raise SnapshotError(
            f"catalog has {len(seen)} unique entries, fewer than {MIN_CATALOG_ENTRIES}"
        )
    records.sort(
        key=lambda record: (
            record["cveID"],
            json.dumps(record, ensure_ascii=False, sort_keys=True),
        )
    )
    return records, duplicate_count


def canonicalize(
    data: bytes, format_name: str, allow_duplicate_ids: bool = False
) -> tuple[bytes, int]:
    if format_name == "csv":
        entries = parse_csv_payload(data)
        declared_count = None
    elif format_name == "json":
        entries, declared_count = parse_json_payload(data)
    else:
        raise SnapshotError(f"unsupported source format: {format_name}")
    records, duplicate_count = normalize_entries(
        entries, declared_count, allow_duplicate_ids
    )
    output = json.dumps(
        {"vulnerabilities": records},
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return (output + "\n").encode(), duplicate_count


def canonical_entries(data: bytes) -> dict[str, list[dict[str, Any]]]:
    entries, _ = parse_json_payload(data)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        grouped.setdefault(entry["cveID"], []).append(entry)
    return grouped


def validate_transition(previous: bytes | None, current: bytes) -> None:
    if previous is None:
        return
    old_count = len(canonical_entries(previous))
    new_count = len(canonical_entries(current))
    minimum = int(old_count * (1 - MAX_REMOVAL_FRACTION))
    if new_count < minimum:
        raise SnapshotError(
            f"catalog count collapsed from {old_count} to {new_count}; "
            "refusing to commit"
        )


def diff_counts(previous: bytes | None, current: bytes) -> tuple[int, int, int]:
    old = canonical_entries(previous) if previous else {}
    new = canonical_entries(current)
    added = set(new) - set(old)
    removed = set(old) - set(new)
    modified = {cve for cve in set(old) & set(new) if old[cve] != new[cve]}
    return len(added), len(removed), len(modified)


def normalize_timestamp(value: str) -> str:
    if re.fullmatch(r"[0-9]{14}", value):
        parsed = datetime.strptime(value, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise SnapshotError(f"timestamp must include a timezone: {value}")
        parsed = parsed.astimezone(UTC)
    return parsed.isoformat().replace("+00:00", "Z")


def timestamp_key(value: str) -> datetime:
    return datetime.fromisoformat(normalize_timestamp(value).replace("Z", "+00:00"))


def request_bytes(url: str, attempts: int = 4) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                if response.status != 200:
                    raise SnapshotError(f"HTTP {response.status} for {url}")
                return response.read()
        except (OSError, urllib.error.URLError, SnapshotError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(2**attempt)
    raise SnapshotError(f"failed to fetch {url}: {last_error}")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        stream.write(data)
        temporary = Path(stream.name)
    os.replace(temporary, path)


def require_git_identity(repo: Path) -> None:
    for key in ("user.name", "user.email"):
        value = str(git(repo, "config", "--get", key)).strip()
        if not value:
            raise SnapshotError(f"Git repository must configure {key}")


def restore_snapshot(repo: Path, path: Path, previous: bytes | None) -> None:
    if previous is None:
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "rm",
                "--cached",
                "--quiet",
                "--ignore-unmatch",
                CATALOG_PATH,
            ],
            check=False,
            capture_output=True,
        )
        path.unlink(missing_ok=True)
        return
    atomic_write(path, previous)
    git(repo, "add", "--", CATALOG_PATH)


def commit_snapshot(
    repo: Path,
    canonical: bytes,
    observation: Observation,
    source_data: bytes,
    duplicate_count: int = 0,
) -> bool:
    path = repo / CATALOG_PATH
    previous = path.read_bytes() if path.is_file() else None
    if previous == canonical:
        return False
    validate_transition(previous, canonical)
    require_git_identity(repo)
    added, removed, modified = diff_counts(previous, canonical)
    cve_count = len(canonical_entries(canonical))
    record_count = len(parse_json_payload(canonical)[0])
    observed_at = normalize_timestamp(observation.observed_at)
    if duplicate_count:
        summary = f"{cve_count} CVEs, {record_count} records"
    else:
        summary = f"{cve_count} CVEs"
    message_lines = [
        f"KEV snapshot: {summary} (+{added} -{removed} ~{modified})",
        "",
        f"Observed-At: {observed_at}",
        f"Source-Type: {observation.source_type}",
        f"Source-URL: {observation.source_url}",
        f"Source-SHA256: {sha256(source_data)}",
        f"Canonical-SHA256: {sha256(canonical)}",
        "Method: observed",
        "Confidence: high",
    ]
    if duplicate_count:
        message_lines.append(f"Duplicate-IDs-Preserved: {duplicate_count}")
    atomic_write(path, canonical)
    git(repo, "add", "--", CATALOG_PATH)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_DATE": observed_at,
            "GIT_COMMITTER_DATE": observed_at,
        }
    )
    result = subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "\n".join(message_lines)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if result.returncode != 0:
        restore_snapshot(repo, path, previous)
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise SnapshotError(f"Git commit failed: {detail}")
    return True


def load_observation(observation: Observation) -> bytes:
    if observation.repo and observation.commit and observation.path:
        return git(
            observation.repo,
            "show",
            f"{observation.commit}:{observation.path}",
            text=False,
        )
    return request_bytes(observation.source_url)


def parse_added_paths(repo: Path, pathspec: str) -> list[tuple[str, str, str]]:
    output = str(
        git(
            repo,
            "log",
            "--reverse",
            "--format=COMMIT%x09%H%x09%cI",
            "--name-status",
            "--diff-filter=A",
            "--",
            pathspec,
        )
    )
    result = []
    commit = ""
    observed_at = ""
    for line in output.splitlines():
        if line.startswith("COMMIT\t"):
            _, commit, observed_at = line.split("\t", 2)
        elif line.startswith("A\t"):
            result.append((commit, observed_at, line.split("\t", 1)[1]))
    return result


def mirror_observations(repo: Path) -> list[Observation]:
    observations = []
    for commit, observed_at, path in parse_added_paths(repo, "docs"):
        if not re.fullmatch(r"docs/[0-9]{4}-[0-9]{2}-[0-9]{2}-cisa-kev\.csv", path):
            continue
        observations.append(
            Observation(
                observed_at=observed_at,
                source_type="hrbrmstr-daily-cisa-mirror",
                source_url=(
                    "https://raw.githubusercontent.com/hrbrmstr/"
                    f"cisa-known-exploited-vulns/{commit}/{path}"
                ),
                format="csv",
                repo=repo,
                commit=commit,
                path=path,
            )
        )
    return observations


def official_observations(repo: Path) -> list[Observation]:
    path = CATALOG_PATH
    output = str(
        git(
            repo,
            "log",
            "--reverse",
            "--format=%H%x09%cI",
            "--",
            path,
        )
    )
    observations = []
    for line in output.splitlines():
        if not line.strip():
            continue
        commit, observed_at = line.split("\t", 1)
        observations.append(
            Observation(
                observed_at=observed_at,
                source_type="official-cisa-git",
                source_url=(
                    "https://raw.githubusercontent.com/cisagov/kev-data/"
                    f"{commit}/{path}"
                ),
                format="json",
                repo=repo,
                commit=commit,
                path=path,
            )
        )
    return observations


def wayback_observations(cdx_url: str) -> list[Observation]:
    try:
        rows = json.loads(request_bytes(cdx_url))
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"invalid Wayback CDX response: {exc}") from exc
    if not rows or rows[0][0] != "timestamp":
        raise SnapshotError("unexpected Wayback CDX response")
    indexes = {name: index for index, name in enumerate(rows[0])}
    observations = []
    for row in rows[1:]:
        timestamp = row[indexes["timestamp"]]
        original = row[indexes["original"]]
        observations.append(
            Observation(
                observed_at=timestamp,
                source_type="wayback-cisa-payload",
                source_url=f"https://web.archive.org/web/{timestamp}id_/{original}",
                format="csv",
            )
        )
    return observations


def backfill(
    repo: Path,
    mirror_repo: Path,
    official_repo: Path,
    cdx_url: str,
    resume: bool = False,
) -> dict[str, int]:
    has_head = (
        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
        ).returncode
        == 0
    )
    if has_head and not resume:
        raise SnapshotError("backfill requires a Git repository with no commits")
    official = official_observations(official_repo)
    if not official:
        raise SnapshotError("official CISA repository has no catalog commits")
    official_start = timestamp_key(official[0].observed_at)
    earlier = mirror_observations(mirror_repo) + wayback_observations(cdx_url)
    observations = [
        observation
        for observation in earlier
        if timestamp_key(observation.observed_at) < official_start
    ] + official
    observations.sort(
        key=lambda item: (
            timestamp_key(item.observed_at),
            item.source_type,
            item.source_url,
        )
    )
    if has_head:
        head_timestamp = timestamp_key(
            str(git(repo, "show", "-s", "--format=%cI")).strip()
        )
        observations = [
            observation
            for observation in observations
            if timestamp_key(observation.observed_at) > head_timestamp
        ]

    counts = {
        "observations": len(observations),
        "commits": 0,
        "unchanged": 0,
        "invalid": 0,
    }
    for index, observation in enumerate(observations, start=1):
        try:
            source_data = load_observation(observation)
            canonical, duplicate_count = canonicalize(
                source_data, observation.format, allow_duplicate_ids=True
            )
            changed = commit_snapshot(
                repo, canonical, observation, source_data, duplicate_count
            )
        except SnapshotError as exc:
            counts["invalid"] += 1
            print(
                f"skip {observation.observed_at} {observation.source_type}: {exc}",
                flush=True,
            )
            continue
        counts["commits" if changed else "unchanged"] += 1
        if index % 100 == 0 or changed:
            action = "commit" if changed else "unchanged"
            print(
                f"{index}/{len(observations)} {action} "
                f"{normalize_timestamp(observation.observed_at)}",
                flush=True,
            )
    return counts


def update(
    repo: Path,
    source_url: str,
    source_file: Path | None,
    observed_at: str | None,
    commit: bool,
) -> bool:
    source_data = source_file.read_bytes() if source_file else request_bytes(source_url)
    canonical, duplicate_count = canonicalize(source_data, "json")
    observation = Observation(
        observed_at=observed_at or datetime.now(UTC).isoformat(),
        source_type="live-cisa-feed",
        source_url=source_url,
        format="json",
    )
    path = repo / CATALOG_PATH
    previous = path.read_bytes() if path.is_file() else None
    if previous == canonical:
        print("unchanged")
        return False
    validate_transition(previous, canonical)
    if commit:
        commit_snapshot(repo, canonical, observation, source_data, duplicate_count)
    else:
        atomic_write(path, canonical)
    print("updated")
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    update_parser = subparsers.add_parser(
        "update", help="archive the current CISA feed"
    )
    update_parser.add_argument("--repo", type=Path, default=Path.cwd())
    update_parser.add_argument("--url", default=LIVE_URL)
    update_parser.add_argument("--input", type=Path)
    update_parser.add_argument("--observed-at")
    update_parser.add_argument("--commit", action="store_true")

    backfill_parser = subparsers.add_parser(
        "backfill", help="reconstruct history from public observations"
    )
    backfill_parser.add_argument("--repo", type=Path, default=Path.cwd())
    backfill_parser.add_argument("--mirror-repo", type=Path, required=True)
    backfill_parser.add_argument("--official-repo", type=Path, required=True)
    backfill_parser.add_argument("--wayback-cdx-url", default=WAYBACK_CDX_URL)
    backfill_parser.add_argument("--resume", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "update":
            update(args.repo, args.url, args.input, args.observed_at, args.commit)
        else:
            counts = backfill(
                args.repo,
                args.mirror_repo,
                args.official_repo,
                args.wayback_cdx_url,
                args.resume,
            )
            print(json.dumps(counts, sort_keys=True))
    except (OSError, subprocess.CalledProcessError, SnapshotError) as exc:
        parser_error = f"error: {exc}"
        print(parser_error, file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
