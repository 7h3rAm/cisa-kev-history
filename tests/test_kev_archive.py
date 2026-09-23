import json
from pathlib import Path
import subprocess

import pytest

import kev_archive as archive


def record(cve: str, name: str = "Example Vulnerability") -> dict[str, object]:
    return {
        "cveID": cve,
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "vulnerabilityName": name,
        "dateAdded": "2021-11-03",
        "dueDate": "2021-11-17",
        "cwes": ["CWE-79"],
    }


def payload(records: list[dict[str, object]]) -> bytes:
    return json.dumps({"count": len(records), "vulnerabilities": records}).encode()


def enough_records(start: int = 0, count: int = archive.MIN_CATALOG_ENTRIES):
    return [record(f"CVE-2021-{index:04d}") for index in range(start, start + count)]


def init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", path], check=True)
    subprocess.run(
        ["git", "-C", path, "config", "user.name", "Archive Test"], check=True
    )
    subprocess.run(
        ["git", "-C", path, "config", "user.email", "archive@example.invalid"],
        check=True,
    )


def commit_count(repo: Path) -> int:
    result = subprocess.run(
        ["git", "-C", repo, "rev-list", "--count", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return int(result.stdout)


def test_canonicalize_sorts_records_keys_and_set_like_cwes():
    records = enough_records()
    records[0]["cwes"] = ["CWE-89", "CWE-79", "CWE-79"]
    records.reverse()

    canonical, duplicates = archive.canonicalize(payload(records), "json")
    parsed = json.loads(canonical)

    assert duplicates == 0
    assert parsed["vulnerabilities"][0]["cveID"] == "CVE-2021-0000"
    assert parsed["vulnerabilities"][0]["cwes"] == ["CWE-79", "CWE-89"]


def test_canonicalize_accepts_historical_date_and_empty_metadata():
    records = enough_records()
    records[0]["dateAdded"] = "11/3/2021"
    records[0]["product"] = ""

    canonical, _ = archive.canonicalize(payload(records), "json")

    first = json.loads(canonical)["vulnerabilities"][0]
    assert first["dateAdded"] == "2021-11-03"
    assert first["product"] == ""


def test_canonicalize_preserves_historical_duplicates_when_enabled():
    records = enough_records()
    records.append(dict(records[0]))
    source = json.dumps({"vulnerabilities": records}).encode()

    canonical, duplicates = archive.canonicalize(
        source, "json", allow_duplicate_ids=True
    )

    assert duplicates == 1
    assert len(json.loads(canonical)["vulnerabilities"]) == (
        archive.MIN_CATALOG_ENTRIES + 1
    )


def test_canonicalize_rejects_duplicates_and_bad_declared_count():
    records = enough_records()
    conflicting = dict(records[0])
    conflicting["product"] = "Different Product"
    with pytest.raises(archive.SnapshotError, match="duplicate CVE ID"):
        archive.canonicalize(
            json.dumps({"vulnerabilities": records + [conflicting]}).encode(),
            "json",
        )
    with pytest.raises(archive.SnapshotError, match="declared count"):
        archive.canonicalize(
            json.dumps({"count": 999, "vulnerabilities": records}).encode(),
            "json",
        )


def test_commit_snapshot_creates_reviewable_commit_and_noops(tmp_path):
    repo = tmp_path / "archive"
    repo.mkdir()
    init_repo(repo)
    source = payload(enough_records())
    canonical, _ = archive.canonicalize(source, "json")
    observation = archive.Observation(
        observed_at="2021-11-03T20:33:03Z",
        source_type="test-fixture",
        source_url="https://example.invalid/kev.json",
        format="json",
    )

    assert archive.commit_snapshot(repo, canonical, observation, source)
    first_head = archive.git(repo, "rev-parse", "HEAD").strip()
    assert not archive.commit_snapshot(repo, canonical, observation, source)

    assert archive.git(repo, "rev-parse", "HEAD").strip() == first_head
    assert commit_count(repo) == 1
    assert archive.git(repo, "show", "-s", "--format=%cI").strip() == (
        "2021-11-03T20:33:03Z"
    )
    message = archive.git(repo, "show", "-s", "--format=%B")
    assert "Source-SHA256:" in message
    assert "Observed-At: 2021-11-03T20:33:03Z" in message


def test_commit_snapshot_rejects_count_collapse_without_touching_repo(tmp_path):
    repo = tmp_path / "archive"
    repo.mkdir()
    init_repo(repo)
    source = payload(enough_records(count=230))
    canonical, _ = archive.canonicalize(source, "json")
    observation = archive.Observation(
        observed_at="2021-11-03T20:33:03Z",
        source_type="test-fixture",
        source_url="https://example.invalid/kev.json",
        format="json",
    )
    archive.commit_snapshot(repo, canonical, observation, source)
    previous_head = archive.git(repo, "rev-parse", "HEAD").strip()
    previous_data = (repo / archive.CATALOG_PATH).read_bytes()
    collapsed_source = payload(enough_records(count=archive.MIN_CATALOG_ENTRIES))
    collapsed, _ = archive.canonicalize(collapsed_source, "json")

    with pytest.raises(archive.SnapshotError, match="collapsed"):
        archive.commit_snapshot(repo, collapsed, observation, collapsed_source)

    assert archive.git(repo, "rev-parse", "HEAD").strip() == previous_head
    assert (repo / archive.CATALOG_PATH).read_bytes() == previous_data
    assert archive.git(repo, "status", "--porcelain") == ""


def test_update_invalid_input_preserves_snapshot_and_clean_worktree(tmp_path):
    repo = tmp_path / "archive"
    repo.mkdir()
    init_repo(repo)
    valid = tmp_path / "valid.json"
    valid.write_bytes(payload(enough_records()))
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"vulnerabilities": []}', encoding="utf-8")

    assert archive.update(
        repo,
        "https://example.invalid/kev.json",
        valid,
        "2021-11-03T20:33:03Z",
        True,
    )
    previous_head = archive.git(repo, "rev-parse", "HEAD").strip()
    with pytest.raises(archive.SnapshotError, match="fewer than"):
        archive.update(
            repo,
            "https://example.invalid/kev.json",
            invalid,
            "2021-11-04T20:33:03Z",
            True,
        )

    assert archive.git(repo, "rev-parse", "HEAD").strip() == previous_head
    assert archive.git(repo, "status", "--porcelain") == ""


def test_changed_snapshot_is_one_commit_with_added_removed_and_modified(tmp_path):
    repo = tmp_path / "archive"
    repo.mkdir()
    init_repo(repo)
    initial_records = enough_records(count=210)
    initial_source = payload(initial_records)
    initial, _ = archive.canonicalize(initial_source, "json")
    first = archive.Observation(
        "2021-11-03T20:33:03Z", "test-fixture", "https://example.invalid/one", "json"
    )
    archive.commit_snapshot(repo, initial, first, initial_source)

    changed_records = initial_records[1:]
    changed_records[0] = record(changed_records[0]["cveID"], "Corrected Name")
    changed_records.append(record("CVE-2021-9999"))
    changed_source = payload(changed_records)
    changed, _ = archive.canonicalize(changed_source, "json")
    second = archive.Observation(
        "2021-11-04T20:33:03Z", "test-fixture", "https://example.invalid/two", "json"
    )

    archive.commit_snapshot(repo, changed, second, changed_source)

    assert commit_count(repo) == 2
    subject = archive.git(repo, "show", "-s", "--format=%s").strip()
    assert subject == "KEV snapshot: 210 CVEs (+1 -1 ~1)"
    changed_files = archive.git(
        repo, "diff", "--name-only", "HEAD^", "HEAD"
    ).splitlines()
    assert changed_files == [archive.CATALOG_PATH]
