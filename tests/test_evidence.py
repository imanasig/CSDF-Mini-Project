import hashlib
from pathlib import Path

import pytest

from cybertrail.evidence import evidence_path, preserve_evidence, verify_evidence


def test_preservation_hash_permissions_duplicates_and_verification(tmp_path):
    data = b"exact\r\nbytes\x00\xff"
    one = preserve_evidence(data, "../../unsafe.csv", tmp_path)
    two = preserve_evidence(data, "../../unsafe.csv", tmp_path)
    assert one["evidence_id"] != two["evidence_id"]
    assert one["sha256"] == hashlib.sha256(data).hexdigest()
    path = evidence_path(tmp_path, one["evidence_id"])
    assert path.read_bytes() == data
    assert path.stat().st_mode & 0o777 == 0o600
    assert verify_evidence(one, tmp_path)["status"] == "Verified"
    with pytest.raises(FileExistsError):
        preserve_evidence(b"replacement", "same.csv", tmp_path, evidence_id=one["evidence_id"])
    assert path.read_bytes() == data
    path.write_bytes(b"altered disposable test evidence")
    assert verify_evidence(one, tmp_path)["status"] == "Modified"
    path.unlink()
    assert verify_evidence(one, tmp_path)["status"] == "Missing"


@pytest.mark.parametrize("identifier", ["../escape", "/tmp/escape", "abc", "a" * 32 + "/x"])
def test_reject_unsafe_identifiers(tmp_path, identifier):
    with pytest.raises(ValueError):
        evidence_path(tmp_path, identifier)


def test_symlink_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.write_bytes(b"unchanged")
    identifier = "a" * 32
    evidence_path(tmp_path, identifier).symlink_to(outside)
    with pytest.raises(ValueError):
        preserve_evidence(b"bad", "demo.csv", tmp_path, evidence_id=identifier)
    assert verify_evidence({"evidence_id": identifier, "sha256": "x"}, tmp_path)["status"] == "Unavailable"
    assert outside.read_bytes() == b"unchanged"


def test_nonregular_file_is_not_verified(tmp_path):
    import os
    identifier = "b" * 32
    os.mkfifo(evidence_path(tmp_path, identifier))
    assert verify_evidence({"evidence_id": identifier, "sha256": "unused"}, tmp_path)["status"] == "Unavailable"
