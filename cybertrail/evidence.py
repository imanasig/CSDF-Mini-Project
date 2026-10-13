"""Preserve exact bytes under generated IDs and verify stored-file integrity."""

import hashlib
import os
import re
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path


def evidence_path(directory, evidence_id):
    if not isinstance(evidence_id, str) or not re.fullmatch(r"[0-9a-f]{32}", evidence_id):
        raise ValueError("Invalid evidence identifier.")
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("Evidence directory must not be a symlink.")
    target = directory / f"{evidence_id}.evidence"
    if target.is_symlink():
        raise ValueError("Evidence files must not be symlinks.")
    return target


def preserve_evidence(original_bytes, original_filename, directory, *, evidence_id=None):
    """Exclusive creation prevents overwrites; original filenames are metadata only."""
    evidence_id = evidence_id or uuid.uuid4().hex
    path = evidence_path(directory, evidence_id)
    digest = hashlib.sha256(original_bytes).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(original_bytes)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return {"evidence_id": evidence_id, "original_filename": original_filename,
            "sha256": digest, "size_bytes": len(original_bytes), "stored_name": path.name}


def verify_evidence(metadata, directory):
    """Compute actual SHA-256; missing/altered/unsafe files never count as verified."""
    result = {"evidence_id": metadata["evidence_id"], "expected_sha256": metadata["sha256"], "actual_sha256": None,
              "checked_at": datetime.now(timezone.utc).isoformat()}
    try:
        path = evidence_path(directory, metadata["evidence_id"])
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("Stored evidence must be a regular file.")
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        result.update(actual_sha256=digest, status="Verified" if digest == metadata["sha256"] else "Modified")
    except FileNotFoundError:
        result["status"] = "Missing"
    except (OSError, ValueError):
        result["status"] = "Unavailable"
    return result
