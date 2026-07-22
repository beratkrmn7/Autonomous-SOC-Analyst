"""Shared idempotency-key derivation for every analysis entry point.

CLI detect/analyze, the synchronous API (/detect/file, /analyze/file), and
background job submission must all derive the same key from the same bytes,
pipeline version, and analysis mode, so the same file submitted through any
entry point reuses one job instead of creating duplicates. Detect and analyze
remain separate idempotency scopes because the mode is part of the key.

This module intentionally has no heavy imports so it is safe to import from
API, worker, and CLI code paths alike.
"""

from __future__ import annotations

import hashlib

_SHA256_CHUNK_BYTES = 1024 * 1024


def compute_file_sha256(file_path: str) -> str:
    """Streaming SHA-256 of a file (matches the staging store's digest)."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_SHA256_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compute_idempotency_key(
    file_sha256: str, pipeline_version: str, analysis_mode: str
) -> str:
    """The canonical idempotency key: sha256 of
    ``{file_sha256}:{pipeline_version}:{analysis_mode}``."""
    idemp_string = f"{file_sha256}:{pipeline_version}:{analysis_mode}"
    return hashlib.sha256(idemp_string.encode("utf-8")).hexdigest()
