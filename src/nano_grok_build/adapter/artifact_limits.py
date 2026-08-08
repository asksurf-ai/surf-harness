"""Shared bounded publication limits for adapter evidence artifacts."""

from __future__ import annotations

DEFAULT_PUBLICATION_FILE_MAX_BYTES = 64 * 1024 * 1024
WORKSPACE_CHANGED_TAR_MAX_BYTES = 80 * 1024 * 1024
PUBLICATION_TOTAL_MAX_BYTES = 256 * 1024 * 1024


def publication_file_max_bytes(name: str) -> int:
    """Return the exact-name per-file publication ceiling."""

    if name == "workspace-changed.tar":
        return WORKSPACE_CHANGED_TAR_MAX_BYTES
    return DEFAULT_PUBLICATION_FILE_MAX_BYTES
