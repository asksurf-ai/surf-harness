"""Compile task-neutral pre-existing Git-history access from canonical instructions."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

GIT_HISTORY_ACCESS_REQUIRED = "required"
GIT_HISTORY_ACCESS_NOT_REQUIRED = "not_required"
CAPABILITY_SCHEMA = "nano-git-history-capability-v1"
CAPABILITY_POLICY_VERSION = "nano-git-history-capability-policy-v4"
_CAPABILITY_KEYS = {
    "schema_version",
    "policy_version",
    "git_history_access",
    "canonical_instruction_sha256",
    "trusted_manifest_sha256",
    "supporting_span_sha256",
}

_NEGATION = re.compile(r"\b(?:not|never|without|don't)\b", re.I)
_NON_HISTORY_RECOVERY_SOURCE = re.compile(
    r"\b(?:recover|restore|retrieve|reconstruct)\b[^.!?\n]{0,160}"
    r"\b(?:from|using)\s+(?:(?:the|a|an)\s+)?"
    r"(?:(?:supplied|provided|saved|local|filesystem)\s+)?"
    r"(?:backup|archive|snapshot)\b|"
    r"\bnot\s+from\s+(?:the\s+)?"
    r"(?:(?:git|commit|repository)\s+)?history\b|"
    r"\b(?:from|using)\s+(?:(?:the|a|an)\s+)?"
    r"(?:(?:supplied|provided|saved|local|filesystem)\s+)?"
    r"(?:backup|archive|snapshot)\b[^.!?\n]{0,160}"
    r"\b(?:recover|restore|retrieve|reconstruct)\b",
    re.I,
)
_EXPLICIT_HISTORY_ACTION = re.compile(
    r"\b(?:inspect|analy[sz]e|review|search|examine|read|use|trace|"
    r"look\s+through|bisect)\b[^.!?\n]{0,96}\b(?:git\s+|commit\s+|"
    r"revision\s+|version\s+)?history\b|"
    r"\b(?:inspect|analy[sz]e|review|search|examine|read|use|trace|"
    r"look\s+through|recover|restore)\b[^.!?\n]{0,96}\breflog\b|"
    r"\b(?:recover|restore|find|inspect|compare)\b[^.!?\n]{0,96}"
    r"\b(?:deleted|lost|prior|previous|earlier|old|pre-existing)\s+"
    r"(?:commit|revision|branch|tag)s?\b|"
    r"\bcompare\b[^.!?\n]{0,96}\b(?:commits|revisions|branches|tags)\b|"
    r"\b(?:find|identify|locate|determine)\b[^.!?\n]{0,96}\bcommit\b"
    r"[^.!?\n]{0,48}\b(?:introduced|caused|before|after)\b|"
    r"\b(?:git\s+)?bisect\b",
    re.I,
)
_BUNDLE_REFERENCE_INSPECTION = re.compile(
    r"\binspect\s+the\s+bundle\s+references\b",
    re.I,
)
_BUNDLE_REFERENCE_SPAN = "inspect the bundle references"
_BRANCH_SWITCH_LOST_WORK = re.compile(
    r"\b(?:check(?:ed|ing)?\s+out|switch(?:ed|ing)?)\b"
    r"[^.!?\n]{0,160}"
    r"(?:"
    r"\b(?:can(?:not|'t)|could(?:not|n't)|unable\s+to)\s+"
    r"(?:find|locate|see)\b[^.!?\n]{0,64}"
    r"\b(?:changes?|edits?|work)\b|"
    r"\b(?:changes?|edits?|work)\b[^.!?\n]{0,64}"
    r"\b(?:disappeared|missing|lost|gone)\b"
    r")|"
    r"\b(?:changes?|edits?|work)\b[^.!?\n]{0,96}"
    r"\b(?:disappeared|missing|lost|gone)\b[^.!?\n]{0,160}"
    r"\b(?:after|when|while)\b[^.!?\n]{0,32}"
    r"\b(?:check(?:ed|ing)?\s+out|switch(?:ed|ing)?)\b",
    re.I,
)
_REWRITTEN_HISTORY_RECOVERY = re.compile(
    r"(?:"
    r"\b(?:secret|credential|data|file|content|value|token)s?\b"
    r"[^.!?\n]{0,192}\b(?:removed|deleted|lost|purged)\b"
    r"[^.!?\n]{0,128}(?:"
    r"\b(?:rewrit(?:e|ing|ten)|rewrote)\b"
    r"[^.!?\n]{0,64}\b(?:git\s+|repository\s+)?history\b|"
    r"\b(?:git\s+|repository\s+)?history\b"
    r"[^.!?\n]{0,64}\b(?:rewritten|rewrote)\b"
    r")|"
    r"\b(?:earlier|previous|prior|old|pre-existing)\s+"
    r"(?:git\s+|repository\s+)?history\b"
    r"[^.!?\n]{0,128}\b(?:removed|deleted|lost|purged|rewritten)\b"
    r")"
    r"[^.!?\n]{0,96}"
    r"(?:[\s,;:\-]{0,64}|[.!?][\t\r\n ]{0,32}"
    r"(?:please\b[\t\r\n ]*)?(?:\d+[.)][\t ]*)?)"
    r"\b(?:recover|restore|retrieve|reconstruct)\b"
    r"[^.!?\n]{0,128}\b(?:secret|credential|data|file|content|value|token)s?\b|"
    r"\b(?:recover|restore|retrieve|reconstruct)\b"
    r"[^.!?\n]{0,128}\b(?:secret|credential|data|file|content|value|token)s?\b"
    r"[^.!?\n]{0,256}?"
    r"(?:"
    r"\b(?:removed|deleted|lost|purged)\b"
    r"[^.!?\n]{0,128}\b(?:rewrit(?:e|ing|ten)|rewrote)\b"
    r"[^.!?\n]{0,64}\b(?:git\s+|repository\s+)?history\b|"
    r"\b(?:earlier|previous|prior|old|pre-existing)\s+"
    r"(?:commit|revision|history)\b"
    r")",
    re.I,
)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _supporting_span(instruction: str) -> str | None:
    if not isinstance(instruction, str) or not instruction.strip():
        raise ValueError("canonical_instruction_invalid")
    matches = sorted(
        (
            *_EXPLICIT_HISTORY_ACTION.finditer(instruction),
            *_BUNDLE_REFERENCE_INSPECTION.finditer(instruction),
            *_BRANCH_SWITCH_LOST_WORK.finditer(instruction),
            *_REWRITTEN_HISTORY_RECOVERY.finditer(instruction),
        ),
        key=lambda match: (match.start(), match.end()),
    )
    for match in matches:
        sentence_start = max(
            instruction.rfind(".", 0, match.start()),
            instruction.rfind("!", 0, match.start()),
            instruction.rfind("?", 0, match.start()),
            instruction.rfind("\n", 0, match.start()),
        )
        prefix = instruction[sentence_start + 1 : match.start()]
        sentence_ends = [
            position
            for delimiter in ".!?\n"
            if (position := instruction.find(delimiter, match.end())) >= 0
        ]
        recovery_clause = instruction[
            sentence_start + 1 : min(sentence_ends, default=len(instruction))
        ]
        negation_prefix = prefix[
            -16 if match.re is _BUNDLE_REFERENCE_INSPECTION else -64 :
        ]
        if (
            not _NEGATION.search(negation_prefix)
            and not _NEGATION.search(match.group(0))
            and (
                match.re is not _REWRITTEN_HISTORY_RECOVERY
                or not _NON_HISTORY_RECOVERY_SOURCE.search(recovery_clause)
            )
        ):
            return (
                _BUNDLE_REFERENCE_SPAN
                if match.re is _BUNDLE_REFERENCE_INSPECTION
                else match.group(0)
            )
    return None


def compile_git_history_access(instruction: str) -> str:
    """Return the task-neutral access enum for one canonical instruction.

    A generic mention of Git, a repository, or making a commit is not a grant.
    Unrecognized or negated history language defaults to ``not_required``.
    """

    return (
        GIT_HISTORY_ACCESS_REQUIRED
        if _supporting_span(instruction) is not None
        else GIT_HISTORY_ACCESS_NOT_REQUIRED
    )


def permits_empty_history_baseline(capability: object) -> bool:
    """Return whether a required capability creates history from supplied bundles."""

    return bool(
        isinstance(capability, Mapping)
        and capability.get("git_history_access") == GIT_HISTORY_ACCESS_REQUIRED
        and capability.get("supporting_span_sha256")
        == _sha256_text(_BUNDLE_REFERENCE_SPAN)
    )


def compile_git_history_capability(
    instruction: str,
    trusted_manifest_sha256: str,
) -> dict[str, object]:
    """Compile the complete immutable capability record before launch."""

    if not _valid_sha256(trusted_manifest_sha256):
        raise ValueError("trusted_manifest_digest_invalid")
    span = _supporting_span(instruction)
    return {
        "schema_version": CAPABILITY_SCHEMA,
        "policy_version": CAPABILITY_POLICY_VERSION,
        "git_history_access": (
            GIT_HISTORY_ACCESS_REQUIRED
            if span is not None
            else GIT_HISTORY_ACCESS_NOT_REQUIRED
        ),
        "canonical_instruction_sha256": _sha256_text(instruction),
        "trusted_manifest_sha256": trusted_manifest_sha256,
        "supporting_span_sha256": _sha256_text(span) if span is not None else None,
    }


def validate_git_history_capability(
    value: object,
    instruction: str,
    trusted_manifest_sha256: str,
) -> dict[str, object]:
    """Fail closed unless a record exactly matches the shared compiler."""

    try:
        expected = compile_git_history_capability(instruction, trusted_manifest_sha256)
    except ValueError as error:
        raise ValueError("git_history_capability_invalid") from error
    if not isinstance(value, Mapping) or set(value) != _CAPABILITY_KEYS:
        raise ValueError("git_history_capability_invalid")
    observed = dict(value)
    if observed != expected:
        raise ValueError("git_history_capability_invalid")
    return expected
