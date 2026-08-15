"""Smoke tests for SECURITY.md TLS / DoS hardening documentation."""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
SECURITY_MD = REPO / "SECURITY.md"
README_MD = REPO / "README.md"

_SECTION_START = "## Self-Hosting: TLS and DoS Posture"
_SECTION_END = "## Known Security Considerations"

_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_HEADING_ANCHOR_RE = re.compile(r"^#{1,6}\s+(.+)$", re.MULTILINE)


def _section_text() -> str:
    text = SECURITY_MD.read_text(encoding="utf-8")
    start = text.index(_SECTION_START)
    end = text.index(_SECTION_END, start)
    return text[start:end]


def _github_anchor(title: str) -> str:
    """GitHub-style heading anchor (matches SECURITY.md in-repo links)."""
    normalized = title.strip().lower()
    normalized = re.sub(r"[^\w\s-]", "", normalized)
    normalized = re.sub(r"\s+", "-", normalized)
    return normalized


def _resolve_anchor(path: pathlib.Path, anchor: str) -> bool:
    content = path.read_text(encoding="utf-8")
    anchors = {_github_anchor(m.group(1)) for m in _HEADING_ANCHOR_RE.finditer(content)}
    return anchor in anchors


def test_security_hardening_section_contains_key_phrases():
    section = _section_text()
    required = [
        "network-trust",
        "reverse proxy",
        "rate limit",
        "body size",
        "concurrency",
        "server_simple.py",
        "Hardening checklist",
        "Cleartext HTTP",
    ]
    missing = [phrase for phrase in required if phrase not in section]
    assert not missing, f"Missing phrases in hardening section: {missing}"


def test_readme_links_to_security_hardening_section():
    text = README_MD.read_text(encoding="utf-8")
    assert "SECURITY.md#self-hosting-tls-and-dos-posture" in text
    assert "simple-mode" in text.lower()


def test_hardening_section_local_links_resolve():
    section = _section_text()
    broken: list[str] = []

    for _label, target in _LINK_RE.findall(section):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        path_part, _, anchor = target.partition("#")
        file_path = SECURITY_MD if not path_part else REPO / path_part
        if not file_path.is_file():
            broken.append(f"missing file: {target}")
            continue
        if anchor and not _resolve_anchor(file_path, anchor):
            broken.append(f"missing anchor #{anchor} in {file_path.relative_to(REPO)}")

    assert not broken, "Broken local links:\n" + "\n".join(broken)


def test_readme_security_link_resolves():
    match = re.search(r"\(SECURITY\.md#([^)]+)\)", README_MD.read_text(encoding="utf-8"))
    assert match, "README missing SECURITY.md hardening link"
    anchor = match.group(1)
    assert _resolve_anchor(SECURITY_MD, anchor), f"README anchor #{anchor} not found"
