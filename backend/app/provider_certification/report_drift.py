"""Generated-report drift detection (message 7).

Compares the deterministic JSON certification reports the framework
would generate RIGHT NOW (in memory — never written to the committed
report paths during a check) against what is actually committed on
disk, and reports any STALE / MISSING / EXTRA files.

Never rewrites committed files during check mode. ``generate_reports()``
is the only function in this module that writes to disk, and it is
only invoked by the explicit ``generate-reports`` CLI command, never
by ``check-reports``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.provider_certification import runner

_REPORTS_DIR = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification"
_ADOPTION_PATH = runner._BACKEND_ROOT / "tests" / "reports" / "provider_certification_adoption.json"


def _expected_report_contents() -> dict[str, str]:
    """Provider-id.json -> exact expected file content (in memory,
    nothing written to disk), plus "summary.json" and the adoption
    report under its own top-level key ``__adoption__``."""
    results = runner.certify_all_providers()
    contents: dict[str, str] = {}
    for pid, result in sorted(results.items()):
        contents[f"{pid}.json"] = result.to_json() + "\n"
    contents["summary.json"] = json.dumps(runner.certification_summary(results), sort_keys=True, indent=2) + "\n"
    contents["__adoption__"] = json.dumps(runner.adoption_report(), sort_keys=True, indent=2) + "\n"
    return contents


@dataclass(frozen=True)
class ReportDriftResult:
    is_clean: bool
    stale: tuple[str, ...]
    missing: tuple[str, ...]
    extra: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "is_clean": self.is_clean,
            "stale": sorted(self.stale),
            "missing": sorted(self.missing),
            "extra": sorted(self.extra),
        }

    @staticmethod
    def _display_name(name: str) -> str:
        return name if name.startswith("provider_certification_") else f"provider_certification/{name}"

    def remediation(self) -> str:
        if self.is_clean:
            return ""
        lines = []
        for name in sorted(self.stale):
            lines.append(f"STALE: {self._display_name(name)}")
        for name in sorted(self.missing):
            lines.append(f"MISSING: {self._display_name(name)}")
        for name in sorted(self.extra):
            lines.append(f"EXTRA: {self._display_name(name)}")
        lines.append("")
        lines.append("Remediation: run `python -m app.provider_certification.cli generate-reports` and commit the result.")
        return "\n".join(lines)


def check_report_drift() -> ReportDriftResult:
    """Never writes to disk. Computes the exact reports the framework
    would generate right now, and diffs them byte-for-byte against the
    committed files."""
    expected = _expected_report_contents()

    stale: list[str] = []
    missing: list[str] = []
    extra: list[str] = []

    # Per-provider + summary.json (live in tests/reports/provider_certification/)
    on_disk_provider_files: set[str] = set()
    if _REPORTS_DIR.is_dir():
        on_disk_provider_files = {p.name for p in _REPORTS_DIR.iterdir() if p.suffix == ".json"}

    expected_provider_files = {k for k in expected if k != "__adoption__"}

    for name in sorted(expected_provider_files):
        path = _REPORTS_DIR / name
        expected_content = expected[name]
        if not path.is_file():
            missing.append(name)
            continue
        actual_content = path.read_text()
        if actual_content != expected_content:
            stale.append(name)

    for name in sorted(on_disk_provider_files - expected_provider_files):
        extra.append(name)

    # Adoption report (lives one level up, tests/reports/, not tests/reports/provider_certification/)
    adoption_expected = expected["__adoption__"]
    if not _ADOPTION_PATH.is_file():
        missing.append("provider_certification_adoption.json")
    elif _ADOPTION_PATH.read_text() != adoption_expected:
        stale.append("provider_certification_adoption.json")

    is_clean = not (stale or missing or extra)
    return ReportDriftResult(is_clean=is_clean, stale=tuple(stale), missing=tuple(missing), extra=tuple(extra))


def generate_reports() -> list[Path]:
    """Regenerate every committed report file (atomic write per file).
    The ONLY function in this module permitted to write to disk."""
    written: list[Path] = []
    results = runner.certify_all_providers()
    for pid in sorted(results):
        written.append(_atomic_write_report(results[pid]))
    written.append(_atomic_write_json(_REPORTS_DIR / "summary.json", runner.certification_summary(results)))
    written.append(_atomic_write_json(_ADOPTION_PATH, runner.adoption_report()))
    return written


def _atomic_write_report(result) -> Path:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = _REPORTS_DIR / f"{result.provider_id}.json"
    _atomic_write_text(path, result.to_json() + "\n")
    return path


def _atomic_write_json(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(path, json.dumps(data, sort_keys=True, indent=2) + "\n")
    return path


def _atomic_write_text(path: Path, content: str) -> None:
    """Write via a temp file + os.replace so a crash mid-write never
    leaves a truncated/corrupt committed report on disk."""
    import os
    import tempfile

    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
