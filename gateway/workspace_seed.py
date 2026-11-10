"""The real-mode workspace (AEGIS_TOOLS=real): invented files the real tools act on.

workspace/ holds the files, outbox/ holds the "sent" emails. Both are rebuilt by
POST /sandbox/reset, so a run can never leave something behind for the next one.

Where the files come from:
- scenarios/real/workspace/ (the template, plain files you can open and edit) is copied as is;
- confidential/customers.csv is generated from gateway/seed.py, the same invented customers the
  simulated sandbox uses, so masking and leak fingerprints recognise every value.

The top-level folder decides a file's classification (gateway/normalize.py classify_path), so the
existing rules apply unchanged: public/ and internal/ can be read, confidential/ can be read but
taints the session, restricted/ can never be read.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from gateway.seed import _retry, _write, customers_csv

FOLDERS = ("public", "internal", "confidential", "restricted", "reports")


def seed(workspace: Path, outbox: Path, template: Path | None = None) -> None:
    workspace, outbox = Path(workspace), Path(outbox)
    if template is not None and Path(template).is_dir():
        # symlinks=True copies a link as a link (never what it points to); the real handlers then
        # refuse to follow it. The template in the repo has none.
        shutil.copytree(template, workspace, symlinks=True, dirs_exist_ok=True)
    for folder in FOLDERS:
        (workspace / folder).mkdir(parents=True, exist_ok=True)
    _write(workspace / "confidential" / "customers.csv", customers_csv())
    for mode in ("protected", "passthrough"):
        (outbox / mode).mkdir(parents=True, exist_ok=True)


def reset(workspace: Path, outbox: Path, template: Path | None = None) -> None:
    """Delete workspace/ and outbox/ completely, then seed again."""
    for target in (Path(workspace), Path(outbox)):
        if target.exists():
            _retry(lambda t=target: shutil.rmtree(t) if t.exists() else None)
    seed(workspace, outbox, template)
