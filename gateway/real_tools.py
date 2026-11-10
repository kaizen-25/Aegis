"""Real-mode tool handlers (AEGIS_TOOLS=real).

These do the same jobs as the handlers in tools.py, on real files the user can open:
- file.read     reads a file under workspace/
- report.write  writes workspace/reports/<name>.md
- email.send    writes a real .eml file (plus a .json copy for the dashboard) to outbox/<mode>/

No SMTP and no network: "sending" means writing the message to the local outbox folder.
db.query, db.delete and email.draft keep their tools.py handlers (the database stays in sandbox/).

Same rule as tools.py: nothing outside `Gateway.execute()` may call a handler. They are only
reachable through REAL_HANDLERS, and the invariant test checks that registry too.

Arguments arrive already validated and normalized (gateway/schemas.py, gateway/normalize.py), so
"..", absolute paths and drive letters were rejected before any rule ran. `workspace_path` checks
again here, and also refuses symbolic links and Windows junctions, which normalization cannot see.
"""
from __future__ import annotations

import email.utils
import json
import os
import stat
import uuid
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from contracts.enums import ToolName
from gateway.errors import ToolError
from gateway.tools import (
    MAX_READ_BYTES,
    Handler,
    ToolEnv,
    handle_db_delete,
    handle_db_query,
    handle_email_draft,
)

SENDER = "agent@novacorp.local"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_link(path: Path) -> bool:
    """True for a symlink, or on Windows for any reparse point (junctions included)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def workspace_path(root: Path, rel: str) -> Path:
    """Turn a normalized relative path into a path inside `root`, or raise ToolError.

    Refuses: absolute paths, drive letters, backslashes, "." or ".." segments, any symbolic link
    or junction on the way (including the root itself), and anything that resolves outside root.
    """
    if not isinstance(rel, str) or not rel:
        raise ToolError("empty path")
    if rel.startswith("/") or "\\" in rel or ":" in rel:
        raise ToolError("path must be relative to the workspace")
    parts = rel.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ToolError("path must not contain empty, . or .. segments")
    root = Path(root)
    if _is_link(root):
        raise ToolError("workspace root is a link")
    current = root
    for part in parts:
        current = current / part
        if _is_link(current):
            raise ToolError("symbolic links are not allowed in the workspace")
    real_root = root.resolve()
    target = current.resolve()
    if target != real_root and real_root not in target.parents:
        raise ToolError("path is outside the workspace")
    return current


def handle_real_file_read(env: ToolEnv, args: dict[str, Any]) -> dict[str, Any]:
    target = workspace_path(env.files_root, args["path"])
    if not target.is_file():
        raise ToolError("file not found")
    with open(target, "rb") as fh:
        data = fh.read(MAX_READ_BYTES)
    return {"path": args["path"], "content": data.decode("utf-8", errors="replace")}


def handle_real_report_write(env: ToolEnv, args: dict[str, Any]) -> dict[str, Any]:
    rel = f"reports/{args['name']}.md"
    target = workspace_path(env.files_root, rel)
    existed = target.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    target = workspace_path(env.files_root, rel)  # re-check: the folder may have just been created
    target.write_text(args["content"], encoding="utf-8", newline="\n")
    return {"path": rel, "bytes": len(args["content"].encode("utf-8")), "overwritten": existed}


def _one_line(text: str) -> str:
    """Header values must not contain line breaks (that would let a subject add headers)."""
    return " ".join(text.splitlines()).strip()


def handle_real_email_send(env: ToolEnv, args: dict[str, Any]) -> dict[str, Any]:
    draft = env.drafts.get(args["draft_id"])
    if draft is None or draft.session_id != env.session_id:
        raise ToolError("no such draft in this session")
    if draft.sent:
        raise ToolError("draft was already sent")
    folder = env.outbox_root / env.mode
    folder.mkdir(parents=True, exist_ok=True)
    email_id = f"mail-{uuid.uuid4().hex[:12]}"
    stem = f"{env.now.strftime('%Y%m%dT%H%M%S%f')}-{email_id}"

    msg = EmailMessage()
    msg["From"] = SENDER
    msg["To"] = draft.to
    msg["Subject"] = _one_line(draft.subject)
    msg["Date"] = email.utils.format_datetime(env.now)
    msg["Message-ID"] = f"<{email_id}@novacorp.local>"
    msg["X-Aegis-Session"] = env.session_id
    msg["X-Aegis-Mode"] = env.mode
    msg.set_content(draft.body, cte="8bit")  # plain readable text in the .eml, no =20 line wrapping
    (folder / f"{stem}.eml").write_bytes(bytes(msg))

    record = {"email_id": email_id, "mode": env.mode, "session_id": env.session_id, "to": draft.to,
              "subject": draft.subject, "body": draft.body, "sent_at": env.now.isoformat(),
              "eml": f"{stem}.eml"}
    (folder / f"{stem}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    draft.sent = True
    return {"email_id": email_id, "to": draft.to, "subject": draft.subject, "outbox": env.mode,
            "eml": f"{stem}.eml"}


REAL_HANDLERS: dict[ToolName, Handler] = {
    ToolName.file_read: handle_real_file_read,
    ToolName.report_write: handle_real_report_write,
    ToolName.db_query: handle_db_query,
    ToolName.db_delete: handle_db_delete,
    ToolName.email_draft: handle_email_draft,
    ToolName.email_send: handle_real_email_send,
}
