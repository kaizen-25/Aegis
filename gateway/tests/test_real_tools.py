"""Real-mode tools (AEGIS_TOOLS=real): workspace/ files and a real .eml outbox.

Same rules and session memory as simulated mode; only the handlers and their folders change.
"""
from __future__ import annotations

import email
import email.policy
import json
import os
import sys
from pathlib import Path

import pytest

from contracts.enums import GatewayMode, ToolName, Verdict
from gateway import real_tools, seed, tools
from gateway.app import Settings, create_app
from gateway.core import Gateway
from gateway.errors import ToolError
from gateway.real_tools import workspace_path

from .conftest import POLICY, SCENARIOS, Driver, broad_scope

OUTSIDER = "partner@outside-mail.test"


@pytest.fixture
def real_gw(tmp_path) -> Gateway:
    gw = Gateway(tmp_path / "sandbox", tmp_path / "audit.db", POLICY, SCENARIOS, tool_mode="real",
                 workspace_dir=tmp_path / "workspace", outbox_dir=tmp_path / "outbox")
    ws = tmp_path / "workspace"
    (ws / "public" / "faq.md").write_text("Office hours are 9 to 5.", encoding="utf-8")
    (ws / "confidential" / "customers.csv").write_text(seed.customers_csv(), encoding="utf-8")
    (ws / "restricted" / "keys.txt").write_text("secret", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside the workspace", encoding="utf-8")
    return gw


@pytest.fixture
def real_spy(monkeypatch):
    calls = []
    for registry in (tools.HANDLERS, real_tools.REAL_HANDLERS):
        for tool, fn in list(registry.items()):
            def wrapper(env, args, fn=fn, tool=tool, registry=registry):
                calls.append((registry is real_tools.REAL_HANDLERS, tool))
                return fn(env, args)
            monkeypatch.setitem(registry, tool, wrapper)
    return calls


def _outbox(gw: Gateway, mode: str) -> list[Path]:
    return sorted((gw.outbox_root / mode).glob("*"))


# ---------------------------------------------------------------- the switch


def test_default_mode_is_simulated_and_unchanged(gw):
    assert gw.tool_mode == "simulated"
    assert gw.files_root == gw.sandbox / "files"
    assert gw.outbox_root == gw.sandbox / "outbox"


def test_bad_mode_or_missing_folders_stop_the_gateway(tmp_path):
    with pytest.raises(ValueError):
        Gateway(tmp_path / "s", tmp_path / "a.db", POLICY, SCENARIOS, tool_mode="live")
    with pytest.raises(ValueError):
        Gateway(tmp_path / "s", tmp_path / "a.db", POLICY, SCENARIOS, tool_mode="real")


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_TOOLS", " REAL ")
    assert Settings.from_env().tool_mode == "real"
    monkeypatch.delenv("AEGIS_TOOLS")
    assert Settings.from_env().tool_mode == "simulated"


def test_health_reports_the_tool_mode(tmp_path):
    cfg = Settings(sandbox_dir=tmp_path / "sandbox", audit_path=tmp_path / "audit.db", policy_path=POLICY,
                   scenarios_dir=SCENARIOS, reports_dir=tmp_path / "r", log_dir=tmp_path / "l",
                   tool_mode="real", workspace_dir=tmp_path / "workspace", outbox_dir=tmp_path / "outbox")
    from fastapi.testclient import TestClient
    body = TestClient(create_app(cfg)).get("/health").json()
    assert body["tool_mode"] == "real"
    assert (tmp_path / "workspace" / "public").is_dir() and (tmp_path / "outbox" / "protected").is_dir()


# ---------------------------------------------------------------- workspace_path (defence in depth)


@pytest.mark.parametrize("bad", ["", "/etc/passwd", "c:/windows/win.ini", "public\\faq.md", "../outside.txt",
                                 "public/../../outside.txt", "public//faq.md", "./public/faq.md", "public/."])
def test_workspace_path_rejects_escapes(tmp_path, bad):
    (tmp_path / "ws").mkdir()
    with pytest.raises(ToolError):
        workspace_path(tmp_path / "ws", bad)


def test_workspace_path_accepts_a_plain_relative_path(tmp_path):
    (tmp_path / "ws" / "public").mkdir(parents=True)
    assert workspace_path(tmp_path / "ws", "public/faq.md") == tmp_path / "ws" / "public" / "faq.md"


def _make_dir_link(link: Path, target: Path) -> None:
    """A directory link that needs no admin rights: a junction on Windows, a symlink elsewhere."""
    if sys.platform == "win32":
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def test_workspace_path_refuses_a_directory_link(tmp_path):
    ws = tmp_path / "ws"
    (ws / "public").mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "secret.txt").write_text("x")
    _make_dir_link(ws / "public" / "door", tmp_path / "elsewhere")
    with pytest.raises(ToolError, match="links"):
        workspace_path(ws, "public/door/secret.txt")


def test_workspace_path_refuses_a_file_symlink(tmp_path):
    ws = tmp_path / "ws"
    (ws / "public").mkdir(parents=True)
    (tmp_path / "secret.txt").write_text("x")
    try:
        os.symlink(tmp_path / "secret.txt", ws / "public" / "link.txt")
    except OSError:
        pytest.skip("creating file symlinks needs Developer Mode or admin on Windows")
    with pytest.raises(ToolError, match="links"):
        workspace_path(ws, "public/link.txt")


# ---------------------------------------------------------------- read_file through the gateway


def test_read_public_file_is_allowed_and_real(real_gw):
    d = Driver(real_gw).do("file.read", {"path": "Public\\FAQ.md"})
    assert (d.verdict, d.status.value) == (Verdict.ALLOW, "EXECUTED")
    assert d.result["content"] == "Office hours are 9 to 5."


@pytest.mark.parametrize("path", ["../outside.txt", "public/../../outside.txt", "C:/outside.txt", "/outside.txt",
                                  "public/faq.md\x00.txt"])
def test_path_traversal_fails_closed_and_runs_nothing(real_gw, real_spy, path):
    d = Driver(real_gw).do("file.read", {"path": path})
    assert (d.verdict, d.status.value) == (Verdict.BLOCK, "FAIL_CLOSED")
    assert real_spy == []


def test_restricted_read_is_blocked_and_never_reaches_a_handler(real_gw, real_spy):
    d = Driver(real_gw).do("file.read", {"path": "restricted/keys.txt"})
    assert (d.verdict, d.status.value) == (Verdict.BLOCK, "BLOCKED")
    assert real_spy == []


def test_junction_inside_workspace_is_a_tool_failure_not_a_read(real_gw, tmp_path):
    _make_dir_link(real_gw.files_root / "public" / "door", tmp_path)
    d = Driver(real_gw).do("file.read", {"path": "public/door/outside.txt"})
    assert d.status.value == "EXECUTION_FAILED" and d.result is None
    assert "links" in (d.error or "")


def test_real_mode_uses_only_the_real_registry_for_files_and_mail(real_gw, real_spy):
    drv = Driver(real_gw)
    drv.do("file.read", {"path": "public/faq.md"})
    drv.do("email.send", {"draft_id": drv.draft("team@novacorp.local")})
    assert real_spy == [(True, ToolName.file_read), (True, ToolName.email_draft), (True, ToolName.email_send)]


# ---------------------------------------------------------------- write_file (report.write)


def test_new_report_is_written_to_the_workspace(real_gw):
    d = Driver(real_gw).do("report.write", {"name": "Summary", "content": "hello"})
    assert (d.verdict, d.status.value) == (Verdict.ALLOW, "EXECUTED")
    assert (real_gw.files_root / "reports" / "summary.md").read_text(encoding="utf-8") == "hello"
    assert not (real_gw.sandbox / "files" / "reports" / "summary.md").exists()


def test_overwrite_in_the_workspace_needs_review(real_gw, real_spy):
    (real_gw.files_root / "reports" / "old.md").write_text("keep me")
    d = Driver(real_gw).do("report.write", {"name": "old", "content": "new"})
    assert d.verdict is Verdict.REVIEW and real_spy == []
    assert (real_gw.files_root / "reports" / "old.md").read_text() == "keep me"


@pytest.mark.parametrize("name", ["../evil", "reports/x", "a\\b", "c:x"])
def test_report_name_with_a_path_fails_closed(real_gw, name):
    d = Driver(real_gw).do("report.write", {"name": name, "content": "x"})
    assert d.status.value == "FAIL_CLOSED"


# ---------------------------------------------------------------- send_email (draft + send)


def test_internal_send_writes_a_real_eml(real_gw):
    drv = Driver(real_gw)
    d = drv.do("email.send", {"draft_id": drv.draft("team@novacorp.local", body="Hi team",
                                                     subject="Line one\nBcc: evil@x.test")})
    assert (d.verdict, d.status.value) == (Verdict.ALLOW, "EXECUTED")
    files = _outbox(real_gw, "protected")
    assert [f.suffix for f in files] == [".eml", ".json"]
    msg = email.message_from_bytes(files[0].read_bytes(), policy=email.policy.default)
    assert msg["To"] == "team@novacorp.local"
    assert msg["Subject"] == "Line one Bcc: evil@x.test"  # one header, no injected Bcc
    assert msg["Bcc"] is None
    assert msg.get_content().strip() == "Hi team"
    record = json.loads(files[1].read_text(encoding="utf-8"))
    assert record["eml"] == files[0].name
    assert real_gw.outbox(GatewayMode.protected)[0]["to"] == "team@novacorp.local"


def test_customer_leak_with_raw_values_is_blocked_and_the_outbox_stays_empty(real_gw, real_spy):
    drv = Driver(real_gw)
    drv.do("file.read", {"path": "confidential/customers.csv"})
    d = drv.do("email.send", {"draft_id": drv.draft(OUTSIDER, body=seed.customers_csv())})
    assert d.verdict is Verdict.BLOCK and "R-FLOW-CONFIDENTIAL-EXTERNAL" in d.matched_rules
    assert _outbox(real_gw, "protected") == []
    assert (True, ToolName.email_send) not in real_spy


def test_agent_only_sees_masked_rows_so_resending_them_is_held_for_review(real_gw, real_spy):
    """Invariant 8: the result returned to the agent is masked. A model that forwards what it was
    shown cannot be proved to leak (no exact value matches), so the send waits for a person."""
    drv = Driver(real_gw)
    shown = drv.do("file.read", {"path": "confidential/customers.csv"}).result["content"]
    assert seed.CANARIES["email_1"] not in shown and "Meera Kapoor" in shown
    d = drv.do("email.send", {"draft_id": drv.draft(OUTSIDER, body=shown)})
    assert (d.verdict, d.status.value) == (Verdict.REVIEW, "PENDING") and d.ticket_id
    assert _outbox(real_gw, "protected") == []
    assert (True, ToolName.email_send) not in real_spy


def test_same_leak_in_passthrough_really_lands_in_the_outbox(real_gw):
    drv = Driver(real_gw, mode=GatewayMode.passthrough)
    drv.do("file.read", {"path": "confidential/customers.csv"})
    d = drv.do("email.send", {"draft_id": drv.draft(OUTSIDER, body=seed.customers_csv())})
    assert d.status.value == "EXECUTED" and d.would_verdict is Verdict.BLOCK
    eml = [f for f in _outbox(real_gw, "passthrough") if f.suffix == ".eml"]
    assert len(eml) == 1 and seed.CANARIES["email_1"] in eml[0].read_text(encoding="utf-8")


# ---------------------------------------------------------------- reset


def test_reset_wipes_workspace_and_outbox(real_gw):
    drv = Driver(real_gw)
    drv.do("email.send", {"draft_id": drv.draft("team@novacorp.local")})
    (real_gw.files_root / "public" / "stray.txt").write_text("x")
    real_gw.reset()
    assert not (real_gw.files_root / "public" / "stray.txt").exists()
    assert _outbox(real_gw, "protected") == []
    assert (real_gw.sandbox / "novacorp.db").exists()


# ---------------------------------------------------------------- seed data and task files (Step 2)

REAL_TASKS = SCENARIOS / "real" / "tasks"


def test_workspace_is_seeded_from_the_template(tmp_path):
    gw = Gateway(tmp_path / "sandbox", tmp_path / "audit.db", POLICY, SCENARIOS, tool_mode="real",
                 workspace_dir=tmp_path / "workspace", outbox_dir=tmp_path / "outbox")
    ws = gw.files_root
    for rel in ("public/faq.md", "internal/vendor_proposal.md", "internal/partner_update.md",
                "internal/team_directory.md", "restricted/api_keys.txt"):
        assert (ws / rel).is_file(), rel
    assert (ws / "confidential" / "customers.csv").read_text(encoding="utf-8") == seed.customers_csv()
    assert "onboarding@brightpath-partners.test" in (ws / "internal" / "partner_update.md").read_text()


def test_task_files_are_valid_scopes_that_point_at_real_files():
    import yaml
    from contracts.models import TaskScope
    files = sorted(REAL_TASKS.glob("*.yaml"))
    assert files
    template = SCENARIOS / "real" / "workspace"
    for path in files:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        scope = TaskScope.model_validate(raw["scope"])
        assert raw["kind"] in ("attack", "benign") and raw["prompt"]
        for pattern in scope.allowed_paths:
            if "*" not in pattern and pattern != "confidential/customers.csv":
                assert (template / pattern).is_file(), (path.name, pattern)


def test_real_tasks_do_not_join_the_scored_scenarios():
    from gateway.policy import load_scenarios
    assert len(load_scenarios(SCENARIOS)) == 20


def test_scored_scenarios_refuse_to_run_in_real_mode(tmp_path):
    from fastapi.testclient import TestClient
    cfg = Settings(sandbox_dir=tmp_path / "sandbox", audit_path=tmp_path / "audit.db", policy_path=POLICY,
                   scenarios_dir=SCENARIOS, reports_dir=tmp_path / "r", log_dir=tmp_path / "l",
                   tool_mode="real", workspace_dir=tmp_path / "workspace", outbox_dir=tmp_path / "outbox")
    client = TestClient(create_app(cfg))
    for path, body in (("/runs", {"scenario_id": "B1", "agent_kind": "scripted"}), ("/eval/run", {})):
        r = client.post(path, json=body)
        assert r.status_code == 409 and r.json()["code"] == "real_tools_mode"


def test_real_eval_report_endpoint(client, settings):
    assert client.get("/eval/real/latest").status_code == 404
    folder = settings.reports_dir / "real-agent"
    folder.mkdir(parents=True)
    (folder / "old.json").write_text('{"run_id": "old"}')
    os.utime(folder / "old.json", (1, 1))
    (folder / "new.json").write_text('{"run_id": "new"}')
    assert client.get("/eval/real/latest").json() == {"run_id": "new"}
    assert client.get("/eval/real/old").json() == {"run_id": "old"}
    assert client.get("/eval/real/missing").status_code == 404
    assert client.get("/eval/real/..%2Fsecret").status_code in (404, 422)
    (folder / "broken.json").write_text("{not json")
    listing = client.get("/eval/real").json()
    assert [r["run_id"] for r in listing] == ["new", "old"]
