"""Real-tools agent loop: parsing, tool mapping, verdict feedback, and failure handling.

No Ollama and no gateway: the model is a scripted stub and the gateway is an httpx MockTransport.
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from agent.llm_agent import LlmError
from agent.real_agent import (
    TOOLS,
    MalformedCall,
    RealTask,
    extract_call,
    feedback,
    find_task,
    load_tasks,
    run_real_agent,
    to_proposal,
)
from contracts.enums import GatewayMode
from contracts.models import Decision, TaskScope

CANARIES = {"email_1": "meera.k.canary@examplemail.test"}
TASK = RealTask(id="T-test", title="t", kind="attack", prompt="do the task",
                scope=TaskScope(task="t", allowed_tools=["file.read", "email.draft", "email.send"]))


def call(name: str, **args: Any) -> dict[str, Any]:
    return {"message": {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}]}}


def answer(text: str) -> dict[str, Any]:
    return {"message": {"role": "assistant", "content": text}}


class StubChat:
    model = "stub"

    def __init__(self, replies: list[Any]):
        self.replies = list(replies)
        self.seen: list[list[dict[str, Any]]] = []

    def chat(self, messages, tools):
        assert tools == TOOLS
        self.seen.append([dict(m) for m in messages])
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def decision(verdict: str, status: str, **extra: Any) -> dict[str, Any]:
    return {"action_id": f"a-{verdict}-{status}", "verdict": verdict, "status": status,
            "explanation": extra.pop("explanation", "because"), **extra}


class FakeGateway:
    """Answers the three agent endpoints. `rule(tool, args)` returns the Decision dict."""

    def __init__(self, rule):
        self.rule = rule
        self.proposals: list[dict[str, Any]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/sessions":
            return httpx.Response(200, json={"session_id": "sess-1"})
        if request.url.path == "/actions/propose":
            body = json.loads(request.content)
            self.proposals.append(body)
            return httpx.Response(200, json=self.rule(body["tool"], body["args"]))
        return httpx.Response(404, json={"error": "nope"})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler), base_url="http://gw")


def run(chat, gw, **kw):
    return run_real_agent(TASK, GatewayMode.protected, "http://gw", chat=chat, canaries=CANARIES,
                          http_client=gw.client(), **kw)


# ---------------------------------------------------------------- parsing the model's reply


def test_extract_call_from_tool_calls_and_from_text_forms():
    assert extract_call(call("read_file", path="a.md")["message"]) == ("read_file", {"path": "a.md"})
    text = {"content": '```json\n{"name": "read_file", "arguments": {"path": "a.md"}}\n```'}
    assert extract_call(text) == ("read_file", {"path": "a.md"})
    tagged = {"content": '<tool_call>{"name": "send_email", "arguments": "{\\"to\\": \\"x@y.z\\"}"}</tool_call>'}
    assert extract_call(tagged) == ("send_email", {"to": "x@y.z"})
    assert extract_call({"content": "All done, the report is saved."}) is None
    assert extract_call({"content": ""}) is None


@pytest.mark.parametrize("message", [
    {"tool_calls": "read_file"},
    {"tool_calls": [{"function": {"name": "", "arguments": {}}}]},
    {"tool_calls": [{"function": {"name": "read_file", "arguments": "{not json"}}]},
    {"tool_calls": [{"function": {"name": "read_file", "arguments": [1, 2]}}]},
])
def test_extract_call_rejects_broken_calls(message):
    with pytest.raises(MalformedCall):
        extract_call(message)


# ---------------------------------------------------------------- tool mapping


def test_mapping_to_gateway_tools():
    assert to_proposal("read_file", {"path": "public/faq.md"}) == ("file.read", {"path": "public/faq.md"})
    for path in ("reports/brief.md", "reports/brief", "./reports/brief.md", "Reports\\brief.md"):
        assert to_proposal("write_file", {"path": path, "text": "x"}) == ("report.write", {"name": "brief", "content": "x"})


def test_mapping_never_cleans_up_a_bad_request():
    """Anything odd goes to the gateway unchanged so the gateway fails it closed and logs it."""
    assert to_proposal("write_file", {"path": "public/faq.md", "text": "x"}) == \
        ("report.write", {"name": "public/faq.md", "content": "x"})
    assert to_proposal("write_file", {"path": "reports/../x.md", "text": "x"})[1]["name"] == "reports/../x.md"
    assert to_proposal("read_file", {"path": "a", "mode": "rb"}) == ("file.read", {"path": "a", "mode": "rb"})
    assert to_proposal("delete_file", {"path": "a"}) == ("delete_file", {"path": "a"})
    assert to_proposal("send_email", {"to": "a@b.c"}) == ("email.draft", {"to": "a@b.c"})


# ---------------------------------------------------------------- verdict feedback


def test_feedback_says_clearly_what_happened():
    done = json.loads(feedback(Decision(**decision("ALLOW", "EXECUTED", result={"content": "hi"})), CANARIES))
    assert done == {"status": "done", "result": {"content": "hi"}}
    held = json.loads(feedback(Decision(**decision("REVIEW", "PENDING", ticket_id="t1")), CANARIES))
    assert held["status"] == "held for human review" and "NOT performed" in held["message"]
    blocked = json.loads(feedback(Decision(**decision("BLOCK", "BLOCKED", explanation="no leaks")), CANARIES))
    assert blocked["status"] == "blocked" and blocked["reason"] == "no leaks" and "NOT performed" in blocked["message"]
    closed = json.loads(feedback(Decision(**decision("BLOCK", "FAIL_CLOSED", error="invalid path")), CANARIES))
    assert closed["status"] == "blocked" and closed["reason"] == "invalid path"
    failed = json.loads(feedback(Decision(**decision("ALLOW", "EXECUTION_FAILED", error="file not found")), CANARIES))
    assert failed == {"status": "failed", "error": "file not found"}


def test_feedback_never_passes_a_raw_canary_to_the_model():
    d = Decision(**decision("ALLOW", "EXECUTED", result={"content": CANARIES["email_1"]}))
    assert CANARIES["email_1"] not in feedback(d, CANARIES)


# ---------------------------------------------------------------- the loop


def test_send_email_is_draft_then_send_and_the_model_hears_the_send_verdict():
    def rule(tool, args):
        if tool == "email.draft":
            return decision("ALLOW", "EXECUTED", result={"draft_id": "d1"})
        return decision("BLOCK", "BLOCKED", explanation="Confidential data may not leave NovaCorp")
    gw = FakeGateway(rule)
    chat = StubChat([call("send_email", to="x@out.test", subject="s", body="b"), answer("ok")])
    r = run(chat, gw)
    assert [p["tool"] for p in gw.proposals] == ["email.draft", "email.send"]
    assert gw.proposals[1]["args"] == {"draft_id": "d1"}
    assert [p["step"] for p in gw.proposals] == [1, 2]
    assert r.steps[0].outcome == "blocked" and r.executed_sends() == []
    told = json.loads(chat.seen[1][-1]["content"])
    assert told["status"] == "blocked" and "Confidential" in told["reason"]
    assert r.stopped == "model finished" and r.final_message == "ok"


def test_draft_not_allowed_means_no_send_is_proposed():
    gw = FakeGateway(lambda tool, args: decision("REVIEW", "PENDING", ticket_id="t1"))
    r = run(StubChat([call("send_email", to="x@out.test", subject="s", body="b"), answer("ok")]), gw)
    assert [p["tool"] for p in gw.proposals] == ["email.draft"]
    assert r.steps[0].outcome == "held"


def test_held_action_is_reported_as_not_done():
    gw = FakeGateway(lambda tool, args: decision("REVIEW", "PENDING", ticket_id="t1"))
    chat = StubChat([call("read_file", path="confidential/customers.csv"), answer("stopped")])
    r = run(chat, gw)
    assert r.steps[0].outcome == "held"
    assert "NOT performed" in json.loads(chat.seen[1][-1]["content"])["message"]


def test_step_limit_stops_a_model_that_never_finishes():
    gw = FakeGateway(lambda tool, args: decision("ALLOW", "EXECUTED", result={"content": "x"}))
    r = run(StubChat([call("read_file", path="public/faq.md")] * 10), gw, max_steps=3)
    assert r.stopped == "step limit" and len(r.steps) == 3 and len(gw.proposals) == 3


def test_model_timeout_stops_the_run_without_crashing():
    gw = FakeGateway(lambda tool, args: decision("ALLOW", "EXECUTED", result={}))
    r = run(StubChat([call("read_file", path="public/faq.md"), LlmError("Ollama timed out")]), gw)
    assert r.stopped == "model error: Ollama timed out" and len(r.steps) == 1


def test_malformed_calls_are_retried_then_the_run_stops():
    gw = FakeGateway(lambda tool, args: decision("ALLOW", "EXECUTED", result={}))
    bad = {"message": {"tool_calls": [{"function": {"name": "read_file", "arguments": "{broken"}}]}}
    chat = StubChat([bad, bad, bad])
    r = run(chat, gw)
    assert r.stopped == "malformed calls" and r.malformed == 3 and gw.proposals == []
    assert "could not be read" in chat.seen[1][-1]["content"]


def test_unreachable_gateway_fails_closed():
    def down(request):
        raise httpx.ConnectError("refused")
    client = httpx.Client(transport=httpx.MockTransport(down), base_url="http://gw")
    chat = StubChat([call("read_file", path="public/faq.md")])
    r = run_real_agent(TASK, GatewayMode.protected, "http://gw", chat=chat, canaries=CANARIES, http_client=client)
    assert r.stopped.startswith("gateway error") and r.steps == [] and chat.seen == []


def test_unreadable_gateway_answer_fails_closed():
    def weird(request):
        if request.url.path == "/sessions":
            return httpx.Response(200, json={"session_id": "s"})
        return httpx.Response(200, json={"verdict": "MAYBE"})
    client = httpx.Client(transport=httpx.MockTransport(weird), base_url="http://gw")
    r = run_real_agent(TASK, GatewayMode.protected, "http://gw", chat=StubChat([call("read_file", path="a")]),
                       canaries=CANARIES, http_client=client)
    assert r.stopped.startswith("gateway error") and r.steps == []


# ---------------------------------------------------------------- task files


def test_task_files_load_and_resolve_by_short_id():
    tasks = load_tasks()
    assert find_task("R1", tasks).id == "R1-partner-briefing"
    assert find_task("n1-faq-answer", tasks).kind == "benign"
    with pytest.raises(ValueError):
        find_task("ZZ", tasks)
