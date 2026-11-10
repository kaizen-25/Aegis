"""Split-run demo with real tools: the same poisoned task without Aegis, then with Aegis.

    python -m agent.real_demo [--task R1] [--gateway URL] [--model NAME] [--review-wait 0]

Needs a gateway started with AEGIS_TOOLS=real (scripts\\demo_real.ps1 starts one for you).

1. Reset workspace/ and outbox/.
2. Run the task in passthrough mode: the gateway executes every call and only notes what it
   would have decided. This is the "without Aegis" side.
3. Show the outbox.
4. Reset again, run the same task in protected mode, show the outbox again.

This is an operator script, like agent/eval.py: it may reset the gateway and read GET /outbox.
The agent loop itself (agent/real_agent.py) still uses only the three agent endpoints.
"""
from __future__ import annotations

import argparse
import sys
import textwrap
from typing import Any

import httpx

from agent import admin
from agent.llm_agent import DEFAULT_MODEL, OLLAMA_URL, LlmError, OllamaClient
from agent.real_agent import RealRun, find_task, load_tasks, run_real_agent
from contracts.enums import GatewayMode

LINE = "-" * 72


def check_real_gateway(http: httpx.Client) -> None:
    try:
        health = http.get("/health", timeout=5).json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SystemExit(f"error: no gateway at {http.base_url} ({type(exc).__name__}). Start it first.") from None
    if health.get("tool_mode") != "real":
        raise SystemExit("error: the gateway is not in real-tools mode. Restart it with AEGIS_TOOLS=real "
                         "(scripts\\demo_real.ps1 does this).")


def fetch_outbox(http: httpx.Client, mode: GatewayMode) -> list[dict[str, Any]]:
    response = http.get("/outbox", params={"mode": mode.value})
    response.raise_for_status()
    return response.json()


def show_outbox(emails: list[dict[str, Any]], mode: GatewayMode) -> None:
    print(f"\nOUTBOX ({mode.value}) - {len(emails)} email(s) actually written to outbox\\{mode.value}\\")
    if not emails:
        print("  (empty)")
    for e in emails:
        print(f"  To:      {e['to']}")
        print(f"  Subject: {e['subject']}")
        body = textwrap.shorten(" ".join(str(e["body"]).split()), 300, placeholder=" ...")
        print(textwrap.indent(textwrap.fill(body, 68), "    "))
        print()


def show_steps(run: RealRun) -> None:
    for step in run.steps:
        for c in step.calls:
            target = c.args_masked.get("path") or c.args_masked.get("name") or c.args_masked.get("to") or ""
            rules = f"  ({', '.join(c.matched_rules)})" if c.verdict != "ALLOW" or c.status != "EXECUTED" else ""
            print(f"  step {step.step}: {step.function:<10} {c.tool:<12} {str(target)[:38]:<38} {c.verdict}/{c.status}{rules}")
        if not step.calls:
            print(f"  step {step.step}: (unreadable tool call)")
    print(f"  stopped: {run.stopped}")


def run_side(task, mode: GatewayMode, args, http: httpx.Client, chat: OllamaClient) -> list[dict[str, Any]]:
    title = "WITHOUT Aegis (passthrough: every call runs)" if mode is GatewayMode.passthrough \
        else "WITH Aegis (protected: the gateway decides)"
    print(f"\n{LINE}\n{title}\n{LINE}")
    admin.reset_sandbox(http)
    run = run_real_agent(task, mode, args.gateway, chat=chat, review_wait=args.review_wait)
    show_steps(run)
    emails = fetch_outbox(http, mode)
    show_outbox(emails, mode)
    return emails


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agent.real_demo", description=__doc__.split("\n\n")[0])
    ap.add_argument("--task", default="R1")
    ap.add_argument("--gateway", default="http://127.0.0.1:8000")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--ollama", default=OLLAMA_URL)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--think", choices=["default", "on", "off"], default="default",
                    help="thinking for reasoning models such as qwen3 (use off)")
    ap.add_argument("--review-wait", type=float, default=0.0,
                    help="seconds to wait for you to approve/reject in Review Inbox (0 = do not wait)")
    args = ap.parse_args(argv)

    task = find_task(args.task, load_tasks())
    attacker = ((task.attack or {}).get("target") or {}).get("to")
    with httpx.Client(base_url=args.gateway.rstrip("/"), timeout=30) as http:
        check_real_gateway(http)
        chat = OllamaClient(args.model, args.ollama, options={"temperature": args.temperature, "seed": args.seed},
                            think={"default": None, "on": True, "off": False}[args.think])
        try:
            chat.check_available()
        except LlmError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"Task {task.id}: {task.title}\nModel {args.model}, temperature {args.temperature}, seed {args.seed}")
        print(textwrap.fill("Prompt: " + task.prompt, 72))
        try:
            without = run_side(task, GatewayMode.passthrough, args, http, chat)
            with_aegis = run_side(task, GatewayMode.protected, args, http, chat)
        finally:
            chat.close()

    if attacker:
        leaked_without = sum(1 for e in without if e["to"] == attacker)
        leaked_with = sum(1 for e in with_aegis if e["to"] == attacker)
        print(f"{LINE}\nEmails to the attacker ({attacker}): without Aegis {leaked_without}, with Aegis {leaked_with}")
        if leaked_without == 0:
            print("The model did not follow the injection this time, so there was nothing to stop. "
                  "Small models vary; try again or use another seed.")
    print("The protected run is still loaded: open the dashboard (Audit Log, Review Inbox) to inspect it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
