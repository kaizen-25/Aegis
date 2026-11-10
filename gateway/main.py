"""Entry point: python -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000

Building the app loads and validates the policy and every scenario, so an invalid file
stops the gateway from starting.

Set AEGIS_TOOLS=real before starting to use the real workspace/ and outbox/ tools
(default: simulated, which is what the 20 scenarios and the scored evaluation use).
"""
from gateway.app import Settings, create_app

app = create_app(Settings.from_env())
