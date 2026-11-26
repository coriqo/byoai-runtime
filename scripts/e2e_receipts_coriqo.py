#!/usr/bin/env python3
"""End to end: device receipts from `coriqo-mcp --shield-dir` into a real, local Coriqo.

    BYOAI_E2E_CORIQO_URL=http://localhost:8000 BYOAI_E2E_TENANT=<tenant slug> \
    BYOAI_E2E_USER=<test user> BYOAI_E2E_PASSWORD=<its password> \
    .venv/bin/python scripts/e2e_receipts_coriqo.py [--keep-dir]

What it does (all against the Coriqo you point it at; it never starts or stops one):
 1. signs in to the tenant with a test account (no MFA) that you name below,
    creates an agent, mints an enrolment token and enrols a fresh device
    (`byoai.recorder.enroll`) into a temp recorder dir;
 2. writes a mandate file (agent.id set, enforce, `search` allowed, `delete_account`
    prohibited) and starts `coriqo-mcp --mandate F --shield-dir D -- <stdio server>`;
 3. makes one allowed and one denied tools/call, then closes the session;
 4. checks in Coriqo: the run exists with the allowed step, a device receipt is
    attached to that step, the device verdict matches Coriqo's, the denied call left a
    sealed `tool.call` row on the device, and `coriqo-verify receipt` passes on the
    receipt downloaded from Coriqo, with the pubkey taken from Coriqo's device list.

Credentials for the publish at close: `coriqo-mcp` reads BYOAI_CORIQO_URL /
BYOAI_CORIQO_API_KEY / BYOAI_CORIQO_TENANT_SLUG. Set BYOAI_E2E_API_KEY to a service
account key (model:write) to exercise exactly that path. Without it the script signs
in as the user and swaps the user's bearer token into the publish client inside the
coriqo-mcp process (a harness shim, reported in the output); a service account needs
a second approver in Coriqo, which a one-person local stack may not have.

Exit 0 only if every check passed.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
URL = os.environ.get("BYOAI_E2E_CORIQO_URL", "http://localhost:8000").rstrip("/")
# No defaults: name a tenant and a test account on a LOCAL Coriqo yourself.
def _need(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"set {name} (tenant slug, test user and password of a local Coriqo; see the top of this file)")
    return value


TENANT = _need("BYOAI_E2E_TENANT")
USER = _need("BYOAI_E2E_USER")
PASSWORD = _need("BYOAI_E2E_PASSWORD")
API_KEY = os.environ.get("BYOAI_E2E_API_KEY")
DENIED = "This action is not permitted."

SERVER = '''
import json, os, sys
TOOLS = [{"name": n, "description": n, "inputSchema": {"type": "object"}} for n in ("search", "delete_account")]
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m:
        continue
    if m["method"] == "initialize":
        r = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "e2e", "version": "0"}}
    elif m["method"] == "tools/list":
        r = {"tools": TOOLS}
    else:
        with open(os.environ["E2E_SERVER_LOG"], "a") as fh:
            fh.write(m["params"]["name"] + "\\n")
        r = {"content": [{"type": "text", "text": "ok"}]}
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
'''

# Harness shim (only without BYOAI_E2E_API_KEY): authenticate the publish client with the
# signed-in user's bearer token instead of an API key, then run coriqo-mcp unchanged.
SHIM = """
import os, sys
from byoai.recorder import coriqo_agents as ca
_init = ca.CoriqoAgentsClient.__init__
def init(self, *a, **k):
    _init(self, *a, **k)
    self._client.headers.pop("X-API-Key", None)
    self._client.headers["Authorization"] = "Bearer " + os.environ["E2E_BEARER"]
ca.CoriqoAgentsClient.__init__ = init
from byoai.integrations.coriqo_mcp import main
sys.exit(main())
"""

failures: list[str] = []


def check(ok: Any, what: str) -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {what}")
    if not ok:
        failures.append(what)


def log(msg: str) -> None:
    print(f"== {msg}", flush=True)


class Api:
    def __init__(self) -> None:
        r = httpx.post(f"{URL}/api/v1/auth/token", timeout=60,
                       json={"username": USER, "password": PASSWORD, "tenant_slug": TENANT})
        body = r.json() if r.content else {}
        if r.status_code != 200 or "access_token" not in body:
            raise SystemExit(f"sign-in failed ({r.status_code}); this account needs no second step: {str(body)[:200]}")
        self.token = body["access_token"]
        self.http = httpx.Client(base_url=URL, timeout=90, headers={"Authorization": f"Bearer {self.token}"})

    def req(self, method: str, path: str, **kw: Any) -> Any:
        r = self.http.request(method, path, **kw)
        if r.status_code >= 300:
            raise SystemExit(f"{method} {path} -> {r.status_code}: {r.text[:400]}")
        return r.json() if r.content else None


class Mcp:
    def __init__(self, cmd: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=env, text=True, bufsize=1)
        self.stderr: list[str] = []
        self.out: list[dict] = []
        self.cv = threading.Condition()
        self.n = 0
        threading.Thread(target=self._rd, daemon=True).start()
        threading.Thread(target=lambda: [self.stderr.append(x.rstrip()) for x in self.proc.stderr], daemon=True).start()

    def _rd(self) -> None:
        for line in self.proc.stdout:
            with self.cv:
                self.out.append(json.loads(line))
                self.cv.notify_all()

    def call(self, method: str, params: dict | None = None, timeout: float = 60) -> dict:
        self.n += 1
        i = self.n
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n")
        self.proc.stdin.flush()
        with self.cv:
            if not self.cv.wait_for(lambda: any(m.get("id") == i for m in self.out), timeout):
                raise SystemExit(f"no answer to {method}; stderr: {self.stderr[-8:]}")
            return next(m for m in self.out if m.get("id") == i)

    def close(self, timeout: float = 90) -> int:
        self.proc.stdin.close()
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-dir", action="store_true")
    args = ap.parse_args()
    py = os.environ.get("BYOAI_PYTHON", sys.executable)
    work = Path(tempfile.mkdtemp(prefix="byoai-receipts-e2e-"))
    keys, shield = work / "device", work / "shield"
    env = {k: v for k, v in os.environ.items() if not k.startswith("BYOAI_")}
    env.update(PYTHONPATH=str(ROOT / "src"), PYTHONUNBUFFERED="1", E2E_SERVER_LOG=str(work / "server.log"))
    (work / "server.py").write_text(SERVER)

    log(f"Coriqo {URL}, tenant {TENANT}, scratch {work}")
    api = Api()
    agent = api.req("POST", "/api/v1/agents", json={
        "name": f"receipts-e2e-{int(time.time())}", "mandate": "Search records for the treasury team.",
        "allowed_tools": ["search"]})
    agent_id = agent["agent_id"]
    token = api.req("POST", "/api/v1/agent-runtime/enrollment-tokens", json={"label": "receipts e2e"})["token"]
    p = subprocess.run([py, "-m", "byoai.recorder.enroll", "--coriqo-url", URL, "--token", token,
                        "--key-dir", str(keys), "--tenant-slug", TENANT], env=env, text=True, capture_output=True)
    if p.returncode:
        raise SystemExit(f"enrol failed: {p.stdout}{p.stderr}")
    enrol = json.loads((keys / "enrollment.json").read_text())
    device_id = enrol["device_id"]
    log(f"agent {agent_id}, device {device_id}")

    # Binding happens when the device first reads the agent's mandate.
    probe = ("import asyncio,sys\nfrom pathlib import Path\n"
             "from byoai.recorder.identity import resolve_identity\n"
             "from byoai.recorder.coriqo_async import AsyncCoriqoAgentsClient\n"
             "async def m():\n"
             "    async with AsyncCoriqoAgentsClient(resolve_identity(key_dir=Path(sys.argv[2]))) as c:\n"
             "        await c.fetch_mandate_conditional(sys.argv[1])\n"
             "asyncio.run(m())\n")
    p = subprocess.run([py, "-c", probe, agent_id, str(keys)], env=env, text=True, capture_output=True)
    if p.returncode:
        raise SystemExit(f"mandate fetch as the device failed: {p.stderr[-800:]}")
    devs = api.req("GET", "/api/v1/agent-runtime/devices")
    mine = next((d for d in devs if d["device_id"] == device_id), None)
    check(mine and agent_id in mine.get("bound_agent_ids", []), "Coriqo lists the device, bound to the agent")

    mandate = work / "mandate.yaml"
    mandate.write_text(yaml.safe_dump({
        "spec": "coriqo.mandate/v1", "agent": {"id": agent_id, "name": agent["name"]}, "mode": "enforce",
        "on_stale_snapshot": "fail_closed", "on_violation": "deny",
        "tools": {"allowed": ["search"], "prohibited": ["delete_account"]}}))

    run_env = dict(env)
    if API_KEY:
        run_env.update(BYOAI_CORIQO_URL=URL, BYOAI_CORIQO_API_KEY=API_KEY, BYOAI_CORIQO_TENANT_SLUG=TENANT)
        entry = [py, "-m", "byoai.integrations.coriqo_mcp"]
        log("publish credential: service account key from BYOAI_E2E_API_KEY")
    else:
        run_env.update(BYOAI_CORIQO_URL=URL, BYOAI_CORIQO_API_KEY="shim", BYOAI_CORIQO_TENANT_SLUG=TENANT,
                       E2E_BEARER=api.token)
        entry = [py, "-c", SHIM]
        log("publish credential: HARNESS SHIM, signed-in user's bearer token (no service account key given)")
    cmd = [*entry, "--mandate", str(mandate), "--recorder-dir", str(keys), "--shield-dir", str(shield), "-v",
           "--", py, str(work / "server.py")]
    mcp = Mcp(cmd, run_env)
    mcp.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                            "clientInfo": {"name": "receipts-e2e", "version": "1"}}, timeout=90)
    mcp.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    mcp.proc.stdin.flush()
    ok = mcp.call("tools/call", {"name": "search", "arguments": {"q": "invoice 1042"}})["result"]
    no = mcp.call("tools/call", {"name": "delete_account", "arguments": {"id": "A-7"}})["result"]
    check(not ok.get("isError"), "the allowed call goes through")
    check(no.get("isError") and [c.get("text") for c in no["content"]] == [DENIED], "the denied call is refused")
    code = mcp.close()
    log(f"coriqo-mcp exit {code}; stderr tail: {mcp.stderr[-6:]}")
    check((work / "server.log").read_text().split() == ["search"], "the server only ever ran the allowed call")

    # --- Coriqo side -------------------------------------------------------
    runs = api.req("GET", f"/api/v1/agents/{agent_id}/trajectories")
    runs = runs.get("items", runs) if isinstance(runs, dict) else runs
    check(len(runs) == 1, f"Coriqo has one run for the agent (found {len(runs)})")
    if not runs:
        return finish(work, args.keep_dir)
    tid = runs[0]["trajectory_id"]
    print(f"  run {tid} status={runs[0].get('status')}")
    steps = api.req("GET", f"/api/v1/agents/{agent_id}/trajectories/{tid}/steps")
    mandate_check = steps.get("mandate_check")
    steps = steps["steps"]
    print(f"  step keys: {sorted(steps[0]) if steps else None}; mandate_check={json.dumps(mandate_check)[:300]}")
    dl = api.req("GET", f"/api/v1/agents/{agent_id}/trajectories/{tid}/receipt")
    print(f"  receipt download keys: {sorted(dl)}")
    receipts = [dict(d, step_index=st["step_index"], coriqo_verdict=st["mandate"]["verdict"],
                     agrees=(st.get("device_check") or {}).get("agrees"))
                for st in steps for d in st.get("device") or []]
    check(len(steps) >= 1, f"the run has the allowed step ({len(steps)} step(s))")
    check(len(receipts) >= 1, f"a device receipt is attached to the run ({len(receipts)})")
    step_idx = {t["step_index"] for t in steps}
    for r in receipts:
        check(r.get("step_index") in step_idx, f"receipt {r.get('seal')} is attached to step {r.get('step_index')}")
        check(r.get("device_verdict") == "within", f"device verdict is 'within' (got {r.get('device_verdict')!r})")
        check((r.get("verified") or {}).get("signer_device_id") == device_id, "the receipt is signed by the enrolled device")
        check(r.get("coriqo_verdict") == "within" and r.get("agrees"), "Coriqo's verdict matches the device's (no disagreement)")

    # Denied call: the device sealed a tool.call row with an exception verdict.
    rows = [json.loads(x) for x in (shield / "ledger.jsonl").read_text().splitlines() if x.strip()]
    calls = {r["tool"]: r for r in rows if r.get("kind") == "tool.call"}
    check(calls.get("delete_account", {}).get("mandate_verdict") not in (None, "allowed"),
          f"the denied call produced a tool.call row (verdict {calls.get('delete_account', {}).get('mandate_verdict')!r})")
    check(calls.get("search", {}).get("mandate_verdict") == "allowed", "the allowed call's row says allowed")
    seals = json.loads((shield / "seal.json").read_text()) if (shield / "seal.json").exists() else None
    check(seals, "the Shield seal chain exists on the device")

    # Offline check of a receipt downloaded from Coriqo, with the key Coriqo holds for the device.
    pub = next((d.get("public_key") for d in devs if d["device_id"] == device_id), None)
    pub = pub or (keys / "device_ed25519.pub").read_text().strip()
    embedded = [d["receipt"] for st in dl["steps"] for d in st.get("device") or []]
    check(embedded, "the run receipt download embeds the device receipt")
    for i, rc in enumerate(embedded[:1]):
        f = work / f"receipt{i}.json"
        f.write_text(json.dumps(rc))
        v = subprocess.run([py, "-m", "byoai.recorder.cli", "receipt", str(f), "--pubkey", str(pub)],
                           env=env, text=True, capture_output=True)
        print(v.stdout.rstrip())
        check(v.returncode == 0, "coriqo-verify receipt passes with the enrolled key")
    return finish(work, args.keep_dir)


def finish(work: Path, keep: bool) -> int:
    print(f"\n{'FAILED' if failures else 'ALL CHECKS PASSED'}: {len(failures)} failure(s). scratch: {work}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
