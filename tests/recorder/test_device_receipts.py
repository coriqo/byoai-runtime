"""Device receipts: sent after the traces, refused ones become findings, the
join keys are sealed on tool rows, and `coriqo-verify receipt` checks one offline."""

from __future__ import annotations

import json

import httpx
import pytest

from byoai.integrations.shield import Feed, SealChain, ShieldConfig
from byoai.recorder.cli import main
from byoai.recorder.coriqo_agents import (
    CoriqoAgentsClient,
    CoriqoCredentials,
    publish_session,
    read_tool_steps,
)
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.receipts import ReceiptStore
from byoai.recorder.schema import EventKind
from byoai.recorder.verify import verify_device_receipt, verify_receipts

from .conftest import make_event

HASH = "sha256:" + "ab" * 32


def _cfg(tmp_path) -> ShieldConfig:
    ledger = tmp_path / "captures.jsonl"
    ledger.touch()
    return ShieldConfig(
        ledger=ledger, seal_path=tmp_path / "seal.json", key_dir=tmp_path / "keys",
        policy_path=tmp_path / "policy.json", managed_policy_path=tmp_path / "managed.json",
    )


def _run(tmp_path, steps=2):
    key = load_or_create_device_key(tmp_path / "keys")
    led = Ledger(tmp_path / "ledger.db", device_id=key.device_id)
    for i in range(steps):
        for kind in (EventKind.TOOL_USE, EventKind.TOOL_RESULT):
            led.append(make_event("dev", "run_1", kind, payload={"i": i},
                                  tool_use_id=f"u{i}", tool_name=f"t{i}"))
    return led


def _seal_steps(chain, led, **extra):
    for step in read_tool_steps(led, "run_1"):
        chain.stamp({"interaction": f"i{step.index}", "status": "answered",
                     "payload_hash": step.args_hash, "mandate_verdict": "allowed", **extra})


def _publish(led, chain, device_handler):
    order: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        order.append(path.rsplit("/", 1)[-1])
        if path.endswith("/device-receipts"):
            return device_handler(json.loads(request.content))
        if path.endswith("/traces/batch"):
            traces = json.loads(request.content)["traces"]
            acks = [{"step_index": t["step_index"], "event_hash": "e", "status": "recorded"}
                    for t in traces]
            return httpx.Response(201, json={"recorded": len(traces), "flagged": 0, "traces": acks})
        return httpx.Response(201, json={"trajectory_id": "tid", "status": "completed"})

    http = httpx.Client(base_url="http://c", transport=httpx.MockTransport(handler))
    client = CoriqoAgentsClient(CoriqoCredentials("http://c", "k", "t"), http_client=http)
    result = publish_session(client, coriqo_agent_id="a", ledger=led, session_id="run_1",
                             seal_chain=chain)
    return result, order


def _findings(led):
    rows = ReceiptStore.for_ledger(led).entries()
    return {r["step_index"]: r.get("device_receipt") for r in rows}


def test_receipts_go_after_traces_and_before_complete_with_their_step(tmp_path):
    led = _run(tmp_path)
    chain = SealChain(_cfg(tmp_path))
    _seal_steps(chain, led)
    sent = []

    def ok(body):
        sent.extend(body["receipts"])
        return httpx.Response(200, json={"stored": len(body["receipts"]), "duplicates": 0})

    result, order = _publish(led, chain, ok)
    assert order.index("batch") < order.index("device-receipts") < order.index("complete")
    assert result.device_receipts == 2 and result.status == "completed"
    assert [s["step_index"] for s in sent] == [0, 1]
    for item, step in zip(sent, read_tool_steps(led, "run_1"), strict=True):
        assert item["receipt"]["payload"]["payload_hash"] == step.args_hash


def test_422_is_a_finding_on_the_receipt_it_names_and_the_run_still_closes(tmp_path):
    led = _run(tmp_path)
    chain = SealChain(_cfg(tmp_path))
    _seal_steps(chain, led)
    refused = read_tool_steps(led, "run_1")[1].args_hash

    def handler(body):
        if any(i["receipt"]["payload"]["payload_hash"] == refused for i in body["receipts"]):
            return httpx.Response(422, json={"detail": "not enrolled"})
        return httpx.Response(200, json={"stored": 1, "duplicates": 0})

    result, order = _publish(led, chain, handler)
    assert order[-1] == "complete" and result.device_receipts == 1
    found = _findings(led)
    assert found[0] is None
    assert found[1]["finding"] == "device_receipt_refused" and found[1]["reason"] == "not enrolled"
    section = verify_receipts(ReceiptStore.for_ledger(led).path)
    assert not section["ok"] and any("not enrolled" in r for r in section["reasons"])


def test_a_server_failure_is_unsent_not_silent_and_not_a_lost_run(tmp_path):
    led = _run(tmp_path, steps=1)
    chain = SealChain(_cfg(tmp_path))
    _seal_steps(chain, led)
    result, order = _publish(led, chain, lambda _b: httpx.Response(503, text="down"))
    assert order[-1] == "complete" and result.status == "completed"
    assert _findings(led)[0]["finding"] == "device_receipt_unsent"
    assert verify_receipts(ReceiptStore.for_ledger(led).path)["device_receipt_unsent"]


def test_a_row_with_message_text_never_leaves_the_device(tmp_path):
    led = _run(tmp_path, steps=1)
    chain = SealChain(_cfg(tmp_path))
    _seal_steps(chain, led, text_redacted="hello [NAME]")

    def fail(_body):
        raise AssertionError("message text was sent")

    result, order = _publish(led, chain, fail)
    assert "device-receipts" not in order and result.device_receipts == 0
    assert _findings(led)[0]["finding"] == "device_receipt_withheld"


def test_a_step_with_no_sealed_row_is_counted(tmp_path):
    led = _run(tmp_path, steps=1)
    result, order = _publish(led, SealChain(_cfg(tmp_path)), lambda _b: httpx.Response(500))
    assert "device-receipts" not in order and result.device_receipts_missing == 1


def _tool_rows(cfg, **extra):
    rows = [
        {"kind": "tool.call", "tool": "credit_check", "call_id": "c1",
         "wall_clock": "2026-11-04 10:00:00", "chars": 5,
         "identity": {"client_name": "agent"}, **extra},
        {"kind": "tool.result", "tool": "credit_check", "call_id": "c1",
         "wall_clock": "2026-11-04 10:00:01"},
    ]
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_tool_row_seals_the_join_keys_through_its_reseal(tmp_path):
    cfg = _cfg(tmp_path)
    _tool_rows(cfg, payload_hash=HASH, mandate_verdict="blocked", prompt="secret words")
    feed = Feed(cfg)
    feed.scan_initial()
    payload = feed.seals.receipts_for_payload_hashes({HASH})[HASH]["payload"]
    assert payload["mandate_verdict"] == "blocked" and payload["status"] == "answered"
    assert "secret words" not in json.dumps(payload)


@pytest.mark.parametrize("extra", [{"payload_hash": "not a hash"}, {"mandate_verdict": "maybe"}])
def test_a_badly_shaped_join_key_is_dropped(tmp_path, extra):
    cfg = _cfg(tmp_path)
    _tool_rows(cfg, **extra)
    feed = Feed(cfg)
    feed.scan_initial()
    assert not set(extra) & set(feed.seals.entries[-1]["payload"])


def test_old_tool_row_keeps_its_seal_across_the_change(tmp_path):
    """A row without the keys seals to the same bytes, so replay adds nothing."""
    cfg = _cfg(tmp_path)
    _tool_rows(cfg)
    feed = Feed(cfg)
    feed.scan_initial()
    entry = feed.seals.entries[-1]
    assert not {"payload_hash", "mandate_verdict"} & set(entry["payload"])
    height = feed.seals.height
    again = Feed(cfg)
    again.scan_initial()
    assert again.seals.height == height
    rc = again.seals.receipt(entry["seal"])
    assert verify_device_receipt(rc, rc["merkle"]["checkpoint"]["public_key_b64"])["ok"]


@pytest.fixture
def receipt(tmp_path):
    chain = SealChain(_cfg(tmp_path))
    seal = chain.stamp({"interaction": "a", "payload_hash": HASH})
    chain.stamp({"interaction": "b"})
    rc = chain.receipt(seal)
    return rc, rc["merkle"]["checkpoint"]["public_key_b64"], tmp_path


def _cli(tmp, doc, key, capsys):
    path = tmp / "r.json"
    path.write_text(json.dumps(doc))
    code = main(["receipt", str(path), "--pubkey", key])
    return code, capsys.readouterr().out


def test_cli_passes_a_good_receipt_with_base64_or_hex_key(receipt, capsys):
    import base64

    rc, key, tmp = receipt
    code, out = _cli(tmp, rc, key, capsys)
    assert code == 0 and out.count("PASS") == 3 and "VERDICT: receipt verified." in out
    assert _cli(tmp, rc, base64.b64decode(key).hex(), capsys)[0] == 0
    assert _cli(tmp, {"seal": rc["seal"], "kind": rc["kind"], "receipt": rc}, key, capsys)[0] == 0


def test_cli_names_each_failed_check(receipt, capsys):
    rc, key, tmp = receipt
    changed = json.loads(json.dumps(rc))
    changed["payload"]["interaction"] = "z"
    code, out = _cli(tmp, changed, key, capsys)
    assert code == 1 and "FAIL  seal" in out and "FAIL  inclusion" in out
    assert "PASS  signature" in out

    other = load_or_create_device_key(tmp / "other").public_key_b64
    code, out = _cli(tmp, rc, other, capsys)
    assert code == 1 and "FAIL  signature" in out and "CANNOT be relied upon" in out


def test_receipt_from_before_the_checkpoint_fix_fails_signature_and_says_why(receipt, capsys):
    rc, key, tmp = receipt
    old = json.loads(json.dumps(rc))
    old["merkle"]["checkpoint"].pop("kind")
    old["merkle"]["checkpoint"].pop("ts")
    code, out = _cli(tmp, old, key, capsys)
    assert code == 1 and "PASS  seal" in out and "PASS  inclusion" in out
    assert "older Shield" in out


def test_cli_unreadable_input_is_exit_2(receipt, capsys):
    _rc, key, tmp = receipt
    assert main(["receipt", str(tmp / "missing.json"), "--pubkey", key]) == 2
    assert _cli(tmp, _rc, "nonsense!", capsys)[0] == 2


def test_a_checkpoint_that_cannot_be_hashed_fails_instead_of_crashing(receipt):
    rc, key, _tmp = receipt
    bad = json.loads(json.dumps(rc))
    bad["merkle"]["checkpoint"]["height"] = float("nan")
    assert verify_device_receipt(bad, key)["checks"]["signature"]["ok"] is False
