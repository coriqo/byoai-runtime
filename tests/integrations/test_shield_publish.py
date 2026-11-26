"""Shield → Coriqo publishing: rare, self-healing, and never needs a person
once enrolled. Coriqo is a mock transport here; the wire format is the one the
recorder's /v1/checkpoints/batch already uses."""
from __future__ import annotations

import gzip
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from byoai.integrations.shield import SealChain, ShieldConfig, load_managed_policy
from byoai.integrations.shield_publish import BACKOFF_CAP_S, Publisher
from byoai.recorder.canonical import canonicalize
from byoai.recorder.enroll import enroll


class Clock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class FakeCoriqo:
    """Answers /v1/enroll and /v1/checkpoints/batch; can be told to fail."""

    def __init__(self):
        self.batches: list[dict] = []
        self.fail_with: int | None = None
        self.retry_after: str | None = None
        #: Set to make /v1/enroll pin a policy key straight away, like an
        #: enrolment response that carries EnrolByTokenOut.policy_key.
        self.enrol_policy_key: dict | None = None
        #: What POST /v1/shield/policy answers next.
        self.policy_changed = False
        self.policy_envelope: dict | None = None
        self.policy_have_version: int | None = None
        self.policy_fail = False
        self.policy_requests: list[dict] = []
        #: GET /api/v1/checkpoints/public-keys — the already-enrolled path.
        self.public_keys: list[dict] = []
        self.public_keys_requests = 0
        self.public_keys_down = False
        #: POST /v1/shield/events: bodies received, in order across routes.
        self.events: list[dict] = []
        self.order: list[str] = []
        self.events_status = 200
        #: Record the batch, then fail the reply (Coriqo counted it; we never heard).
        self.lose_reply = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/enroll":
            body = {"device_id": "dev-enrolled-1", "coriqo_base_url": "https://coriqo.test",
                    "tenant_slug": "acme_bank", "label": "shield"}
            if self.enrol_policy_key:
                body["policy_key"] = self.enrol_policy_key
            return httpx.Response(201, json=body)
        if request.url.path == "/v1/checkpoints/batch":
            if self.fail_with:
                headers = {"retry-after": self.retry_after} if self.retry_after else {}
                return httpx.Response(self.fail_with, json={"detail": "nope"}, headers=headers)
            body = json.loads(gzip.decompress(request.content))
            assert request.headers["x-coriqo-signature"]
            self.batches.append(body)
            self.order.append("checkpoint")
            return httpx.Response(200, json={"accepted": 1, "duplicates": 0, "rejected": []})
        if request.url.path == "/v1/shield/events":
            body = json.loads(gzip.decompress(request.content))
            if self.events_status != 200:
                return httpx.Response(self.events_status, json={"error": "x"})
            self.events.append(body)
            self.order.append("events")
            if self.lose_reply:
                raise httpx.ReadTimeout("reply lost")
            return httpx.Response(200, json={"accepted": len(body.get("events") or []),
                                             "duplicates": 0})
        if request.url.path == "/v1/shield/policy":
            if self.policy_fail:
                return httpx.Response(500, json={"detail": "nope"})
            self.policy_requests.append(json.loads(gzip.decompress(request.content)))
            if self.policy_changed:
                return httpx.Response(200, json={"changed": True, "envelope": self.policy_envelope})
            return httpx.Response(200, json={"changed": False, "version": self.policy_have_version})
        if request.url.path == "/api/v1/checkpoints/public-keys":
            self.public_keys_requests += 1
            if self.public_keys_down:
                return httpx.Response(503)
            return httpx.Response(200, json={"keys": self.public_keys})
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def setup(tmp_path):
    cfg = ShieldConfig(ledger=tmp_path / "c.jsonl", seal_path=tmp_path / "s.json",
                       key_dir=tmp_path / "keys", sig_every=4)
    seals = SealChain(cfg)
    coriqo = FakeCoriqo()
    clock = Clock()
    pub = Publisher(seals, cfg.key_dir, tmp_path, every_hours=6, now=clock,
                    client_factory=coriqo.client)
    return seals, coriqo, clock, pub, cfg


def _enrol(cfg, coriqo):
    enroll(coriqo_base_url="https://coriqo.test", token="cik_live_x",
           key_dir=cfg.key_dir, http_client=coriqo.client())


def _grow(seals, n=1):
    for _ in range(n):
        seals.stamp({"interaction": f"i{seals.height}", "flags": [], "chars": 3})


def test_nothing_happens_until_the_mac_is_enrolled(setup):
    seals, coriqo, clock, pub, cfg = setup
    _grow(seals, 3)
    assert pub.tick() is False and coriqo.batches == []
    assert pub.status()["connected"] is False


def test_sends_only_the_signed_seal_once_per_head(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 3)
    assert pub.tick() is True
    (batch,) = coriqo.batches
    (cp,) = batch["checkpoints"]
    assert cp["seq_start"] == cp["seq_end"] == 1 and cp["entries"] == 3
    assert cp["chain_hash"] == cp["checkpoint"]["root_hex"]
    assert cp["session_id"] == "coriqo-shield"
    # no ledger rows, no text: the seal, when it left, and the protection state
    assert set(batch) == {"device_id", "checkpoints", "sent_at", "shield"}
    # same head again: nothing new to send before the heartbeat is due
    clock.t += 5 * 3600
    assert pub.tick() is False and len(coriqo.batches) == 1
    s = pub.status()
    assert s["connected"] and s["tenant"] == "acme_bank" and s["has_new"] is False


def test_new_entries_wait_for_the_interval(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 2)
    pub.tick()
    _grow(seals, 5)
    clock.t += 2 * 3600
    assert pub.tick() is False                      # grew, but only 2h later
    assert pub.status()["has_new"] is True
    clock.t += 4 * 3600
    assert pub.tick() is True and len(coriqo.batches) == 2
    last = coriqo.batches[-1]["checkpoints"][0]
    assert last["seq_end"] == 2 and last["entries"] == 7


def test_failures_back_off_and_recover_on_their_own(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 2)
    coriqo.fail_with = 503
    pub.tick()
    s = pub.state
    assert s.failures == 1 and 45 <= s.next_attempt_at - clock.t <= 75
    assert pub.tick() is False                      # still backing off
    clock.t = s.next_attempt_at + 1
    pub.tick()
    assert pub.state.failures == 2                  # doubled
    for _ in range(20):                             # never beyond the cap
        clock.t = pub.state.next_attempt_at + 1
        pub.tick()
    assert pub.state.next_attempt_at - clock.t <= BACKOFF_CAP_S * 1.2 + 1
    assert pub.status()["needs_attention"] is False
    coriqo.fail_with = None
    clock.t = pub.state.next_attempt_at + 1
    pub.tick()
    assert pub.state.failures == 0 and pub.state.last_error is None
    assert len(coriqo.batches) == 1


def test_retry_after_is_honoured(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals)
    coriqo.fail_with, coriqo.retry_after = 429, "3600"
    pub.tick()
    assert pub.state.next_attempt_at - clock.t >= 3600


def test_a_revoked_mac_is_the_one_state_that_asks_for_a_person(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals)
    coriqo.fail_with = 401
    pub.tick()
    s = pub.status()
    assert s["needs_attention"] is True and "enrolment token" in s["last_error"]


def test_state_survives_a_restart(setup, tmp_path):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 2)
    pub.tick()
    again = Publisher(seals, cfg.key_dir, tmp_path, now=clock, client_factory=coriqo.client)
    assert again.state.last_height == 2 and again.state.last_seq == 1
    assert again.tick() is False                    # restart doesn't resend straight away
    clock.t += 7 * 3600
    assert again.tick() is True                     # the heartbeat: same entry, same number
    assert coriqo.batches[-1]["checkpoints"] == coriqo.batches[0]["checkpoints"]
    assert again.state.last_seq == 1


def test_a_broken_transport_never_escapes_tick(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals)

    def boom():
        raise RuntimeError("socket exploded")
    pub._client_factory = boom
    assert pub.tick() is True                       # attempted, didn't raise
    assert pub.state.failures == 1


def test_enrol_validates_input(setup):
    seals, coriqo, clock, pub, cfg = setup
    with pytest.raises(ValueError):
        pub.enrol("coriqo.test", "tok")
    with pytest.raises(ValueError):                 # a token never crosses a network in clear
        pub.enrol("http://coriqo.example.com", "tok")
    with pytest.raises(ValueError):
        pub.enrol("https://coriqo.test", "  ")


def test_sealing_and_signing_from_two_threads_keeps_the_chain_intact(setup):
    import threading
    seals, coriqo, clock, pub, cfg = setup

    def stamper():
        for i in range(150):
            seals.stamp({"interaction": f"t{i}", "flags": [], "chars": i})

    def signer():
        for _ in range(150):
            if seals.height:
                seals.sign_checkpoint()

    threads = [threading.Thread(target=stamper), threading.Thread(target=signer)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert seals.height == 150
    assert seals.verify_chain()["tamper_evident"] is True
    assert SealChain(cfg).verify_chain()["tamper_evident"] is True   # the file too



# -------------------------------------------- what Coriqo's verifier needs


def test_the_entry_verifies_the_way_coriqo_checks_it(setup):
    """Coriqo (ledger_checkpoint_verify.signing_bytes) verifies Ed25519 over
    canonical(entry minus sig/signature) with the device's enrolled key."""
    from byoai.recorder.canonical import canonicalize
    from byoai.recorder.keys import DeviceKey
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 2)
    pub.tick()
    (entry,) = coriqo.batches[0]["checkpoints"]
    body = {k: v for k, v in entry.items() if k not in ("sig", "signature")}
    assert DeviceKey.verify(seals._key.public_key_b64, canonicalize(body), entry["sig"])


def test_send_numbers_never_repeat_with_a_different_head(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    heads = {}
    for _ in range(4):
        _grow(seals)
        clock.t += 7 * 3600
        pub.tick()
    for b in coriqo.batches:
        cp = b["checkpoints"][0]
        assert heads.setdefault(cp["seq_end"], cp["chain_hash"]) == cp["chain_hash"]
    assert sorted(heads) == [1, 2, 3, 4]


def test_a_failed_send_is_retried_unchanged(setup):
    """The outbox: after a failure the same signed entry goes again, even if
    new entries were sealed meanwhile, so one number never names two heads."""
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 2)
    coriqo.fail_with = 503
    pub.tick()
    waiting = dict(pub.state.outbox)
    _grow(seals, 3)                                 # chain moves on meanwhile
    coriqo.fail_with = None
    clock.t = pub.state.next_attempt_at + 1
    pub.tick()
    (sent,) = coriqo.batches
    assert sent["checkpoints"][0] == waiting
    assert pub.state.outbox is None and pub.status()["has_new"] is True


def test_publishing_continues_after_a_restart(setup, tmp_path):
    """The chain now reloads in full (no 512-entry window), so the count after
    a restart is the count that was sent. Change is still detected by root, so
    new activity goes out, and an unchanged chain sends only a heartbeat."""
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 523)
    pub.tick()
    reloaded = SealChain(cfg)                       # restart: everything is kept
    assert reloaded.height == 523
    again = Publisher(reloaded, cfg.key_dir, tmp_path, now=clock, client_factory=coriqo.client)
    _grow(reloaded, 3)
    clock.t += 7 * 3600
    assert again.tick() is True and len(coriqo.batches) == 2


def test_no_proxy_is_used(setup, monkeypatch):
    seals, coriqo, clock, pub, cfg = setup
    fresh = Publisher(seals, cfg.key_dir, cfg.key_dir.parent)
    with fresh._client_factory() as client:
        assert client._trust_env is False


def test_an_idle_mac_sends_a_heartbeat_that_is_the_same_entry(setup):
    """Nothing new for hours: Shield resends the accepted seal byte for byte,
    so Coriqo hears from the Mac without storing a second entry."""
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 3)
    pub.tick()
    clock.t += 6 * 3600
    assert pub.tick() is True and len(coriqo.batches) == 2
    assert coriqo.batches[1]["checkpoints"] == coriqo.batches[0]["checkpoints"]
    assert pub.state.last_seq == 1 and pub.state.last_sent_at == clock.t
    # and not again until the next interval
    clock.t += 3600
    assert pub.tick() is False and len(coriqo.batches) == 2


def test_the_heartbeat_stays_between_one_and_six_hours(setup, tmp_path):
    seals, coriqo, clock, _pub, cfg = setup
    fast = Publisher(seals, cfg.key_dir, tmp_path, every_hours=0, now=clock,
                     client_factory=coriqo.client)
    slow = Publisher(seals, cfg.key_dir, tmp_path, every_hours=48, now=clock,
                     client_factory=coriqo.client)
    assert fast.heartbeat_s == 3600 and slow.heartbeat_s == 6 * 3600


def test_a_mac_upgraded_from_before_heartbeats_numbers_its_seal_once_more(setup, tmp_path):
    """State written before heartbeats has no last_entry. The unchanged seal
    goes out once under a new number; from then on the heartbeat repeats it."""
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 2)
    pub.tick()
    pub.state.last_entry = None
    pub._save()
    clock.t += 6 * 3600
    assert pub.tick() is True
    assert coriqo.batches[-1]["checkpoints"][0]["seq_end"] == 2
    clock.t += 6 * 3600
    assert pub.tick() is True
    assert coriqo.batches[-1]["checkpoints"] == coriqo.batches[-2]["checkpoints"]


def test_nothing_is_sent_for_an_empty_record(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    clock.t += 24 * 3600
    assert pub.tick() is False and coriqo.batches == []


# ------------------------------------ freshness, protection, record identity


def test_every_request_says_when_it_left_and_whether_shield_protects(setup, tmp_path):
    seals, coriqo, clock, _pub, cfg = setup
    state = {"protecting": True, "reasons": [], "mode": "redact"}
    pub = Publisher(seals, cfg.key_dir, tmp_path, now=clock,
                    client_factory=coriqo.client, protection=lambda: dict(state))
    _enrol(cfg, coriqo)
    _grow(seals, 2)
    pub.tick()
    first = coriqo.batches[0]
    assert first["sent_at"] == "1970-01-12T13:46:40Z"   # the injected clock, RFC3339 UTC
    assert first["shield"] == {"protecting": True, "reasons": [], "mode": "redact",
                                "policy_version": None}
    state.update(protecting=False, reasons=["capture_stopped"])
    clock.t += 6 * 3600
    assert pub.tick() is True                       # heartbeat
    second = coriqo.batches[1]
    assert second["shield"] == {"protecting": False, "reasons": ["capture_stopped"],
                                "mode": "redact", "policy_version": None}
    assert second["sent_at"] != first["sent_at"]
    # the entry is byte for byte the one Coriqo already holds
    assert json.dumps(second["checkpoints"], sort_keys=True) == \
        json.dumps(first["checkpoints"], sort_keys=True)


def test_a_body_is_signed_with_its_top_level_fields(setup):
    """sent_at and shield sit inside what the Mac signs, so neither can be
    swapped on the way."""
    from byoai.recorder.canonical import canonicalize
    from byoai.recorder.keys import DeviceKey
    seals, coriqo, clock, pub, cfg = setup
    seen = {}

    def handler(request):
        if request.url.path == "/v1/checkpoints/batch":
            seen["raw"] = gzip.decompress(request.content)
            seen["headers"] = dict(request.headers)
        return coriqo.handler(request)
    pub._client_factory = lambda: httpx.Client(transport=httpx.MockTransport(handler))
    _enrol(cfg, coriqo)
    _grow(seals)
    pub.tick()
    body = json.loads(seen["raw"])
    assert "sent_at" in body and "shield" in body
    assert seen["raw"] == canonicalize(body)        # the signed bytes are the whole body
    assert DeviceKey.verify(seals._key.public_key_b64, seen["raw"],
                            seen["headers"]["x-coriqo-signature"])


def test_without_a_protection_check_shield_never_claims_protection(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals)
    pub.tick()
    assert coriqo.batches[0]["shield"] == {"protecting": False,
                                          "reasons": ["state_unknown"], "mode": None,
                                          "policy_version": None}


def test_a_failing_protection_check_does_not_stop_the_send(setup, tmp_path):
    seals, coriqo, clock, _pub, cfg = setup

    def broken():
        raise RuntimeError("scutil exploded")
    pub = Publisher(seals, cfg.key_dir, tmp_path, now=clock,
                    client_factory=coriqo.client, protection=broken)
    _enrol(cfg, coriqo)
    _grow(seals)
    assert pub.tick() is True and len(coriqo.batches) == 1
    assert coriqo.batches[0]["shield"]["protecting"] is False


def test_record_id_is_stable_across_restart(setup, tmp_path):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 520)
    rid = seals.record_id
    assert rid
    pub.tick()
    assert coriqo.batches[0]["checkpoints"][0]["record_id"] == rid
    reloaded = SealChain(cfg)                       # restart
    assert reloaded.height == 520 and reloaded.record_id == rid
    again = Publisher(reloaded, cfg.key_dir, tmp_path, now=clock, client_factory=coriqo.client)
    _grow(reloaded)
    clock.t += 7 * 3600
    again.tick()
    assert coriqo.batches[-1]["checkpoints"][0]["record_id"] == rid


def test_record_id_changes_when_the_record_is_wiped(setup, tmp_path):
    seals, coriqo, clock, pub, cfg = setup
    _grow(seals)
    rid = seals.record_id
    cfg.seal_path.unlink()                          # the local record is deleted
    fresh = SealChain(cfg)
    assert fresh.record_id and fresh.record_id != rid
    _grow(fresh)
    assert SealChain(cfg).record_id == fresh.record_id   # and the new one is kept


def test_a_seal_file_from_before_record_ids_gets_one_and_keeps_it(setup):
    seals, coriqo, clock, pub, cfg = setup
    _grow(seals, 2)
    old = json.loads(cfg.seal_path.read_text())
    del old["record_id"]
    cfg.seal_path.write_text(json.dumps(old))
    first = SealChain(cfg)
    assert first.record_id and SealChain(cfg).record_id == first.record_id


def test_prev_chain_hash_links_each_new_entry_to_the_last_accepted(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals, 2)
    pub.tick()
    first = coriqo.batches[0]["checkpoints"][0]
    assert first["prev_chain_hash"] is None         # first entry after enrolment
    _grow(seals)
    clock.t += 7 * 3600
    pub.tick()
    second = coriqo.batches[1]["checkpoints"][0]
    assert second["prev_chain_hash"] == first["chain_hash"]
    assert second["chain_hash"] != first["chain_hash"]


def test_prev_chain_hash_skips_a_send_coriqo_never_accepted(setup):
    """A failed send is retried unchanged, so the next new entry still points
    at the last one Coriqo actually stored."""
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals)
    pub.tick()
    accepted = coriqo.batches[0]["checkpoints"][0]["chain_hash"]
    _grow(seals)
    clock.t += 7 * 3600
    coriqo.fail_with = 503
    pub.tick()
    assert pub.state.outbox["prev_chain_hash"] == accepted


def test_reenrolling_starts_the_link_again(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals)
    pub.tick()
    pub.enrol("https://coriqo.test", "cik_live_y")
    assert coriqo.batches[-1]["checkpoints"][0]["prev_chain_hash"] is None
    pub.tick()
    assert coriqo.batches[-1]["checkpoints"][0]["prev_chain_hash"] is None


def test_a_clock_refusal_says_fix_the_clock_and_keeps_retrying(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals)

    def stale(request):
        if request.url.path == "/v1/checkpoints/batch":
            return httpx.Response(401, json={"detail": "Request is stale or dated in "
                                             "the future; check this Mac's clock."})
        return coriqo.handler(request)
    pub._client_factory = lambda: httpx.Client(transport=httpx.MockTransport(stale))
    pub.tick()
    s = pub.status()
    assert s["last_error"] == ("This Mac's clock is wrong. Fix the date and time, "
                               "and Shield will send again on its own.")
    assert s["needs_attention"] is False and "enrolment token" not in s["last_error"]
    assert pub.state.failures == 1 and pub.state.next_attempt_at > clock.t
    # backs off like any transient failure, then recovers on its own
    pub.tick()
    assert pub.state.failures == 1                  # still waiting
    clock.t = pub.state.next_attempt_at + 1
    pub._client_factory = coriqo.client
    pub.tick()
    assert pub.state.failures == 0 and pub.status()["last_error"] is None
    assert len(coriqo.batches) == 1


def test_a_401_without_the_clock_is_still_a_refusal(setup):
    seals, coriqo, clock, pub, cfg = setup
    _enrol(cfg, coriqo)
    _grow(seals)
    coriqo.fail_with = 401
    pub.tick()
    assert pub.status()["needs_attention"] is True


# ------------------------------------------- what "protecting" means on a Mac


@pytest.fixture(autouse=True)
def _proxy_port_answers(monkeypatch):
    """Protection tests fake the proxy's process; its port is faked as open
    too, except where a test says otherwise."""
    import byoai.integrations.shield as shield
    monkeypatch.setattr(shield, "_port_open", lambda port: True)


def test_a_reused_pid_with_nothing_on_the_port_does_not_count(tmp_path, monkeypatch):
    import byoai.integrations.shield as shield
    from byoai.integrations.shield import protection_state
    cfg = _protection_cfg(tmp_path)
    _proxy_running(cfg)
    monkeypatch.setattr(shield, "_port_open", lambda port: False)
    assert protection_state(cfg, system_proxy=lambda: None)["reasons"] == ["capture_stopped"]


def _protection_cfg(tmp_path, policy=None):
    cfg = ShieldConfig(ledger=tmp_path / "c.jsonl", seal_path=tmp_path / "s.json",
                       key_dir=tmp_path / "keys", policy_path=tmp_path / "policy.json")
    if policy is not None:
        (tmp_path / "policy.json").write_text(json.dumps({"policy_version": 2, **policy}))
    return cfg


def _proxy_running(cfg, port=8080):
    import os

    from byoai.integrations.shield import proxy_alive_path
    proxy_alive_path(cfg.ledger).write_text(json.dumps({"pid": os.getpid(), "port": port}))


def test_protecting_when_the_proxy_runs_and_redacts(tmp_path):
    from byoai.integrations.shield import protection_state
    cfg = _protection_cfg(tmp_path)
    _proxy_running(cfg)
    got = protection_state(cfg, system_proxy=lambda: (True, 8080))
    assert got == {"protecting": True, "reasons": [], "mode": "redact"}


def test_not_protecting_names_each_reason(tmp_path):
    from byoai.integrations.shield import protection_state
    cfg = _protection_cfg(tmp_path, {"mode": "observe",
                                     "apps": {"claude": False, "chatgpt": False}})
    got = protection_state(cfg, system_proxy=lambda: (True, 8080))
    assert got["protecting"] is False and got["mode"] == "observe"
    assert got["reasons"] == ["capture_stopped", "policy_monitor_only", "no_apps_enabled"]


def test_system_proxy_off_or_elsewhere_is_not_protecting(tmp_path):
    from byoai.integrations.shield import protection_state
    cfg = _protection_cfg(tmp_path)
    _proxy_running(cfg, port=8080)
    assert protection_state(cfg, system_proxy=lambda: (False, None))["reasons"] == ["proxy_off"]
    assert protection_state(cfg, system_proxy=lambda: (True, 9999))["reasons"] == ["proxy_off"]
    # not a Mac, or scutil unreadable: no claim either way about the system proxy
    assert protection_state(cfg, system_proxy=lambda: None)["protecting"] is True


def test_a_crashed_proxy_leaves_a_marker_that_does_not_count(tmp_path):
    from byoai.integrations.shield import protection_state, proxy_alive_path
    cfg = _protection_cfg(tmp_path)
    proxy_alive_path(cfg.ledger).write_text(json.dumps({"pid": 2 ** 22 + 12345, "port": 8080}))
    assert protection_state(cfg, system_proxy=lambda: None)["reasons"] == ["capture_stopped"]


def test_the_proxy_marks_itself_running_and_clears_on_stop(tmp_path):
    from byoai.integrations.shield import proxy_alive_path, read_proxy_alive
    from byoai.integrations.shield_proxy import ShieldProxy
    ledger = tmp_path / "c.jsonl"
    proxy = ShieldProxy(ledger=ledger, policy_path=tmp_path / "policy.json")
    proxy.running()
    assert read_proxy_alive(ledger) is not None
    proxy.done()
    assert not proxy_alive_path(ledger).exists() and read_proxy_alive(ledger) is None


# --------------------------------------------------- managed policy polling
#
# Managed policy: poll POST /v1/shield/policy, signed exactly like the
# checkpoint post above; pin the signing key at enrolment or (an
# already-enrolled device) by fetching the public-keys list once; verify and
# apply via byoai.integrations.shield.apply_managed_envelope.



# Coriqo signs with its own server key, not a device key: lowercase hex of the
# raw 32-byte public key and the raw 64-byte signature, no "ed25519:" prefix.
# These fixtures build server-shaped envelopes/responses, not DeviceKey's.


def _server_key():
    return Ed25519PrivateKey.generate()


def _pub_hex(key) -> str:
    return key.public_key().public_bytes_raw().hex()


def _policy_envelope(key, **doc_overrides):
    doc = {
        "policy_id": "pol_1", "version": 1, "tenant_slug": "acme_bank",
        "device_id": None, "issued_at": "2026-09-26T10:00:00Z",
        "key_id": "coriqo-v1", "managed_by": "Acme IT",
        "policy": {"mode": "block", "apps": {"claude": True}, "keep_text": False,
                   "retention_days": 7, "notice": True},
        "locked": ["mode"],
    }
    doc.update(doc_overrides)
    return {"document": doc, "signature": key.sign(canonicalize(doc)).hex()}


def test_poll_policy_with_a_key_pinned_at_enrolment_applies_a_good_signature(setup, tmp_path):
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    coriqo.enrol_policy_key = {"key_id": "coriqo-v1", "public_key": _pub_hex(key)}
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key)
    pub.poll_policy(force=True)
    stored = load_managed_policy(pub.managed_policy_path)
    assert stored["envelope"]["document"]["version"] == 1
    assert pub.policy_status()["error"] is None
    (req,) = coriqo.policy_requests
    assert "sent_at" in req and req["have_version"] is None


def test_poll_policy_pins_the_key_by_fetching_public_keys_once(setup, tmp_path):
    """An already-enrolled device (no policy_key from /v1/enroll) fetches
    GET .../public-keys once and pins whichever entry matches the envelope's
    key_id."""
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)                              # no policy_key pinned
    coriqo.public_keys = [{"key_id": "coriqo-v1", "public_key": _pub_hex(key)}]
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key)
    pub.poll_policy(force=True)
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 1
    assert coriqo.public_keys_requests == 1
    # a second poll with another changed envelope reuses the pinned key
    coriqo.policy_envelope = _policy_envelope(key, version=2)
    pub.poll_policy(force=True)
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 2
    assert coriqo.public_keys_requests == 1          # not fetched again


def test_poll_policy_pins_a_pem_key_from_the_real_public_keys_shape(setup, tmp_path):
    """Coriqo's GET .../public-keys sends ``public_key_pem`` (an SPKI PEM),
    not ``public_key`` — Shield loads it and pins the raw hex form."""
    from cryptography.hazmat.primitives import serialization
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)
    coriqo.public_keys = [{"key_id": "coriqo-v1", "public_key_pem": pem, "revoked": False,
                          "active": True}]
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key)
    pub.poll_policy(force=True)
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 1
    assert pub.state.policy_public_key == _pub_hex(key)


def test_a_base64_key_pinned_at_enrolment_is_normalised_to_hex(setup, tmp_path):
    import base64
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    raw = key.public_key().public_bytes_raw()
    coriqo.enrol_policy_key = {"key_id": "coriqo-v1",
                               "public_key": base64.b64encode(raw).decode()}
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key)
    pub.poll_policy(force=True)
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 1
    assert pub.policy_status()["error"] is None


def test_a_key_list_outage_is_not_reported_as_an_unknown_key_and_retries_soon(setup, tmp_path):
    from byoai.integrations.shield_publish import POLICY_POLL_S
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)
    coriqo.public_keys = [{"key_id": "coriqo-v1", "public_key": _pub_hex(key)}]
    coriqo.public_keys_down = True
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key)
    pub.poll_policy(force=True)
    assert load_managed_policy(pub.managed_policy_path) is None
    assert "signing key" in pub.policy_status()["error"]
    assert "unknown" not in pub.policy_status()["error"]
    clock.t += 61                                    # due again in a minute, not ten
    assert pub.policy_due() and 61 < POLICY_POLL_S
    coriqo.public_keys_down = False
    pub.poll_policy()
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 1


def test_a_revoked_key_is_refused_even_if_the_id_matches(setup, tmp_path):
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    from cryptography.hazmat.primitives import serialization
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)
    coriqo.public_keys = [{"key_id": "coriqo-v1", "public_key_pem": pem, "revoked": True}]
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key)
    pub.poll_policy(force=True)
    assert load_managed_policy(pub.managed_policy_path) is None
    assert "unknown key" in pub.policy_status()["error"]


def test_an_unknown_key_id_is_refused_and_fetched_only_once(setup, tmp_path):
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    other = _server_key()
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)
    coriqo.public_keys = [{"key_id": "some-other-key", "public_key": _pub_hex(other)}]
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key)   # signed with a key Coriqo never lists
    pub.poll_policy(force=True)
    assert load_managed_policy(pub.managed_policy_path) is None
    assert "unknown key" in pub.policy_status()["error"]
    assert coriqo.public_keys_requests == 1
    pub.poll_policy(force=True)                      # doesn't refetch every poll
    assert coriqo.public_keys_requests == 1


def test_a_bad_signature_wrong_tenant_and_rollback_are_refused_and_keep_the_policy(setup, tmp_path):
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    coriqo.enrol_policy_key = {"key_id": "coriqo-v1", "public_key": _pub_hex(key)}
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key, version=5)
    pub.poll_policy(force=True)
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 5

    bad = _policy_envelope(key, version=6)
    bad["signature"] = bad["signature"][:-4] + "abcd"
    coriqo.policy_envelope = bad
    pub.poll_policy(force=True)
    assert "signature" in pub.policy_status()["error"]
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 5

    coriqo.policy_envelope = _policy_envelope(key, version=6, tenant_slug="someone_else")
    pub.poll_policy(force=True)
    assert "tenant" in pub.policy_status()["error"]
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 5

    coriqo.policy_envelope = _policy_envelope(key, version=4)   # older than what's stored
    pub.poll_policy(force=True)
    assert "rollback" in pub.policy_status()["error"]
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 5


def test_unmanage_clears_the_locked_keys(setup, tmp_path):
    from byoai.integrations.shield import load_policy, merge_policy, save_policy
    seals, coriqo, clock, pub, cfg = setup
    cfg.managed_policy_path = tmp_path / "managed.json"
    pub.managed_policy_path = cfg.managed_policy_path
    key = _server_key()
    coriqo.enrol_policy_key = {"key_id": "coriqo-v1", "public_key": _pub_hex(key)}
    _enrol(cfg, coriqo)
    save_policy(cfg, merge_policy({"mode": "redact"}))
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key)
    pub.poll_policy(force=True)
    assert load_policy(cfg)["mode"] == "block"
    coriqo.policy_envelope = _policy_envelope(key, version=2, policy=None, locked=[])
    pub.poll_policy(force=True)
    assert load_policy(cfg)["mode"] == "redact"


def test_a_poll_failure_keeps_the_current_policy_and_never_raises(setup, tmp_path):
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    coriqo.enrol_policy_key = {"key_id": "coriqo-v1", "public_key": _pub_hex(key)}
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)
    coriqo.policy_changed = True
    coriqo.policy_envelope = _policy_envelope(key)
    pub.poll_policy(force=True)
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 1
    coriqo.policy_fail = True
    coriqo.policy_envelope = _policy_envelope(key, version=2)
    pub.poll_policy(force=True)                      # never raises
    assert load_managed_policy(pub.managed_policy_path)["envelope"]["document"]["version"] == 1
    assert pub.policy_status()["error"] is not None
    _grow(seals)
    assert pub.tick() is True                        # capture/publishing keeps going


def test_poll_policy_only_runs_every_ten_minutes_and_on_send_now(setup, tmp_path):
    seals, coriqo, clock, pub, cfg = setup
    key = _server_key()
    coriqo.enrol_policy_key = {"key_id": "coriqo-v1", "public_key": _pub_hex(key)}
    pub.managed_policy_path = tmp_path / "managed.json"
    _enrol(cfg, coriqo)
    pub.tick()                                       # "at start"
    assert len(coriqo.policy_requests) == 1
    pub.tick()                                       # not due yet
    assert len(coriqo.policy_requests) == 1
    clock.t += 601
    pub.tick()
    assert len(coriqo.policy_requests) == 2
    _grow(seals)
    pub.publish_now()                                # "Send now" forces a poll
    assert len(coriqo.policy_requests) == 3



# --------------------------------------------------------------- activity sync

import calendar  # noqa: E402
import time  # noqa: E402

from byoai.integrations.shield_sync import EVENT_FIELDS  # noqa: E402

SECRET = "4111 1111 1111 1111"


@pytest.fixture
def sync(tmp_path):
    """A publisher wired for activity sync: a settable policy, a feed list."""
    cfg = ShieldConfig(ledger=tmp_path / "c.jsonl", seal_path=tmp_path / "s.json",
                       key_dir=tmp_path / "keys", sig_every=4)
    seals = SealChain(cfg)
    coriqo = FakeCoriqo()
    clock = Clock(calendar.timegm((2026, 9, 26, 12, 0, 0)))
    policy = {"sync": "events", "retention_days": 30}
    feed: list[dict] = []
    pub = Publisher(seals, cfg.key_dir, tmp_path, every_hours=6, now=clock,
                    client_factory=coriqo.client, policy=lambda: policy,
                    events=lambda: feed)
    _enrol(cfg, coriqo)

    def add(n=1, date=None, **over):
        for _ in range(n):
            i = len(feed)
            # Stamped at the fake clock (local time, as the feed does), unless
            # a date is given: sharing only sends what happens after it began.
            at = time.localtime(clock.t)
            item = {"id": f"row{i:05d}", "source": "desktop", "surface": "Claude · desktop",
                    "ts": time.strftime("%H:%M:%S", at),
                    "date": date or time.strftime("%Y-%m-%d", at), "status": "answered", "tool": None,
                    "flags": [{"tier": "pii", "rule": "emails"}], "verdict": "redacted(1)",
                    "chars": 40 + i, "redactions": ["emails"], "identity": {},
                    "verb": f"Message: {SECRET}", "text_hmac": "deadbeef" * 8,
                    "preview": SECRET, **over}
            item["seal"] = seals.stamp({"interaction": item["id"], "chars": item["chars"]})
            feed.insert(0, item)  # the feed is newest first
    return pub, coriqo, clock, policy, add


def test_events_go_after_a_checkpoint_that_covers_them(sync):
    pub, coriqo, clock, policy, add = sync
    add(3)
    pub.tick()
    assert coriqo.order == ["checkpoint", "events"]
    (body,) = coriqo.events
    assert body["level"] == "events" and len(body["events"]) == 3
    assert set(body) == {"device_id", "sent_at", "level", "policy_version",
                         "batch_id", "events"}
    assert all(set(e) == set(EVENT_FIELDS) for e in body["events"])
    assert SECRET not in json.dumps(body) and "deadbeef" not in json.dumps(body)
    assert pub.status()["sync"]["pending"] == 0


def test_a_sent_event_is_not_sent_again(sync):
    pub, coriqo, clock, policy, add = sync
    add(2)
    pub.tick()
    clock.t += 120
    pub.tick()
    assert len(coriqo.events) == 1
    add(1)
    clock.t += 120
    pub.tick()
    assert [len(b["events"]) for b in coriqo.events] == [2, 1]


def test_daily_sends_totals_not_rows(sync):
    pub, coriqo, clock, policy, add = sync
    policy["sync"] = "daily"
    add(3)
    pub.tick()
    (body,) = coriqo.events
    assert body["level"] == "daily" and "events" not in body
    (row,) = body["daily"]
    assert row["messages"] == 3 and row["flags"] == {"pii:emails": 3}
    assert row["redacted"] == 3 and row["app"] == "claude"


def test_seal_level_sends_nothing_and_does_not_backfill_later(sync):
    pub, coriqo, clock, policy, add = sync
    policy["sync"] = "seal"
    add(3)
    pub.tick()
    assert coriqo.events == []
    clock.t += 120
    policy["sync"] = "events"       # sharing turned up: only what happens next
    pub.tick()
    clock.t += 120
    add(1)
    pub.tick()
    assert [len(b["events"]) for b in coriqo.events] == [1]


def test_what_happened_while_sharing_was_off_stays_unsent(sync):
    pub, coriqo, clock, policy, add = sync
    add(1)
    pub.tick()
    assert len(coriqo.events) == 1
    policy["sync"] = "seal"
    clock.t += 120
    coriqo.events_status = 503
    pub.tick()
    add(2)                            # sharing is off
    clock.t += 120
    pub.tick()
    clock.t += 120
    policy["sync"] = "events"
    coriqo.events_status = 200
    pub.tick()
    add(1)
    clock.t += 120
    pub.tick()
    assert [len(b["events"]) for b in coriqo.events] == [1, 1]


def test_history_before_enrolment_is_never_sent(sync):
    pub, coriqo, clock, policy, add = sync
    add(3, date="2026-09-25")
    pub.tick()
    assert coriqo.events == []
    add(1)
    clock.t += 120
    pub.tick()
    assert [len(b["events"]) for b in coriqo.events] == [1]


def test_turning_sharing_down_drops_what_was_waiting(sync):
    pub, coriqo, clock, policy, add = sync
    coriqo.events_status = 503
    add(2)
    pub.tick()
    assert pub.status()["sync"]["pending"] == 2
    policy["sync"] = "seal"
    clock.t += 3600
    pub.tick()
    assert pub.status()["sync"]["pending"] == 0 and coriqo.events == []


def test_failure_keeps_the_batch_and_never_slows_the_seal(sync):
    pub, coriqo, clock, policy, add = sync
    coriqo.events_status = 503
    add(2)
    pub.tick()
    assert pub.status()["sync"]["pending"] == 2 and pub.status()["last_error"] is None
    assert pub.state.sync_next_attempt_at > clock.t          # its own backoff
    assert pub.state.next_attempt_at == 0                    # the seal's is untouched
    coriqo.events_status = 200
    clock.t += 3600
    pub.tick()
    (body,) = coriqo.events
    assert len(body["events"]) == 2 and pub.status()["sync"]["last_error"] is None


def test_a_batch_coriqo_calls_malformed_is_dropped_not_retried_forever(sync):
    pub, coriqo, clock, policy, add = sync
    coriqo.events_status = 422
    add(2)
    pub.tick()
    assert pub.status()["sync"]["pending"] == 0
    assert "malformed" in pub.status()["sync"]["last_error"]
    # the same feed items are not rebuilt into the same refusal, and the
    # dropped range is recorded as a gap
    coriqo.events_status = 200
    clock.t += 3600
    pub.tick()
    # the dropped range goes out on its own, as a gap with no events
    (gap_only,) = coriqo.events
    assert gap_only["events"] == [] and "gap" in gap_only and pub.state.sync_gap is None
    add(1)
    clock.t += 120
    pub.tick()
    assert len(coriqo.events[1]["events"]) == 1 and "gap" not in coriqo.events[1]


def test_events_are_batched_and_the_backlog_drains(sync):
    pub, coriqo, clock, policy, add = sync
    add(450)
    for _ in range(3):
        pub.tick()
        clock.t += 120
    assert [len(b["events"]) for b in coriqo.events] == [200, 200, 50]


def test_events_past_retention_become_a_gap_marker(sync):
    pub, coriqo, clock, policy, add = sync
    pub.tick()                       # sharing begins now
    add(1, date="2026-01-01")        # older than the 30-day window
    pub.state.sync_since = 1.0       # (as if sharing had begun long ago)
    add(1)
    pub.tick()
    (body,) = coriqo.events
    assert len(body["events"]) == 1
    assert body["gap"]["from"].startswith("2026-01-01")
    coriqo.events.clear()
    add(1)
    clock.t += 120
    pub.tick()
    assert "gap" not in coriqo.events[0]      # sent once, then cleared


def test_a_level_mismatch_triggers_a_policy_check(sync):
    pub, coriqo, clock, policy, add = sync
    coriqo.events_status = 409
    add(1)
    pub.tick()
    assert coriqo.policy_requests and pub.status()["sync"]["pending"] == 1


def test_no_sync_without_wiring_or_enrolment(tmp_path):
    cfg = ShieldConfig(ledger=tmp_path / "c.jsonl", seal_path=tmp_path / "s.json",
                       key_dir=tmp_path / "keys", sig_every=4)
    seals = SealChain(cfg)
    coriqo = FakeCoriqo()
    bare = Publisher(seals, cfg.key_dir, tmp_path, client_factory=coriqo.client)
    assert bare.sync_tick() is False
    unenrolled = Publisher(seals, cfg.key_dir, tmp_path, client_factory=coriqo.client,
                           policy=lambda: {"sync": "events"}, events=lambda: [])
    assert unenrolled.sync_tick() is False and coriqo.events == []


def test_a_422_drops_the_batch_and_keeps_and_widens_the_gap(sync):
    pub, coriqo, clock, policy, add = sync
    pub.tick()
    gap = {"from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z"}
    pub.state.sync_gap = dict(gap)
    coriqo.events_status = 422
    add(2)
    clock.t += 3600
    pub.tick()
    assert pub.status()["sync"]["pending"] == 0            # refused, dropped once
    assert pub.state.sync_gap["from"] == gap["from"]        # the old gap survives
    assert pub.state.sync_gap["to"] > gap["to"]             # widened over the batch
    coriqo.events_status = 200
    add(1)
    clock.t += 3600
    pub.tick()
    (body,) = coriqo.events
    assert len(body["events"]) == 1 and body["gap"]["from"] == gap["from"]


def test_a_seal_going_out_keeps_sync_and_policy_state(sync):
    pub, coriqo, clock, policy, add = sync
    pub.state.policy_key_id, pub.state.policy_public_key = "k1", "ab" * 32
    add(2)
    pub.tick()
    assert pub.state.policy_key_id == "k1" and pub.state.sync_since


def test_a_resend_after_a_lost_reply_is_the_same_batch_whatever_arrived_since(sync):
    pub, coriqo, clock, policy, add = sync
    policy["sync"] = "daily"
    add(3)
    coriqo.lose_reply = True
    pub.tick()
    first = coriqo.events[0]
    assert pub.status()["sync"]["pending"] == 3          # not acknowledged
    coriqo.lose_reply = False
    add(2)                                               # arrives before the retry
    clock.t += 7200
    pub.tick()
    resent = coriqo.events[1]
    assert resent["batch_id"] == first["batch_id"] and resent["daily"] == first["daily"]
    assert resent["daily"][0]["messages"] == 3
    # the two new events follow as their own batch
    assert coriqo.events[2]["daily"][0]["messages"] == 2
    assert coriqo.events[2]["batch_id"] != first["batch_id"]


def test_a_gap_is_sent_even_when_no_events_are_waiting(sync):
    pub, coriqo, clock, policy, add = sync
    pub.tick()
    pub.state.sync_gap = {"from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z"}
    clock.t += 3600
    pub.tick()
    (body,) = coriqo.events
    assert body["events"] == [] and body["gap"]["from"].startswith("2026-09-01")
    assert pub.state.sync_gap is None


def test_a_backlog_drains_in_one_window_even_at_daily(sync):
    pub, coriqo, clock, policy, add = sync
    policy["sync"] = "daily"
    add(450)
    pub.tick()
    assert len(coriqo.events) == 3 and pub.status()["sync"]["pending"] == 0


def test_a_gap_that_widens_while_a_batch_is_in_flight_is_still_owed(sync):
    pub, coriqo, clock, policy, add = sync
    pub.tick()
    old = {"from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z"}
    pub.state.sync_gap = dict(old)
    add(1)
    coriqo.lose_reply = True
    clock.t += 3600
    pub.tick()
    first = coriqo.events[-1]
    assert first["gap"] == old
    pub.state.sync_gap = {"from": old["from"], "to": "2026-09-05T00:00:00Z"}  # widened
    coriqo.lose_reply = False
    clock.t += 7200
    pub.tick()
    resent = coriqo.events[-1] if coriqo.events[-1]["batch_id"] == first["batch_id"] else None
    assert resent is not None and resent["gap"] == old            # byte-identical resend
    clock.t += 3600
    pub.tick()
    assert coriqo.events[-1]["gap"]["to"] == "2026-09-05T00:00:00Z"  # the rest is still sent
    assert pub.state.sync_gap is None


def test_a_refused_gap_only_batch_is_dropped_not_resent_forever(sync):
    pub, coriqo, clock, policy, add = sync
    pub.tick()
    pub.state.sync_gap = {"from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z"}
    coriqo.events_status = 422
    clock.t += 3600
    pub.tick()
    assert pub.state.sync_gap is None and "gap marker" in pub.status()["sync"]["last_error"]


def test_two_gap_only_batches_never_share_a_batch_id(sync):
    pub, coriqo, clock, policy, add = sync
    pub.tick()
    for _ in range(2):
        pub.state.sync_gap = {"from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z"}
        clock.t += 3600
        pub.tick()
    a, b = coriqo.events
    assert a["batch_id"] != b["batch_id"]


def test_retention_never_trims_the_batch_that_is_in_flight(sync):
    pub, coriqo, clock, policy, add = sync
    add(3)
    coriqo.lose_reply = True
    pub.tick()
    first = coriqo.events[0]
    coriqo.lose_reply = False
    policy["retention_days"] = 1
    clock.t += 3 * 86400          # everything is now past the window
    pub.tick()
    resent = coriqo.events[1]
    assert resent["batch_id"] == first["batch_id"] and len(resent["events"]) == 3
    assert "gap" not in resent    # nothing was dropped: they were in flight


def test_a_gap_widened_during_a_refused_gap_only_batch_is_kept(sync):
    pub, coriqo, clock, policy, add = sync
    pub.tick()
    pub.state.sync_gap = {"from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z"}
    pub.state.sync_inflight = {"ids": [], "level": "events", "batch_id": "b1",
                               "gap": dict(pub.state.sync_gap)}
    pub.state.sync_gap = {"from": "2026-09-01T00:00:00Z", "to": "2026-09-09T00:00:00Z"}
    coriqo.events_status = 422
    clock.t += 3600
    pub.tick()
    assert pub.state.sync_gap == {"from": "2026-09-01T00:00:00Z", "to": "2026-09-09T00:00:00Z"}
