"""DA-2: asset class, venue and payment limits, enforced from the mandate."""

from __future__ import annotations

import pytest

from byoai.errors import MandateDeniedError
from byoai.recorder.governed_tool import governed_tool, use_gate
from byoai.recorder.mandate import Allow, Deny, MandateSnapshot, ProposedAction, Reason

from .test_mandate import FakeClock, gate_with

SCOPE = {"asset_classes": ["stablecoin", "fiat"], "venues": ["acme_exchange"]}


def act(**asset) -> ProposedAction:
    return ProposedAction(tool="search", asset=asset)


def test_reason_strings_are_exact():
    assert Reason.ASSET_CLASS_NOT_ALLOWED == "asset_class_not_allowed"
    assert Reason.VENUE_NOT_ALLOWED == "venue_not_allowed"
    assert Reason.TRANSACTION_LIMIT_EXCEEDED == "transaction_limit_exceeded"
    assert Reason.DAILY_TRANSACTION_LIMIT_EXCEEDED == "daily_transaction_limit_exceeded"


@pytest.mark.parametrize("asset_class", ["crypto_asset", None])
def test_asset_class_outside_scope_or_missing_denies(asset_class):
    gate = gate_with(asset_scope=SCOPE)
    verdict = gate.decide(act(asset_class=asset_class, venue="acme_exchange"))
    assert isinstance(verdict, Deny)
    assert verdict.reason == "asset_class_not_allowed"


@pytest.mark.parametrize("venue", ["other_dex", None])
def test_venue_outside_scope_or_missing_denies(venue):
    gate = gate_with(asset_scope=SCOPE)
    verdict = gate.decide(act(asset_class="fiat", venue=venue))
    assert isinstance(verdict, Deny)
    assert verdict.reason == "venue_not_allowed"


def test_in_scope_asset_is_allowed():
    gate = gate_with(asset_scope=SCOPE)
    assert isinstance(gate.decide(act(asset_class="fiat", venue="acme_exchange")), Allow)


def test_asset_class_is_checked_before_venue():
    gate = gate_with(asset_scope=SCOPE)
    verdict = gate.decide(act(asset_class="crypto_asset", venue="other_dex"))
    assert verdict.reason == "asset_class_not_allowed"


def test_per_transaction_limit():
    gate = gate_with(max_transaction_usd=100)
    assert isinstance(gate.decide(act(amount_usd=100)), Allow)
    verdict = gate.decide(act(amount_usd=100.01))
    assert isinstance(verdict, Deny)
    assert verdict.reason == "transaction_limit_exceeded"


def test_missing_amount_is_refused_when_the_mandate_caps_payments():
    gate = gate_with(max_transaction_usd=1, max_transaction_usd_per_day=1)
    assert gate.decide(act(asset_class="fiat")).reason == "transaction_limit_exceeded"


def test_daily_limit_counts_only_allowed_calls_and_rolls_off():
    clock = FakeClock()
    gate = gate_with(clock=clock, max_transaction_usd=60, max_transaction_usd_per_day=100)
    assert isinstance(gate.decide(act(amount_usd=60)), Allow)
    # Denied per-transaction: must not count toward the day.
    assert gate.decide(act(amount_usd=61)).reason == "transaction_limit_exceeded"
    # 60 + 50 > 100: denied, and not counted either.
    verdict = gate.decide(act(amount_usd=50))
    assert isinstance(verdict, Deny)
    assert verdict.reason == "daily_transaction_limit_exceeded"
    assert isinstance(gate.decide(act(amount_usd=40)), Allow)
    assert gate.decide(act(amount_usd=1)).reason == "daily_transaction_limit_exceeded"
    clock.advance(24 * 3600 + 1)
    assert isinstance(gate.decide(act(amount_usd=60)), Allow)


def test_call_denied_by_another_budget_is_not_counted():
    clock = FakeClock()
    gate = gate_with(clock=clock, max_calls_per_minute=1, max_transaction_usd_per_day=100)
    assert isinstance(gate.decide(act(amount_usd=10)), Allow)
    assert gate.decide(act(amount_usd=90)).reason == "budget_call_rate_exceeded"
    clock.advance(61)
    assert isinstance(gate.decide(act(amount_usd=90)), Allow)


def test_no_asset_given_is_unchanged():
    gate = gate_with(asset_scope=SCOPE, max_transaction_usd=1, max_transaction_usd_per_day=1)
    verdict = gate.decide("search")
    assert isinstance(verdict, Allow)
    assert verdict.reason == Reason.IN_SCOPE


def test_asset_given_but_no_scope_or_limits_is_allowed():
    gate = gate_with()
    assert isinstance(
        gate.decide(act(asset_class="crypto_asset", venue="x", amount_usd=1e9)), Allow
    )


def test_snapshot_parses_new_fields_and_tolerates_old_payloads():
    snap = MandateSnapshot.from_payload(
        {
            "asset_scope": {"asset_classes": ["fiat"], "venues": None},
            "max_transaction_usd": 5,
            "max_transaction_usd_per_day": "20",
        },
        received_at=0.0,
    )
    assert snap.asset_classes == ("fiat",)
    assert snap.venues is None
    assert snap.max_transaction_usd == 5.0
    assert snap.max_transaction_usd_per_day == 20.0

    for payload in ({}, {"asset_scope": None}, {"asset_scope": "junk", "max_transaction_usd": "x"}):
        old = MandateSnapshot.from_payload(payload, received_at=0.0)
        assert old.asset_classes is None and old.venues is None
        assert old.max_transaction_usd is None and old.max_transaction_usd_per_day is None


def test_governed_tool_asset_mapping_and_callable():
    gate = gate_with(
        allowed_tools=["pay", "swap"], asset_scope=SCOPE, max_transaction_usd=50
    )
    ran: list[str] = []

    @governed_tool(asset={"asset_class": "fiat", "venue": "acme_exchange"})
    def pay(amount):
        ran.append("pay")

    @governed_tool(asset=lambda a: {"asset_class": "stablecoin", "venue": "acme_exchange",
                                    "amount_usd": a["usd"]})
    def swap(usd):
        ran.append("swap")

    with use_gate(gate):
        swap(40)
        with pytest.raises(MandateDeniedError):
            swap(60)
        # pay declares an asset but no amount, and the mandate caps payments:
        # refused rather than let through unchecked.
        with pytest.raises(MandateDeniedError):
            pay(10)
    assert ran == ["swap"]


@pytest.mark.parametrize("bad", [-500, float("nan"), float("inf"), "ten", None])
def test_unusable_amount_is_refused_when_a_limit_is_set(bad):
    clock = FakeClock()
    gate = gate_with(clock=clock, max_transaction_usd_per_day=100)
    assert isinstance(gate.decide(act(amount_usd=90)), Allow)
    verdict = gate.decide(act(amount_usd=bad))
    assert verdict.reason == "transaction_limit_exceeded"
    # Nothing was added: 10 more still fits.
    assert isinstance(gate.decide(act(amount_usd=10)), Allow)


def test_unusable_amount_is_fine_when_no_limit_is_set():
    gate = gate_with(asset_scope=SCOPE)
    assert isinstance(gate.decide(act(asset_class="fiat", venue="acme_exchange")), Allow)
