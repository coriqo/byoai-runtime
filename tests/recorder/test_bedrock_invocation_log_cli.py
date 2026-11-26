"""``byoai-bedrock-log-reader``: what the command refuses before it reads or seals anything."""

from __future__ import annotations

import pytest

from byoai.recorder import bedrock_invocation_log_cli as cli
from byoai.recorder.bedrock_invocation_log_source import AwsLogSource

ARGS = ["--once", "--log-group", "/aws/bedrock/invocations", "--region", "eu-west-1"]


@pytest.fixture
def no_aws(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("the command reached AWS")

    monkeypatch.setattr(AwsLogSource, "from_environment", classmethod(refuse))


def test_an_unknown_payload_mode_exits_2_and_names_the_valid_ones(monkeypatch, capsys, tmp_path, no_aws):
    monkeypatch.setenv("BYOAI_RECORDER_PAYLOAD_MODE", "everything")

    code = cli.main([*ARGS, "--dir", str(tmp_path / "reader")])

    assert code == 2
    err = capsys.readouterr().err
    assert "'everything'" in err and "redacted" in err and "hash-only" in err
    assert not (tmp_path / "reader").exists()


def test_a_missing_log_group_exits_2(monkeypatch, capsys, no_aws):
    monkeypatch.delenv("BYOAI_BEDROCK_LOG_GROUP", raising=False)

    code = cli.main(["--once", "--region", "eu-west-1"])

    assert code == 2
    assert "--log-group" in capsys.readouterr().err


def test_coriqo_settings_cannot_be_overridden_on_the_host(no_aws):
    with pytest.raises(SystemExit) as exited:
        cli.main([*ARGS, "--set", "interval_minutes=1"])

    assert exited.value.code == 2
