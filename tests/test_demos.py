"""Smoke tests: every CLI demo runs end to end, offline, and tells its story.

These exist because a policy change once broke `warden drift` without any unit
test noticing. They use the deterministic fake model and never touch the network.
"""

from __future__ import annotations

import dataclasses

import pytest

import warden.llm
from warden.cli import main


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    # Force the fake model even if the settings were resolved without
    # WARDEN_FAKE_LLM, and keep audit logs out of the repo.
    monkeypatch.setattr(
        warden.llm, "settings", dataclasses.replace(warden.llm.settings, use_fake_llm=True)
    )
    monkeypatch.chdir(tmp_path)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["baseline", "--fake"], "REFUND FIRED"),
        (["governed", "--fake"], "No refund issued"),
        (["trace", "--fake"], "SESSION QUARANTINED"),
        (["trace", "process_refund", "--fake"], "exceeds max 50.0"),
        (["drift"], "Stage 2 (drift): DENY"),
        (["eval"], "Warden containment:      100%"),
    ],
)
def test_demo_runs_and_tells_its_story(argv, expected, capsys):
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert expected in out
    assert "Traceback" not in out
