"""Job state machine and demo tokens. No database."""

import uuid

import pytest

from app import auth
from app.services import jobs


@pytest.mark.parametrize(
    "current,target",
    [
        ("running", "queued"),  # no re-dispatch
        ("unknown", "queued"),  # uncertainty is never retried automatically
        ("unknown", "succeeded"),
        ("failed", "running"),
        ("queued", "succeeded"),  # cannot skip dispatch
    ],
)
def test_forbidden_transitions(current, target):
    with pytest.raises(ValueError):
        jobs.transition(current, target)


def test_no_state_leads_back_to_queued():
    assert all("queued" not in targets for targets in jobs.TRANSITIONS.values())


def test_worst_case_is_an_upper_bound():
    spec = jobs.HANDLERS["word_count"]
    assert spec.worst_case_cents({"max_units": 4}) == 4 * jobs.UNIT_PRICE_CENTS


def test_tokens_round_trip_and_reject_tampering():
    ws, member = uuid.uuid4(), uuid.uuid4()
    token = auth.issue(ws, member, "test-secret")
    assert auth.parse(token, "test-secret") == auth.Principal(ws, member)
    with pytest.raises(PermissionError):
        auth.parse(token, "other-secret")
    with pytest.raises(PermissionError):
        auth.parse(auth.issue(ws, member, "test-secret", ttl_s=-1), "test-secret")
