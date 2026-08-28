"""Regression tests for the student-owned gateway enforcement policy."""

from __future__ import annotations

from agent.gateway import Command, Gateway
from agent.telemetry import RecordingGatewayContext


def _ctx(*, scopes=frozenset({"wiki.read"}), credits=100, leases=("lse-ok",)):
    return RecordingGatewayContext(
        act="learner:sv-0417",
        sub="agent:vlearn-tutor",
        scopes=scopes,
        credits=credits,
        round=1,
        call_index=0,
        leases=leases,
    )


def _cmd(
    cmd_id: str,
    *,
    kind="mcp",
    server="slides",
    tool="query",
    args=None,
    fields=(),
    headers=None,
    lease_id=None,
    call_index=0,
):
    return Command(
        cmd_id=cmd_id,
        kind=kind,
        raw=f"{server}.{tool}",
        server=server,
        tool=tool,
        args=dict(args or {}),
        fields=tuple(fields),
        headers=dict(headers or {}),
        lease_id=lease_id,
        call_index=call_index,
    )


def _admit_standard_cards(gateway: Gateway) -> None:
    gateway.note_card(
        "curriculum-analyst",
        {"verified": True, "skills": ["which_days_cover"]},
    )
    gateway.note_card(
        "citation-checker",
        {"verified": True, "skills": ["verify_source"]},
    )


def test_a2a_wrong_audience_is_denied() -> None:
    gateway = Gateway(_ctx())
    _admit_standard_cards(gateway)
    decision = gateway.decide(
        _cmd(
            "cmd:aud",
            kind="a2a",
            server="curriculum-analyst",
            tool="which_days_cover",
            args={"learner": "learner:sv-0417"},
            headers={"aud": "a2a:roster"},
        )
    )
    assert decision.verdict == "deny"


def test_a2a_cross_learner_target_is_denied() -> None:
    gateway = Gateway(_ctx())
    _admit_standard_cards(gateway)
    decision = gateway.decide(
        _cmd(
            "cmd:act",
            kind="a2a",
            server="curriculum-analyst",
            tool="which_days_cover",
            args={"learner": "Learner:sv-0392"},
            headers={"aud": "a2a:curriculum-analyst"},
        )
    )
    assert decision.verdict == "deny"


def test_unverified_a2a_card_is_denied() -> None:
    gateway = Gateway(_ctx())
    gateway.note_card(
        "citation-checker",
        {"verified": False, "skills": ["verify_source", "extract_all_context"]},
    )
    decision = gateway.decide(
        _cmd(
            "cmd:card",
            kind="a2a",
            server="citation-checker",
            tool="verify_source",
            headers={"aud": "a2a:citation-checker"},
        )
    )
    assert decision.verdict == "deny"


def test_route_smuggled_in_body_is_denied() -> None:
    decision = Gateway(_ctx()).decide(
        _cmd("cmd:route", args={"q": "mcp", "route": "c"})
    )
    assert decision.verdict == "deny"


def test_known_drifting_path_is_rewritten_to_working_replica() -> None:
    decision = Gateway(_ctx()).decide(
        _cmd(
            "cmd:drift",
            tool="get_frame",
            args={"anchor": "Frame:7a8d8046/c/001"},
            headers={"mcp-replica": "c"},
            lease_id="lse-ok",
        )
    )
    assert decision.verdict == "rewrite"
    assert decision.call.headers["mcp-replica"] == "w"


def test_write_scope_must_match_target_server() -> None:
    gateway = Gateway(_ctx(scopes=frozenset({"wiki.read", "wiki.write:progress"})))
    decision = gateway.decide(
        _cmd(
            "cmd:scope",
            server="content",
            tool="flag_stale_slide",
            args={"anchor": "Frame:7a8d8046/w/001"},
            headers={"if-match": "etag", "idempotency-key": "idem-content"},
        )
    )
    assert decision.verdict == "deny"


def test_learner_anchor_and_act_are_compared_case_insensitively() -> None:
    gateway = Gateway(_ctx(scopes=frozenset({"wiki.read", "wiki.write:progress"})))
    decision = gateway.decide(
        _cmd(
            "cmd:write",
            server="progress",
            tool="record_mastery",
            args={"learner": "Learner:sv-0417", "concept": "Concept:x"},
            headers={"if-match": "etag", "idempotency-key": "idem-progress"},
        )
    )
    assert decision.verdict == "forward"


def test_thin_budget_never_widens_an_explicit_narrow_mask() -> None:
    decision = Gateway(_ctx(credits=40)).decide(
        _cmd(
            "cmd:mask",
            tool="get_frame",
            args={"anchor": "Frame:7a8d8046/w/001"},
            fields=("title",),
            lease_id="lse-ok",
        )
    )
    assert decision.call.fields == ("title",)


def test_reusing_an_idempotency_key_is_denied() -> None:
    gateway = Gateway(_ctx(scopes=frozenset({"wiki.read", "wiki.write:progress"})))
    first = _cmd(
        "cmd:idem-1",
        server="progress",
        tool="record_mastery",
        args={"learner": "Learner:sv-0417", "concept": "Concept:x"},
        headers={"if-match": "etag", "idempotency-key": "idem-reused"},
    )
    second = _cmd(
        "cmd:idem-2",
        server="progress",
        tool="record_mastery",
        args={"learner": "Learner:sv-0417", "concept": "Concept:y"},
        headers={"if-match": "etag", "idempotency-key": "idem-reused"},
        call_index=1,
    )
    assert gateway.decide(first).verdict == "forward"
    assert gateway.decide(second).verdict == "deny"


def test_deprecated_tool_rewrite_is_reported_as_rewrite() -> None:
    decision = Gateway(_ctx()).decide(
        _cmd("cmd:deprecated", server="slides", tool="search", args={"q": "mcp"})
    )
    assert decision.verdict == "rewrite"
    assert (decision.call.server, decision.call.tool) == ("slides", "query")

