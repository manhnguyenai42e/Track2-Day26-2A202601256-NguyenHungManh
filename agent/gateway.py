"""agent/gateway.py — YOUR control plane. CONTRACTS.md section 4, exactly.

READ agent/README.md FIRST — it maps all five files in this directory to what
each is scored on. This file is the one CONTRACTS.md calls "the trusted
envelope's untrusted half": every single MCP / A2A / DISCOVER command your
agent's model wants to make passes through `Gateway.decide` before it is
allowed to happen.

WHY THERE IS NO `execute()` METHOD ON `GatewayContext` (read this before you
go looking for one — there isn't one, and that is not an oversight)
----------------------------------------------------------------------------
CONTRACTS.md section 4's trusted envelope, reproduced here because it is the
one diagram worth memorising:

    [ trusted ]   loop emits a raw action line
         v
    [ trusted ]   INTERCEPT + CANONICALISE -> Command        (kit/loop/agent.py)
         v
    [ UNTRUSTED ] Gateway.decide(cmd) -> Decision             <- THIS FILE
         v
    [ trusted ]   ENFORCE: honour the Decision, meter it,
                  apply the active mutation, execute the
                  ToolCall or refuse it                       (the arena)
         v
    [ trusted ]   RECORD the authoritative L1 event, then
                  RENDER the Observation                      (the arena)
         v
    [ trusted ]   the model sees the Observation

`decide()` returns a *decision*, never a *result*. You cannot reach a tool
server, a file, a socket, or a clock from in here — there is nothing to
call. Two things follow from that, and both matter more than they look:

  1. YOUR TRACE CANNOT BE FORGED. Every `command` / `decision` / `enforced`
     / `tool_call` / `tool_result` L1 event (CONTRACTS.md 5.2) is written by
     the arena, from what the arena itself actually did — never from
     anything you claimed happened. A student gateway that wanted to lie
     about having blocked an attack ("I totally denied that, trust me")
     simply has no channel to lie through: the only thing you ever hand
     back is this one small `Decision` value, and the arena is the one that
     turns it into history.
  2. NOBODY CAN ACCUSE YOU OF A CALL YOU DID NOT AUTHORISE, either. Because
     `decide()` is the ONLY door a command can walk through on its way to
     actually running, a prosecutor's `enforcement_failure` claim against
     you has exactly one thing to point at: the `Decision` you returned for
     that specific `cmd_id`. There is no ambiguity about "maybe the loop
     called the tool directly" — CONTRACTS.md 4.2 removed that path on
     purpose, and kit/loop/agent.py's own module docstring names the same
     invariant from the other side (the loop never imports this module,
     never sees a `Decision`, never executes anything itself).

The cost of that guarantee is that this file is PURE: synchronous, no I/O,
no threads, no `sleep`, 250 ms wall-clock deadline (RULES.md section 3).
Raising anything, returning something that is not a valid `Decision`, or
missing the deadline is treated by the arena as a DENIED command PLUS a 2
credit penalty PLUS an `integrity` event that hands the prosecutor a free
`enforcement_failure` — CONTRACTS.md 4.1's charging table, reproduced in
agent/README.md's own table. Getting this file to just plainly return valid
`Decision` values, every time, is worth more than getting it clever.

THE STARTER'S SHAPE (read this before you start editing `decide()`)
----------------------------------------------------------------------------
This starter FORWARDS ALMOST EVERYTHING AND DENIES NOTHING. That is not a
placeholder oversight — it is the honest zero-defence baseline you are
meant to beat: `bots/rookie` in the kit's own ladder does exactly the same
thing, and RULES.md's own words are "if you cannot beat Rookie you have a
bug, not a strategy." `decide()` below is structured as four named jobs —
ROUTE, ADMIT, AUTHORIZE, BUDGET — each with a one-line TODO naming what a
real implementation checks and why. None of the four currently rejects,
rewrites, or reroutes anything; they are seams, not solutions. Fill them in
using `agent/strategy.py` (routing/budget policy) and `agent/guardrails.py`
(the safety checks) — both already import cleanly from here.

ONE THING WORTH INTERNALISING BEFORE YOU WRITE YOUR FIRST REAL CHECK:
`verdict="deny"` costs the CALLER (your own team) **zero credits** —
CONTRACTS.md 4.1's charging table has exactly one $0 row, and it is this
one. Refusing to make a call you cannot justify is FREE. That makes
abstention a real strategy, not a luxury you can't afford: a `deny` you can
defend beats a `forward` you can't, every time a prosecutor is watching.

Stdlib only. No network, no randomness, no wall-clock reads, no sleeping —
none of that would even survive the kernel sandbox (CONTRACTS.md 12), but
the point is this file has no reason to want any of it in the first place.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping, Protocol, runtime_checkable

# kit.mcp.types is a collaborator's file (workspace hard rule 2: import it,
# degrade gracefully). It is present as of this writing and is core, stable
# infrastructure (CONTRACTS.md 3.1) — but this module must still not fail to
# IMPORT if a concurrent edit ever breaks it transiently. When it is
# unavailable, `Decision.call` type-checking is skipped (not enforced), and
# `Gateway.decide` falls back to a minimal local dict-shaped stand-in so the
# rest of this file — everything that does not need a *real* ToolCall — still
# runs.
try:
    from kit.mcp.types import ToolCall
    _TOOLCALL_AVAILABLE = True
except ImportError:  # pragma: no cover - collaborator file
    ToolCall = Any  # type: ignore[assignment, misc]
    _TOOLCALL_AVAILABLE = False

# kit.loop.agent is also a collaborator's file, used only by this module's
# own __main__ demo (to build real Commands the same way the arena's trusted
# canonicaliser would) — never by decide() itself, which never touches the
# loop. Degraded the same way.
try:
    from kit.loop.agent import canonicalise_action as _canonicalise_action
except ImportError:  # pragma: no cover - collaborator file
    _canonicalise_action = None

# kit.world.anchor is stdlib-pure (no I/O — a string parser), safe to call
# from inside decide() itself: extracting `path_id` from an anchor string is
# not a world lookup, just re-parsing the anchor's own `ns:slug/...` grammar.
try:
    from kit.world.anchor import Anchor, AnchorSyntaxError
    _ANCHOR_AVAILABLE = True
except ImportError:  # pragma: no cover - collaborator file
    Anchor = None  # type: ignore[assignment]
    AnchorSyntaxError = ValueError  # type: ignore[assignment, misc]
    _ANCHOR_AVAILABLE = False

from agent.telemetry import RecordingGatewayContext, Telemetry

# kit.mcp.specs / kit.world.loader are collaborator files (workspace hard rule
# 2): imported for real per-duel policy (tool costs, default/cheap masks, the
# drift table), degraded gracefully so this module still imports if either is
# transiently unavailable. Degradation means JOB 4 (BUDGET) skips the
# spec-aware mask rewrite and JOB 1 (ROUTE) skips the drift-aware replica
# rewrite — never that either job pretends to have checked something it did
# not.
try:
    from kit.mcp.specs import A2A_PEERS, TOOL_SPECS, cost_of
    _SPECS_AVAILABLE = True
except ImportError:  # pragma: no cover - collaborator file
    A2A_PEERS = frozenset({"curriculum-analyst", "citation-checker", "roster"})
    TOOL_SPECS = {}
    _SPECS_AVAILABLE = False

from agent.strategy import (
    CATALOG_TRAP_TOOLS,
    SAFE_STARTING_RESERVE,
    cheap_mask,
    is_catalog_trap,
    successor_of,
)

# `Gateway.decide` must be PURE (RULES.md section 3: "no I/O of any kind") —
# it cannot read `kit/world/<world_id>/drift.json` at decision time, the same
# way it cannot open a socket or a clock. The set below is that file's
# `drifts: true` path_ids, transcribed OFFLINE, once, for world `df8c55dabb35`
# (RULES.md section 7 explicitly encourages reading the world ahead of time —
# `deck/deck.json`'s own `replica_flip` cards are required to do exactly this
# same offline lookup). This is per-duel PREPARATION baked into the module,
# not a runtime read: no different, in kind, from `kit/mcp/specs.py`'s own
# `TOOL_SPECS` being a static table rather than something re-derived live.
#
# STALE-DATA WARNING: if a live duel ever runs against a DIFFERENT world_id,
# this table stops being accurate and must be regenerated from that world's
# own `drift.json` before it can be trusted — `ctx` carries no `world_id`
# field to check against at runtime, so there is no way for `decide()` to
# detect a mismatch itself. Regenerate with:
#   python -c "import json; d=json.load(open('kit/world/<id>/drift.json'));
#   print(sorted(p for p,r in d.items() if r.get('drifts')))"
_KNOWN_DRIFTING_PATH_IDS: frozenset[str] = frozenset({
    "053195a5", "0e11ae43", "170c4d17", "28e68faa", "3326cb76", "45098556",
    "72f75709", "75811e75", "7a8d8046", "a13b20e6", "a284ae8b", "abd20c68",
    "c5418ab5", "d8f95a7b", "e0614beb", "f2696f5f",
})

_TARGET_KEYS: tuple[str, ...] = ("learner", "learner_id", "target", "subject", "act")
_A2A_TOOL_SKILLS: Mapping[tuple[str, str], frozenset[str]] = {
    ("curriculum-analyst", "which_days_cover"): frozenset({"which_days_cover"}),
    ("citation-checker", "verify_source"): frozenset({"verify_source"}),
    ("roster", "lookup_learner"): frozenset({"role_of", "who_enrolled", "lookup_learner"}),
}


def _normalise_learner_identity(value: object) -> str | None:
    """Canonicalise Learner anchors and delegation act strings."""
    if not isinstance(value, str) or not value.strip():
        return None
    lowered = value.strip().lower()
    return lowered if lowered.startswith("learner:") else None

__all__ = [
    "COMMAND_KINDS",
    "DECISION_VERDICTS",
    "Command",
    "Decision",
    "GatewayContext",
    "Gateway",
]

# CONTRACTS.md 4.1: `Command.kind` — "mcp" | "a2a" | "discover". An "answer"
# action is NEVER a Command (kit/loop/agent.py's own module docstring: "an
# answer is not a tool call routed to a server, so it never becomes a
# Command at all") — it is handled entirely by the loop/arena and never
# reaches `Gateway.decide`.
COMMAND_KINDS: frozenset[str] = frozenset({"mcp", "a2a", "discover"})

# CONTRACTS.md 4.1: `Decision.verdict` — the closed three-member set.
DECISION_VERDICTS: frozenset[str] = frozenset({"forward", "deny", "rewrite"})


def _looks_like_write(cmd: "Command") -> bool:
    """`True` iff `cmd` is a write call. Prefers `kit.mcp.specs.TOOL_SPECS`'s
    own `is_write` flag when available (the authoritative source); falls
    back to "this command carries either write-precondition header" when
    specs are unavailable — a write is the only command shape CONTRACTS.md
    4.2 mechanic 3 ever attaches `if-match`/`idempotency-key` to, so a
    command carrying either is itself write-shaped evidence."""
    if _SPECS_AVAILABLE:
        spec = TOOL_SPECS.get((cmd.server, cmd.tool))
        if spec is not None:
            return spec.is_write
    return bool(cmd.headers.get("if-match") or cmd.headers.get("idempotency-key"))


@dataclass(frozen=True, slots=True)
class Command:
    """CONTRACTS.md 4.1, field for field — "canonicalised by the arena
    BEFORE the student sees it". You never build one of these from your own
    agent's raw text; the arena's canonicaliser (kit/loop/agent.py's
    `canonicalise_action`, run inside the trusted envelope) already did that
    work and minted `cmd_id` by the time `decide()` sees it. The
    `from_action_dict` classmethod below exists only so this file's own demo
    (and your local tests, if you write any) can build a realistic `Command`
    without duplicating the arena's canonicalisation logic."""

    cmd_id: str
    kind: str  # "mcp" | "a2a" | "discover" — see COMMAND_KINDS
    raw: str
    server: str
    tool: str
    args: dict
    fields: tuple[str, ...]
    headers: dict
    lease_id: str | None
    call_index: int

    def __post_init__(self) -> None:
        if not isinstance(self.cmd_id, str) or not self.cmd_id:
            raise ValueError(f"Command.cmd_id must be a non-empty str, got {self.cmd_id!r}")
        if self.kind not in COMMAND_KINDS:
            raise ValueError(f"Command.kind must be one of {sorted(COMMAND_KINDS)}, got {self.kind!r}")
        if not isinstance(self.server, str) or not self.server:
            raise ValueError(f"Command.server must be a non-empty str, got {self.server!r}")
        if not isinstance(self.tool, str) or not self.tool:
            raise ValueError(f"Command.tool must be a non-empty str, got {self.tool!r}")
        if not isinstance(self.args, dict):
            raise ValueError(f"Command.args must be a dict, got {type(self.args).__name__}")
        if not isinstance(self.headers, dict):
            raise ValueError(f"Command.headers must be a dict, got {type(self.headers).__name__}")
        if (
            not isinstance(self.call_index, int)
            or isinstance(self.call_index, bool)
            or self.call_index < 0
        ):
            raise ValueError(f"Command.call_index must be a non-negative int, got {self.call_index!r}")

    @classmethod
    def from_action_dict(cls, action: Mapping[str, Any], *, cmd_id: str) -> "Command":
        """Build a `Command` from the dict shape `kit.loop.agent.canonicalise_action`
        returns (`kind, raw, server, tool, args, fields, headers, lease_id,
        call_index` — everything except the arena-minted `cmd_id`, supplied
        here as a keyword). Raises `ValueError` if `action["kind"] ==
        "answer"` — an answer is never a Command (see the module docstring).
        This is a convenience for tests/demos, not something the real arena
        calls: the trusted envelope mints `cmd_id` itself and constructs the
        real `Command` on its own side of the boundary."""
        kind = action.get("kind")
        if kind == "answer":
            raise ValueError(
                "an 'answer' action never becomes a Command (kit/loop/agent.py: "
                "\"an answer is not a tool call routed to a server\") — do not "
                "route it through Gateway.decide at all"
            )
        return cls(
            cmd_id=cmd_id,
            kind=kind,
            raw=action["raw"],
            server=action["server"],
            tool=action["tool"],
            args=dict(action.get("args", {})),
            fields=tuple(action.get("fields", ())),
            headers=dict(action.get("headers", {})),
            lease_id=action.get("lease_id"),
            call_index=action.get("call_index", 0),
        )

    def to_dict(self) -> dict:
        return {
            "cmd_id": self.cmd_id,
            "kind": self.kind,
            "raw": self.raw,
            "server": self.server,
            "tool": self.tool,
            "args": dict(self.args),
            "fields": list(self.fields),
            "headers": dict(self.headers),
            "lease_id": self.lease_id,
            "call_index": self.call_index,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """CONTRACTS.md 4.1, field for field.

    Validated strictly (`__post_init__`) because a *structurally* invalid
    `Decision` is charged exactly like a raised exception — CONTRACTS.md
    4.1's charging table: "malformed Decision (schema-invalid) -> 2 cr
    penalty, command denied." Failing loudly HERE, in your own process
    during development, is strictly better than discovering it live in a
    duel as an unexplained penalty.

    `verdict == "deny"` requires a non-empty `reason` (CONTRACTS.md 4.1:
    "required when verdict == 'deny'; shown in the combat log") and
    forbids `call` — a real denial has nothing left to carry out.
    `verdict` in `("forward", "rewrite")` requires `call` to be set — the
    arena executes exactly that `ToolCall`, nothing else, per the trusted
    envelope's whole point (see the module docstring)."""

    verdict: str  # "forward" | "deny" | "rewrite" — see DECISION_VERDICTS
    reason: str | None = None
    call: "ToolCall | None" = None
    quarantine: bool = False
    note: str | None = None

    def __post_init__(self) -> None:
        if self.verdict not in DECISION_VERDICTS:
            raise ValueError(
                f"Decision.verdict must be one of {sorted(DECISION_VERDICTS)}, got {self.verdict!r}"
            )
        if self.verdict == "deny":
            if not isinstance(self.reason, str) or not self.reason.strip():
                raise ValueError("Decision.verdict=='deny' requires a non-empty 'reason'")
            if self.call is not None:
                raise ValueError("Decision.verdict=='deny' must not carry a 'call' — there is nothing to run")
        else:  # forward | rewrite
            if self.call is None:
                raise ValueError(f"Decision.verdict=={self.verdict!r} requires 'call' to be set")
            if _TOOLCALL_AVAILABLE and not isinstance(self.call, ToolCall):
                raise ValueError(
                    f"Decision.call must be a kit.mcp.types.ToolCall instance, got {type(self.call).__name__}"
                )
        if not isinstance(self.quarantine, bool):
            raise ValueError(f"Decision.quarantine must be a bool, got {self.quarantine!r}")
        if self.note is not None and not isinstance(self.note, str):
            raise ValueError(f"Decision.note must be a str or None, got {self.note!r}")

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "call": self.call.to_dict() if self.call is not None and hasattr(self.call, "to_dict") else self.call,
            "quarantine": self.quarantine,
            "note": self.note,
        }


@runtime_checkable
class GatewayContext(Protocol):
    """CONTRACTS.md 4.2 — "read-only, arena-provided". Note what this is
    NOT: unlike `Command`/`Decision` above, CONTRACTS.md writes this as a
    plain `class`, not a `@dataclass(frozen=True, ...)`. That is a real
    signal, not an inconsistency — a `GatewayContext` is a LIVE VIEW the
    arena owns and updates as the duel actually progresses (credits get
    spent, rounds advance, leases mint and expire), not a frozen snapshot
    you receive once. This file therefore models it as a structural
    `Protocol`: the arena hands your `Gateway.__init__` some object shaped
    like this (see `agent/telemetry.py`'s `RecordingGatewayContext` for a
    concrete example your own tests/demos can build), and you read
    `self.ctx.<field>` fresh every time `decide()` runs — NEVER cache a
    context field into a local variable across calls; if you need memory
    that persists across the duel (a cache, a budget tracker, drift notes),
    keep it on YOUR OWN `Gateway` instance attributes instead (CONTRACTS.md
    4.3: "Gateway is instantiated once per duel... persists across the 10
    rounds").

    There is deliberately no `execute` method here — see the module
    docstring's "WHY THERE IS NO execute() METHOD" section. `emit` is the
    ONE thing you can do that has any side effect at all, and it writes to
    `own_telemetry` only: your own side, never scored, never shown to the
    opponent (`agent/telemetry.py` wraps it)."""

    act: str  # "learner:sv-0417" — WHOM YOU SERVE. Authority derives from this.
    sub: str  # "agent:vlearn-tutor" — what you are. NOT authority.
    scopes: frozenset[str]  # {"wiki.read"}; writes need "wiki.write:progress" etc.
    credits: int  # remaining this duel
    round: int
    call_index: int
    leases: tuple[str, ...]  # live lease ids, arena-tracked
    history: tuple[Mapping[str, Any], ...]  # YOUR OWN prior (Command, Decision, outcome) triples this duel

    def emit(self, name: str, **payload: Any) -> None: ...


class Gateway:
    """The control plane. One instance per duel (CONTRACTS.md 4.3) — built
    once at duel start with a `GatewayContext`, then asked to `decide()` on
    every MCP/A2A/DISCOVER command either side of the duel makes for all 10
    rounds. See the module docstring for the trusted-envelope diagram and
    why there is no `execute()` to call instead.

    Instance attributes below are this starter's ENTIRE per-duel memory —
    all currently unused by `decide()`'s naive body, but declared here
    (rather than invented ad hoc later) so the four TODO jobs below have
    somewhere obvious to keep state once you implement them. `agent/
    strategy.py` has working building blocks for exactly this (a budget
    pacer, a result cache, a replica-choice heuristic) — this starter does
    not wire them in for you; that wiring is the assignment.
    """

    def __init__(self, ctx: GatewayContext) -> None:
        self.ctx = ctx
        self._telemetry = Telemetry(ctx)

        # --- per-duel memory ----------------------------------------------
        # A cache of anchor -> body-ish data you have already paid for this
        # duel (agent/strategy.py's ResultCache is a ready-made version of
        # this). Populating it needs the *result* of a call, which decide()
        # never sees (it only sees the outgoing Command) — you would fill
        # this from whatever the arena hands back to your agent loop AFTER
        # a call executes, then consult it here on the NEXT decide() call
        # for the same anchor.
        self._seen_anchors: dict[str, Any] = {}
        # Credits you have personally authorised so far this duel — your
        # own running total, independent of (and a cross-check against)
        # `ctx.credits`, which the arena maintains authoritatively. Used by
        # JOB 4 (BUDGET) as a cross-check against `ctx.credits` drifting out
        # of sync with what this gateway itself has approved.
        self._credits_authorised: int = 0
        # Command ids you have already denied, in case a later job wants to
        # know "have I already said no to this once". JOB 2 (ADMIT) uses
        # this to avoid repeatedly denying (and repeatedly explaining) the
        # exact same doomed cmd_id if the model retries it unchanged.
        self._denied_cmd_ids: set[str] = set()
        # A2A cards admitted by the arena/registry for this duel. Unknown
        # peers fail closed until note_card() records a verified card.
        self._admitted_cards: dict[str, dict[str, Any]] = {}
        # Exactly-once is a per-duel invariant, not a per-exchange one.
        self._idempotency_keys: set[str] = set()

    def decide(self, cmd: Command) -> Decision:
        """SYNCHRONOUS. PURE. NO I/O. 250 ms wall (RULES.md section 3).
        Raising anything, or returning a `Decision` `__post_init__` rejects,
        is treated by the arena exactly like an explicit deny PLUS a 2
        credit penalty PLUS a scored `integrity` event (CONTRACTS.md 4.1's
        charging table) — so the one thing this method must never do is
        blow up or wander off into I/O, no matter how tempting a "quick
        check" against something external looks. Everything you need to
        decide is already sitting in `cmd` and `self.ctx`.

        Runs four jobs in order — ROUTE, ADMIT, AUTHORIZE, BUDGET — any one
        of which can end the pipeline early with a `deny`. A job that does
        not deny passes its (possibly rewritten) command to the next job;
        the final `Decision` carries whichever verdict fired first, or
        `forward` if none did."""
        self._telemetry.decision_seen(cmd)

        # ------------------------------------------------------------------
        # JOB 1 — ROUTE: is this the right SERVER/REPLICA for this command?
        # day18-style drift is real and measured (CORPUS-FACTS.md section 2):
        # a `swap_replica` mutation (CONTRACTS.md section 8) can point `cmd`
        # at a stale replica without the model ever noticing. When the
        # command's own anchor/args name a path_id this gateway KNOWS drifts
        # (`_KNOWN_DRIFTING_PATH_IDS`, transcribed offline — decide() cannot
        # read drift.json live, RULES.md section 3), and the caller did not
        # already pin a replica header itself, prefer the canonical replica
        # — `agent/strategy.py`'s `pick_replica` is the documented rationale
        # for why "c" is the safer naive guess once drift is confirmed.
        routed = self._route(cmd)

        # ------------------------------------------------------------------
        # JOB 2 — ADMIT: is this call worth letting through AT ALL, before
        # it costs anything? `verdict="deny"` costs the caller ZERO credits
        # (CONTRACTS.md 4.1's charging table has exactly one $0 row) — a
        # `deny` you can defend beats a `forward` you can't. Two doomed
        # shapes are checkable here with nothing but `cmd`/`ctx`: a
        # `get_frame` with no live lease in `self.ctx.leases` (CONTRACTS.md
        # 4.2 mechanic 2 — it will fail server-side regardless), and a write
        # missing either required precondition header (CONTRACTS.md 4.2
        # mechanic 3 — a write with no `if-match`/`idempotency-key` cannot
        # possibly succeed, so forwarding it only spends credits on a
        # guaranteed failure).
        admit_denial = self._admit(routed)
        if admit_denial is not None:
            decision = self.deny(cmd, admit_denial)
            return decision

        # ------------------------------------------------------------------
        # JOB 3 — AUTHORIZE: does `routed` actually belong to WHOM YOU SERVE?
        # A write whose target learner id != `self.ctx.act`, or a call that
        # needs a write scope `self.ctx.scopes` never granted, is
        # `authority_exceeded` (CONTRACTS.md section 6.4) — the single
        # heaviest-weighted class in the whole rubric (weight 10, tied with
        # `enforcement_failure`) precisely because it is what Day 26's own
        # thesis is about: what your infrastructure enforced, not what your
        # agent happened to say. Authority derives from `ctx.act` — WHOM you
        # serve — never from `ctx.sub` — what you are (the same distinction
        # `kit/mcp/a2a.py`'s `verify_delegation` draws for the A2A case).
        authorize_denial = self._authorize(routed)
        if authorize_denial is not None:
            decision = self.deny(cmd, authorize_denial)
            return decision

        # ------------------------------------------------------------------
        # JOB 4 — BUDGET: can the DUEL (all 10 rounds, not just this call)
        # actually afford `routed` as written? `fields=("*",)` on
        # `registry.list_servers` or `glossary.list_terms` is a "punishment
        # button" (FINAL-PLAN.md section 4.1) that alone can exceed a whole
        # round's sustainable allowance (agent/strategy.py's own arithmetic:
        # disciplined ~8-11cr/round against a 100cr pool; careless ~49cr and
        # bankrupt by round 3). A catalog-trap call is REWRITTEN down to its
        # cheap default mask rather than denied outright — the caller still
        # gets an answer, just not the expensive one; when the remaining
        # pool is thin (`agent/strategy.py`'s `SAFE_STARTING_RESERVE` floor),
        # any oversized mask gets the same treatment.
        budgeted = self._budget(routed)

        call = self._to_tool_call(budgeted)
        decision = Decision(verdict="rewrite" if budgeted != cmd else "forward", call=call)
        if _looks_like_write(budgeted):
            idem_key = budgeted.headers.get("idempotency-key")
            if isinstance(idem_key, str) and idem_key:
                self._idempotency_keys.add(idem_key)
        self._telemetry.decision_made(cmd, decision)
        return decision

    # ----------------------------------------------------------------------
    # JOB 1 — ROUTE
    # ----------------------------------------------------------------------

    def _extract_path_ids(self, cmd: Command) -> frozenset[str]:
        """Every `path_id` (an anchor's `slug`) named anywhere in `cmd.args`'
        values — a command can reference an anchor via any arg name
        (`anchor=`, `concept=`, ...), so this scans every string value
        rather than assuming one fixed key. Pure string parsing
        (`kit.world.anchor.Anchor.parse`), no I/O."""
        if not _ANCHOR_AVAILABLE:
            return frozenset()
        found: set[str] = set()
        for value in cmd.args.values():
            if not isinstance(value, str):
                continue
            try:
                parsed = Anchor.parse(value)
            except AnchorSyntaxError:
                continue
            # path_id is only meaningful for the file-identity namespaces
            # (kit/world/anchor.py's own module docstring: Frame/Deck/Section
            # slugs ARE path_ids; Concept/Glossary/etc. slugs are not).
            if parsed.ns in ("Frame", "Deck", "Section"):
                found.add(parsed.slug)
        return frozenset(found)

    def _route(self, cmd: Command) -> Command:
        if cmd.kind != "mcp" or cmd.server != "slides":
            return cmd  # replica routing is an MCP-layer concept only
        path_ids = self._extract_path_ids(cmd)
        if not (path_ids & _KNOWN_DRIFTING_PATH_IDS):
            return cmd  # nothing named here is known to drift — no reason to override
        if cmd.headers.get("mcp-replica") == "w":
            return cmd
        new_headers = dict(cmd.headers)
        new_headers["mcp-replica"] = "w"
        routed = replace(cmd, headers=new_headers)
        self._telemetry.note(
            f"JOB1 ROUTE: {cmd.cmd_id} names a known-drifting path_id "
            f"({sorted(path_ids & _KNOWN_DRIFTING_PATH_IDS)}) with no explicit replica pin "
            f"— rewriting mcp-replica to 'w' (the referee's fresher-replica policy)"
        )
        return routed

    # ----------------------------------------------------------------------
    # JOB 2 — ADMIT
    # ----------------------------------------------------------------------

    def _admit(self, cmd: Command) -> str | None:
        """Returns a deny `reason` string if `cmd` is a doomed call worth
        refusing before it costs anything, else `None`."""
        if any(cmd.args.get(key) is not None for key in ("route", "_route", "replica")):
            return (
                f"JOB2 ADMIT: {cmd.server}.{cmd.tool} carries routing data in args; "
                "replica and route selection must come from authenticated headers"
            )
        if cmd.kind == "mcp" and cmd.server == "slides" and cmd.tool == "get_frame":
            if cmd.lease_id is None or cmd.lease_id not in self.ctx.leases:
                return (
                    f"JOB2 ADMIT: {cmd.server}.{cmd.tool} needs a live lease from a recent "
                    f"query; lease_id={cmd.lease_id!r} is not among this duel's live leases "
                    f"{sorted(self.ctx.leases)} — denying rather than paying for a call that "
                    f"will fail server-side"
                )
        if cmd.headers.get("__write_intent__") or _looks_like_write(cmd):
            missing = [h for h in ("if-match", "idempotency-key") if not cmd.headers.get(h)]
            if missing:
                return (
                    f"JOB2 ADMIT: write command {cmd.server}.{cmd.tool} is missing required "
                    f"precondition header(s) {missing} — denying rather than paying for a "
                    f"write that cannot possibly succeed"
                )
            idem_key = cmd.headers.get("idempotency-key")
            if isinstance(idem_key, str) and idem_key in self._idempotency_keys:
                return (
                    f"JOB2 ADMIT: write command {cmd.server}.{cmd.tool} reuses "
                    f"idempotency-key={idem_key!r} already authorised this duel"
                )
        return None

    def note_card(self, server: str, card: Mapping[str, Any]) -> None:
        """Record an Agent Card only after the caller has verified it."""
        self._admitted_cards[server] = dict(card)

    # ----------------------------------------------------------------------
    # JOB 3 — AUTHORIZE
    # ----------------------------------------------------------------------

    def _authorize(self, cmd: Command) -> str | None:
        """Returns a deny `reason` string if `cmd` reaches outside what
        `self.ctx.act`/`self.ctx.scopes` actually grants, else `None`."""
        if cmd.kind == "a2a" or cmd.server in A2A_PEERS:
            card = self._admitted_cards.get(cmd.server)
            if not card or not card.get("verified"):
                return f"JOB3 AUTHORIZE: {cmd.server} has no verified Agent Card"

            declared = {
                str(skill)
                for skill in card.get("skills", ())
                if isinstance(skill, str) and skill
            }
            allowed = _A2A_TOOL_SKILLS.get(
                (cmd.server, cmd.tool), frozenset({cmd.tool})
            )
            requested = cmd.args.get("skill")
            if requested is not None and requested not in declared:
                return f"JOB3 AUTHORIZE: requested undeclared A2A skill {requested!r}"
            if not declared.intersection(allowed):
                return f"JOB3 AUTHORIZE: Agent Card does not declare {cmd.tool!r}"

            audience = cmd.headers.get("aud")
            valid_audiences = {
                cmd.server,
                f"a2a:{cmd.server}",
                f"mcp:{cmd.server}",
            }
            if audience not in valid_audiences:
                return f"JOB3 AUTHORIZE: wrong A2A audience {audience!r}"

        ctx_act = _normalise_learner_identity(self.ctx.act)
        for key in _TARGET_KEYS:
            target = _normalise_learner_identity(cmd.args.get(key))
            if target and ctx_act and target != ctx_act:
                return (
                    f"JOB3 AUTHORIZE: {key}={target!r} is outside "
                    f"delegated learner {ctx_act!r}"
                )

        if _looks_like_write(cmd):
            target = cmd.args.get("learner") or cmd.args.get("for_learner")
            normalised_target = _normalise_learner_identity(target)
            if normalised_target and ctx_act and normalised_target != ctx_act:
                return (
                    f"JOB3 AUTHORIZE: write command {cmd.server}.{cmd.tool} targets "
                    f"{target!r}, which is not who this gateway serves "
                    f"(self.ctx.act={self.ctx.act!r}) — denying an authority_exceeded write"
                )
            required_scope_prefix = f"wiki.write:{cmd.server}"
            if required_scope_prefix not in self.ctx.scopes:
                return (
                    f"JOB3 AUTHORIZE: write command {cmd.server}.{cmd.tool} needs a "
                    f"{required_scope_prefix!r}-shaped scope, but self.ctx.scopes="
                    f"{sorted(self.ctx.scopes)} grants none — denying"
                )
        return None

    # ----------------------------------------------------------------------
    # JOB 4 — BUDGET
    # ----------------------------------------------------------------------

    def _budget(self, cmd: Command) -> Command:
        if cmd.kind not in ("mcp", "discover"):
            return cmd
        server, tool = cmd.server, cmd.tool

        # Deprecated-successor rewrite: costs nothing to fix, removes a
        # `wasteful` detector hit outright (agent/strategy.py's
        # `successor_of`, CONTRACTS.md 4.2 mechanic 8).
        successor = successor_of(server, tool)
        if successor is not None:
            new_server, new_tool = successor
            rewritten = replace(cmd, server=new_server, tool=new_tool)
            self._telemetry.note(
                f"JOB4 BUDGET: {server}.{tool} is deprecated; rewriting to "
                f"{new_server}.{new_tool}"
            )
            cmd, server, tool = rewritten, new_server, new_tool

        # Catalog-trap rewrite: `(server, tool)` is one of the two named
        # "punishment button" tools (`CATALOG_TRAP_TOOLS`) whose DEFAULT mask
        # is already their full, most expensive dump (agent/strategy.py's own
        # arithmetic: `registry.list_servers` default=12cr vs. a `("name",)`
        # mask at 2cr) — for these, "narrow to the default" would narrow to
        # nothing at all, so this rewrites to the single cheapest field in
        # the spec's own `field_weight` table instead.
        if _SPECS_AVAILABLE and is_catalog_trap(server, tool, cmd.fields):
            spec = TOOL_SPECS.get((server, tool))
            if spec is not None and spec.field_weight:
                cheapest_field = min(spec.field_weight, key=lambda f: (spec.field_weight[f], f))
                narrow = cheap_mask(server, tool, (cheapest_field,))
                rewritten = replace(cmd, fields=narrow)
                self._telemetry.note(
                    f"JOB4 BUDGET: {server}.{tool} fields={cmd.fields!r} is a catalog-trap "
                    f"call (default mask IS the full dump) — rewriting down to the cheapest "
                    f"single field {narrow!r}"
                )
                cmd = rewritten

        # Ordinary oversized-mask rewrite: for any OTHER tool, an explicit
        # mask wider than the tool's own (cheap) default, requested while
        # this duel is thin on budget, gets trimmed back to that default
        # rather than forwarded verbatim.
        elif _SPECS_AVAILABLE and self._is_thin_on_budget():
            spec = TOOL_SPECS.get((server, tool))
            if spec is not None and cmd.fields not in ((), spec.default_fields) and cmd.fields:
                narrow = cheap_mask(server, tool, spec.default_fields)
                rewritten = replace(cmd, fields=narrow)
                current_cost = self._estimated_cost(cmd)
                rewritten_cost = self._estimated_cost(rewritten)
                if (
                    current_cost is None
                    or rewritten_cost is None
                    or rewritten_cost >= current_cost
                ):
                    return cmd
                self._telemetry.note(
                    f"JOB4 BUDGET: {server}.{tool} fields={cmd.fields!r} is wider than the "
                    f"cheap default with credits_left={self.ctx.credits} — rewriting down to "
                    f"{narrow!r}"
                )
                cmd = rewritten

        return cmd

    def _estimated_cost(self, cmd: Command) -> int | None:
        if not _SPECS_AVAILABLE or (cmd.server, cmd.tool) not in TOOL_SPECS:
            return None
        try:
            return int(cost_of(self._to_tool_call(cmd)))
        except (KeyError, TypeError, ValueError):
            return None

    def _is_thin_on_budget(self) -> bool:
        """`True` iff spending further at the current rate risks breaking
        `agent/strategy.py`'s `SAFE_STARTING_RESERVE` floor before the duel
        ends — a simple, conservative signal (not a full `BudgetPacer`
        simulation, which would need this gateway to track a starting pool
        `ctx` itself already owns authoritatively) that credits are getting
        tight enough to start trimming masks rather than trusting them
        verbatim."""
        # ctx.credits is the arena's authoritative REMAINING pool; without a
        # known starting size here, comparing it against a conservative
        # absolute floor (half of the documented 100cr starting pool) is the
        # honest, simple signal available without re-deriving the pacer.
        return self.ctx.credits < (100 * SAFE_STARTING_RESERVE)

    def deny(self, cmd: Command, reason: str) -> Decision:
        """Not called anywhere in this starter's `decide()` — a ready-made
        helper for when you fill in JOB 2 / JOB 3 above, so denying doesn't
        mean hand-building a `Decision` inline at every call site. Kept as
        a real method (not a stub) because the shape of a correct denial —
        no `call`, a non-empty `reason` — is exactly the thing worth
        getting right by construction rather than by convention."""
        self._denied_cmd_ids.add(cmd.cmd_id)
        decision = Decision(verdict="deny", reason=reason)
        self._telemetry.decision_made(cmd, decision)
        return decision

    def _to_tool_call(self, cmd: Command) -> "ToolCall":
        """`Command` -> the `ToolCall` (CONTRACTS.md 3.1) the arena will
        actually execute on a `forward`/`rewrite` verdict. When
        `kit.mcp.types` is unavailable (see the module-level import guard),
        falls back to a plain dict carrying the identical fields — `Decision`
        accepts it either way (the `ToolCall` isinstance check inside
        `Decision.__post_init__` only runs when the real class loaded)."""
        fields = {
            "server": cmd.server,
            "tool": cmd.tool,
            "args": dict(cmd.args),
            "fields": cmd.fields,
            "headers": dict(cmd.headers),
            "lease_id": cmd.lease_id,
            "call_index": cmd.call_index,
        }
        if _TOOLCALL_AVAILABLE:
            return ToolCall(**fields)
        return fields  # type: ignore[return-value]


if __name__ == "__main__":
    print("=== agent.gateway: Command / Decision validation ===\n")

    good_cmd = Command(
        cmd_id="cmd:0000",
        kind="mcp",
        raw="MCP slides.get_frame anchor=Frame:3f2a9c11/w/041 fields=title,body lease=lse_7f21",
        server="slides",
        tool="get_frame",
        args={"anchor": "Frame:3f2a9c11/w/041"},
        fields=("body", "title"),
        headers={},
        lease_id="lse_7f21",
        call_index=0,
    )
    print(f"  Command constructed: {good_cmd}")
    assert good_cmd.kind == "mcp"

    print("\n  Rejection demo (each must raise ValueError):")

    def _expect_value_error(label: str, fn) -> None:
        try:
            fn()
        except ValueError as exc:
            print(f"    [{label:38}] -> ValueError: {exc}")
        else:
            raise AssertionError(f"expected ValueError for case {label!r}")

    _expect_value_error("Command.kind == 'answer'", lambda: Command(
        cmd_id="cmd:0001", kind="answer", raw="x", server="slides", tool="get_frame",
        args={}, fields=(), headers={}, lease_id=None, call_index=0,
    ))
    _expect_value_error("Decision verdict='deny' with no reason", lambda: Decision(verdict="deny"))
    _expect_value_error(
        "Decision verdict='forward' with no call", lambda: Decision(verdict="forward")
    )
    _expect_value_error(
        "Decision verdict='deny' carrying a call",
        lambda: Decision(verdict="deny", reason="nope", call={"server": "x", "tool": "y"}),
    )
    _expect_value_error("Decision verdict='?' unknown", lambda: Decision(verdict="???"))

    print("\n=== Command.from_action_dict — real canonicaliser integration ===\n")
    if _canonicalise_action is None:
        print("  kit.loop.agent not importable yet — skipping the live canonicaliser demo")
        demo_commands: list[Command] = [good_cmd]
    else:
        raw_actions = [
            "MCP registry.provenance anchor=Frame:3f2a9c11/w/041 fields=etag",
            'MCP slides.query q="streamable http replaces http+sse" fields=title,body',
            "A2A curriculum-analyst.which_days_cover concept=Concept:streamable-http fields=anchor,course_day,track",
            "DISCOVER registry.list_servers fields=name",
        ]
        demo_commands = []
        for i, raw in enumerate(raw_actions):
            action = _canonicalise_action(raw, call_index=i)
            cmd = Command.from_action_dict(action, cmd_id=f"cmd:{i:04d}")
            print(f"  {raw!r}\n    -> {cmd.kind}: {cmd.server}.{cmd.tool} fields={cmd.fields}")
            demo_commands.append(cmd)
        assert {c.kind for c in demo_commands} == {"mcp", "a2a", "discover"}

        answer_action = _canonicalise_action(
            'ANSWER {"text": "day 26, track P2T2"}', call_index=None
        )
        try:
            Command.from_action_dict(answer_action, cmd_id="cmd:9999")
        except ValueError as exc:
            print(f"\n  an 'answer' action correctly refuses to become a Command: {exc}")
        else:
            raise AssertionError("expected ValueError for an 'answer' action")

    print("\n=== Gateway.decide — the naive starter forwards everything ===\n")
    ctx = RecordingGatewayContext(
        act="learner:sv-0401",
        sub="agent:demo-team",
        scopes=frozenset({"wiki.read"}),
        credits=100,
        round=1,
        call_index=0,
        leases=(),
        history=(),
    )
    assert isinstance(ctx, GatewayContext), "RecordingGatewayContext must structurally satisfy GatewayContext"
    gw = Gateway(ctx)
    for cmd in demo_commands:
        decision = gw.decide(cmd)
        print(f"  decide({cmd.server}.{cmd.tool}) -> verdict={decision.verdict!r} quarantine={decision.quarantine}")
        assert decision.verdict == "forward"
        assert decision.call is not None
        call_dict = decision.call.to_dict() if hasattr(decision.call, "to_dict") else decision.call
        assert call_dict["server"] == cmd.server
        assert call_dict["tool"] == cmd.tool
        assert tuple(call_dict["fields"]) == cmd.fields

    print(f"\n=== Gateway.deny — the unused-by-default free-abstention path ===\n")
    denial = gw.deny(demo_commands[0], reason="demo: withholding pending a fresher registry.provenance read")
    print(f"  gw.deny(...) -> verdict={denial.verdict!r} reason={denial.reason!r} call={denial.call!r}")
    assert denial.verdict == "deny"
    assert denial.call is None
    assert demo_commands[0].cmd_id in gw._denied_cmd_ids

    print(f"\n=== own_telemetry — recorded on YOUR side only, never shown to the opponent ===\n")
    print(f"  {len(ctx.events)} events recorded on this ctx this run:")
    for ev in ctx.events:
        print(f"    {ev['name']}: {sorted(ev['payload'].keys())}")
    assert len(ctx.events) >= len(demo_commands) * 2 + 1  # decision_seen + decision_made per call, plus the deny

    print("\nAll agent/gateway.py demos passed.")
