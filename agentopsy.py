#!/usr/bin/env python3
"""
agentopsy.py

Local, dependency-free forensic analyser for Claude Code and OpenAI Codex CLI
session transcripts.

Goals:
  * locate live Claude/Codex session stores automatically
  * accept exported directories and ZIP archives
  * parse both transcript formats without loading whole files into memory
  * report token/context behaviour, tool-output pressure, activity bursts,
    compactions, repeated reads/commands, long-gap reuse, subagent usage,
    and other workflow defects
  * produce human-readable terminal/Markdown reports plus machine-readable JSON
  * optionally poll as a passive local watcher

This tool deliberately does NOT send transcript contents to any model or
external service. Session logs can contain source code, prompts, paths, command
output, and other sensitive information.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import enum
import hashlib
import json
import math
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import statistics
import sys
import tempfile
import textwrap
import time
import zipfile
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

VERSION = "0.6.1"
PARSER_VERSION = 1
SCHEMA_VERSION = 6
IDENTITY_TTL_SECONDS = 15 * 60

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


class Severity(str, enum.Enum):
    """How urgently a Guardian signal should be understood."""
    SAFE = "SAFE"
    LIGHT = "LIGHT"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    SUPER_CRITICAL = "SUPER_CRITICAL"
    EMERGENCY = "EMERGENCY"


CONTEXT_SEVERITY_RANK = {severity: index for index, severity in enumerate((Severity.SAFE, Severity.LIGHT, Severity.HIGH, Severity.CRITICAL, Severity.SUPER_CRITICAL, Severity.EMERGENCY))}


class EventLifecycle(str, enum.Enum):
    """Whether an event is a presently-active condition or durable history."""
    ACTIVE_CONDITION = "ACTIVE_CONDITION"
    OCCURRENCE = "OCCURRENCE"


OCCURRENCE_EVENT_CODES = frozenset({"GIANT_TOOL_RESULT", "COMMAND_REPETITION"})


def event_lifecycle(code: str) -> EventLifecycle:
    return EventLifecycle.OCCURRENCE if code in OCCURRENCE_EVENT_CODES else EventLifecycle.ACTIVE_CONDITION


class ImpactLane(str, enum.Enum):
    """Independent workflow dimension affected by a Guardian signal."""
    CONTEXT_PRESSURE = "CONTEXT_PRESSURE"
    CONTEXT_VELOCITY = "CONTEXT_VELOCITY"
    TOKEN_AMPLIFICATION = "TOKEN_AMPLIFICATION"
    CACHE_REUSE = "CACHE_REUSE"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    REPETITION = "REPETITION"
    INSTRUCTION_OVERHEAD = "INSTRUCTION_OVERHEAD"
    DELEGATION_ADVISOR = "DELEGATION_ADVISOR"
    COMPACTION_HEALTH = "COMPACTION_HEALTH"
    SESSION_LIFECYCLE = "SESSION_LIFECYCLE"
    INTEGRITY = "INTEGRITY"


class ActionSafety(str, enum.Enum):
    """Whether a signal is merely advisory or safe for an opt-in control action."""
    ADVISE_ONLY = "ADVISE_ONLY"
    ACTION_CANDIDATE = "ACTION_CANDIDATE"
    WAITING_SAFE = "WAITING_SAFE"
    SAFE_TO_ACT = "SAFE_TO_ACT"
    ACTION_BLOCKED = "ACTION_BLOCKED"


class AutoActMode(str, enum.Enum):
    OBSERVE = "observe"
    COMPACT = "compact"
    FULL = "full"


@dataclasses.dataclass(frozen=True)
class ControlDecision:
    mode: AutoActMode
    allowed: bool
    reason: str
    action: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class ControlAdapter:
    provider: str
    harness: str
    capabilities: dict[str, ProviderCapability]

    def capability(self, action: str) -> ProviderCapability:
        return self.capabilities.get(action, ProviderCapability.UNAVAILABLE)


def control_adapters() -> tuple[ControlAdapter, ...]:
    """No blind PTY typing: capabilities are unavailable until positively established."""
    actions = ("compact", "new_session", "clear", "identify_active_session", "safe_idle", "verify_acceptance")
    unavailable = {action: ProviderCapability.UNAVAILABLE for action in actions}
    return (ControlAdapter("claude", "native", unavailable), ControlAdapter("codex", "native", unavailable), ControlAdapter("herdr", "integration", unavailable))


def classify_compaction(before_context: int, after_context: int, refill_context: Optional[int], repeated_after: int, compaction_count: int, *, compaction_window_seconds: Optional[float] = None) -> dict[str, Any]:
    """Classify observed/provider-verified compactions; never invoke one here."""
    reduction = max(0, before_context - after_context)
    ratio = reduction / before_context if before_context else 0.0
    rapid_refill = refill_context is not None and refill_context >= before_context * .9
    frequent = compaction_count >= 5 and compaction_window_seconds is not None and compaction_window_seconds <= 3600
    ineffective_or_repeated = ratio < .2 or repeated_after >= 2
    if before_context <= 0:
        # A missing/absent before-sample is not evidence of an ineffective
        # compaction; never turn missing provider telemetry into a negative signal.
        outcome = "UNKNOWN"
    elif frequent and (rapid_refill or ineffective_or_repeated): outcome = "THRASH"
    elif rapid_refill: outcome = "RAPID_REFILL"
    elif ratio >= .5 and repeated_after < 2: outcome = "EFFECTIVE"
    elif ratio >= .2: outcome = "WEAK"
    else: outcome = "INEFFECTIVE"
    return {"outcome": outcome, "context_before": before_context, "context_after": after_context, "reduction": reduction, "reduction_pct": ratio, "repeated_after": repeated_after, "compaction_frequency": compaction_count, "compaction_window_seconds": compaction_window_seconds}


def rotation_plan(project: str, *, safe_to_act: bool, adapter_capability: ProviderCapability) -> dict[str, Any]:
    handoff = validate_handoff(project)
    if not handoff.get("valid") or not safe_to_act or adapter_capability == ProviderCapability.UNAVAILABLE:
        return {"action_safety": ActionSafety.ACTION_BLOCKED.value, "reason": "Durable valid handoff, safe boundary, and verified native new-session capability are required.", "handoff": handoff, "action": None}
    return {"action_safety": ActionSafety.SAFE_TO_ACT.value, "reason": "Preconditions passed; preserve handoff until native session identity transition is verified.", "handoff": handoff, "action": "native_new_session"}


def fail_safe_control(reason: str, *, provider: str, session_id: str, malformed_records: int = 0) -> GuardianEvent:
    """Fail closed on integrity uncertainty; evidence is compact and transcript-free."""
    severity = Severity.SUPER_CRITICAL if malformed_records > 10 else Severity.HIGH
    return GuardianEvent("CONTROL_FAIL_SAFE", severity, (ImpactLane.INTEGRITY,), ActionSafety.ACTION_BLOCKED, {"malformed_records": malformed_records, "control_disabled": True})


def evaluate_control_request(mode: AutoActMode, *, exact_provider: bool, exact_session: bool, exact_harness: bool, capability: ProviderCapability, safe_idle_boundary: bool, active_critical_operation: bool, integrity_ok: bool) -> ControlDecision:
    """Control is opt-in and capability gated; this function never performs it."""
    if mode == AutoActMode.OBSERVE: return ControlDecision(mode, False, "Observe mode only advises; it never alters a provider session.")
    if not all((exact_provider, exact_session, exact_harness, safe_idle_boundary, integrity_ok)) or capability == ProviderCapability.UNAVAILABLE or active_critical_operation:
        return ControlDecision(mode, False, "Control blocked: exact mapping, supported capability, safe idle boundary, no critical operation, and healthy integrity are all required.")
    return ControlDecision(mode, True, "All safety preconditions passed; adapter execution remains separately verified.", "compact" if mode == AutoActMode.COMPACT else "full")


def control_decision_for_live_session(row: sqlite3.Row, mode: AutoActMode, store: Any = None) -> ControlDecision:
    """Route a live risk candidate through the fail-closed control decision layer.

    Transcript-derived session IDs are not native interactive-session identities.
    Until an adapter proves that mapping and a safe input boundary, this function
    deliberately evaluates a blocked request rather than attempting an action.
    """
    if row["health_state"] not in {"CHECKPOINT_RECOMMENDED", "ROTATION_RECOMMENDED"}:
        return ControlDecision(mode, False, "No control requested: live risk has not reached a checkpoint or rotation recommendation.")
    if int(row["malformed_records"] or 0):
        return ControlDecision(mode, False, "Control blocked by transcript-integrity uncertainty.")
    mapping = exact_identity_for_live_session(store, row) if store is not None else None
    exact = mapping is not None
    idle = bool(mapping and herdr_pane_is_idle(mapping))
    return evaluate_control_request(
        mode,
        exact_provider=row["provider"] in {"claude", "codex"},
        exact_session=exact,
        exact_harness=exact,
        capability=ProviderCapability.EXACT if exact else ProviderCapability.UNAVAILABLE,
        safe_idle_boundary=idle,
        active_critical_operation=False,
        integrity_ok=True,
    )


class ProviderCapability(str, enum.Enum):
    EXACT = "EXACT"
    OBSERVED = "OBSERVED"
    PROXY = "PROXY"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"


class ExtensionLoadMode(str, enum.Enum):
    ALWAYS_LOADED = "ALWAYS_LOADED"
    LAZY_LOADED = "LAZY_LOADED"
    EVENT_LOADED = "EVENT_LOADED"
    UNKNOWN = "UNKNOWN"


@dataclasses.dataclass(frozen=True)
class GuardianEvent:
    """A compact, transcript-free event spanning one or more impact lanes."""
    code: str
    severity: Severity
    lanes: tuple[ImpactLane, ...]
    action_safety: ActionSafety
    evidence: dict[str, int | float | bool | None] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.code:
            raise ValueError("Guardian event code is required")
        if not self.lanes:
            raise ValueError("Guardian event must affect at least one impact lane")
        if len(set(self.lanes)) != len(self.lanes):
            raise ValueError("Guardian event impact lanes must be unique")
        if any(not isinstance(value, (int, float, bool, type(None))) for value in self.evidence.values()):
            raise ValueError("Guardian evidence must contain only compact numeric or boolean facts")


@dataclasses.dataclass(frozen=True)
class SignalDefinition:
    code: str
    title: str
    lanes: tuple[ImpactLane, ...]
    measurement: str
    why_it_matters: str
    expected_impact: str
    corrective_action: str
    alternative_action: str
    claude: ProviderCapability
    codex: ProviderCapability
    extension_load_mode: Optional[ExtensionLoadMode] = None


SIGNAL_REGISTRY_VERSION = 1
MARKER_SCORING_VERSION = 1
MARKER_SCORING_STATUS = "provisional"
BEHAVIORAL_SEVERITY_POLICY_VERSION = 1


def _signal(code: str, title: str, lanes: tuple[ImpactLane, ...], measurement: str, claude: ProviderCapability, codex: ProviderCapability, *, impact: str = "Use the measured trend to prioritise a bounded corrective step.", corrective: str = "Reduce the contributing work and re-measure before escalating.", alternative: str = "Record the observation and continue with a smaller, focused next step.", extension: Optional[ExtensionLoadMode] = None) -> SignalDefinition:
    return SignalDefinition(code, title, lanes, measurement, f"{title} helps distinguish a measurable workflow condition from an assumption.", impact, corrective, alternative, claude, codex, extension)


SIGNAL_REGISTRY: tuple[SignalDefinition, ...] = (
    _signal("PRE_SUBMIT_PREFLIGHT", "Pre-submit stale-session interception", (ImpactLane.SESSION_LIFECYCLE,), "Provider/harness hook before new user work enters a session.", ProviderCapability.UNAVAILABLE, ProviderCapability.UNAVAILABLE, impact="Current providers expose no safe pre-submit interception hook; advisory checks remain available.", corrective="Run the local preflight before continuing a stale, high-context session."),
    _signal("SESSION_CONTEXT_OCCUPANCY", "Session/context occupancy", (ImpactLane.CONTEXT_PRESSURE,), "Current context divided by a provider-reported window; Claude is a documented absolute-token proxy.", ProviderCapability.PROXY, ProviderCapability.EXACT),
    _signal("CONTEXT_TOKENS_WINDOW", "Context tokens and window", (ImpactLane.CONTEXT_PRESSURE,), "Logged context tokens and, where exposed, the context-window denominator.", ProviderCapability.PARTIAL, ProviderCapability.EXACT),
    _signal("MODEL_TURNS", "Model turns", (ImpactLane.TOKEN_AMPLIFICATION,), "Deduplicated assistant usage or token-snapshot iterations.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("WALL_CLOCK_DURATION", "Wall-clock duration", (ImpactLane.SESSION_LIFECYCLE,), "Elapsed time between first and last timestamp.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("ACTIVE_DURATION_BURSTS", "Active duration and bursts", (ImpactLane.SESSION_LIFECYCLE,), "Timestamp clusters separated by configured idle gaps.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("IDLE_GAPS_STALE_RESUME", "Idle gaps and stale resume", (ImpactLane.SESSION_LIFECYCLE,), "Observed timestamp gaps before later activity.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("INPUT_TOKENS", "Input tokens", (ImpactLane.TOKEN_AMPLIFICATION,), "Provider usage input-token counters, with Codex cumulative snapshots.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("OUTPUT_TOKENS", "Output tokens", (ImpactLane.TOKEN_AMPLIFICATION,), "Provider usage output-token counters.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("CACHE_READS", "Cached input/cache reads", (ImpactLane.CACHE_REUSE,), "Provider cache-read input telemetry.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("TOOL_CALLS_RESULTS", "Tool calls and results", (ImpactLane.TOOL_OUTPUT,), "Deduplicated tool calls and aggregate result character counts.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("TOOL_RESULT_SIZE", "Individual tool result size", (ImpactLane.TOOL_OUTPUT,), "Maximum observed result character count, labelled as a token proxy when needed.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("ROLLING_TOOL_OUTPUT", "Rolling tool output", (ImpactLane.TOOL_OUTPUT,), "Aggregate tool-result volume available to the incremental collector; rolling windows begin in Stage 3.", ProviderCapability.PARTIAL, ProviderCapability.PARTIAL),
    _signal("REPEATED_READS", "Repeated reads", (ImpactLane.REPETITION,), "Hashed repeated read targets.", ProviderCapability.EXACT, ProviderCapability.PARTIAL),
    _signal("REPEATED_PATH_RANGE_READS", "Repeated path and range reads", (ImpactLane.REPETITION,), "Read target plus range only when the provider record exposes both.", ProviderCapability.PARTIAL, ProviderCapability.PARTIAL),
    _signal("REPEATED_COMMANDS", "Repeated commands", (ImpactLane.REPETITION,), "Normalised, hashed command repetitions.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("MALFORMED_PROVIDER_RECORDS", "Malformed/provider records", (ImpactLane.INTEGRITY,), "JSON parsing failures and unsupported provider record shapes.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("PARSER_DB_SERVICE_INTEGRITY", "Parser, database, and service integrity", (ImpactLane.INTEGRITY,), "Collector error counters and transactional database outcomes; no transcript content retained.", ProviderCapability.EXACT, ProviderCapability.EXACT),
    _signal("CLAUDE_CACHE_CREATE", "Claude cache creation", (ImpactLane.CACHE_REUSE,), "Claude cache-creation input tokens.", ProviderCapability.EXACT, ProviderCapability.UNAVAILABLE),
    _signal("CLAUDE_LOGGED_REQUEST_CONTEXT", "Claude logged request context", (ImpactLane.CONTEXT_PRESSURE,), "Claude input, cache-read, and cache-create tokens per logged request.", ProviderCapability.EXACT, ProviderCapability.UNAVAILABLE),
    _signal("CLAUDE_HIGH_CONTEXT_DWELL", "Claude high-context dwell", (ImpactLane.CONTEXT_PRESSURE,), "Time above a documented Claude context proxy threshold; implementation begins in Stage 3.", ProviderCapability.PARTIAL, ProviderCapability.UNAVAILABLE),
    _signal("CLAUDE_ADVISOR_CALLS", "Claude advisor calls", (ImpactLane.DELEGATION_ADVISOR,), "Advisor/tool calls only when an observable record identifies them.", ProviderCapability.OBSERVED, ProviderCapability.UNAVAILABLE),
    _signal("CLAUDE_ADVISOR_AMPLIFICATION", "Claude advisor amplification", (ImpactLane.DELEGATION_ADVISOR, ImpactLane.TOKEN_AMPLIFICATION), "Advisor input/context contribution when identifiable in records.", ProviderCapability.PARTIAL, ProviderCapability.UNAVAILABLE),
    _signal("CLAUDE_SUBAGENTS", "Claude subagents", (ImpactLane.DELEGATION_ADVISOR,), "Discovered Claude subagent transcripts and parent association where inferable.", ProviderCapability.OBSERVED, ProviderCapability.UNAVAILABLE),
    _signal("CLAUDE_SUBAGENT_WORK_RETURN", "Claude subagent work and return size", (ImpactLane.DELEGATION_ADVISOR, ImpactLane.TOOL_OUTPUT), "Subagent work/return volume only when structured records expose it.", ProviderCapability.PARTIAL, ProviderCapability.UNAVAILABLE),
    _signal("CLAUDE_UNSCOPED_LARGE_READS", "Claude unscoped large reads", (ImpactLane.TOOL_OUTPUT, ImpactLane.REPETITION), "Large Read tool results without an observable range.", ProviderCapability.PARTIAL, ProviderCapability.UNAVAILABLE),
    _signal("CLAUDE_LIFECYCLE_EVENTS", "Claude lifecycle events", (ImpactLane.SESSION_LIFECYCLE,), "Observed clear/new/compact records where exposed by the installed Claude version.", ProviderCapability.OBSERVED, ProviderCapability.UNAVAILABLE),
    _signal("CLAUDE_EXTENSION_MATERIAL", "Claude instruction, skill, and hook material", (ImpactLane.INSTRUCTION_OVERHEAD,), "Only observable extension/startup metadata; load classification is conservative.", ProviderCapability.OBSERVED, ProviderCapability.UNAVAILABLE, extension=ExtensionLoadMode.UNKNOWN),
    _signal("CODEX_TOTAL_LAST_TOKEN_SNAPSHOTS", "Codex total and last token snapshots", (ImpactLane.CONTEXT_PRESSURE, ImpactLane.TOKEN_AMPLIFICATION), "Codex token_count total-session and last-turn usage snapshots.", ProviderCapability.UNAVAILABLE, ProviderCapability.EXACT),
    _signal("CODEX_REASONING_TOKENS", "Codex reasoning tokens", (ImpactLane.TOKEN_AMPLIFICATION,), "Reasoning-output token counter where Codex emits it.", ProviderCapability.UNAVAILABLE, ProviderCapability.EXACT),
    _signal("CODEX_COMPACTIONS", "Codex compactions", (ImpactLane.COMPACTION_HEALTH,), "Observed compacted lifecycle records.", ProviderCapability.UNAVAILABLE, ProviderCapability.EXACT),
    _signal("CODEX_CONTEXT_COMPACTION_DELTA", "Codex context before and after compaction", (ImpactLane.COMPACTION_HEALTH,), "Adjacent context snapshots around observed compaction; implementation begins in Stage 3.", ProviderCapability.UNAVAILABLE, ProviderCapability.PARTIAL),
    _signal("CODEX_POST_COMPACT_REFILL", "Codex post-compact refill", (ImpactLane.COMPACTION_HEALTH, ImpactLane.CONTEXT_VELOCITY), "Context growth after a known compaction; implementation begins in Stage 3.", ProviderCapability.UNAVAILABLE, ProviderCapability.PARTIAL),
    _signal("CODEX_POST_COMPACT_REFETCH", "Codex post-compact refetch", (ImpactLane.COMPACTION_HEALTH, ImpactLane.REPETITION), "Repeated reads following known compaction when structured tool arguments expose them.", ProviderCapability.UNAVAILABLE, ProviderCapability.PARTIAL),
    _signal("CODEX_STARTUP_INSTRUCTION_PAYLOAD", "Codex startup and instruction payload", (ImpactLane.INSTRUCTION_OVERHEAD,), "Observable startup/instruction metadata only; never invent unlogged payloads.", ProviderCapability.UNAVAILABLE, ProviderCapability.OBSERVED, extension=ExtensionLoadMode.UNKNOWN),
    _signal("CODEX_EXTENSION_MATERIAL", "Codex skills, hooks, plugins, and MCP material", (ImpactLane.INSTRUCTION_OVERHEAD,), "Observable extension metadata only; classify load timing when records state it.", ProviderCapability.UNAVAILABLE, ProviderCapability.OBSERVED, extension=ExtensionLoadMode.UNKNOWN),
    _signal("CODEX_RATE_LIMIT_TELEMETRY", "Codex rate-limit telemetry", (ImpactLane.INTEGRITY,), "Provider-emitted rate-limit values, retained only as informational data.", ProviderCapability.UNAVAILABLE, ProviderCapability.OBSERVED, impact="Informational only; it must not be scored as context health or action safety."),
    _signal("CODEX_NATIVE_LIFECYCLE_EVENTS", "Codex native lifecycle events", (ImpactLane.SESSION_LIFECYCLE,), "Observed native lifecycle records.", ProviderCapability.UNAVAILABLE, ProviderCapability.OBSERVED),
)
SIGNALS_BY_CODE = {signal.code: signal for signal in SIGNAL_REGISTRY}


def signal_capability(code: str, provider: str) -> ProviderCapability:
    signal = SIGNALS_BY_CODE[code]
    if provider not in {"claude", "codex"}:
        raise ValueError("provider must be claude or codex")
    return getattr(signal, provider)


def signal_value_or_unavailable(code: str, provider: str, value: Any) -> Any:
    """Never turn missing provider telemetry into a zero or a negative signal."""
    return None if signal_capability(code, provider) is ProviderCapability.UNAVAILABLE else value


def render_signals() -> str:
    lines = [f"Agentopsy signal registry v{SIGNAL_REGISTRY_VERSION}", "code | Claude | Codex | lanes"]
    lines.extend(f"{s.code} | {s.claude.value} | {s.codex.value} | {','.join(l.value for l in s.lanes)}" for s in SIGNAL_REGISTRY)
    return "\n".join(lines)


def explain_signal(code: str) -> str:
    signal = SIGNALS_BY_CODE.get(code.upper())
    if signal is None:
        raise ValueError(f"Unknown signal code: {code}")
    limits = "; ".join(f"{provider}: {getattr(signal, provider).value}" for provider in ("claude", "codex"))
    if signal.extension_load_mode:
        limits += f"; extension load evidence: {signal.extension_load_mode.value}"
    return "\n".join((f"{signal.code} — {signal.title}", f"What it means: {signal.title}.", f"How it is measured: {signal.measurement}", f"Why it matters: {signal.why_it_matters}", f"Expected impact: {signal.expected_impact}", f"Corrective action: {signal.corrective_action}", f"Alternative action: {signal.alternative_action}", f"Provider limitations: {limits}. UNAVAILABLE means absent telemetry, never a zero or bad metric."))

# Conservative defaults. They are intentionally configurable from the CLI.
DEFAULT_GAP_MINUTES = 30.0
LONG_GAP_HOURS = 12.0
VERY_LONG_GAP_HOURS = 72.0
CLAUDE_COSTLY_CONTEXT_TOKENS = 150_000
CLAUDE_VERY_HIGH_CONTEXT_TOKENS = 250_000
CLAUDE_EXTREME_CONTEXT_TOKENS = 400_000
CODEX_PREPARE_CONTEXT_PCT = 0.65
CODEX_HIGH_CONTEXT_PCT = 0.80
CODEX_CRITICAL_CONTEXT_PCT = 0.90
LARGE_RESULT_TOKENS = 4_000
GIANT_RESULT_TOKENS = 10_000
HIGH_TOOL_OUTPUT_TOKENS = 100_000
EXTREME_TOOL_OUTPUT_TOKENS = 250_000

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "magenta": "\033[35m",
    "orange": "\033[93m",
    "strong_red": "\033[1;31m",
    "reverse_red": "\033[1;7;31m",
}


def c(text: str, colour: str, enabled: bool) -> str:
    return f"{ANSI[colour]}{text}{ANSI['reset']}" if enabled else text


def colour_enabled(mode: str, stream: Any = sys.stdout, environ: Optional[dict[str, str]] = None) -> bool:
    """Respect accessible explicit colour controls and the NO_COLOR convention."""
    env = os.environ if environ is None else environ
    if mode == "never":
        return False
    if mode == "always":
        return True
    return bool(getattr(stream, "isatty", lambda: False)()) and not bool(env.get("NO_COLOR"))


def context_severity(context_pct: Optional[float]) -> Severity:
    """Factory v0.4 context bands; percentage is a 0..1 fraction."""
    pct = max(0.0, min(1.0, float(context_pct or 0.0)))
    if pct > 0.90: return Severity.EMERGENCY
    if pct > 0.85: return Severity.SUPER_CRITICAL
    if pct > 0.75: return Severity.CRITICAL
    if pct > 0.65: return Severity.HIGH
    if pct > 0.55: return Severity.LIGHT
    return Severity.SAFE


def provider_context_evaluation(row: Any, *, current: bool = False) -> dict[str, Any]:
    """One provider-aware context interpretation; Claude has no invented window %."""
    keys = row.keys() if hasattr(row, "keys") else row.keys()
    provider = str(row["provider"]) if "provider" in keys else "codex"
    if provider == "claude":
        key = "current_context_tokens" if current else "peak_context_tokens"
        tokens = safe_int(row[key] or 0) if key in keys else 0
        if not tokens:
            return {"severity": Severity.SAFE, "tokens": 0, "pct": None, "semantics": "N/A"}
        if tokens >= CLAUDE_EXTREME_CONTEXT_TOKENS: severity = Severity.EMERGENCY
        elif tokens >= CLAUDE_VERY_HIGH_CONTEXT_TOKENS: severity = Severity.CRITICAL
        elif tokens >= CLAUDE_COSTLY_CONTEXT_TOKENS: severity = Severity.HIGH
        else: severity = Severity.SAFE
        return {"severity": severity, "tokens": tokens, "pct": None, "semantics": "absolute-token proxy"}
    key = "current_context_pct" if current else "peak_context_pct"
    pct = row[key] if key in keys else None
    if pct is None and current and "peak_context_pct" in keys:
        pct, key = row["peak_context_pct"], "peak_context_pct"
    if pct is None:
        token_key = "current_context_tokens" if current else "peak_context_tokens"
        return {"severity": Severity.SAFE, "tokens": safe_int(row[token_key] or 0) if token_key in keys else 0, "pct": None, "semantics": "N/A"}
    token_key = "current_context_tokens" if current else "peak_context_tokens"
    if token_key not in keys and current and "peak_context_tokens" in keys: token_key = "peak_context_tokens"
    return {"severity": context_severity(float(pct)), "tokens": safe_int(row[token_key] or 0) if token_key in keys else 0, "pct": float(pct), "semantics": "measured"}


def context_status_text(severity: Severity) -> str:
    return "SESSION HEALTHY" if severity == Severity.SAFE else f"CONTEXT {severity.value}"


def behavioural_severity(metrics: dict[str, Optional[float]]) -> dict[str, Severity]:
    """Versioned provisional ladders; related pressure signals compound together."""
    ladders = {
        "context_velocity": (0.01, 0.03, 0.06, 0.10), "high_context_dwell": (60, 300, 900, 1800),
        "individual_tool_output": (4_000, 10_000, 25_000, 50_000), "rolling_tool_output": (25_000, 100_000, 250_000, 500_000),
        "repeated_reads": (2, 4, 8, 12), "repeated_path_range_reads": (2, 4, 8, 12),
        "command_repetition": (3, 5, 10, 20), "cache_reuse_degradation": (0.10, 0.25, 0.50, 0.75),
        "instruction_overhead": (25_000, 50_000, 100_000, 200_000), "advisor_subagent_amplification": (2, 3, 5, 8),
        "stale_resume": (1, 24, 72, 168), "compaction_health": (1, 3, 5, 8),
    }
    levels = (Severity.LIGHT, Severity.HIGH, Severity.CRITICAL, Severity.SUPER_CRITICAL)
    result = {name: next((level for threshold, level in reversed(tuple(zip(thresholds, levels))) if float(metrics.get(name) or 0) >= threshold), Severity.SAFE) for name, thresholds in ladders.items()}
    # A pair of related severe observations predicts more than either alone.
    pressure = (result["context_velocity"], result["high_context_dwell"], result["rolling_tool_output"])
    if sum(level in {Severity.CRITICAL, Severity.SUPER_CRITICAL, Severity.EMERGENCY} for level in pressure) >= 2:
        result["compound_context_pressure"] = Severity.EMERGENCY
    else:
        result["compound_context_pressure"] = max(pressure, key=lambda level: _SEVERITY_RANK[level])
    return result


def iso_to_dt(value: Any) -> Optional[dt.datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


PROVIDER_TIMESTAMP_MAX_FUTURE_SKEW_SECONDS = 60


class TemporalSemanticError(ValueError):
    """A supplied provider timestamp cannot safely participate in chronology."""


def normalise_provider_timestamp(value: Any, *, now: Optional[dt.datetime] = None) -> str:
    """Validate one supplied provider timestamp and return canonical UTC text.

    Provider transcripts may legitimately omit a timestamp, but a supplied one
    must be an aware ISO-8601 string.  The one-minute skew matches the
    project's existing trusted runtime-receipt bound while avoiding acceptance
    of a future value that would poison durable ordering and telemetry.
    """
    if type(value) is not str or not value:
        raise TemporalSemanticError("timestamp must be a non-empty ISO-8601 string")
    stamp = iso_to_dt(value)
    if stamp is None:
        raise TemporalSemanticError("timestamp is malformed")
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise TemporalSemanticError("timestamp must include a timezone offset")
    stamp = stamp.astimezone(dt.timezone.utc)
    reference = now or dt.datetime.now(dt.timezone.utc)
    if stamp > reference + dt.timedelta(seconds=PROVIDER_TIMESTAMP_MAX_FUTURE_SKEW_SECONDS):
        raise TemporalSemanticError("timestamp exceeds the permitted future clock skew")
    return stamp.isoformat().replace("+00:00", "Z")


def optional_provider_timestamp(value: Any, *, now: Optional[dt.datetime] = None) -> str:
    """Keep an omitted provider timestamp distinct from a malformed supplied one."""
    if value is None:
        return ""
    return normalise_provider_timestamp(value, now=now)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


SQLITE_INT64_MIN = -(2 ** 63)
SQLITE_INT64_MAX = 2 ** 63 - 1


class NumericSemanticError(ValueError):
    """A provider record contains a numeric value outside its public domain."""


def require_int(value: Any, field: str, *, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    """Accept only a real JSON integer that is safe for SQLite persistence."""
    if type(value) is not int:
        raise NumericSemanticError(f"{field} must be an integer")
    if not SQLITE_INT64_MIN <= value <= SQLITE_INT64_MAX:
        raise NumericSemanticError(f"{field} exceeds SQLite INTEGER bounds")
    if minimum is not None and value < minimum:
        raise NumericSemanticError(f"{field} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise NumericSemanticError(f"{field} must be at most {maximum}")
    return value


def optional_nonnegative_int(values: dict[str, Any], key: str, field: str) -> int:
    """Missing provider counters preserve their established zero default."""
    return 0 if key not in values else require_int(values[key], field, minimum=0)


def codex_token_count_values(record: dict[str, Any]) -> dict[str, Any]:
    """Validate one Codex token-count record before it can reach state/telemetry."""
    payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    total = info.get("total_token_usage") if isinstance(info.get("total_token_usage"), dict) else {}
    last = info.get("last_token_usage") if isinstance(info.get("last_token_usage"), dict) else {}
    values = {
        "input_tokens": optional_nonnegative_int(total, "input_tokens", "total_token_usage.input_tokens"),
        "cached_input_tokens": optional_nonnegative_int(total, "cached_input_tokens", "total_token_usage.cached_input_tokens"),
        "output_tokens": optional_nonnegative_int(total, "output_tokens", "total_token_usage.output_tokens"),
        "reasoning_tokens": optional_nonnegative_int(total, "reasoning_output_tokens", "total_token_usage.reasoning_output_tokens"),
        "total_tokens": optional_nonnegative_int(total, "total_tokens", "total_token_usage.total_tokens"),
        "last_total_tokens": optional_nonnegative_int(last, "total_tokens", "last_token_usage.total_tokens"),
    }
    window = 0 if "model_context_window" not in info else require_int(
        info["model_context_window"], "model_context_window", minimum=1
    )
    if window and values["last_total_tokens"] > window:
        raise NumericSemanticError("last_token_usage.total_tokens exceeds model_context_window")
    values.update({
        "context_window_tokens": window,
        "peak_context_tokens": values["last_total_tokens"],
        "peak_context_pct": values["last_total_tokens"] / window if window else 0.0,
        "model_turns": 1,
        "has_total_usage": bool(total),
    })
    return values


def json_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(value)


def estimate_tokens_from_chars(chars: int) -> int:
    # A deliberately labelled proxy, not a tokenizer claim.
    return max(0, chars // 4)


def human_int(n: Optional[int]) -> str:
    if n is None:
        return "-"
    n = int(n)
    if abs(n) >= 1_000_000_000:
        return f"{n/1_000_000_000:.2f}B"
    if abs(n) >= 1_000_000:
        return f"{n/1_000_000:.2f}M"
    if abs(n) >= 1_000:
        return f"{n/1_000:.1f}k"
    return str(n)


def human_bytes(n: int) -> str:
    f = float(max(0, n))
    for unit in ("B", "KiB", "MiB", "GiB"):
        if f < 1024 or unit == "GiB":
            return f"{f:.1f} {unit}" if unit != "B" else f"{int(f)} B"
        f /= 1024
    return f"{f:.1f} GiB"


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def truncate(text: str, width: int) -> str:
    text = text.replace("\n", " ").replace("\r", " ")
    if len(text) <= width:
        return text
    return text[: max(1, width - 1)] + "…"


def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()


def parse_relative_time(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    now = dt.datetime.now(dt.timezone.utc)
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([mhdw])\s*", value.lower())
    if m:
        amount = float(m.group(1))
        unit = m.group(2)
        seconds = amount * {"m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
        return now - dt.timedelta(seconds=seconds)
    parsed = iso_to_dt(value)
    if parsed and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


@dataclasses.dataclass
class Defect:
    severity: str
    code: str
    message: str
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class MarkerTrend(str, enum.Enum):
    """Direction is unknown for a single completed-session snapshot."""
    UNKNOWN = "UNKNOWN"


@dataclasses.dataclass(frozen=True)
class MarkerDefinition:
    code: str
    title: str
    lane: ImpactLane
    providers: tuple[str, ...]
    defect_codes: tuple[str, ...]


@dataclasses.dataclass
class MarkerScore:
    code: str
    title: str
    lane: ImpactLane
    score: Optional[int]
    percent: Optional[int]
    severity: Severity
    trend: MarkerTrend = MarkerTrend.UNKNOWN
    corrective_opportunity: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["lane"] = self.lane.value
        data["severity"] = self.severity.value
        data["trend"] = self.trend.value
        return data


@dataclasses.dataclass
class CausalRisk:
    current_severity: Severity = Severity.SAFE
    effective_severity: Severity = Severity.SAFE
    trend: str = "STABLE"
    contributing_lanes: list[ImpactLane] = dataclasses.field(default_factory=list)
    predicted_next_risk_state: Optional[Severity] = None
    explanations: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"current_severity": self.current_severity.value, "effective_severity": self.effective_severity.value,
                "trend": self.trend, "contributing_lanes": [lane.value for lane in self.contributing_lanes],
                "predicted_next_risk_state": self.predicted_next_risk_state.value if self.predicted_next_risk_state else None,
                "explanations": self.explanations}


# These markers intentionally aggregate only explainable existing defect rules.
# Their 5..1 thresholds are the corresponding configured rule thresholds above;
# versioning makes future recalibration explicit rather than changing history.
MARKER_DEFINITIONS: tuple[MarkerDefinition, ...] = (
    MarkerDefinition("CONTEXT_PRESSURE", "Context pressure", ImpactLane.CONTEXT_PRESSURE, ("claude", "codex"),
                     ("CLAUDE_EXTREME_CONTEXT", "CLAUDE_VERY_HIGH_CONTEXT", "CLAUDE_COSTLY_CONTEXT", "CLAUDE_HIGH_CONTEXT_DWELL", "CODEX_CONTEXT_CRITICAL", "CODEX_CONTEXT_HIGH", "CODEX_CONTEXT_PRESSURE", "CODEX_HIGH_CONTEXT_DWELL")),
    MarkerDefinition("TOOL_OUTPUT", "Tool output discipline", ImpactLane.TOOL_OUTPUT, ("claude", "codex"),
                     ("GIANT_TOOL_RESULT", "LARGE_TOOL_RESULT", "TOOL_OUTPUT_FLOOD", "HIGH_TOOL_OUTPUT_VOLUME", "UNSCOPED_LARGE_READS", "UNSCOPED_LARGE_READ")),
    MarkerDefinition("REPETITION", "Repeated work", ImpactLane.REPETITION, ("claude", "codex"),
                     ("COMMAND_REPETITION", "REPEATED_READ")),
    MarkerDefinition("SESSION_LIFECYCLE", "Session lifecycle", ImpactLane.SESSION_LIFECYCLE, ("claude", "codex"),
                     ("LONG_GAP_REUSE", "STALE_SESSION_REUSE", "VERY_LONG_ACTIVE_BURST", "LONG_ACTIVE_BURST")),
    MarkerDefinition("TOKEN_AMPLIFICATION", "Token amplification", ImpactLane.TOKEN_AMPLIFICATION, ("claude", "codex"),
                     ("EXCESSIVE_MODEL_TURNS", "MANY_MODEL_TURNS", "ADVISOR_CONTEXT_MULTIPLIER")),
    MarkerDefinition("INTEGRITY", "Telemetry integrity", ImpactLane.INTEGRITY, ("claude", "codex"),
                     ("UNREADABLE_SESSION", "MALFORMED_LOG_LINES", "DUPLICATE_TOKEN_EVENTS")),
    MarkerDefinition("COMPACTION_HEALTH", "Compaction health", ImpactLane.COMPACTION_HEALTH, ("codex",),
                     ("COMPACTION_THRASH", "POST_COMPACT_REFETCH")),
    MarkerDefinition("INSTRUCTION_OVERHEAD", "Instruction overhead", ImpactLane.INSTRUCTION_OVERHEAD, ("codex",),
                     ("HEAVY_STARTUP_INSTRUCTIONS", "LARGE_STARTUP_INSTRUCTIONS")),
    MarkerDefinition("DELEGATION_ADVISOR", "Delegation/advisor use", ImpactLane.DELEGATION_ADVISOR, ("claude",),
                     ("ADVISOR_CONTEXT_MULTIPLIER",)),
)


@dataclasses.dataclass
class Burst:
    start: str
    end: str
    duration_seconds: float
    event_count: int
    gap_after_seconds: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class ToolStat:
    calls: int = 0
    result_chars: int = 0
    result_tokens_proxy: int = 0
    max_result_chars: int = 0
    max_result_tokens_proxy: int = 0
    errors: int = 0

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class SessionSummary:
    provider: str
    session_id: str
    path: str
    source: str
    # `session_id` is provider-native.  A provider can legitimately expose
    # multiple execution streams for one native session, so structured reports
    # retain the provider-neutral stream discriminator separately.
    stream_id: str = ""
    role: str = "MAIN"
    project: str = ""
    cwd: str = ""
    title: str = ""
    version: str = ""
    model: str = ""
    effort: str = ""
    git_branch: str = ""
    start: str = ""
    end: str = ""
    wall_seconds: float = 0.0
    active_seconds: float = 0.0
    longest_burst_seconds: float = 0.0
    bursts: list[Burst] = dataclasses.field(default_factory=list)
    max_idle_gap_seconds: float = 0.0
    event_count: int = 0
    user_prompts: int = 0
    model_turns: int = 0
    tool_calls: int = 0
    tool_results: int = 0
    tool_result_chars: int = 0
    tool_result_tokens_proxy: int = 0
    max_tool_result_chars: int = 0
    max_tool_result_tokens_proxy: int = 0
    tool_stats: dict[str, ToolStat] = dataclasses.field(default_factory=dict)
    repeated_commands: list[tuple[str, int]] = dataclasses.field(default_factory=list)
    repeated_reads: list[tuple[str, int]] = dataclasses.field(default_factory=list)
    unscoped_large_reads: int = 0
    persisted_output_files: int = 0
    persisted_output_bytes: int = 0
    compactions: int = 0
    post_compact_repeats: int = 0
    clear_commands: int = 0
    new_commands: int = 0
    subagent_count: int = 0
    subagent_types: dict[str, int] = dataclasses.field(default_factory=dict)
    subagent_logged_tokens: int = 0
    delegation_calls: int = 0
    # Provider-specific token data, normalised into explicit named fields.
    input_tokens: int = 0
    cached_input_tokens: int = 0
    cache_creation_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    logged_processed_tokens: int = 0
    advisor_calls: int = 0
    advisor_input_tokens: int = 0
    advisor_output_tokens: int = 0
    peak_context_tokens: int = 0
    context_window_tokens: int = 0
    peak_context_pct: float = 0.0
    costly_context_turns: int = 0
    costly_context_turn_pct: float = 0.0
    context65_turns: int = 0
    context80_turns: int = 0
    context90_turns: int = 0
    token_count_events: int = 0
    duplicate_token_events: int = 0
    rate_limit_start_pct: Optional[float] = None
    rate_limit_end_pct: Optional[float] = None
    rate_limit_peak_pct: Optional[float] = None
    plan_type: str = ""
    instruction_chars: int = 0
    instruction_duplicates: int = 0
    raw_session_bytes: int = 0
    malformed_lines: int = 0
    defects: list[Defect] = dataclasses.field(default_factory=list)
    score: int = 0
    grade: str = "A"
    marker_scores: list[MarkerScore] = dataclasses.field(default_factory=list)
    lane_scores: dict[str, Optional[int]] = dataclasses.field(default_factory=dict)
    overall_efficiency_score: Optional[int] = None
    effective_severity: Severity = Severity.SAFE
    trend: MarkerTrend = MarkerTrend.UNKNOWN
    worst_indicators: list[str] = dataclasses.field(default_factory=list)
    corrective_opportunities: list[str] = dataclasses.field(default_factory=list)
    causal_risk: CausalRisk = dataclasses.field(default_factory=CausalRisk)
    notes: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["stream_id"] = self.stream_id or self.session_id
        d["tool_stats"] = {k: v.to_dict() if isinstance(v, ToolStat) else v for k, v in self.tool_stats.items()}
        d["bursts"] = [b.to_dict() if isinstance(b, Burst) else b for b in self.bursts]
        d["defects"] = [x.to_dict() if isinstance(x, Defect) else x for x in self.defects]
        d["marker_scores"] = [x.to_dict() if isinstance(x, MarkerScore) else x for x in self.marker_scores]
        d["effective_severity"] = self.effective_severity.value
        d["trend"] = self.trend.value
        d["causal_risk"] = self.causal_risk.to_dict()
        return d


@dataclasses.dataclass
class Candidate:
    provider: str
    path: Path
    display_path: str
    source_label: str
    is_subagent: bool = False
    parent_session_id: str = ""
    trusted_root: Optional[Path] = None


class ProviderAdapter:
    """Small provider boundary used by the incremental collector.

    The mature full-file parsers below remain the source of truth for forensic
    reports.  Adapters deliberately expose only compact, append-safe facts.
    """
    name = ""

    def discover_sessions(self, roots: list[tuple[Path, str]]) -> list[Candidate]:
        return [c for c in collect_candidates(roots, self.name)]

    def identify_session(self, record: dict[str, Any], path: Path) -> str:
        return path.stem

    def begin_transcript(self, path: Path) -> None:
        """Forget any parser-local transcript state before a fresh replay."""

    def extract_timestamp(self, record: dict[str, Any]) -> str:
        return optional_provider_timestamp(record.get("timestamp"))

    def extract_usage(self, record: dict[str, Any]) -> dict[str, Any]:
        return {}

    def extract_tool_event(self, record: dict[str, Any]) -> dict[str, Any]:
        return {}

    def parse_record(self, record: dict[str, Any], path: Path) -> dict[str, Any]:
        sid = self.identify_session(record, path)
        return {"session_id": sid, "stream_id": sid, "timestamp": self.extract_timestamp(record)}


def is_claude_compaction_boundary(record: dict[str, Any]) -> bool:
    """Normalize the two observed Claude transcript compaction wire formats."""
    if record.get("type") == "compacted":
        return True
    return (record.get("type") == "system"
            and record.get("subtype") == "compact_boundary"
            and isinstance(record.get("compactMetadata"), dict))


class ClaudeAdapter(ProviderAdapter):
    name = "claude"

    def identify_session(self, record: dict[str, Any], path: Path) -> str:
        native = record.get("sessionId")
        if isinstance(native, str) and native.strip():
            return native.strip()
        # Some Claude records do not carry the transcript-level native ID.
        # Preserve the established filename fallback for those records.
        return path.stem

    def extract_usage(self, record: dict[str, Any]) -> dict[str, Any]:
        msg = record.get("message") if isinstance(record.get("message"), dict) else {}
        usage = msg.get("usage") if isinstance(msg.get("usage"), dict) else {}
        iterations = usage.get("iterations") if isinstance(usage.get("iterations"), list) else [usage]
        values = {"input_tokens": 0, "cached_input_tokens": 0, "cache_creation_tokens": 0,
                  "output_tokens": 0, "reasoning_tokens": 0, "model_turns": 0, "peak_context_tokens": 0}
        if record.get("type") != "assistant":
            return values
        has_usage = False
        for item in iterations:
            if not isinstance(item, dict):
                continue
            has_usage = True
            inp = safe_int(item.get("input_tokens")); cached = safe_int(item.get("cache_read_input_tokens"))
            created = safe_int(item.get("cache_creation_input_tokens")); out = safe_int(item.get("output_tokens"))
            values["input_tokens"] += inp; values["cached_input_tokens"] += cached
            values["cache_creation_tokens"] += created; values["output_tokens"] += out
            values["peak_context_tokens"] = max(values["peak_context_tokens"], inp + cached + created)
        values["model_turns"] = int(has_usage)
        return values

    def extract_tool_event(self, record: dict[str, Any]) -> dict[str, Any]:
        event = {"tool_calls": 0, "tool_result_chars": 0, "max_tool_result_chars": 0,
                 "compactions": int(is_claude_compaction_boundary(record)), "read_key": "", "command_key": "", "content_key": "", "tool_call_items": [], "tool_result_items": []}
        msg = record.get("message") if isinstance(record.get("message"), dict) else {}
        content = msg.get("content")
        if record.get("type") == "assistant" and isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    event["tool_calls"] += 1
                    event["tool_call_items"].append(str(block.get("id") or ""))
                    name, inp = str(block.get("name") or ""), block.get("input") or {}
                    if name == "Read":
                        target = str(inp.get("file_path") or inp.get("path") or "")
                        event["read_key"] = json.dumps((target, inp.get("offset"), inp.get("limit")), separators=(",", ":")) if target else ""
                    if name == "Bash": event["command_key"] = normalise_command(str(inp.get("command") or ""))
        if record.get("type") == "user" and isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    chars = content_len(block.get("content")); event["tool_result_chars"] += chars
                    event["max_tool_result_chars"] = max(event["max_tool_result_chars"], chars)
                    event["content_key"] = json_text(block.get("content"))
                    event["tool_result_items"].append((str(block.get("tool_use_id") or ""), chars))
        return event

    def parse_record(self, record: dict[str, Any], path: Path) -> dict[str, Any]:
        result = super().parse_record(record, path)
        result.update(self.extract_usage(record)); result.update(self.extract_tool_event(record))
        msg = record.get("message") if isinstance(record.get("message"), dict) else {}
        result.update({"project": str(record.get("cwd") or ""), "model": str(msg.get("model") or ""),
                       "effort": str(record.get("effort") or ""), "version": str(record.get("version") or "")})
        if record.get("type") == "assistant":
            result["usage_key"] = str(msg.get("id") or record.get("requestId") or record.get("uuid") or "")
        return result


class CodexAdapter(ProviderAdapter):
    name = "codex"

    def __init__(self) -> None:
        # session_meta is transcript metadata, not an event stream.  Keep the
        # first complete identity for each transcript so a repeated or corrupt
        # later metadata record cannot create a new execution stream.
        self._authoritative_metadata: dict[Path, dict[str, str]] = {}

    def begin_transcript(self, path: Path) -> None:
        self._authoritative_metadata.pop(path, None)

    def identify_session(self, record: dict[str, Any], path: Path) -> str:
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        # `payload.id` on response items is an item/call ID, not a session ID.
        # Native session identity is carried by the session_meta record.
        if record.get("type") == "session_meta":
            return str(payload.get("session_id") or payload.get("id") or path.stem)
        return path.stem

    def extract_usage(self, record: dict[str, Any]) -> dict[str, Any]:
        values = {"input_tokens": None, "cached_input_tokens": None, "output_tokens": None,
                  "reasoning_tokens": None, "peak_context_tokens": 0, "context_window_tokens": 0,
                  "peak_context_pct": 0.0, "model_turns": 0}
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        if record.get("type") != "event_msg" or payload.get("type") != "token_count": return values
        numeric = codex_token_count_values(record)
        values.update({key: numeric[key] for key in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "peak_context_tokens", "context_window_tokens", "peak_context_pct", "model_turns")})
        values["usage_key"] = json.dumps(tuple(numeric[key] for key in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "total_tokens", "last_total_tokens", "context_window_tokens")))
        return values

    def extract_tool_event(self, record: dict[str, Any]) -> dict[str, Any]:
        event = {"tool_calls": 0, "tool_result_chars": 0, "max_tool_result_chars": 0,
                 "compactions": int(record.get("type") == "compacted"), "read_key": "", "command_key": "", "content_key": ""}
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        if record.get("type") != "response_item": return event
        typ = payload.get("type")
        if typ in {"function_call", "custom_tool_call"}:
            event["tool_calls"] = 1; name = str(payload.get("name") or "")
            args = payload.get("arguments") or payload.get("input") or {}
            if isinstance(args, str):
                try: args = json.loads(args)
                except json.JSONDecodeError: args = {}
            if name == "exec_command" and isinstance(args, dict): event["command_key"] = normalise_command(str(args.get("cmd") or ""))
            if name in {"read_file", "read"} and isinstance(args, dict):
                target = str(args.get("path") or args.get("file_path") or "")
                event["read_key"] = json.dumps((target, args.get("offset"), args.get("limit")), separators=(",", ":")) if target else ""
        elif typ in {"function_call_output", "custom_tool_call_output"}:
            chars = len(json_text(payload.get("output") if "output" in payload else payload.get("content")))
            event["tool_result_chars"] = chars; event["max_tool_result_chars"] = chars
            event["content_key"] = json_text(payload.get("output") if "output" in payload else payload.get("content"))
        return event

    def parse_record(self, record: dict[str, Any], path: Path) -> dict[str, Any]:
        result = super().parse_record(record, path)
        result.update(self.extract_usage(record)); result.update(self.extract_tool_event(record))
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        if record.get("type") == "session_meta":
            native = str(payload.get("session_id") or payload.get("id") or path.stem)
            stream = str(payload.get("id") or native)
            source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
            subagent = source.get("subagent") if isinstance(source.get("subagent"), dict) else {}
            thread_source = str(payload.get("thread_source") or "")
            subagent_kind = str(subagent.get("other") or "").lower()
            role = "GUARDIAN" if subagent_kind == "guardian" else "APPROVAL_REVIEW" if subagent_kind in {"approval_review", "auto_review", "reviewer"} else "SUBAGENT" if thread_source == "subagent" or subagent else "MAIN"
            identity = {"session_id": native, "stream_id": stream, "role": role,
                        "parent_session_id": str(payload.get("parent_thread_id") or ""),
                        "parent_stream_id": str(payload.get("parent_rollout_id") or ""),
                        "thread_source": thread_source}
            # A real native or rollout ID makes this metadata authoritative.
            # Keep the established filename fallback provisional so a later
            # complete session_meta can still identify the transcript.
            authoritative = self._authoritative_metadata.get(path)
            has_native_identity = bool(str(payload.get("session_id") or payload.get("id") or "").strip())
            if authoritative is None and has_native_identity:
                self._authoritative_metadata[path] = identity
            elif authoritative is not None:
                if any(identity[field] != authoritative[field] for field in identity):
                    result["metadata_conflict"] = True
                identity = authoritative
            result.update(identity)
        result.update({"project": str(payload.get("cwd") or ""), "model": str(payload.get("model") or ""),
                       "effort": str(payload.get("effort") or payload.get("reasoning_effort") or ""),
                       "version": str(payload.get("cli_version") or "")})
        return result


ADAPTERS: dict[str, ProviderAdapter] = {"claude": ClaudeAdapter(), "codex": CodexAdapter()}


class MaterialisedSources:
    """Materialise ZIPs into temporary dirs and expose scan roots."""

    def __init__(self, sources: list[str]):
        self.requested = sources
        self.tempdirs: list[tempfile.TemporaryDirectory[str]] = []
        self.roots: list[tuple[Path, str]] = []

    def __enter__(self) -> "MaterialisedSources":
        if not self.requested:
            self.roots = discover_live_roots()
            return self
        for raw in self.requested:
            p = Path(os.path.expanduser(raw)).resolve()
            if not p.exists():
                raise FileNotFoundError(f"source does not exist: {p}")
            if p.is_file() and zipfile.is_zipfile(p):
                td = tempfile.TemporaryDirectory(prefix="agentopsy-")
                self.tempdirs.append(td)
                with zipfile.ZipFile(p) as zf:
                    zf.extractall(td.name)
                self.roots.append((Path(td.name), f"zip:{p}"))
            elif p.is_dir():
                self.roots.append((p, str(p)))
            elif p.suffix == ".jsonl":
                self.roots.append((p, str(p)))
            else:
                raise ValueError(f"unsupported source: {p}")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        for td in self.tempdirs:
            td.cleanup()


def discover_live_roots() -> list[tuple[Path, str]]:
    roots: list[tuple[Path, str]] = []
    claude_home = Path(os.path.expanduser(os.environ.get("CLAUDE_CONFIG_DIR", "~/.claude")))
    codex_home = Path(os.path.expanduser(os.environ.get("CODEX_HOME", "~/.codex")))
    for p in [claude_home / "projects"]:
        if p.exists():
            roots.append((p, "claude-live"))
    for p, label in [
        (codex_home / "sessions", "codex-live"),
        (codex_home / "archived_sessions", "codex-archived"),
    ]:
        if p.exists():
            roots.append((p, label))
    return roots


def _is_trusted_transcript(path: Path, trusted_root: Path) -> bool:
    """Whether *path* is an ordinary transcript inside its scan boundary.

    Transcript discovery is deliberately symlink-free.  This matches the
    existing security-boundary policy elsewhere in the application and keeps
    a configured provider directory from becoming an indirect capability to
    read another directory.
    """
    try:
        root = trusted_root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        leaf = path.lstat()
        if stat.S_ISLNK(leaf.st_mode) or not stat.S_ISREG(leaf.st_mode):
            return False
        if root.is_dir():
            resolved.relative_to(root)
        elif resolved != root:
            return False
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _open_transcript(path: Path, trusted_root: Optional[Path] = None, *, binary: bool = False) -> Optional[Any]:
    """Open an ordinary transcript without ever blocking on special files."""
    if trusted_root is not None and not _is_trusted_transcript(path, trusted_root):
        return None
    try:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        # The lstat above provides the policy decision; O_NOFOLLOW closes the
        # leaf replacement race on platforms which expose it.
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
        return os.fdopen(fd, "rb" if binary else "r", encoding=None if binary else "utf-8", errors=None if binary else "replace")
    except (OSError, RuntimeError, ValueError):
        return None


def classify_jsonl(path: Path, trusted_root: Optional[Path] = None) -> Optional[str]:
    try:
        f = _open_transcript(path, trusted_root)
        if f is None:
            return None
        with f:
            for _ in range(12):
                line = f.readline()
                if not line:
                    break
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                typ = rec.get("type")
                if typ == "session_meta" and isinstance(rec.get("payload"), dict):
                    return "codex"
                if typ in {
                    "assistant", "user", "system", "mode", "ai-title",
                    "agent-name", "file-history-snapshot", "worktree-state",
                    "attachment", "last-prompt", "relocated",
                } and ("sessionId" in rec or "message" in rec or typ in {"mode", "ai-title", "agent-name"}):
                    return "claude"
    except OSError:
        return None
    return None


def collect_candidates(roots: list[tuple[Path, str]], provider_filter: str, classifier: Optional[Any] = None) -> list[Candidate]:
    candidates: list[Candidate] = []
    seen: set[Path] = set()
    for root, label in roots:
        paths = root.rglob("*.jsonl") if root.is_dir() else ([root] if root.suffix == ".jsonl" else [])
        for path in paths:
            if not _is_trusted_transcript(path, root):
                continue
            rp = path.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            provider = (classifier or (lambda candidate: classify_jsonl(candidate, root)))(path)
            if provider is None or (provider_filter != "all" and provider_filter != provider):
                continue
            parts = path.parts
            is_subagent = provider == "claude" and "subagents" in parts
            parent = ""
            if is_subagent:
                try:
                    idx = parts.index("subagents")
                    parent = parts[idx - 1]
                except Exception:
                    pass
            try:
                display = str(path.relative_to(root))
            except ValueError:
                display = str(path)
            candidates.append(Candidate(provider, path, display, label, is_subagent, parent, root))
    return sorted(candidates, key=lambda x: (x.provider, x.display_path))


def content_len(content: Any) -> int:
    if content is None:
        return 0
    if isinstance(content, str):
        return len(content)
    if isinstance(content, list):
        total = 0
        for block in content:
            if isinstance(block, dict):
                if "text" in block:
                    total += len(str(block["text"]))
                elif "content" in block:
                    total += content_len(block["content"])
                else:
                    total += len(json_text(block))
            else:
                total += len(str(block))
        return total
    if isinstance(content, dict):
        return len(json_text(content))
    return len(str(content))


def calculate_bursts(timestamps: list[dt.datetime], gap_minutes: float) -> list[Burst]:
    if not timestamps:
        return []
    ts = sorted(timestamps)
    threshold = gap_minutes * 60.0
    groups: list[tuple[dt.datetime, dt.datetime, int, Optional[float]]] = []
    start = prev = ts[0]
    count = 1
    for cur in ts[1:]:
        gap = (cur - prev).total_seconds()
        if gap > threshold:
            groups.append((start, prev, count, gap))
            start = cur
            count = 1
        else:
            count += 1
        prev = cur
    groups.append((start, prev, count, None))
    return [
        Burst(
            start=a.isoformat(),
            end=b.isoformat(),
            duration_seconds=max(0.0, (b - a).total_seconds()),
            event_count=count,
            gap_after_seconds=gap,
        )
        for a, b, count, gap in groups
    ]


def add_defect(summary: SessionSummary, severity: str, code: str, message: str,
               recommendation: str = "", **evidence: Any) -> None:
    summary.defects.append(Defect(severity, code, message, evidence, recommendation))


def finalise_grade(summary: SessionSummary) -> None:
    summary.score = sum(SEVERITY_WEIGHT.get(d.severity, 0) for d in summary.defects)
    critical = sum(1 for d in summary.defects if d.severity == "critical")
    high = sum(1 for d in summary.defects if d.severity == "high")
    if critical >= 2 or summary.score >= 50:
        summary.grade = "F"
    elif critical or summary.score >= 30:
        summary.grade = "D"
    elif high >= 2 or summary.score >= 18:
        summary.grade = "C"
    elif high or summary.score >= 8:
        summary.grade = "B"
    else:
        summary.grade = "A"
    finalise_marker_scorecard(summary)
    finalise_causal_risk(summary)


_MARKER_SCORE_BY_DEFECT_SEVERITY = {"low": 4, "medium": 3, "high": 2, "critical": 1}
_MARKER_SEVERITY_BY_SCORE = {
    5: Severity.SAFE,
    4: Severity.LIGHT,
    3: Severity.HIGH,
    2: Severity.CRITICAL,
    1: Severity.SUPER_CRITICAL,
}
_SEVERITY_RANK = {severity: index for index, severity in enumerate(Severity)}


def finalise_marker_scorecard(summary: SessionSummary) -> None:
    """Build a provider-aware 5-point scorecard without diluting serious flags.

    A completed transcript is a point-in-time observation, so trend stays
    explicitly UNKNOWN until rolling observations can establish a direction.
    """
    scores: list[MarkerScore] = []
    for definition in MARKER_DEFINITIONS:
        if summary.provider not in definition.providers:
            scores.append(MarkerScore(
                definition.code, definition.title, definition.lane, None, None,
                Severity.SAFE,
            ))
            continue
        matching = [d for d in summary.defects if d.code in definition.defect_codes]
        point_score = min((_MARKER_SCORE_BY_DEFECT_SEVERITY.get(d.severity, 5) for d in matching), default=5)
        severity = _MARKER_SEVERITY_BY_SCORE[point_score]
        # Context at the legacy critical threshold is an explicit hard floor:
        # excellent scores elsewhere cannot reduce this to an average warning.
        if definition.code == "CONTEXT_PRESSURE" and any(d.severity == "critical" for d in matching):
            severity = Severity.EMERGENCY
        recommendation = next((d.recommendation for d in matching if d.recommendation), "")
        scores.append(MarkerScore(
            definition.code, definition.title, definition.lane, point_score,
            point_score * 20, severity, corrective_opportunity=recommendation,
        ))

    applicable = [marker for marker in scores if marker.score is not None]
    summary.marker_scores = scores
    summary.overall_efficiency_score = (
        round(100 * sum(marker.score or 0 for marker in applicable) / (5 * len(applicable)))
        if applicable else None
    )
    summary.lane_scores = {
        lane.value: round(100 * sum(marker.score or 0 for marker in lane_markers) / (5 * len(lane_markers)))
        if lane_markers else None
        for lane in ImpactLane
        for lane_markers in [[marker for marker in applicable if marker.lane == lane]]
    }
    summary.effective_severity = max(
        (marker.severity for marker in applicable), key=lambda severity: _SEVERITY_RANK[severity], default=Severity.SAFE,
    )
    worst = sorted(
        (marker for marker in applicable if marker.score is not None and marker.score < 5),
        key=lambda marker: (marker.score or 0, marker.code),
    )
    summary.worst_indicators = [marker.code for marker in worst[:3]]
    summary.corrective_opportunities = list(dict.fromkeys(
        marker.corrective_opportunity for marker in worst if marker.corrective_opportunity
    ))[:3]


def finalise_causal_risk(summary: SessionSummary) -> None:
    """Explain promotions from observed combinations; never forecast token counts."""
    current = max((context_severity(summary.peak_context_pct), summary.effective_severity), key=lambda value: _SEVERITY_RANK[value])
    paths: list[tuple[str, tuple[ImpactLane, ...], Severity]] = []
    repeats = max([count for _, count in summary.repeated_reads], default=0)
    if repeats >= 2 and summary.peak_context_pct > .55:
        paths.append(("Repeated reads combine with elevated context pressure, predicting further input amplification.", (ImpactLane.REPETITION, ImpactLane.CONTEXT_PRESSURE, ImpactLane.CONTEXT_VELOCITY), Severity.HIGH))
    if summary.max_tool_result_tokens_proxy >= LARGE_RESULT_TOKENS and summary.model_turns >= 10:
        paths.append(("Large tool output plus sustained turn activity predicts context acceleration.", (ImpactLane.TOOL_OUTPUT, ImpactLane.CONTEXT_VELOCITY), Severity.HIGH))
    if summary.max_idle_gap_seconds >= 24 * 3600 and summary.peak_context_pct > .55 and not summary.cached_input_tokens:
        paths.append(("Stale resume, elevated context, and absent cache reuse predict elevated processing pressure.", (ImpactLane.SESSION_LIFECYCLE, ImpactLane.CONTEXT_PRESSURE, ImpactLane.CACHE_REUSE), Severity.CRITICAL))
    if summary.compactions and summary.post_compact_repeats >= 2:
        paths.append(("Compaction followed by repeated work predicts ineffective compaction and rapid refill.", (ImpactLane.COMPACTION_HEALTH, ImpactLane.REPETITION, ImpactLane.CONTEXT_VELOCITY), Severity.CRITICAL))
    promoted = max([current] + [severity for _, _, severity in paths], key=lambda value: _SEVERITY_RANK[value])
    trend = "RAPIDLY_DETERIORATING" if any(severity == Severity.CRITICAL for _, _, severity in paths) else "DETERIORATING" if paths else "STABLE"
    lanes = list(dict.fromkeys(lane for _, path_lanes, _ in paths for lane in path_lanes))
    prediction = promoted if paths and _SEVERITY_RANK[promoted] > _SEVERITY_RANK[current] else None
    summary.causal_risk = CausalRisk(current, promoted, trend, lanes, prediction, [text for text, _, _ in paths])


def extract_plain_user_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        bits = []
        for b in content:
            if not isinstance(b, dict):
                continue
            if b.get("type") in {"text", "input_text"} and b.get("text"):
                bits.append(str(b["text"]))
        return "\n".join(bits)
    return ""


def normalise_command(cmd: str) -> str:
    cmd = re.sub(r"\s+", " ", cmd.strip())
    # Strip obvious volatile shell prefixes but preserve actual operation.
    cmd = re.sub(r"^(?:cd\s+[^;&|]+\s*(?:&&|;)\s*)", "", cmd)
    return cmd


def shell_looks_read_heavy(cmd: str) -> bool:
    return bool(re.search(r"(?:^|[;&|]\s*|\s)(cat|sed|head|tail|nl|rg|grep|find|ls|wc|git\s+(?:show|diff|log|status))\b", cmd))


def shell_looks_test(cmd: str) -> bool:
    return bool(re.search(r"\b(pytest|ruff|mypy|tox|npm\s+test|cargo\s+test|go\s+test|make\s+test|bandit|compileall)\b", cmd))


def extract_probable_paths(cmd: str) -> list[str]:
    # Deliberately conservative. This is for repeated-read hints, not source-of-truth parsing.
    patterns = re.findall(
        r"(?<![A-Za-z0-9_])((?:/|\./|\.\./)?[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+\-]+)+|[A-Za-z0-9_.@+-]+\.(?:py|md|toml|yaml|yml|json|jsonl|txt|sh|rs|go|js|ts|tsx|jsx|html|css))",
        cmd,
    )
    out = []
    for p in patterns:
        if p not in out and not p.startswith("http"):
            out.append(p)
    return out[:20]


def parse_claude(candidate: Candidate, gap_minutes: float) -> SessionSummary:
    p = candidate.path
    summary = SessionSummary(
        provider="claude",
        session_id=p.stem,
        path=candidate.display_path,
        source=candidate.source_label,
        raw_session_bytes=p.stat().st_size if p.exists() else 0,
    )
    timestamps: list[dt.datetime] = []
    unique_assistant: set[str] = set()
    tool_calls: dict[str, tuple[str, dict[str, Any], Optional[dt.datetime]]] = {}
    seen_tool_calls: set[str] = set()
    tool_result_sizes: dict[str, int] = {}
    commands = collections.Counter()
    reads = collections.Counter()
    model_counts = collections.Counter()
    effort_counts = collections.Counter()
    context_samples: list[int] = []
    context_time_samples: list[tuple[dt.datetime, int]] = []
    advisor_context_samples: list[int] = []
    plain_user_seen: set[str] = set()
    titles: list[str] = []
    versions = collections.Counter()
    branches = collections.Counter()
    cwds = collections.Counter()
    persisted_refs: set[str] = set()

    fh = _open_transcript(p, candidate.trusted_root)
    if fh is None:
        summary.notes.append("cannot open transcript safely")
        add_defect(summary, "critical", "UNREADABLE_SESSION", "Cannot read transcript safely")
        finalise_grade(summary)
        return summary

    with fh:
        for line in fh:
            summary.event_count += 1
            try:
                rec = json.loads(line)
            except ValueError:
                summary.malformed_lines += 1
                continue
            try:
                timestamp = optional_provider_timestamp(rec.get("timestamp"))
            except TemporalSemanticError:
                summary.malformed_lines += 1
                continue
            ts = iso_to_dt(timestamp)
            if ts:
                timestamps.append(ts)
            typ = rec.get("type")
            if is_claude_compaction_boundary(rec):
                summary.compactions += 1
            native = rec.get("sessionId")
            if not summary.stream_id and isinstance(native, str) and native.strip():
                summary.session_id = native.strip()
                summary.stream_id = native.strip()
            if rec.get("cwd"):
                cwds[str(rec["cwd"])] += 1
            if rec.get("version"):
                versions[str(rec["version"])] += 1
            if rec.get("gitBranch"):
                branches[str(rec["gitBranch"])] += 1
            if typ == "ai-title" and rec.get("aiTitle"):
                titles.append(str(rec["aiTitle"]))
            elif typ == "agent-name" and rec.get("agentName") and not titles:
                titles.append(str(rec["agentName"]))
            elif typ == "user":
                msg = rec.get("message") or {}
                content = msg.get("content") if isinstance(msg, dict) else None
                plain = extract_plain_user_text(content)
                if plain:
                    for command_name in re.findall(r"<command-name>(/[^<]+)</command-name>", plain):
                        if command_name.strip() == "/clear":
                            summary.clear_commands += 1
                        if command_name.strip() == "/new":
                            summary.new_commands += 1
                    is_meta = bool(rec.get("isMeta")) or plain.startswith("<local-command-caveat>")
                    if not is_meta and "<command-name>" not in plain and plain not in plain_user_seen:
                        summary.user_prompts += 1
                        plain_user_seen.add(plain)
                if isinstance(content, list):
                    for block in content:
                        if not isinstance(block, dict) or block.get("type") != "tool_result":
                            continue
                        tid = str(block.get("tool_use_id") or "")
                        if tid in tool_result_sizes:
                            continue
                        chars = content_len(block.get("content"))
                        tool_result_sizes[tid] = chars
                        summary.tool_results += 1
                        summary.tool_result_chars += chars
                        summary.max_tool_result_chars = max(summary.max_tool_result_chars, chars)
                        name, inp, _ = tool_calls.get(tid, ("unknown", {}, None))
                        stat = summary.tool_stats.setdefault(name, ToolStat())
                        stat.result_chars += chars
                        stat.max_result_chars = max(stat.max_result_chars, chars)
                        if block.get("is_error"):
                            stat.errors += 1
                        text = json_text(block.get("content"))
                        m = re.search(r"Full output saved to:\s*([^\n]+/tool-results/([^\s]+))", text)
                        if m:
                            persisted_refs.add(m.group(2).strip())
                        if name == "Read":
                            file_path = str(inp.get("file_path") or inp.get("path") or "")
                            if file_path:
                                reads[file_path] += 1
                            scoped = inp.get("offset") is not None or inp.get("limit") is not None
                            if not scoped and estimate_tokens_from_chars(chars) >= LARGE_RESULT_TOKENS:
                                summary.unscoped_large_reads += 1
            elif typ == "assistant":
                msg = rec.get("message") or {}
                if not isinstance(msg, dict):
                    continue
                mid = str(msg.get("id") or rec.get("requestId") or rec.get("uuid") or f"line-{summary.event_count}")
                model = msg.get("model")
                if model:
                    model_counts[str(model)] += 1
                if rec.get("effort"):
                    effort_counts[str(rec["effort"])] += 1
                if mid not in unique_assistant:
                    unique_assistant.add(mid)
                    summary.model_turns += 1
                    usage = msg.get("usage") or {}
                    iterations = usage.get("iterations") if isinstance(usage, dict) else None
                    if isinstance(iterations, list) and iterations:
                        for it in iterations:
                            if not isinstance(it, dict):
                                continue
                            inp = safe_int(it.get("input_tokens"))
                            ccreate = safe_int(it.get("cache_creation_input_tokens"))
                            cread = safe_int(it.get("cache_read_input_tokens"))
                            out = safe_int(it.get("output_tokens"))
                            prompt = inp + ccreate + cread
                            itype = str(it.get("type") or "message")
                            summary.input_tokens += inp
                            summary.cache_creation_tokens += ccreate
                            summary.cached_input_tokens += cread
                            summary.output_tokens += out
                            summary.logged_processed_tokens += prompt + out
                            if itype == "advisor_message":
                                summary.advisor_calls += 1
                                summary.advisor_input_tokens += prompt
                                summary.advisor_output_tokens += out
                                advisor_context_samples.append(prompt)
                            else:
                                context_samples.append(prompt)
                                if ts:
                                    context_time_samples.append((ts, prompt))
                    else:
                        inp = safe_int(usage.get("input_tokens"))
                        ccreate = safe_int(usage.get("cache_creation_input_tokens"))
                        cread = safe_int(usage.get("cache_read_input_tokens"))
                        out = safe_int(usage.get("output_tokens"))
                        think = safe_int((usage.get("output_tokens_details") or {}).get("thinking_tokens"))
                        prompt = inp + ccreate + cread
                        summary.input_tokens += inp
                        summary.cache_creation_tokens += ccreate
                        summary.cached_input_tokens += cread
                        summary.output_tokens += out
                        summary.reasoning_tokens += think
                        summary.logged_processed_tokens += prompt + out
                        context_samples.append(prompt)
                        if ts:
                            context_time_samples.append((ts, prompt))
                content = msg.get("content")
                if isinstance(content, list):
                    for block in content:
                        if not isinstance(block, dict) or block.get("type") != "tool_use":
                            continue
                        tid = str(block.get("id") or "")
                        if tid in seen_tool_calls:
                            continue
                        seen_tool_calls.add(tid)
                        name = str(block.get("name") or "unknown")
                        inp = block.get("input") if isinstance(block.get("input"), dict) else {}
                        tool_calls[tid] = (name, inp, ts)
                        summary.tool_calls += 1
                        stat = summary.tool_stats.setdefault(name, ToolStat())
                        stat.calls += 1
                        if name == "Read":
                            fp = str(inp.get("file_path") or inp.get("path") or "")
                            if fp:
                                reads[fp] += 1
                        if name == "Bash":
                            cmd = str(inp.get("command") or "")
                            if cmd:
                                commands[normalise_command(cmd)] += 1
                                if shell_looks_read_heavy(cmd):
                                    for fp in extract_probable_paths(cmd):
                                        reads[fp] += 1
                        if name in {"Agent", "Task", "TaskCreate"}:
                            # Agent is the direct delegation tool in observed CC logs;
                            # Task* can be workflow bookkeeping, so only Agent drives count.
                            if name == "Agent":
                                summary.delegation_calls += 1

    summary.tool_result_tokens_proxy = estimate_tokens_from_chars(summary.tool_result_chars)
    summary.max_tool_result_tokens_proxy = estimate_tokens_from_chars(summary.max_tool_result_chars)
    for stat in summary.tool_stats.values():
        stat.result_tokens_proxy = estimate_tokens_from_chars(stat.result_chars)
        stat.max_result_tokens_proxy = estimate_tokens_from_chars(stat.max_result_chars)

    if cwds:
        summary.cwd = cwds.most_common(1)[0][0]
        summary.project = summary.cwd
    else:
        summary.project = p.parent.name
    if versions:
        summary.version = versions.most_common(1)[0][0]
    if branches:
        summary.git_branch = branches.most_common(1)[0][0]
    if titles:
        summary.title = titles[-1]
    if model_counts:
        summary.model = model_counts.most_common(1)[0][0]
    if effort_counts:
        summary.effort = effort_counts.most_common(1)[0][0]

    if timestamps:
        stamps = sorted(timestamps)
        summary.start = stamps[0].isoformat()
        summary.end = stamps[-1].isoformat()
        summary.wall_seconds = max(0.0, (stamps[-1] - stamps[0]).total_seconds())
        summary.bursts = calculate_bursts(stamps, gap_minutes)
        summary.active_seconds = sum(b.duration_seconds for b in summary.bursts)
        summary.longest_burst_seconds = max((b.duration_seconds for b in summary.bursts), default=0.0)
        summary.max_idle_gap_seconds = max((b.gap_after_seconds or 0.0 for b in summary.bursts), default=0.0)

    summary.peak_context_tokens = max(context_samples + advisor_context_samples, default=0)
    summary.costly_context_turns = sum(1 for x in context_samples if x >= CLAUDE_COSTLY_CONTEXT_TOKENS)
    summary.costly_context_turn_pct = (
        summary.costly_context_turns / len(context_samples) if context_samples else 0.0
    )
    summary.repeated_commands = [(k, v) for k, v in commands.most_common(10) if v >= 2]
    summary.repeated_reads = [(k, v) for k, v in reads.most_common(10) if v >= 2]

    # Persisted output files are not assumed to have entered model context. They are
    # reported separately because they reveal commands that produced huge raw output.
    sidecar_dir = p.with_suffix("") / "tool-results"
    if sidecar_dir.exists():
        for f in sidecar_dir.iterdir():
            if f.is_file() and (not persisted_refs or f.name in persisted_refs):
                summary.persisted_output_files += 1
                try:
                    summary.persisted_output_bytes += f.stat().st_size
                except OSError:
                    pass

    # Claude subagent metadata/usage attached to a top-level session.
    subdir = p.with_suffix("") / "subagents"
    if subdir.exists() and not candidate.is_subagent:
        metas = list(subdir.glob("*.meta.json"))
        summary.subagent_count = len(list(subdir.glob("*.jsonl")))
        for mp in metas:
            try:
                meta = json.loads(mp.read_text(encoding="utf-8", errors="replace"))
                at = str(meta.get("agentType") or "unknown")
                summary.subagent_types[at] = summary.subagent_types.get(at, 0) + 1
            except Exception:
                continue
        # Cheap token-only pass, avoiding recursive defect generation.
        for sp in subdir.glob("*.jsonl"):
            seen_mid: set[str] = set()
            try:
                with sp.open("r", encoding="utf-8", errors="replace") as sf:
                    for line in sf:
                        try:
                            r = json.loads(line)
                        except ValueError:
                            continue
                        if r.get("type") != "assistant":
                            continue
                        m = r.get("message") or {}
                        mid = str(m.get("id") or r.get("requestId") or r.get("uuid") or "")
                        if not mid or mid in seen_mid:
                            continue
                        seen_mid.add(mid)
                        u = m.get("usage") or {}
                        its = u.get("iterations")
                        if isinstance(its, list) and its:
                            for it in its:
                                if isinstance(it, dict):
                                    summary.subagent_logged_tokens += sum(safe_int(it.get(k)) for k in (
                                        "input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens"
                                    ))
                        else:
                            summary.subagent_logged_tokens += sum(safe_int(u.get(k)) for k in (
                                "input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens"
                            ))
            except OSError:
                pass

    evaluate_common_defects(summary)
    evaluate_claude_defects(summary)
    finalise_grade(summary)
    return summary


def parse_codex(candidate: Candidate, gap_minutes: float) -> SessionSummary:
    p = candidate.path
    summary = SessionSummary(
        provider="codex",
        session_id=p.stem.replace("rollout-", "").split("-")[-5:] and p.stem.split("-")[-1] or p.stem,
        path=candidate.display_path,
        source=candidate.source_label,
        raw_session_bytes=p.stat().st_size if p.exists() else 0,
    )
    timestamps: list[dt.datetime] = []
    commands = collections.Counter()
    reads = collections.Counter()
    tool_calls: dict[str, tuple[str, dict[str, Any], Optional[dt.datetime]]] = {}
    tool_result_seen: set[str] = set()
    token_signatures = collections.Counter()
    context_samples: list[int] = []
    context_pct_samples: list[float] = []
    rate_samples: list[float] = []
    compaction_times: list[dt.datetime] = []
    command_history: list[tuple[dt.datetime, str]] = []
    instruction_hashes = collections.Counter()
    instruction_lengths: dict[str, int] = {}
    model_counts = collections.Counter()
    effort_counts = collections.Counter()
    user_message_hashes: set[str] = set()
    latest_total_usage: dict[str, Any] = {}
    latest_rate: dict[str, Any] = {}

    fh = _open_transcript(p, candidate.trusted_root)
    if fh is None:
        summary.notes.append("cannot open transcript safely")
        add_defect(summary, "critical", "UNREADABLE_SESSION", "Cannot read transcript safely")
        finalise_grade(summary)
        return summary

    with fh:
        for line in fh:
            summary.event_count += 1
            try:
                rec = json.loads(line)
            except ValueError:
                summary.malformed_lines += 1
                continue
            try:
                timestamp = optional_provider_timestamp(rec.get("timestamp"))
            except TemporalSemanticError:
                summary.malformed_lines += 1
                continue
            ts = iso_to_dt(timestamp)
            if ts:
                timestamps.append(ts)
            typ = rec.get("type")
            payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}

            if typ == "session_meta":
                sid = payload.get("session_id") or payload.get("id")
                if sid:
                    summary.session_id = str(sid)
                summary.stream_id = str(payload.get("id") or summary.session_id)
                source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
                subagent = source.get("subagent") if isinstance(source.get("subagent"), dict) else {}
                kind = str(subagent.get("other") or "").lower()
                thread_source = str(payload.get("thread_source") or "")
                summary.role = "GUARDIAN" if kind == "guardian" else "APPROVAL_REVIEW" if kind in {"approval_review", "auto_review", "reviewer"} else "SUBAGENT" if thread_source == "subagent" or subagent else "MAIN"
                summary.cwd = str(payload.get("cwd") or "")
                summary.project = summary.cwd
                summary.version = str(payload.get("cli_version") or "")
                base = payload.get("base_instructions")
                if isinstance(base, dict):
                    text = str(base.get("text") or "")
                    if text:
                        h = sha1_text(text)
                        instruction_hashes[h] += 1
                        instruction_lengths.setdefault(h, len(text))
                elif isinstance(base, str):
                    h = sha1_text(base)
                    instruction_hashes[h] += 1
                    instruction_lengths.setdefault(h, len(base))
            elif typ == "turn_context":
                if payload.get("cwd") and not summary.cwd:
                    summary.cwd = str(payload["cwd"])
                    summary.project = summary.cwd
                model = payload.get("model")
                if model:
                    model_counts[str(model)] += 1
                effort = payload.get("effort") or payload.get("reasoning_effort")
                if effort:
                    effort_counts[str(effort)] += 1
            elif typ == "world_state":
                state = payload.get("state") if isinstance(payload.get("state"), dict) else {}
                agents = state.get("agents_md") if isinstance(state, dict) else None
                if isinstance(agents, dict):
                    text = str(agents.get("text") or "")
                    if text:
                        h = sha1_text(text)
                        instruction_hashes[h] += 1
                        instruction_lengths.setdefault(h, len(text))
            elif typ == "compacted":
                summary.compactions += 1
                if ts:
                    compaction_times.append(ts)
            elif typ == "event_msg":
                etype = payload.get("type")
                if etype == "token_count":
                    try:
                        numeric = codex_token_count_values(rec)
                    except NumericSemanticError:
                        summary.malformed_lines += 1
                        continue
                    summary.token_count_events += 1
                    window = numeric["context_window_tokens"]
                    sig = (
                        numeric["input_tokens"], numeric["cached_input_tokens"], numeric["output_tokens"],
                        numeric["reasoning_tokens"], numeric["total_tokens"], numeric["last_total_tokens"], window,
                    )
                    token_signatures[sig] += 1
                    if numeric["has_total_usage"]:
                        latest_total_usage = numeric
                    if window:
                        summary.context_window_tokens = max(summary.context_window_tokens, window)
                    last_total = numeric["last_total_tokens"]
                    if last_total:
                        context_samples.append(last_total)
                        if window:
                            pct = last_total / window
                            context_pct_samples.append(pct)
                            summary.context65_turns += int(pct >= 0.65)
                            summary.context80_turns += int(pct >= 0.80)
                            summary.context90_turns += int(pct >= 0.90)
                    rate = payload.get("rate_limits") if isinstance(payload.get("rate_limits"), dict) else {}
                    latest_rate = rate or latest_rate
                    primary = rate.get("primary") if isinstance(rate.get("primary"), dict) else {}
                    used = primary.get("used_percent")
                    if isinstance(used, (int, float)):
                        rate_samples.append(float(used))
                    if rate.get("plan_type"):
                        summary.plan_type = str(rate["plan_type"])
                elif etype == "user_message":
                    text = str(payload.get("message") or "")
                    h = sha1_text(text)
                    if text and h not in user_message_hashes:
                        user_message_hashes.add(h)
                        summary.user_prompts += 1
                elif etype == "task_started":
                    window = safe_int(payload.get("model_context_window"))
                    if window:
                        summary.context_window_tokens = max(summary.context_window_tokens, window)
                elif etype == "item_completed":
                    item = payload.get("item") if isinstance(payload.get("item"), dict) else {}
                    if item.get("type") == "ContextCompaction":
                        # A matching top-level `compacted` record is preferred; only use
                        # this as fallback if no compacted record exists later.
                        if ts:
                            compaction_times.append(ts)
            elif typ == "response_item":
                rtype = payload.get("type")
                if rtype == "message":
                    role = payload.get("role")
                    content = payload.get("content")
                    if role == "user":
                        text = extract_plain_user_text(content)
                        if text:
                            # AGENTS/system-like injected user messages are tracked as
                            # instruction payload, not human prompts.
                            if text.startswith("# AGENTS.md instructions") or text.startswith("<environment_context>"):
                                h = sha1_text(text)
                                instruction_hashes[h] += 1
                                instruction_lengths.setdefault(h, len(text))
                            else:
                                h = sha1_text(text)
                                if h not in user_message_hashes:
                                    user_message_hashes.add(h)
                                    summary.user_prompts += 1
                    elif role in {"developer", "system"}:
                        text = extract_plain_user_text(content)
                        if text:
                            h = sha1_text(text)
                            instruction_hashes[h] += 1
                            instruction_lengths.setdefault(h, len(text))
                elif rtype in {"function_call", "custom_tool_call"}:
                    call_id = str(payload.get("call_id") or payload.get("id") or f"call-{summary.event_count}")
                    if call_id in tool_calls:
                        continue
                    name = str(payload.get("name") or rtype)
                    raw_args = payload.get("arguments") or payload.get("input") or {}
                    if isinstance(raw_args, str):
                        try:
                            args = json.loads(raw_args)
                            if not isinstance(args, dict):
                                args = {"raw": raw_args}
                        except json.JSONDecodeError:
                            args = {"raw": raw_args}
                    elif isinstance(raw_args, dict):
                        args = raw_args
                    else:
                        args = {"raw": json_text(raw_args)}
                    tool_calls[call_id] = (name, args, ts)
                    summary.tool_calls += 1
                    summary.tool_stats.setdefault(name, ToolStat()).calls += 1
                    if name in {"spawn_agent", "collab_spawn", "delegate", "create_agent"}:
                        summary.delegation_calls += 1
                    cmd = ""
                    if name == "exec_command":
                        cmd = str(args.get("cmd") or args.get("command") or "")
                    elif name in {"shell", "bash"}:
                        cmd = str(args.get("command") or args.get("cmd") or "")
                    if cmd:
                        norm = normalise_command(cmd)
                        commands[norm] += 1
                        if ts:
                            command_history.append((ts, norm))
                        if shell_looks_read_heavy(cmd):
                            for fp in extract_probable_paths(cmd):
                                reads[fp] += 1
                elif rtype in {"function_call_output", "custom_tool_call_output"}:
                    call_id = str(payload.get("call_id") or payload.get("id") or f"out-{summary.event_count}")
                    if call_id in tool_result_seen:
                        continue
                    tool_result_seen.add(call_id)
                    out = json_text(payload.get("output") if "output" in payload else payload.get("content"))
                    chars = len(out)
                    summary.tool_results += 1
                    summary.tool_result_chars += chars
                    summary.max_tool_result_chars = max(summary.max_tool_result_chars, chars)
                    name, args, _ = tool_calls.get(call_id, ("unknown", {}, None))
                    stat = summary.tool_stats.setdefault(name, ToolStat())
                    stat.result_chars += chars
                    stat.max_result_chars = max(stat.max_result_chars, chars)
                    # Codex exec output often contains a real tokenizer count. Preserve
                    # it when available instead of replacing it with chars/4.
                    m = re.search(r"Original token count:\s*([0-9,]+)", out)
                    actual_proxy = int(m.group(1).replace(",", "")) if m else estimate_tokens_from_chars(chars)
                    stat.result_tokens_proxy += actual_proxy
                    stat.max_result_tokens_proxy = max(stat.max_result_tokens_proxy, actual_proxy)
                    summary.tool_result_tokens_proxy += actual_proxy
                    summary.max_tool_result_tokens_proxy = max(summary.max_tool_result_tokens_proxy, actual_proxy)

    if timestamps:
        stamps = sorted(timestamps)
        summary.start = stamps[0].isoformat()
        summary.end = stamps[-1].isoformat()
        summary.wall_seconds = max(0.0, (stamps[-1] - stamps[0]).total_seconds())
        summary.bursts = calculate_bursts(stamps, gap_minutes)
        summary.active_seconds = sum(b.duration_seconds for b in summary.bursts)
        summary.longest_burst_seconds = max((b.duration_seconds for b in summary.bursts), default=0.0)
        summary.max_idle_gap_seconds = max((b.gap_after_seconds or 0.0 for b in summary.bursts), default=0.0)

    summary.model_turns = len({x for x in token_signatures})
    summary.duplicate_token_events = sum(max(0, count - 1) for count in token_signatures.values())
    if latest_total_usage:
        summary.input_tokens = safe_int(latest_total_usage.get("input_tokens"))
        summary.cached_input_tokens = safe_int(latest_total_usage.get("cached_input_tokens"))
        summary.output_tokens = safe_int(latest_total_usage.get("output_tokens"))
        summary.reasoning_tokens = safe_int(latest_total_usage.get("reasoning_tokens"))
        summary.logged_processed_tokens = safe_int(latest_total_usage.get("total_tokens"))
    summary.peak_context_tokens = max(context_samples, default=0)
    summary.peak_context_pct = max(context_pct_samples, default=0.0)
    summary.costly_context_turns = summary.context65_turns
    summary.costly_context_turn_pct = (
        summary.context65_turns / len(context_pct_samples) if context_pct_samples else 0.0
    )
    if rate_samples:
        summary.rate_limit_start_pct = rate_samples[0]
        summary.rate_limit_end_pct = rate_samples[-1]
        summary.rate_limit_peak_pct = max(rate_samples)
    if model_counts:
        summary.model = model_counts.most_common(1)[0][0]
    if effort_counts:
        summary.effort = effort_counts.most_common(1)[0][0]
    summary.repeated_commands = [(k, v) for k, v in commands.most_common(10) if v >= 2]
    summary.repeated_reads = [(k, v) for k, v in reads.most_common(10) if v >= 2]
    summary.instruction_chars = sum(instruction_lengths.values())
    summary.instruction_duplicates = sum(max(0, n - 1) for n in instruction_hashes.values())

    # De-duplicate compaction timestamps and prefer the top-level compacted count.
    if summary.compactions == 0 and compaction_times:
        # Event + top-level records can share timestamps; cluster to 5 seconds.
        compact_sorted = sorted(compaction_times)
        groups = []
        for t in compact_sorted:
            if not groups or (t - groups[-1]).total_seconds() > 5:
                groups.append(t)
        summary.compactions = len(groups)
    elif summary.compactions:
        # Capture actual top-level compaction times for post-compact analysis by
        # rescanning only if there are compactions. This keeps normal sessions cheap.
        top_times: list[dt.datetime] = []
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if r.get("type") == "compacted":
                        t = iso_to_dt(r.get("timestamp"))
                        if t:
                            top_times.append(t)
            if top_times:
                compaction_times = top_times
        except OSError:
            pass

    # Count exact repeated shell commands within 5 minutes after compaction when
    # the same command had already appeared before that compaction.
    if compaction_times and command_history:
        for ct in compaction_times:
            before = {cmd for t, cmd in command_history if t < ct}
            after = [(t, cmd) for t, cmd in command_history if ct <= t <= ct + dt.timedelta(minutes=5)]
            summary.post_compact_repeats += sum(1 for _, cmd in after if cmd in before)

    evaluate_common_defects(summary)
    evaluate_codex_defects(summary)
    finalise_grade(summary)
    return summary


def evaluate_common_defects(s: SessionSummary) -> None:
    gap_h = s.max_idle_gap_seconds / 3600.0
    if gap_h >= VERY_LONG_GAP_HOURS:
        add_defect(
            s, "high", "LONG_GAP_REUSE",
            f"The same session was reused after a {gap_h:.1f}h idle gap.",
            "Prefer a fresh session plus durable handoff after multi-day gaps; never silently auto-resume a bloated thread.",
            max_idle_gap_hours=round(gap_h, 2), bursts=len(s.bursts),
        )
    elif gap_h >= LONG_GAP_HOURS:
        add_defect(
            s, "medium", "STALE_SESSION_REUSE",
            f"The session resumed after a {gap_h:.1f}h idle gap.",
            "Review whether this should have been a fresh session with a handoff.",
            max_idle_gap_hours=round(gap_h, 2),
        )

    longest_h = s.longest_burst_seconds / 3600.0
    if longest_h >= 6:
        add_defect(s, "high", "VERY_LONG_ACTIVE_BURST", f"One uninterrupted activity burst lasted {longest_h:.1f}h.",
                   "Split large work into explicit checkpoints and rotate context between logical stages.", longest_burst_hours=round(longest_h, 2))
    elif longest_h >= 3:
        add_defect(s, "medium", "LONG_ACTIVE_BURST", f"One activity burst lasted {longest_h:.1f}h.",
                   "Check context pressure at stage boundaries rather than allowing a single session to grow indefinitely.", longest_burst_hours=round(longest_h, 2))

    if s.max_tool_result_tokens_proxy >= GIANT_RESULT_TOKENS:
        add_defect(s, "high", "GIANT_TOOL_RESULT",
                   f"A single tool result contributed about {human_int(s.max_tool_result_tokens_proxy)} tokens/proxy tokens.",
                   "Scope reads/commands and return summaries or bounded ranges instead of large raw payloads.",
                   max_tool_result_tokens=s.max_tool_result_tokens_proxy)
    elif s.max_tool_result_tokens_proxy >= LARGE_RESULT_TOKENS:
        add_defect(s, "medium", "LARGE_TOOL_RESULT",
                   f"A single tool result contributed about {human_int(s.max_tool_result_tokens_proxy)} tokens/proxy tokens.",
                   "Prefer bounded output for read/test/log commands.", max_tool_result_tokens=s.max_tool_result_tokens_proxy)

    if s.tool_result_tokens_proxy >= EXTREME_TOOL_OUTPUT_TOKENS:
        add_defect(s, "high", "TOOL_OUTPUT_FLOOD",
                   f"Tool results contributed about {human_int(s.tool_result_tokens_proxy)} tokens/proxy tokens in this session.",
                   "Reduce main-context exploration, use quiet output, and delegate read-heavy discovery when appropriate.",
                   tool_result_tokens=s.tool_result_tokens_proxy)
    elif s.tool_result_tokens_proxy >= HIGH_TOOL_OUTPUT_TOKENS:
        add_defect(s, "medium", "HIGH_TOOL_OUTPUT_VOLUME",
                   f"Tool results contributed about {human_int(s.tool_result_tokens_proxy)} tokens/proxy tokens.",
                   "Audit repeated reads and verbose command output.", tool_result_tokens=s.tool_result_tokens_proxy)

    if s.repeated_commands:
        max_cmd, repeats = s.repeated_commands[0]
        if repeats >= 10:
            add_defect(s, "high", "COMMAND_REPETITION",
                       f"The same command was executed {repeats} times.",
                       "Cache/retain the result when valid, or identify why the agent is re-running the same check.",
                       repeats=repeats, command=truncate(max_cmd, 180))
        elif repeats >= 5:
            add_defect(s, "medium", "COMMAND_REPETITION",
                       f"The same command was executed {repeats} times.",
                       "Check whether repeated verification can be narrowed or deferred to stage closure.",
                       repeats=repeats, command=truncate(max_cmd, 180))

    if s.repeated_reads:
        target, repeats = s.repeated_reads[0]
        if repeats >= 8:
            add_defect(s, "high", "REPEATED_READ",
                       f"A file/path appears to have been read {repeats} times.",
                       "Retain the relevant facts in a small working note or use targeted ranges instead of re-reading.",
                       repeats=repeats, target=target)
        elif repeats >= 4:
            add_defect(s, "medium", "REPEATED_READ",
                       f"A file/path appears to have been read {repeats} times.",
                       "Inspect whether the same material is repeatedly re-entering context.", repeats=repeats, target=target)

    if s.malformed_lines:
        add_defect(s, "low", "MALFORMED_LOG_LINES", f"{s.malformed_lines} transcript lines could not be parsed as JSON.",
                   "Treat token totals as potentially incomplete for this session.", malformed_lines=s.malformed_lines)


def evaluate_claude_defects(s: SessionSummary) -> None:
    peak = s.peak_context_tokens
    if peak >= CLAUDE_EXTREME_CONTEXT_TOKENS:
        add_defect(s, "critical", "CLAUDE_EXTREME_CONTEXT",
                   f"Logged request/advisor context reached about {human_int(peak)} tokens.",
                   "Rotate well before this point. Use handoff + /clear at a safe checkpoint and avoid advisor calls on an already huge context.",
                   peak_context_tokens=peak)
    elif peak >= CLAUDE_VERY_HIGH_CONTEXT_TOKENS:
        add_defect(s, "high", "CLAUDE_VERY_HIGH_CONTEXT",
                   f"Logged request context reached about {human_int(peak)} tokens.",
                   "Arm rotation earlier and keep read-heavy work out of the main session.", peak_context_tokens=peak)
    elif peak >= CLAUDE_COSTLY_CONTEXT_TOKENS:
        add_defect(s, "medium", "CLAUDE_COSTLY_CONTEXT",
                   f"Logged request context exceeded 150k and peaked near {human_int(peak)} tokens.",
                   "Treat >150k as a cost-pressure zone and prepare a checkpoint before context grows further.", peak_context_tokens=peak)

    if s.costly_context_turn_pct >= 0.75 and s.costly_context_turns >= 10:
        add_defect(s, "critical", "CLAUDE_HIGH_CONTEXT_DWELL",
                   f"{s.costly_context_turn_pct*100:.0f}% of logged main-message iterations ran at >=150k prompt context.",
                   "The session spent too long in the expensive context zone; rotate sooner instead of merely surviving until auto-compact.",
                   costly_turns=s.costly_context_turns, costly_pct=round(s.costly_context_turn_pct * 100, 1))
    elif s.costly_context_turn_pct >= 0.35 and s.costly_context_turns >= 10:
        add_defect(s, "high", "CLAUDE_HIGH_CONTEXT_DWELL",
                   f"{s.costly_context_turn_pct*100:.0f}% of logged main-message iterations ran at >=150k prompt context.",
                   "Move the rotation threshold earlier and reduce main-context reads.",
                   costly_turns=s.costly_context_turns, costly_pct=round(s.costly_context_turn_pct * 100, 1))

    if s.unscoped_large_reads >= 3:
        add_defect(s, "high", "UNSCOPED_LARGE_READS",
                   f"Detected {s.unscoped_large_reads} large Claude Read results without offset/limit scoping.",
                   "Use grep/rg first, then bounded Read offset/limit ranges.", count=s.unscoped_large_reads)
    elif s.unscoped_large_reads:
        add_defect(s, "medium", "UNSCOPED_LARGE_READ",
                   f"Detected {s.unscoped_large_reads} large Claude Read result(s) without offset/limit scoping.",
                   "Use bounded Read calls for large files.", count=s.unscoped_large_reads)

    if s.advisor_calls >= 3 and s.advisor_input_tokens >= 500_000:
        sev = "high" if s.peak_context_tokens >= CLAUDE_COSTLY_CONTEXT_TOKENS else "medium"
        add_defect(s, sev, "ADVISOR_CONTEXT_MULTIPLIER",
                   f"Advisor iterations processed about {human_int(s.advisor_input_tokens)} input/context tokens across {s.advisor_calls} calls.",
                   "Use advisor selectively; avoid invoking it repeatedly once the main context is already large.",
                   advisor_calls=s.advisor_calls, advisor_input_tokens=s.advisor_input_tokens)

    if s.model_turns >= 500:
        add_defect(s, "high", "EXCESSIVE_MODEL_TURNS", f"The session contains {s.model_turns} unique assistant/model turns.",
                   "Create more stage boundaries and rotate context rather than keeping one thread alive indefinitely.", model_turns=s.model_turns)
    elif s.model_turns >= 250:
        add_defect(s, "medium", "MANY_MODEL_TURNS", f"The session contains {s.model_turns} unique assistant/model turns.",
                   "Review whether this should have been split into multiple checkpointed sessions.", model_turns=s.model_turns)


def evaluate_codex_defects(s: SessionSummary) -> None:
    pct = s.peak_context_pct
    if pct >= CODEX_CRITICAL_CONTEXT_PCT:
        add_defect(s, "critical", "CODEX_CONTEXT_CRITICAL",
                   f"Peak logged Codex turn reached {pct*100:.1f}% of the model context window.",
                   "Checkpoint and start a fresh chat before this zone; do not rely on repeated compaction as the only control.",
                   peak_context_pct=round(pct * 100, 2), peak_context_tokens=s.peak_context_tokens, context_window=s.context_window_tokens)
    elif pct >= CODEX_HIGH_CONTEXT_PCT:
        add_defect(s, "high", "CODEX_CONTEXT_HIGH",
                   f"Peak logged Codex turn reached {pct*100:.1f}% of the model context window.",
                   "Arm a handoff/rotation around the next safe boundary.", peak_context_pct=round(pct * 100, 2))
    elif pct >= CODEX_PREPARE_CONTEXT_PCT:
        add_defect(s, "medium", "CODEX_CONTEXT_PRESSURE",
                   f"Peak logged Codex turn reached {pct*100:.1f}% of the model context window.",
                   "Prepare a checkpoint before context pressure rises further.", peak_context_pct=round(pct * 100, 2))

    # contextXX counts come from token snapshots; duplicates can inflate them, so
    # use a conservative absolute threshold rather than a percentage here.
    if s.context80_turns >= 20:
        add_defect(s, "high", "CODEX_HIGH_CONTEXT_DWELL",
                   f"At least {s.context80_turns} token snapshots were >=80% context.",
                   "Rotate earlier; extended dwell near the context ceiling amplifies cached-input usage.", snapshots=s.context80_turns)

    # Historical report parsing has no durable before/after/refill telemetry.
    # Do not label a count as causal THRASH; live stream classification does so
    # only from measured telemetry in stream_compaction_outcomes().
    if s.post_compact_repeats >= 3:
        add_defect(s, "high", "POST_COMPACT_REFETCH",
                   f"Detected {s.post_compact_repeats} exact command re-runs within 5 minutes after compaction.",
                   "Persist compact state externally or rotate to a fresh session instead of immediately rebuilding discarded context.",
                   repeated_commands_after_compaction=s.post_compact_repeats)

    if s.token_count_events and s.duplicate_token_events / s.token_count_events >= 0.10:
        add_defect(s, "low", "DUPLICATE_TOKEN_EVENTS",
                   f"About {s.duplicate_token_events}/{s.token_count_events} token_count events repeat an existing snapshot.",
                   "Do not sum last_token_usage events blindly; use cumulative total_token_usage and deduplicate snapshots.",
                   duplicates=s.duplicate_token_events, token_events=s.token_count_events)

    if s.instruction_chars >= 100_000:
        add_defect(s, "high", "HEAVY_STARTUP_INSTRUCTIONS",
                   f"Persisted startup/instruction payload is at least {human_int(s.instruction_chars)} characters.",
                   "Keep AGENTS.md and always-loaded instructions compact; move specialist material to lazy-loaded skills/docs.", instruction_chars=s.instruction_chars)
    elif s.instruction_chars >= 50_000:
        add_defect(s, "medium", "LARGE_STARTUP_INSTRUCTIONS",
                   f"Persisted startup/instruction payload is at least {human_int(s.instruction_chars)} characters.",
                   "Review always-loaded instructions for material that can be lazy-loaded.", instruction_chars=s.instruction_chars)


def filter_sessions(sessions: list[SessionSummary], since: Optional[dt.datetime], project: str,
                    include_subagents: bool, candidates_by_path: dict[str, Candidate]) -> list[SessionSummary]:
    out = []
    for s in sessions:
        cand = candidates_by_path.get(f"{s.source}|{s.path}")
        if cand and cand.is_subagent and not include_subagents:
            continue
        if project and project.lower() not in (s.project + " " + s.cwd + " " + s.path).lower():
            continue
        if since:
            end = iso_to_dt(s.end)
            if not end or end < since:
                continue
        out.append(s)
    return out


def severity_counts(sessions: list[SessionSummary]) -> collections.Counter[str]:
    cts: collections.Counter[str] = collections.Counter()
    for s in sessions:
        for d in s.defects:
            cts[d.severity] += 1
    return cts


def provider_aggregate(sessions: list[SessionSummary], provider: str) -> dict[str, Any]:
    ss = [s for s in sessions if s.provider == provider]
    return {
        "sessions": len(ss),
        "raw_bytes": sum(s.raw_session_bytes for s in ss),
        "model_turns": sum(s.model_turns for s in ss),
        "tool_calls": sum(s.tool_calls for s in ss),
        "tool_result_tokens_proxy": sum(s.tool_result_tokens_proxy for s in ss),
        "logged_processed_tokens": sum(s.logged_processed_tokens for s in ss),
        "cached_input_tokens": sum(s.cached_input_tokens for s in ss),
        "input_tokens": sum(s.input_tokens for s in ss),
        "output_tokens": sum(s.output_tokens for s in ss),
        "reasoning_tokens": sum(s.reasoning_tokens for s in ss),
        "compactions": sum(s.compactions for s in ss),
        "advisor_calls": sum(s.advisor_calls for s in ss),
        "subagents": sum(s.subagent_count for s in ss),
        "max_peak_context_tokens": max((s.peak_context_tokens for s in ss), default=0),
        "max_peak_context_pct": max((s.peak_context_pct for s in ss), default=0.0),
    }


def rank_sessions(sessions: list[SessionSummary]) -> list[SessionSummary]:
    return sorted(
        sessions,
        key=lambda s: (
            s.score,
            max((SEVERITY_ORDER.get(d.severity, 0) for d in s.defects), default=0),
            s.logged_processed_tokens,
            s.tool_result_tokens_proxy,
        ),
        reverse=True,
    )


def render_terminal(sessions: list[SessionSummary], roots: list[tuple[Path, str]], top: int,
                    details: int, colour: bool, show_all: bool) -> str:
    lines: list[str] = []
    lines.append(c(f"Agentopsy v{VERSION}", "bold", colour))
    lines.append("Local forensic analysis. No transcript content is sent externally.")
    lines.append("")
    lines.append(c("Sources", "cyan", colour))
    for root, label in roots:
        lines.append(f"  - {label}: {root}")
    lines.append("")

    by_provider = collections.Counter(s.provider for s in sessions)
    sev = severity_counts(sessions)
    lines.append(c("Inventory", "cyan", colour))
    lines.append(
        f"  Sessions: {len(sessions)}  |  Claude: {by_provider['claude']}  |  Codex: {by_provider['codex']}  |  "
        f"Defects: critical={sev['critical']} high={sev['high']} medium={sev['medium']} low={sev['low']}"
    )
    lines.append("")

    for provider in ("claude", "codex"):
        a = provider_aggregate(sessions, provider)
        if not a["sessions"]:
            continue
        lines.append(c(provider.upper(), "magenta", colour))
        if provider == "claude":
            lines.append(
                f"  sessions={a['sessions']}  model-turns={human_int(a['model_turns'])}  "
                f"logged model-token work≈{human_int(a['logged_processed_tokens'])}  "
                f"cache-read={human_int(a['cached_input_tokens'])}  tool-result≈{human_int(a['tool_result_tokens_proxy'])}  "
                f"advisor-calls={a['advisor_calls']}  subagents={a['subagents']}  "
                f"max logged request context≈{human_int(a['max_peak_context_tokens'])}"
            )
        else:
            lines.append(
                f"  sessions={a['sessions']}  cumulative logged total={human_int(a['logged_processed_tokens'])}  "
                f"input={human_int(a['input_tokens'])} (cached subset {human_int(a['cached_input_tokens'])})  "
                f"output={human_int(a['output_tokens'])}  tool-result≈{human_int(a['tool_result_tokens_proxy'])}  "
                f"compactions={a['compactions']}  max context={a['max_peak_context_pct']*100:.1f}%"
            )
        lines.append("")

    ranked = rank_sessions(sessions)
    display = ranked if show_all else ranked[:top]
    lines.append(c("Session health ranking", "cyan", colour))
    header = f"{'#':>2} {'G':<1} {'Prov':<6} {'Score':>5} {'Turns':>6} {'Context':>10} {'ToolOut':>9} {'Gap':>8}  Session / project"
    lines.append(header)
    lines.append("-" * min(160, len(header) + 40))
    for i, s in enumerate(display, 1):
        grade_colour = {"A": "green", "B": "blue", "C": "yellow", "D": "red", "F": "red"}.get(s.grade, "reset")
        ctx = f"{s.peak_context_pct*100:.1f}%" if s.provider == "codex" and s.peak_context_pct else human_int(s.peak_context_tokens)
        gap = f"{s.max_idle_gap_seconds/3600:.1f}h" if s.max_idle_gap_seconds else "-"
        label = s.title or s.session_id
        proj = s.cwd or s.project
        lines.append(
            f"{i:>2} {c(s.grade, grade_colour, colour):<1} {s.provider:<6} {s.score:>5} {s.model_turns:>6} "
            f"{ctx:>10} {human_int(s.tool_result_tokens_proxy):>9} {gap:>8}  {truncate(label, 30)} | {truncate(proj, 48)}"
        )
    lines.append("")

    for s in ranked[:details]:
        lines.extend(render_terminal_detail(s, colour))
        lines.append("")
    return "\n".join(lines)


def marker_score_text(marker: MarkerScore, include_percent: bool = False) -> str:
    if marker.score is None:
        return "N/A"
    if include_percent:
        return f"{marker.score}/5 ({marker.percent}%)"
    return f"{marker.score}/5"


def lane_score_text(score: Optional[int]) -> str:
    return "N/A" if score is None else f"{score}/100"


def render_terminal_detail(s: SessionSummary, colour: bool) -> list[str]:
    lines: list[str] = []
    title = s.title or s.session_id
    lines.append(c(f"[{s.grade}] {s.provider.upper()} — {title}", "bold", colour))
    lines.append(f"  id={s.session_id}  version={s.version or '-'}  model={s.model or '-'}  effort={s.effort or '-'}")
    lines.append(f"  cwd={s.cwd or '-'}")
    lines.append(f"  span={s.start or '-'} → {s.end or '-'}  active≈{human_duration(s.active_seconds)}  bursts={len(s.bursts)}  max-gap={s.max_idle_gap_seconds/3600:.1f}h")
    if s.provider == "claude":
        lines.append(
            f"  model-turns={s.model_turns}  logged-token-work≈{human_int(s.logged_processed_tokens)}  "
            f"cache-read={human_int(s.cached_input_tokens)}  cache-create={human_int(s.cache_creation_tokens)}  "
            f"peak-request-context≈{human_int(s.peak_context_tokens)}  >=150k turns={s.costly_context_turns} ({s.costly_context_turn_pct*100:.0f}%)"
        )
        if s.advisor_calls:
            lines.append(f"  advisor={s.advisor_calls} calls, input≈{human_int(s.advisor_input_tokens)}  subagents={s.subagent_count}, subagent logged≈{human_int(s.subagent_logged_tokens)}")
    else:
        lines.append(
            f"  cumulative={human_int(s.logged_processed_tokens)}  input={human_int(s.input_tokens)} (cached subset {human_int(s.cached_input_tokens)})  "
            f"output={human_int(s.output_tokens)}  reasoning={human_int(s.reasoning_tokens)}"
        )
        lines.append(
            f"  peak-context={human_int(s.peak_context_tokens)}/{human_int(s.context_window_tokens)} ({s.peak_context_pct*100:.1f}%)  "
            f"compactions={s.compactions}  post-compact repeats={s.post_compact_repeats}  rate-limit={s.rate_limit_start_pct}->{s.rate_limit_end_pct}%"
        )
    lines.append(
        f"  tools={s.tool_calls} calls / {s.tool_results} results, tool-output≈{human_int(s.tool_result_tokens_proxy)} tokens/proxy, max≈{human_int(s.max_tool_result_tokens_proxy)}"
    )
    marker_text = ", ".join(f"{marker.code}={marker_score_text(marker)}" for marker in s.marker_scores)
    lines.append(
        f"  scorecard=v{MARKER_SCORING_VERSION} {MARKER_SCORING_STATUS}; efficiency="
        f"{s.overall_efficiency_score if s.overall_efficiency_score is not None else 'N/A'}/100; "
        f"effective-severity={s.effective_severity.value}; trend={s.trend.value}"
    )
    lines.append(f"  markers: {marker_text}")
    if s.worst_indicators:
        lines.append(f"  worst indicators: {', '.join(s.worst_indicators)}")
    risk = s.causal_risk
    lines.append(f"  causal-risk: current={risk.current_severity.value}; effective={risk.effective_severity.value}; trend={risk.trend}; predicted={risk.predicted_next_risk_state.value if risk.predicted_next_risk_state else 'N/A'}")
    for explanation in risk.explanations:
        lines.append(f"  causal path: {explanation}")
    for opportunity in s.corrective_opportunities:
        lines.append(f"  corrective opportunity: {opportunity}")
    if s.repeated_reads:
        lines.append(f"  top repeated read: {truncate(s.repeated_reads[0][0], 100)} ×{s.repeated_reads[0][1]}")
    if s.repeated_commands:
        lines.append(f"  top repeated command: {truncate(s.repeated_commands[0][0], 100)} ×{s.repeated_commands[0][1]}")
    if s.persisted_output_files:
        lines.append(f"  sidecar raw outputs: {s.persisted_output_files} files / {human_bytes(s.persisted_output_bytes)} (reported separately; not assumed in context)")
    if not s.defects:
        lines.append(c("  No configured defects triggered.", "green", colour))
    else:
        lines.append("  Flags:")
        for d in sorted(s.defects, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
            col = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}.get(d.severity, "reset")
            lines.append(f"    {c(d.severity.upper(), col, colour):<8} {d.code}: {d.message}")
            if d.recommendation:
                lines.append(f"             ↳ {d.recommendation}")
    return lines


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(sessions: list[SessionSummary], roots: list[tuple[Path, str]], details: int = 20) -> str:
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    sev = severity_counts(sessions)
    lines = [
        "# Agentopsy Session Analysis Report",
        "",
        f"Generated: `{now}`  ",
        f"Analyzer version: `{VERSION}`",
        "",
        "> Local forensic analysis only. Transcript content was not sent to any model or external service.",
        "",
        "## Sources",
        "",
    ]
    for root, label in roots:
        lines.append(f"- `{label}`: `{root}`")
    lines += [
        "",
        "## Executive summary",
        "",
        f"- Sessions analysed: **{len(sessions)}**",
        f"- Claude sessions: **{sum(s.provider == 'claude' for s in sessions)}**",
        f"- Codex sessions: **{sum(s.provider == 'codex' for s in sessions)}**",
        f"- Flags: **{sev['critical']} critical**, **{sev['high']} high**, **{sev['medium']} medium**, **{sev['low']} low**",
        "",
    ]
    for provider in ("claude", "codex"):
        a = provider_aggregate(sessions, provider)
        if not a["sessions"]:
            continue
        lines.append(f"### {provider.title()} aggregate")
        lines.append("")
        if provider == "claude":
            lines += [
                f"- Sessions: {a['sessions']}",
                f"- Unique model turns: {human_int(a['model_turns'])}",
                f"- Logged model-token work (iteration-aware): ~{human_int(a['logged_processed_tokens'])}",
                f"- Cache-read tokens logged: {human_int(a['cached_input_tokens'])}",
                f"- Tool-result/output volume: ~{human_int(a['tool_result_tokens_proxy'])} proxy tokens",
                f"- Advisor calls: {a['advisor_calls']}",
                f"- Claude subagents attached to top-level sessions: {a['subagents']}",
                f"- Highest logged single request/advisor context: ~{human_int(a['max_peak_context_tokens'])}",
            ]
        else:
            lines += [
                f"- Sessions: {a['sessions']}",
                f"- Cumulative logged total tokens: {human_int(a['logged_processed_tokens'])}",
                f"- Input tokens: {human_int(a['input_tokens'])} (cached input is a subset: {human_int(a['cached_input_tokens'])})",
                f"- Output tokens: {human_int(a['output_tokens'])}",
                f"- Tool-result/output volume: ~{human_int(a['tool_result_tokens_proxy'])} proxy/recorded tokens",
                f"- Compactions: {a['compactions']}",
                f"- Highest context-window occupancy: {a['max_peak_context_pct']*100:.1f}%",
            ]
        lines.append("")

    lines += [
        "## All sessions",
        "",
        "| Grade | Provider | Score | Session | Project/CWD | Turns | Peak context | Tool output | Max idle gap | Critical/High flags |",
        "|---|---|---:|---|---|---:|---:|---:|---:|---|",
    ]
    for s in rank_sessions(sessions):
        ctx = f"{s.peak_context_pct*100:.1f}%" if s.provider == "codex" and s.peak_context_pct else human_int(s.peak_context_tokens)
        gap = f"{s.max_idle_gap_seconds/3600:.1f}h" if s.max_idle_gap_seconds else "-"
        flags = ", ".join(d.code for d in s.defects if d.severity in {"critical", "high"}) or "-"
        lines.append(
            f"| **{s.grade}** | {s.provider} | {s.score} | `{md_escape(s.session_id)}` | `{md_escape(truncate(s.cwd or s.project, 70))}` | "
            f"{s.model_turns} | {ctx} | {human_int(s.tool_result_tokens_proxy)} | {gap} | {md_escape(flags)} |"
        )

    lines += ["", f"## Detailed findings, top {min(details, len(sessions))} sessions", ""]
    for s in rank_sessions(sessions)[:details]:
        lines.extend(render_markdown_detail(s))
    lines += [
        "## Interpretation notes",
        "",
        "- Claude logs can repeat streaming records for the same assistant message. The analyser deduplicates by message/request ID before counting usage.",
        "- Claude `usage.iterations` is used when present. This separates ordinary message iterations from advisor iterations and avoids treating a multi-iteration aggregate as one context window.",
        "- Claude context figures are logged request-context estimates (`input + cache creation + cache read` per iteration). The transcript does not provide a reliable universal model-context-window denominator, so the default report uses absolute thresholds such as 150k/250k/400k rather than inventing a percentage.",
        "- Codex `total_token_usage` is cumulative session usage. `last_token_usage` is used for context-window occupancy; cached input is a subset of input tokens and is not added a second time.",
        "- Tool-result token figures use Codex `Original token count` when available, which can describe pre-truncation command output; otherwise they use a `characters / 4` proxy. They are noise/efficiency diagnostics, not billing figures and not necessarily all model-visible context.",
        "- Claude persisted-output sidecar files are reported separately and are **not** assumed to have entered model context unless the transcript itself contains them.",
        "- A long-gap reuse flag means the same transcript resumed after a long idle period. It does not infer who or what resumed it; it flags the workflow risk.",
        "",
    ]
    return "\n".join(lines)


def render_markdown_detail(s: SessionSummary) -> list[str]:
    lines = [
        f"### [{s.grade}] {s.provider.title()} `{s.session_id}`",
        "",
        f"- Path: `{s.path}`",
        f"- CWD/project: `{s.cwd or s.project}`",
        f"- Version/model/effort: `{s.version or '-'} / {s.model or '-'} / {s.effort or '-'}`",
        f"- Span: `{s.start or '-'}` → `{s.end or '-'}`",
        f"- Active time across bursts: ~{human_duration(s.active_seconds)}; longest burst {human_duration(s.longest_burst_seconds)}; max idle gap {s.max_idle_gap_seconds/3600:.1f}h",
        f"- Tool calls/results: {s.tool_calls}/{s.tool_results}; tool output generated/proxy ~{human_int(s.tool_result_tokens_proxy)} tokens/proxy; largest ~{human_int(s.max_tool_result_tokens_proxy)}",
    ]
    if s.provider == "claude":
        lines += [
            f"- Unique model turns: {s.model_turns}",
            f"- Logged model-token work: ~{human_int(s.logged_processed_tokens)}",
            f"- Cache read/create: {human_int(s.cached_input_tokens)} / {human_int(s.cache_creation_tokens)}",
            f"- Peak logged request/advisor context: ~{human_int(s.peak_context_tokens)}",
            f"- Main-message iterations at >=150k: {s.costly_context_turns} ({s.costly_context_turn_pct*100:.1f}%)",
            f"- Advisor: {s.advisor_calls} calls, ~{human_int(s.advisor_input_tokens)} input/context tokens",
            f"- Attached Claude subagents: {s.subagent_count}; subagent logged token work ~{human_int(s.subagent_logged_tokens)}",
        ]
    else:
        lines += [
            f"- Cumulative token usage: {human_int(s.logged_processed_tokens)}",
            f"- Input: {human_int(s.input_tokens)}; cached-input subset: {human_int(s.cached_input_tokens)}; output: {human_int(s.output_tokens)}; reasoning-output subset: {human_int(s.reasoning_tokens)}",
            f"- Peak context: {human_int(s.peak_context_tokens)} / {human_int(s.context_window_tokens)} ({s.peak_context_pct*100:.1f}%)",
            f"- Compactions: {s.compactions}; exact command repeats within 5m post-compaction: {s.post_compact_repeats}",
            f"- Rate-limit used % observed: {s.rate_limit_start_pct} → {s.rate_limit_end_pct} (peak {s.rate_limit_peak_pct})",
            f"- Persisted instruction payload observed: {human_int(s.instruction_chars)} chars; duplicate instruction blocks: {s.instruction_duplicates}",
        ]
    if s.repeated_reads:
        lines.append(f"- Top repeated read/path: `{md_escape(truncate(s.repeated_reads[0][0], 160))}` ×{s.repeated_reads[0][1]}")
    if s.repeated_commands:
        lines.append(f"- Top repeated command: `{md_escape(truncate(s.repeated_commands[0][0], 160))}` ×{s.repeated_commands[0][1]}")
    if s.persisted_output_files:
        lines.append(f"- Persisted raw-output sidecars: {s.persisted_output_files} files, {human_bytes(s.persisted_output_bytes)}")
    lines += [
        f"- Marker scorecard: provisional v{MARKER_SCORING_VERSION}; overall efficiency **{s.overall_efficiency_score if s.overall_efficiency_score is not None else 'N/A'}/100**; effective severity **{s.effective_severity.value}**; trend `{s.trend.value}`.",
        "- Marker scores: " + "; ".join(
            f"`{marker.code}` {marker_score_text(marker, include_percent=True)}" for marker in s.marker_scores
        ),
        "- Lane scores: " + "; ".join(
            f"`{lane}` {lane_score_text(score)}" for lane, score in s.lane_scores.items()
        ),
    ]
    if s.worst_indicators:
        lines.append("- Worst indicators: " + ", ".join(f"`{code}`" for code in s.worst_indicators))
    if s.corrective_opportunities:
        lines.append("- Corrective opportunities: " + " ".join(s.corrective_opportunities))
    lines.append(f"- Causal risk: current **{s.causal_risk.current_severity.value}**; effective **{s.causal_risk.effective_severity.value}**; trend `{s.causal_risk.trend}`; predicted next state `{s.causal_risk.predicted_next_risk_state.value if s.causal_risk.predicted_next_risk_state else 'N/A'}`.")
    for explanation in s.causal_risk.explanations:
        lines.append(f"  - Causal path: {explanation}")
    lines += ["", "**Flags**", ""]
    if not s.defects:
        lines.append("- None triggered by the current rules.")
    else:
        for d in sorted(s.defects, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
            lines.append(f"- **{d.severity.upper()} `{d.code}`**: {d.message}")
            if d.recommendation:
                lines.append(f"  - Recommendation: {d.recommendation}")
    lines.append("")
    return lines


def write_json_report(path: Path, sessions: list[SessionSummary], roots: list[tuple[Path, str]]) -> None:
    payload = {
        "schema": 1,
        "analyzer_version": VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "sources": [{"path": str(p), "label": label} for p, label in roots],
        "sessions": [s.to_dict() for s in sessions],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def scan_once(args: argparse.Namespace) -> tuple[list[SessionSummary], list[tuple[Path, str]], list[Candidate]]:
    with MaterialisedSources(args.source) as ms:
        roots = list(ms.roots)
        if not roots:
            raise RuntimeError(
                "No session stores found. Expected ~/.claude/projects and/or ~/.codex/sessions, "
                "or pass --source PATH/ZIP."
            )
        candidates = collect_candidates(roots, args.provider)
        if not candidates:
            raise RuntimeError("No Claude Code or Codex JSONL sessions found in the selected sources.")
        summaries: list[SessionSummary] = []
        for cand in candidates:
            if args.verbose:
                print(f"[scan] {cand.provider:6s} {cand.display_path}", file=sys.stderr)
            if cand.provider == "claude":
                summaries.append(parse_claude(cand, args.gap_minutes))
            else:
                summaries.append(parse_codex(cand, args.gap_minutes))
        cindex = {f"{c.source_label}|{c.display_path}": c for c in candidates}
        summaries = filter_sessions(
            summaries,
            parse_relative_time(args.since),
            args.project or "",
            args.include_subagents,
            cindex,
        )
        # Materialised ZIP temp paths are about to vanish; rewrite roots to stable labels
        # for report output while keeping source descriptions accurate.
        stable_roots = []
        for root, label in roots:
            if label.startswith("zip:"):
                stable_roots.append((Path(label[4:]), label))
            else:
                stable_roots.append((root, label))
        return summaries, stable_roots, candidates



def _session_sort_dt(s: SessionSummary) -> dt.datetime:
    value = iso_to_dt(s.end) or iso_to_dt(s.start)
    if value is None:
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value


def select_sessions(sessions: list[SessionSummary], selectors: list[str], last_n: int) -> list[SessionSummary]:
    """Apply explicit session-ID/prefix or latest-per-provider selection."""
    if selectors and last_n:
        raise ValueError("--session and --last are alternative selectors; use one or the other")

    if selectors:
        selected: list[SessionSummary] = []
        seen: set[tuple[str, str, str]] = set()
        for raw in selectors:
            token = raw.strip().lower()
            if not token:
                continue
            exact = [s for s in sessions if s.session_id.lower() == token]
            matches = exact or [s for s in sessions if s.session_id.lower().startswith(token)]
            ids = sorted({s.session_id for s in matches})
            if not matches:
                raise ValueError(f"No selected session matches {raw!r}. Run --sessions to list available IDs.")
            if len(ids) > 1:
                preview = ", ".join(ids[:6])
                if len(ids) > 6:
                    preview += ", ..."
                raise ValueError(f"Session prefix {raw!r} is ambiguous: {preview}")
            for item in matches:
                key = (item.provider, item.session_id, item.path)
                if key not in seen:
                    selected.append(item)
                    seen.add(key)
        return sorted(selected, key=_session_sort_dt, reverse=True)

    if last_n:
        if last_n < 1:
            raise ValueError("--last must be at least 1")
        selected = []
        for provider in ("claude", "codex"):
            provider_sessions = [s for s in sessions if s.provider == provider]
            selected.extend(sorted(provider_sessions, key=_session_sort_dt, reverse=True)[:last_n])
        return sorted(selected, key=_session_sort_dt, reverse=True)

    return sessions


def format_session_date(s: SessionSummary) -> str:
    stamp = _session_sort_dt(s)
    if stamp.year == 1:
        return "-"
    return stamp.astimezone().strftime("%Y-%m-%d %H:%M %Z")


def format_summary_timestamp(value: str) -> str:
    stamp = iso_to_dt(value)
    if not stamp:
        return "time unavailable"
    if stamp.tzinfo is None:
        zone = "timezone unknown"
    else:
        zone = stamp.tzname() or "timezone unknown"
    return f"{stamp.strftime('%Y-%m-%d %H:%M')} {zone}"


def format_summary_session_span(s: SessionSummary) -> str:
    start = iso_to_dt(s.start)
    end = iso_to_dt(s.end)
    if not start or not end:
        if start:
            return f"{format_summary_timestamp(s.start)}–time unavailable"
        if end:
            return f"time unavailable–{format_summary_timestamp(s.end)}"
        return "time unavailable"

    start_text = format_summary_timestamp(s.start)
    end_text = format_summary_timestamp(s.end)
    if start.date() == end.date() and start.tzname() == end.tzname():
        zone = start.tzname() if start.tzinfo is not None else "timezone unknown"
        return f"{start.strftime('%Y-%m-%d %H:%M')}–{end.strftime('%H:%M')} {zone}"
    return f"{start_text}–{end_text}"


def render_session_list(sessions: list[SessionSummary]) -> str:
    """Minimal copy-friendly list for later --session selection."""
    ordered = sorted(sessions, key=_session_sort_dt, reverse=True)
    lines = ["#   Provider  Date/Time                 Session ID", "-" * 88]
    for index, s in enumerate(ordered, 1):
        lines.append(f"{index:<3} {s.provider:<8} {format_session_date(s):<25} {s.session_id}")
    if not ordered:
        lines.append("(no sessions selected)")
    return "\n".join(lines)


def render_summary(sessions: list[SessionSummary]) -> str:
    """Provider aggregate summary only, intentionally compact and copy-friendly."""
    lines: list[str] = []
    number = 0
    for provider in ("claude", "codex"):
        a = provider_aggregate(sessions, provider)
        if not a["sessions"]:
            continue
        number += 1
        label = provider.title()
        provider_sessions = [s for s in sessions if s.provider == provider]
        heading = f"{number}. {label}"
        if len(provider_sessions) == 1:
            heading += f" — {format_summary_session_span(provider_sessions[0])}"
        lines += [heading, "─" * 48]
        if provider == "claude":
            lines += [
                f"{a['sessions']} session{'s' if a['sessions'] != 1 else ''}",
                f"~{human_int(a['model_turns'])} unique model iterations",
                f"~{human_int(a['logged_processed_tokens'])} logged model-token work",
                f"~{human_int(a['cached_input_tokens'])} cache-read tokens",
                f"~{human_int(a['tool_result_tokens_proxy'])} tool-result proxy tokens",
                f"{a['advisor_calls']} advisor calls",
                f"{a['subagents']} attached subagents",
                f"highest logged request/advisor context: ~{human_int(a['max_peak_context_tokens'])}",
            ]
        else:
            lines += [
                f"{a['sessions']} session{'s' if a['sessions'] != 1 else ''}",
                f"~{human_int(a['logged_processed_tokens'])} cumulative logged tokens",
                f"~{human_int(a['input_tokens'])} input",
                f"~{human_int(a['cached_input_tokens'])} cached-input subset",
                f"~{human_int(a['output_tokens'])} output",
                f"{a['compactions']} compactions",
                f"highest context occupancy: {a['max_peak_context_pct']*100:.1f}%",
                f"tool-output generated/proxy: ~{human_int(a['tool_result_tokens_proxy'])}",
            ]
        lines.append("")
    return "\n".join(lines).rstrip()


def render_summary_markdown(sessions: list[SessionSummary], roots: list[tuple[Path, str]]) -> str:
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    lines = [
        "# Agentopsy Summary",
        "",
        f"Generated: `{now}`",
        "",
        "> Local analysis only. Transcript content was not sent to any model or external service.",
        "",
        "```text",
        render_summary(sessions),
        "```",
        "",
    ]
    return "\n".join(lines)


def write_markdown_export(path_value: str, sessions: list[SessionSummary], roots: list[tuple[Path, str]], summary_only: bool, details: int) -> Path:
    path = Path(os.path.expanduser(path_value))
    path.parent.mkdir(parents=True, exist_ok=True)
    text = render_summary_markdown(sessions, roots) if summary_only else render_markdown(sessions, roots, details=details)
    path.write_text(text, encoding="utf-8")
    return path


def export_selected(args: argparse.Namespace, sessions: list[SessionSummary], roots: list[tuple[Path, str]]) -> list[str]:
    notices: list[str] = []
    requests = [
        (args.export_file, sessions, "Report"),
        (args.export_claude, [s for s in sessions if s.provider == "claude"], "Claude report"),
        (args.export_codex, [s for s in sessions if s.provider == "codex"], "Codex report"),
    ]
    for filename, subset, label in requests:
        if not filename:
            continue
        if not subset:
            notices.append(f"{label}: skipped, no matching sessions in the current selection")
            continue
        path = write_markdown_export(filename, subset, roots, args.summary, args.details)
        notices.append(f"{label}: {path}")
    return notices


def default_state_dir(value: Optional[str] = None) -> Path:
    return Path(os.path.expanduser(value or os.environ.get("AGENTOPSY_STATE_DIR", "~/.local/state/agentopsy")))


def _canonical_transcript_path(value: str) -> str:
    """Canonicalise metadata only; never open or retain transcript contents."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("missing transcript_path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("transcript_path must be absolute")
    return str(path.resolve(strict=False))


def _identity_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _socket_request(socket_path: str, method: str, params: dict[str, Any], *, timeout: float = 0.5) -> Optional[dict[str, Any]]:
    """Small local-only Herdr RPC helper. A transport error is never fatal."""
    request = {"id": f"agentopsy:{time.time_ns()}", "method": method, "params": params}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(socket_path)
            client.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
            response = client.recv(16384)
        parsed = json.loads(response.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def report_herdr_session(provider: str, native_session_id: str, pane_id: str, socket_path: str, *, source: str) -> bool:
    """Register a provider-native ID on the current Herdr pane and require an RPC acknowledgement."""
    if provider != "codex" or not native_session_id or not pane_id or not socket_path:
        return False
    reply = _socket_request(socket_path, "pane.report_agent_session", {
        "pane_id": pane_id, "source": source, "agent": provider,
        "seq": time.time_ns(), "agent_session_id": native_session_id,
    })
    return bool(reply and "error" not in reply and "result" in reply)


def identity_hook_payload(payload: Any, *, state_dir: Optional[str] = None, environ: Optional[dict[str, str]] = None) -> bool:
    """Consume trusted Codex lifecycle JSON. Never writes stdout or transcript content."""
    if not isinstance(payload, dict):
        return False
    env = os.environ if environ is None else environ
    if payload.get("hook_event_name") not in {"SessionStart", "PreCompact", "PostCompact"}:
        return False
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return False
    provider = "codex"
    event = str(payload["hook_event_name"])
    source = payload.get("source") if event == "SessionStart" else None
    source = source if isinstance(source, str) and source else ""
    transcript = payload.get("transcript_path")
    try:
        transcript_path = _canonical_transcript_path(transcript) if isinstance(transcript, str) else ""
    except ValueError:
        return False
    store = StateStore(state_dir)
    try:
        if event != "SessionStart":
            store.record_identity_lifecycle(provider, session_id, event, source)
            store.db.commit()
            return True
        if env.get("HERDR_ENV") != "1":
            return False
        pane_id, socket_path = env.get("HERDR_PANE_ID", ""), env.get("HERDR_SOCKET_PATH", "")
        if not report_herdr_session(provider, session_id, pane_id, socket_path, source="agentopsy:codex"):
            return False
        store.register_identity(provider, session_id, transcript_path, pane_id, source)
        store.db.commit()
        return True
    except Exception:
        return False
    finally:
        store.close()


def identity_hook_main(provider: str, state_dir: Optional[str] = None) -> int:
    """Hook command entry point: fail closed and always return success to Codex."""
    if provider != "codex":
        return 0
    try:
        raw = sys.stdin.buffer.read(65536)
        payload = json.loads(raw.decode("utf-8")) if raw else None
        identity_hook_payload(payload, state_dir=state_dir)
    except Exception:
        pass
    return 0


class StateStore:
    """Transactional, local-only state. Raw transcript records are never stored."""
    def __init__(self, state_dir: Optional[str] = None):
        self.dir = default_state_dir(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        try: os.chmod(self.dir, 0o700)
        except OSError: pass
        self.path = self.dir / "agentopsy.db"
        self.db = sqlite3.connect(self.path)
        try: os.chmod(self.path, 0o600)
        except OSError: pass
        try:
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self._migrate()
        except BaseException:
            try: self.db.close()
            except BaseException: pass
            raise

    def close(self) -> None: self.db.close()

    def _migrate(self) -> None:
        # A routine collector opening an already-current database should not
        # contend for a writer lock merely to restate metadata.  This read-only
        # fast path is also important for a daemon and CLI briefly overlapping.
        try:
            version = self.db.execute("SELECT value FROM service_meta WHERE key='schema_version'").fetchone()
            parser = self.db.execute("SELECT value FROM service_meta WHERE key='parser_version'").fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc).lower():
                raise
        else:
            if version and int(version[0]) == SCHEMA_VERSION and parser and int(parser[0]) == PARSER_VERSION:
                return
        self.db.execute("CREATE TABLE IF NOT EXISTS service_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            version = self.db.execute("SELECT value FROM service_meta WHERE key='schema_version'").fetchone()
            current = int(version[0]) if version else 0
            self._migration_origin_version = current
            if current > SCHEMA_VERSION:
                raise RuntimeError("state database is newer than this Agentopsy version")
            for target, migration in self._migration_steps():
                if target <= current:
                    continue
                migration()
                self.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('schema_version',?)", (str(target),))
                current = target
            self.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('parser_version',?)", (str(PARSER_VERSION),))
        except Exception:
            self.db.rollback()
            raise
        else:
            self.db.commit()

    def _migration_steps(self) -> tuple[tuple[int, Any], ...]:
        return ((1, self._migration_v1), (2, self._migration_v2), (3, self._migration_v3), (4, self._migration_v4), (5, self._migration_v5), (6, self._migration_v6))

    def _migration_v1(self) -> None:
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS files (
              id INTEGER PRIMARY KEY, provider TEXT NOT NULL, path TEXT NOT NULL UNIQUE,
              identity TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, mtime_ns INTEGER NOT NULL DEFAULT 0,
              last_offset INTEGER NOT NULL DEFAULT 0, partial_line TEXT NOT NULL DEFAULT '', session_id TEXT NOT NULL DEFAULT '',
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, parser_version INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'ok');
            CREATE TABLE IF NOT EXISTS sessions (
              session_id TEXT NOT NULL, provider TEXT NOT NULL, project TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '',
              started_at TEXT NOT NULL DEFAULT '', last_activity_at TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', effort TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
              model_turns INTEGER NOT NULL DEFAULT 0, tool_calls INTEGER NOT NULL DEFAULT 0, tool_result_chars INTEGER NOT NULL DEFAULT 0,
              max_tool_result_chars INTEGER NOT NULL DEFAULT 0, input_tokens INTEGER NOT NULL DEFAULT 0, cached_input_tokens INTEGER NOT NULL DEFAULT 0,
              cache_creation_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, reasoning_tokens INTEGER NOT NULL DEFAULT 0,
              peak_context_tokens INTEGER NOT NULL DEFAULT 0, context_window_tokens INTEGER NOT NULL DEFAULT 0, peak_context_pct REAL NOT NULL DEFAULT 0,
              compactions INTEGER NOT NULL DEFAULT 0, repeated_reads INTEGER NOT NULL DEFAULT 0, repeated_commands INTEGER NOT NULL DEFAULT 0,
              malformed_records INTEGER NOT NULL DEFAULT 0, health_state TEXT NOT NULL DEFAULT 'HEALTHY', health_since TEXT NOT NULL DEFAULT '',
              PRIMARY KEY(session_id, provider));
            CREATE TABLE IF NOT EXISTS health_events (
              id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, session_id TEXT NOT NULL, provider TEXT NOT NULL,
              severity TEXT NOT NULL, code TEXT NOT NULL, message TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '{}', resolved_at TEXT, UNIQUE(session_id, provider, code, resolved_at));
            CREATE TABLE IF NOT EXISTS occurrences (
              session_id TEXT NOT NULL, provider TEXT NOT NULL, kind TEXT NOT NULL, key_hash TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(session_id, provider, kind, key_hash));
            CREATE TABLE IF NOT EXISTS record_dedup (
              session_id TEXT NOT NULL, provider TEXT NOT NULL, kind TEXT NOT NULL, key_hash TEXT NOT NULL,
              PRIMARY KEY(session_id, provider, kind, key_hash));
            """)

    def _migration_v2(self) -> None:
        """Add Context Guardian's multi-lane, action-safety event foundation."""
        self.db.execute("""CREATE TABLE guardian_events (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, session_id TEXT NOT NULL, provider TEXT NOT NULL,
            severity TEXT NOT NULL, action_safety TEXT NOT NULL, code TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '{}', resolved_at TEXT)""")
        self.db.execute("""CREATE TABLE guardian_event_lanes (
            event_id INTEGER NOT NULL REFERENCES guardian_events(id) ON DELETE CASCADE,
            lane TEXT NOT NULL, PRIMARY KEY(event_id, lane))""")
        self.db.execute("CREATE INDEX guardian_events_session_idx ON guardian_events(session_id, provider, timestamp DESC)")

    def _migration_v3(self) -> None:
        self.db.execute("""CREATE TABLE telemetry_samples (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, session_id TEXT NOT NULL, provider TEXT NOT NULL,
            turn_index INTEGER NOT NULL, context_tokens INTEGER, context_pct REAL,
            tool_output_chars INTEGER NOT NULL DEFAULT 0, read_hash TEXT NOT NULL DEFAULT '', command_hash TEXT NOT NULL DEFAULT '', content_hash TEXT NOT NULL DEFAULT '',
            cached_input_tokens INTEGER, instruction_chars INTEGER, compaction INTEGER NOT NULL DEFAULT 0)""")
        self.db.execute("CREATE INDEX telemetry_samples_session_idx ON telemetry_samples(session_id, provider, id DESC)")

    def _migration_v4(self) -> None:
        """Metadata-only, short-lived provider-to-Herdr identity bridge."""
        self.db.execute("""CREATE TABLE identity_mappings (
            id INTEGER PRIMARY KEY, provider TEXT NOT NULL, native_session_id TEXT NOT NULL,
            transcript_path TEXT NOT NULL, pane_id TEXT NOT NULL, lifecycle_source TEXT NOT NULL DEFAULT '',
            observed_at TEXT NOT NULL, expires_at TEXT NOT NULL, confidence TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            UNIQUE(provider, native_session_id, transcript_path, pane_id))""")
        self.db.execute("CREATE INDEX identity_mappings_lookup_idx ON identity_mappings(provider, native_session_id, active, expires_at DESC)")
        self.db.execute("CREATE INDEX identity_mappings_pane_idx ON identity_mappings(provider, pane_id, active)")
        self.db.execute("""CREATE TABLE identity_lifecycle (
            id INTEGER PRIMARY KEY, provider TEXT NOT NULL, native_session_id TEXT NOT NULL,
            hook_event_name TEXT NOT NULL, lifecycle_source TEXT NOT NULL DEFAULT '', observed_at TEXT NOT NULL)""")
        self.db.execute("CREATE INDEX identity_lifecycle_lookup_idx ON identity_lifecycle(provider, native_session_id, observed_at DESC)")

    def _migration_v5(self) -> None:
        """Replace unsplittable v4 derived state with a durable v5 rebuild gate.

        v4's (provider, session_id) aggregates cannot be safely partitioned
        into rollout streams.  Keeping them would make a merged reviewer look
        like a MAIN stream, so migration deliberately invalidates source-derived
        state and requires one transactional replay from discoverable roots.
        """
        # Some early development databases recorded schema_version=1 while
        # lacking optional v1 tables.  Materialise empty legacy shapes so this
        # migration remains a safe upgrade rather than assuming a perfect dump.
        self.db.execute("CREATE TABLE IF NOT EXISTS health_events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, session_id TEXT NOT NULL, provider TEXT NOT NULL, severity TEXT NOT NULL, code TEXT NOT NULL, message TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '{}', resolved_at TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS occurrences (session_id TEXT NOT NULL, provider TEXT NOT NULL, kind TEXT NOT NULL, key_hash TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(session_id,provider,kind,key_hash))")
        self.db.execute("CREATE TABLE IF NOT EXISTS record_dedup (session_id TEXT NOT NULL, provider TEXT NOT NULL, kind TEXT NOT NULL, key_hash TEXT NOT NULL, PRIMARY KEY(session_id,provider,kind,key_hash))")
        for table in ("guardian_event_lanes", "guardian_events", "telemetry_samples", "record_dedup", "occurrences", "health_events", "sessions"):
            self.db.execute(f"ALTER TABLE {table} RENAME TO {table}_v4")
        self.db.executescript("""
            CREATE TABLE sessions (
              session_id TEXT NOT NULL, provider TEXT NOT NULL, stream_id TEXT NOT NULL DEFAULT '',
              role TEXT NOT NULL DEFAULT 'MAIN', parent_session_id TEXT NOT NULL DEFAULT '', parent_stream_id TEXT NOT NULL DEFAULT '', thread_source TEXT NOT NULL DEFAULT '',
              project TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL DEFAULT '', last_activity_at TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', effort TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
              model_turns INTEGER NOT NULL DEFAULT 0, tool_calls INTEGER NOT NULL DEFAULT 0, tool_result_chars INTEGER NOT NULL DEFAULT 0, max_tool_result_chars INTEGER NOT NULL DEFAULT 0,
              input_tokens INTEGER NOT NULL DEFAULT 0, cached_input_tokens INTEGER NOT NULL DEFAULT 0, cache_creation_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, reasoning_tokens INTEGER NOT NULL DEFAULT 0,
              peak_context_tokens INTEGER NOT NULL DEFAULT 0, context_window_tokens INTEGER NOT NULL DEFAULT 0, peak_context_pct REAL NOT NULL DEFAULT 0,
              current_context_tokens INTEGER, current_context_pct REAL,
              compactions INTEGER NOT NULL DEFAULT 0, repeated_reads INTEGER NOT NULL DEFAULT 0, repeated_commands INTEGER NOT NULL DEFAULT 0,
              malformed_records INTEGER NOT NULL DEFAULT 0, health_state TEXT NOT NULL DEFAULT 'HEALTHY', health_since TEXT NOT NULL DEFAULT '',
              PRIMARY KEY(provider, stream_id));
            CREATE TABLE health_events (
              id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, session_id TEXT NOT NULL, provider TEXT NOT NULL, stream_id TEXT NOT NULL DEFAULT '',
              severity TEXT NOT NULL, code TEXT NOT NULL, message TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '{}', resolved_at TEXT,
              UNIQUE(provider, stream_id, code, resolved_at));
            CREATE TABLE occurrences (session_id TEXT NOT NULL, provider TEXT NOT NULL, stream_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, key_hash TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(provider, stream_id, kind, key_hash));
            CREATE TABLE record_dedup (session_id TEXT NOT NULL, provider TEXT NOT NULL, stream_id TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, key_hash TEXT NOT NULL, PRIMARY KEY(provider, stream_id, kind, key_hash));
            CREATE TABLE telemetry_samples (
              id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, session_id TEXT NOT NULL, provider TEXT NOT NULL, stream_id TEXT NOT NULL DEFAULT '', turn_index INTEGER NOT NULL,
              context_tokens INTEGER, context_pct REAL, tool_output_chars INTEGER NOT NULL DEFAULT 0, read_hash TEXT NOT NULL DEFAULT '', command_hash TEXT NOT NULL DEFAULT '', content_hash TEXT NOT NULL DEFAULT '', cached_input_tokens INTEGER, instruction_chars INTEGER, compaction INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE guardian_events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, session_id TEXT NOT NULL, provider TEXT NOT NULL, stream_id TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL, action_safety TEXT NOT NULL, code TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '{}', resolved_at TEXT);
            CREATE TABLE guardian_event_lanes (event_id INTEGER NOT NULL REFERENCES guardian_events(id) ON DELETE CASCADE, lane TEXT NOT NULL, PRIMARY KEY(event_id, lane));
            CREATE INDEX telemetry_samples_stream_idx ON telemetry_samples(provider, stream_id, id DESC);
            CREATE INDEX guardian_events_stream_idx ON guardian_events(provider, stream_id, timestamp DESC);
            CREATE INDEX sessions_native_idx ON sessions(provider, session_id, role, last_activity_at DESC);
        """)
        # Do not copy any v4 aggregate, event, dedup, or cursor.  A partial
        # copy is worse than an empty state because it can silently authorize
        # health/control decisions from a merged execution stream.
        for table in ("guardian_event_lanes_v4", "guardian_events_v4", "telemetry_samples_v4", "record_dedup_v4", "occurrences_v4", "health_events_v4", "sessions_v4"):
            self.db.execute(f"DROP TABLE {table}")
        self.db.execute("ALTER TABLE files ADD COLUMN stream_id TEXT NOT NULL DEFAULT ''")
        self.db.execute("DELETE FROM files")
        self.db.execute("DELETE FROM identity_mappings")
        self.db.execute("DELETE FROM identity_lifecycle")
        self.db.execute("DELETE FROM service_meta WHERE key IN ('calibration_profile','last_successful_scan')")
        if getattr(self, "_migration_origin_version", 0) >= 4:
            self.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('v5_rebuild_state','required')")

    def _migration_v6(self) -> None:
        """Privacy-safe Claude runtime semantic aggregates; never raw samples."""
        self.db.executescript("""
            CREATE TABLE claude_runtime_semantic_evidence (
              provider TEXT NOT NULL, claude_code_version TEXT NOT NULL,
              model_id TEXT NOT NULL, model_context_window_tokens INTEGER NOT NULL,
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
              samples_total INTEGER NOT NULL DEFAULT 0, stream_cursor_epochs_seen INTEGER NOT NULL DEFAULT 0,
              complete_nonzero_count INTEGER NOT NULL DEFAULT 0, complete_all_zero_count INTEGER NOT NULL DEFAULT 0,
              current_usage_null_count INTEGER NOT NULL DEFAULT 0, current_usage_missing_count INTEGER NOT NULL DEFAULT 0,
              partial_usage_count INTEGER NOT NULL DEFAULT 0, invalid_count INTEGER NOT NULL DEFAULT 0,
              counter_identity_testable INTEGER NOT NULL DEFAULT 0, counter_identity_pass INTEGER NOT NULL DEFAULT 0, counter_identity_fail INTEGER NOT NULL DEFAULT 0,
              window_present_count INTEGER NOT NULL DEFAULT 0, window_missing_count INTEGER NOT NULL DEFAULT 0, window_invalid_count INTEGER NOT NULL DEFAULT 0,
              numeric_valid_count INTEGER NOT NULL DEFAULT 0, numeric_invalid_count INTEGER NOT NULL DEFAULT 0,
              percentage_present_count INTEGER NOT NULL DEFAULT 0, percentage_missing_count INTEGER NOT NULL DEFAULT 0,
              percentage_valid_type_count INTEGER NOT NULL DEFAULT 0, percentage_invalid_type_count INTEGER NOT NULL DEFAULT 0,
              unknown_field_occurrence_count INTEGER NOT NULL DEFAULT 0, contradiction_count INTEGER NOT NULL DEFAULT 0,
              normal_to_zero INTEGER NOT NULL DEFAULT 0, normal_to_null INTEGER NOT NULL DEFAULT 0,
              zero_to_normal INTEGER NOT NULL DEFAULT 0, null_to_normal INTEGER NOT NULL DEFAULT 0,
              zero_to_zero INTEGER NOT NULL DEFAULT 0, null_to_null INTEGER NOT NULL DEFAULT 0,
              transition_without_recovery INTEGER NOT NULL DEFAULT 0,
              recovery_le_5s INTEGER NOT NULL DEFAULT 0, recovery_le_30s INTEGER NOT NULL DEFAULT 0,
              recovery_le_2m INTEGER NOT NULL DEFAULT 0, recovery_gt_2m INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(provider,claude_code_version,model_id,model_context_window_tokens)
            );
            CREATE TABLE claude_runtime_semantic_fingerprints (
              provider TEXT NOT NULL, claude_code_version TEXT NOT NULL, model_id TEXT NOT NULL, model_context_window_tokens INTEGER NOT NULL,
              context_window_fingerprint TEXT NOT NULL, current_usage_fingerprint TEXT NOT NULL,
              context_window_fields TEXT NOT NULL, current_usage_fields TEXT NOT NULL, unknown_fields_present INTEGER NOT NULL,
              count INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
              PRIMARY KEY(provider,claude_code_version,model_id,model_context_window_tokens,context_window_fingerprint,current_usage_fingerprint)
            );
            CREATE TABLE claude_runtime_semantic_streams (
              stream_hash TEXT PRIMARY KEY, previous_state TEXT NOT NULL, previous_receipt_ns INTEGER NOT NULL,
              provider TEXT NOT NULL, claude_code_version TEXT NOT NULL, model_id TEXT NOT NULL, model_context_window_tokens INTEGER NOT NULL,
              last_seen TEXT NOT NULL
            );
        """)

    def record_identity_lifecycle(self, provider: str, native_session_id: str, event: str, source: str = "") -> None:
        if provider != "codex" or not native_session_id or event not in {"SessionStart", "PreCompact", "PostCompact"}:
            raise ValueError("unsupported lifecycle identity metadata")
        self.db.execute("INSERT INTO identity_lifecycle(provider,native_session_id,hook_event_name,lifecycle_source,observed_at) VALUES(?,?,?,?,?)",
                        (provider, native_session_id, event, source, _identity_now().isoformat()))

    def register_identity(self, provider: str, native_session_id: str, transcript_path: str, pane_id: str, source: str = "") -> None:
        """Atomically supersede conflicting registrations; no heuristic joins."""
        if provider != "codex" or not native_session_id or not pane_id:
            raise ValueError("unsupported or incomplete identity registration")
        transcript_path = _canonical_transcript_path(transcript_path)
        now = _identity_now(); expiry = now + dt.timedelta(seconds=IDENTITY_TTL_SECONDS)
        # A pane may never retain an old native ID, and an ID may never retain an old transcript.
        self.db.execute("UPDATE identity_mappings SET active=0 WHERE provider=? AND active=1 AND (pane_id=? AND native_session_id<>? OR native_session_id=? AND transcript_path<>?)",
                        (provider, pane_id, native_session_id, native_session_id, transcript_path))
        self.db.execute("""INSERT INTO identity_mappings(provider,native_session_id,transcript_path,pane_id,lifecycle_source,observed_at,expires_at,confidence,active)
            VALUES(?,?,?,?,?,?,?,?,1)
            ON CONFLICT(provider,native_session_id,transcript_path,pane_id) DO UPDATE SET
              lifecycle_source=excluded.lifecycle_source,observed_at=excluded.observed_at,expires_at=excluded.expires_at,confidence='EXACT',active=1""",
                        (provider, native_session_id, transcript_path, pane_id, source, now.isoformat(), expiry.isoformat(), "EXACT"))
        self.record_identity_lifecycle(provider, native_session_id, "SessionStart", source)

    def invalidate_identity(self, provider: str, native_session_id: str, *, pane_id: str = "") -> int:
        sql, args = "UPDATE identity_mappings SET active=0 WHERE provider=? AND native_session_id=? AND active=1", [provider, native_session_id]
        if pane_id:
            sql += " AND pane_id=?"; args.append(pane_id)
        return self.db.execute(sql, args).rowcount

    def exact_identity(self, provider: str, native_session_id: str, transcript_path: str, *, now: Optional[dt.datetime] = None) -> Optional[sqlite3.Row]:
        """Return only a current exact three-way registration, never a best match."""
        try:
            transcript_path = _canonical_transcript_path(transcript_path)
        except ValueError:
            return None
        now_text = (now or _identity_now()).isoformat()
        rows = self.db.execute("""SELECT * FROM identity_mappings WHERE provider=? AND native_session_id=? AND transcript_path=?
            AND active=1 AND confidence='EXACT' AND expires_at>? ORDER BY id DESC""", (provider, native_session_id, transcript_path, now_text)).fetchall()
        return rows[0] if len(rows) == 1 else None

    def file(self, path: Path) -> Optional[sqlite3.Row]:
        return self.db.execute("SELECT * FROM files WHERE path=?", (str(path),)).fetchone()

    def reset_file_session(self, row: sqlite3.Row) -> None:
        if row["session_id"]:
            # A replaced transcript can no longer be an exact live-session witness.
            self.db.execute("UPDATE identity_mappings SET active=0 WHERE provider=? AND native_session_id=? AND transcript_path=?", (row["provider"], row["session_id"], _canonical_transcript_path(str(row["path"]))))
            stream = row["stream_id"] or row["session_id"]
            self.db.execute("DELETE FROM sessions WHERE stream_id=? AND provider=?", (stream, row["provider"]))
            self.db.execute("DELETE FROM occurrences WHERE stream_id=? AND provider=?", (stream, row["provider"]))
            self.db.execute("DELETE FROM record_dedup WHERE stream_id=? AND provider=?", (stream, row["provider"]))
            self.db.execute("DELETE FROM telemetry_samples WHERE stream_id=? AND provider=?", (stream, row["provider"]))
            self.db.execute("DELETE FROM health_events WHERE stream_id=? AND provider=?", (stream, row["provider"]))
            self.db.execute("DELETE FROM guardian_events WHERE stream_id=? AND provider=?", (stream, row["provider"]))
            if row["provider"] == "claude":
                self.db.execute("DELETE FROM service_meta WHERE key=?", (_claude_runtime_meta_key(stream),))

    def cached_provider(self, path: Path) -> Optional[str]:
        """Use durable file identity to avoid opening unchanged transcript files."""
        row = self.file(path)
        if row is None or int(row["parser_version"]) != PARSER_VERSION:
            return None
        try:
            stat = path.stat()
        except OSError:
            return None
        if row["identity"] != f"{stat.st_dev}:{stat.st_ino}" or stat.st_size < int(row["last_offset"]) or stat.st_mtime_ns != int(row["mtime_ns"]):
            return None
        return str(row["provider"])

    def upsert_file(self, *, provider: str, path: Path, identity: str, size: int, mtime_ns: int, offset: int, partial: str, session_id: str, status: str, stream_id: str = "") -> None:
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        self.db.execute("""INSERT INTO files(provider,path,identity,size,mtime_ns,last_offset,partial_line,session_id,stream_id,first_seen,last_seen,parser_version,status)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET provider=excluded.provider,identity=excluded.identity,size=excluded.size,mtime_ns=excluded.mtime_ns,last_offset=excluded.last_offset,partial_line=excluded.partial_line,session_id=excluded.session_id,stream_id=excluded.stream_id,last_seen=excluded.last_seen,parser_version=excluded.parser_version,status=excluded.status""",
            (provider, str(path), identity, size, mtime_ns, offset, partial, session_id, stream_id or session_id, now, now, PARSER_VERSION, status))

    def apply_record(self, provider: str, path: Path, data: dict[str, Any], malformed: bool = False) -> str:
        sid = str(data.get("session_id") or path.stem)
        stream = str(data.get("stream_id") or sid)
        try:
            # Adapters represent a legitimately omitted source timestamp as
            # an empty internal value; raw supplied empties are rejected by
            # the adapter before this durable boundary is reached.
            ts = "" if data.get("timestamp") == "" else optional_provider_timestamp(data.get("timestamp"))
        except TemporalSemanticError:
            # This direct persistence boundary is also used by focused callers.
            # Do not let an invalid time retain any record-derived telemetry.
            malformed = True
            ts = ""
            data = {"session_id": sid, "stream_id": stream, "record_key": data.get("record_key", "")}
        # A transcript may be replayed from an earlier offset after a crash or
        # conservative cursor recovery.  Its physical record position is a
        # stable, privacy-safe identity: it distinguishes equal commands on
        # separate lines while preventing their derived effects from doubling.
        record_key = str(data.get("record_key") or "")
        if record_key and not self.mark_unique(provider, stream, "transcript_record", record_key, sid):
            return stream
        row = self.db.execute("SELECT * FROM sessions WHERE stream_id=? AND provider=?", (stream, provider)).fetchone()
        if row is None:
            # INSERT OR IGNORE: a concurrent scan (daemon + CLI) may race to create
            # the same session row; the later writer's UPDATE below still applies.
            self.db.execute("INSERT OR IGNORE INTO sessions(session_id,provider,stream_id,role,parent_session_id,parent_stream_id,thread_source,project,path,started_at,last_activity_at,health_since) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (sid, provider, stream, str(data.get("role") or "MAIN"), str(data.get("parent_session_id") or ""), str(data.get("parent_stream_id") or ""), str(data.get("thread_source") or ""), str(data.get("project") or ""), str(path), ts, ts, dt.datetime.now(dt.timezone.utc).isoformat()))
        # Codex token snapshots are cumulative; append-only Claude values are additive.
        cumulative = provider == "codex" and data.get("input_tokens") is not None
        set_parts, args = [], []
        for field in ("project", "model", "effort", "version", "role", "parent_session_id", "parent_stream_id", "thread_source"):
            if data.get(field): set_parts.append(f"{field}=?"); args.append(str(data[field]))
        prior_activity = iso_to_dt(row["last_activity_at"]) if row else None
        if prior_activity is not None and (prior_activity.tzinfo is None or prior_activity.utcoffset() is None):
            prior_activity = None
        current_activity = iso_to_dt(ts)
        # Equal provider timestamps are common for a metadata record and its
        # first event; only an earlier timestamp is stale for chronology.
        stale_timestamp = bool(ts and prior_activity is not None and (current_activity is None or current_activity < prior_activity))
        if ts and not stale_timestamp:
            set_parts.append("last_activity_at=?"); args.append(ts)
            set_parts.append("started_at=CASE WHEN started_at='' THEN ? ELSE started_at END"); args.append(ts)
        if not stale_timestamp:
            for field in ("peak_context_tokens", "context_window_tokens", "peak_context_pct", "max_tool_result_chars"):
                val = data.get(field)
                if val not in (None, "", 0, 0.0): set_parts.append(f"{field}=MAX({field},?)"); args.append(val)
        for field in ("model_turns", "tool_calls", "tool_result_chars", "cache_creation_tokens", "compactions"):
            val = safe_int(data.get(field));
            if val: set_parts.append(f"{field}={field}+?"); args.append(val)
        for field in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens"):
            val = data.get(field)
            if val is not None:
                set_parts.append(f"{field}=?" if cumulative else f"{field}={field}+?"); args.append(safe_int(val))
        if malformed: set_parts.append("malformed_records=malformed_records+1")
        if set_parts:
            args.extend([stream, provider]); self.db.execute(f"UPDATE sessions SET {','.join(set_parts)} WHERE stream_id=? AND provider=?", args)
        for kind, key in (("read", data.get("read_key")), ("command", data.get("command_key"))):
            if key:
                digest = sha1_text(str(key)); self.db.execute("INSERT INTO occurrences(session_id,provider,stream_id,kind,key_hash,count) VALUES(?,?,?,?,?,1) ON CONFLICT(provider,stream_id,kind,key_hash) DO UPDATE SET count=count+1", (sid, provider, stream, kind, digest))
                col = "repeated_reads" if kind == "read" else "repeated_commands"
                self.db.execute(f"UPDATE sessions SET {col}=(SELECT COALESCE(MAX(count),0) FROM occurrences WHERE stream_id=? AND provider=? AND kind=?) WHERE stream_id=? AND provider=?", (stream, provider, kind, stream, provider))
        if not stale_timestamp:
            self.record_telemetry(provider, sid, stream, ts, data)
        return stream

    def record_telemetry(self, provider: str, sid: str, stream: str, timestamp: str, data: dict[str, Any]) -> None:
        """Persist a bounded numeric/hash-only ring; never transcript payloads."""
        meaningful = any(data.get(key) not in (None, "", 0, 0.0) for key in ("peak_context_tokens", "peak_context_pct", "tool_result_chars", "read_key", "command_key", "content_key", "cached_input_tokens", "compactions", "instruction_chars"))
        if not meaningful:
            return
        row = self.db.execute("SELECT model_turns FROM sessions WHERE stream_id=? AND provider=?", (stream, provider)).fetchone()
        stamp = timestamp if iso_to_dt(timestamp) else dt.datetime.now(dt.timezone.utc).isoformat()
        self.db.execute("""INSERT INTO telemetry_samples(timestamp,session_id,provider,stream_id,turn_index,context_tokens,context_pct,tool_output_chars,read_hash,command_hash,content_hash,cached_input_tokens,instruction_chars,compaction)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (stamp, sid, provider, stream, int(row[0] if row else 0), data.get("peak_context_tokens") or None, data.get("peak_context_pct") or None, safe_int(data.get("tool_result_chars")), sha1_text(str(data["read_key"])) if data.get("read_key") else "", sha1_text(str(data["command_key"])) if data.get("command_key") else "", sha1_text(str(data["content_key"])) if data.get("content_key") else "", data.get("cached_input_tokens"), data.get("instruction_chars"), int(bool(data.get("compactions")))))
        if data.get("peak_context_tokens") not in (None, "", 0) or data.get("peak_context_pct") not in (None, "", 0, 0.0):
            self.db.execute("UPDATE sessions SET current_context_tokens=?, current_context_pct=? WHERE provider=? AND stream_id=?", (data.get("peak_context_tokens") or None, data.get("peak_context_pct") if data.get("peak_context_pct") not in (None, "") else None, provider, stream))
        self.db.execute("""DELETE FROM telemetry_samples WHERE stream_id=? AND provider=? AND id NOT IN
            (SELECT id FROM telemetry_samples WHERE stream_id=? AND provider=? ORDER BY id DESC LIMIT 250)""", (stream, provider, stream, provider))

    def rolling_telemetry(self, provider: str, stream_id: str, now: Optional[dt.datetime] = None) -> dict[str, Any]:
        rows = self.db.execute("SELECT * FROM telemetry_samples WHERE stream_id=? AND provider=? ORDER BY id", (stream_id, provider)).fetchall()
        now = now or dt.datetime.now(dt.timezone.utc)
        parsed = [(r, iso_to_dt(r["timestamp"]) or now) for r in rows]
        def summarise(samples: list[tuple[sqlite3.Row, dt.datetime]]) -> dict[str, Any]:
            contexts = [float(r["context_tokens"]) for r, _ in samples if r["context_tokens"] is not None]
            pcts = [float(r["context_pct"]) for r, _ in samples if r["context_pct"] is not None]
            turns = max((int(r["turn_index"]) for r, _ in samples), default=0) - min((int(r["turn_index"]) for r, _ in samples), default=0)
            cache = [int(r["cached_input_tokens"]) for r, _ in samples if r["cached_input_tokens"] is not None]
            return {"samples": len(samples), "context_growth_tokens": (contexts[-1] - contexts[0]) if len(contexts) > 1 else None, "context_growth_pct": (pcts[-1] - pcts[0]) if len(pcts) > 1 else None, "context_growth_tokens_per_turn": ((contexts[-1] - contexts[0]) / turns) if len(contexts) > 1 and turns else None, "context_growth_pct_per_turn": ((pcts[-1] - pcts[0]) / turns) if len(pcts) > 1 and turns else None, "tool_output_chars": sum(int(r["tool_output_chars"]) for r, _ in samples), "repeated_read_rate": sum(bool(r["read_hash"]) for r, _ in samples) / len(samples) if samples else None, "repeated_command_rate": sum(bool(r["command_hash"]) for r, _ in samples) / len(samples) if samples else None, "cache_reuse_change": cache[-1] - cache[0] if len(cache) > 1 else None, "advisor_subagent_amplification": None, "instruction_startup_overhead": None}
        result = {"last_5m": summarise([(r, t) for r, t in parsed if t >= now - dt.timedelta(minutes=5)]), "last_15m": summarise([(r, t) for r, t in parsed if t >= now - dt.timedelta(minutes=15)])}
        turn_rows = [(r, t) for r, t in parsed if int(r["turn_index"]) > 0]
        for size in (10, 20, 50): result[f"last_{size}_turns"] = summarise(turn_rows[-size:])
        high = [(r, t) for r, t in parsed if float(r["context_pct"] or 0) >= CODEX_HIGH_CONTEXT_PCT]
        result["high_context_dwell_seconds"] = sum(max(0, (high[i][1] - high[i - 1][1]).total_seconds()) for i in range(1, len(high)))
        compact = [i for i, (r, _) in enumerate(parsed) if r["compaction"]]
        result["compaction_snapshots"] = len(compact)
        result["context_refill_after_compaction"] = None
        if compact:
            index = compact[-1]; after = parsed[index][0]["context_tokens"]; latest = next((r["context_tokens"] for r, _ in reversed(parsed) if r["context_tokens"] is not None), None)
            if after is not None and latest is not None: result["context_refill_after_compaction"] = max(0, int(latest) - int(after))
        return result

    def mark_unique(self, provider: str, stream_id: str, kind: str, key: str, session_id: Optional[str] = None) -> bool:
        if not key: return True
        cur = self.db.execute("INSERT OR IGNORE INTO record_dedup(session_id,provider,stream_id,kind,key_hash) VALUES(?,?,?,?,?)", (session_id or stream_id, provider, stream_id, kind, sha1_text(key)))
        return cur.rowcount == 1

    def sessions(self, provider: str = "all", session: str = "") -> list[sqlite3.Row]:
        if self.v5_rebuild_required():
            return []
        sql, args = "SELECT * FROM sessions", []
        where = []
        if provider != "all": where.append("provider=?"); args.append(provider)
        if session: where.append("(session_id LIKE ? OR stream_id LIKE ?)"); args.extend([session + "%", session + "%"])
        if where: sql += " WHERE " + " AND ".join(where)
        return self.db.execute(sql + " ORDER BY last_activity_at DESC", args).fetchall()

    def v5_rebuild_required(self) -> bool:
        row = self.db.execute("SELECT value FROM service_meta WHERE key='v5_rebuild_state'").fetchone()
        return bool(row and row[0] != "complete")

    def reconcile_parent_streams(self) -> None:
        """Link child streams only where one exact MAIN parent is known."""
        self.db.execute("""UPDATE sessions AS child SET parent_stream_id=(
            SELECT parent.stream_id FROM sessions AS parent
            WHERE parent.provider=child.provider AND parent.session_id=child.parent_session_id AND parent.role='MAIN'
        ) WHERE child.parent_session_id<>'' AND child.parent_stream_id='' AND
          1=(SELECT COUNT(*) FROM sessions AS parent WHERE parent.provider=child.provider AND parent.session_id=child.parent_session_id AND parent.role='MAIN')""")

    def event(self, provider: str, stream_id: str, severity: str, code: str, message: str, evidence: dict[str, Any], cooldown: int = 900) -> None:
        row = self.db.execute("SELECT session_id FROM sessions WHERE provider=? AND stream_id=?", (provider, stream_id)).fetchone()
        sid = str(row[0]) if row else stream_id
        now = dt.datetime.now(dt.timezone.utc); evidence_json = json.dumps(evidence, sort_keys=True)
        lifecycle = event_lifecycle(code)
        if lifecycle == EventLifecycle.OCCURRENCE:
            # Aggregate maxima/counters can remain true forever.  Retain one
            # exact historical observation but never represent it as active.
            existing = self.db.execute("SELECT id FROM health_events WHERE stream_id=? AND provider=? AND code=? AND evidence=? LIMIT 1", (stream_id, provider, code, evidence_json)).fetchone()
            if existing: return
            resolved_at = now.isoformat()
        else:
            previous = self.db.execute("SELECT timestamp FROM health_events WHERE stream_id=? AND provider=? AND code=? AND resolved_at IS NULL ORDER BY id DESC LIMIT 1", (stream_id, provider, code)).fetchone()
            if previous and (now - iso_to_dt(previous[0])).total_seconds() < cooldown: return
            resolved_at = None
        self.db.execute("INSERT INTO health_events(timestamp,session_id,provider,stream_id,severity,code,message,evidence,resolved_at) VALUES(?,?,?,?,?,?,?,?,?)", (now.isoformat(), sid, provider, stream_id, severity, code, message, evidence_json, resolved_at))
        lanes = {"HIGH_CONTEXT": ("context_pressure",), "EXTREME_CONTEXT": ("context_pressure",), "GIANT_TOOL_RESULT": ("tool_output",), "REPEATED_READ": ("workflow",), "COMMAND_REPETITION": ("workflow",)}.get(code, ("integrity",) if code == "CONTROL_FAIL_SAFE" else ())
        event_id = self.db.execute("INSERT INTO guardian_events(timestamp,session_id,provider,stream_id,severity,action_safety,code,evidence,resolved_at) VALUES(?,?,?,?,?,?,?,?,?)", (now.isoformat(), sid, provider, stream_id, severity, "ADVISE_ONLY", code, evidence_json, resolved_at)).lastrowid
        for lane in lanes: self.db.execute("INSERT INTO guardian_event_lanes(event_id,lane) VALUES(?,?)", (event_id, lane))

    def resolve_inactive_events(self, provider: str, stream_id: str, active_codes: set[str]) -> None:
        base = dt.datetime.now(dt.timezone.utc)
        rows = self.db.execute("SELECT id,code FROM health_events WHERE provider=? AND stream_id=? AND resolved_at IS NULL", (provider, stream_id)).fetchall()
        for offset, row in enumerate(rows):
            if event_lifecycle(row["code"]) == EventLifecycle.OCCURRENCE or row["code"] not in active_codes:
                resolved_at = (base + dt.timedelta(microseconds=offset)).isoformat()
                self.db.execute("UPDATE health_events SET resolved_at=? WHERE id=?", (resolved_at, row["id"]))
                self.db.execute("UPDATE guardian_events SET resolved_at=? WHERE provider=? AND stream_id=? AND code=? AND resolved_at IS NULL", (resolved_at, provider, stream_id, row["code"]))


def stream_compaction_outcomes(store: StateStore, row: sqlite3.Row) -> list[dict[str, Any]]:
    """Classify only compactions with surrounding measured stream telemetry."""
    samples = store.db.execute("SELECT * FROM telemetry_samples WHERE provider=? AND stream_id=? ORDER BY id", (row["provider"], row["stream_id"])).fetchall()
    markers = [index for index, sample in enumerate(samples) if sample["compaction"]]
    if not markers:
        return []
    marker_times = [iso_to_dt(samples[index]["timestamp"]) for index in markers]
    window = None
    if len(marker_times) > 1 and marker_times[0] and marker_times[-1]: window = (marker_times[-1] - marker_times[0]).total_seconds()
    outcomes = []
    for index in markers:
        before = next((safe_int(samples[i]["context_tokens"]) for i in range(index - 1, -1, -1) if samples[i]["context_tokens"] is not None), 0)
        after = safe_int(samples[index]["context_tokens"] or 0)
        refill = next((safe_int(samples[i]["context_tokens"]) for i in range(len(samples) - 1, index, -1) if samples[i]["context_tokens"] is not None), None)
        repeated = sum(bool(samples[i]["command_hash"]) for i in range(index + 1, len(samples)))
        outcomes.append(classify_compaction(before, after, refill, repeated, len(markers), compaction_window_seconds=window))
    return outcomes


def exact_identity_for_live_session(store: Optional[StateStore], row: sqlite3.Row) -> Optional[sqlite3.Row]:
    """Join only equal native IDs plus equal canonical transcript paths."""
    if store is None or row["provider"] != "codex" or not row["session_id"] or not row["path"]:
        return None
    return store.exact_identity("codex", str(row["session_id"]), str(row["path"]))


def herdr_pane_is_idle(mapping: sqlite3.Row, *, socket_path: Optional[str] = None) -> bool:
    """Re-query Herdr so a restart or pane reuse immediately blocks control."""
    sock = socket_path or os.environ.get("HERDR_SOCKET_PATH") or str(Path.home() / ".config" / "herdr" / "herdr.sock")
    reply = _socket_request(sock, "agent.list", {})
    agents = ((reply or {}).get("result") or {}).get("agents")
    if not isinstance(agents, list):
        return False
    for agent in agents:
        session = agent.get("agent_session") if isinstance(agent, dict) else None
        if not isinstance(session, dict):
            continue
        if (agent.get("agent") == mapping["provider"] and agent.get("pane_id") == mapping["pane_id"]
                and session.get("value") == mapping["native_session_id"] and agent.get("agent_status") == "idle"):
            return True
    return False


class CompactVerification(str, enum.Enum):
    REQUESTED = "REQUESTED"
    ACCEPTED = "ACCEPTED"
    PROVIDER_CONFIRMED = "PROVIDER_CONFIRMED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    TIMED_OUT = "TIMED_OUT"
    IDENTITY_LOST = "IDENTITY_LOST"
    AMBIGUOUS = "AMBIGUOUS"
    FAILED = "FAILED"


@dataclasses.dataclass(frozen=True)
class CompactRequest:
    state: CompactVerification
    requested_at: dt.datetime
    before_compactions: int
    before_context: Optional[int]
    before_telemetry_id: int


def compact_request_snapshot(store: StateStore, mapping: sqlite3.Row) -> CompactRequest:
    """Capture compact numeric state immediately before the one allowed request."""
    row = store.db.execute("SELECT compactions FROM sessions WHERE session_id=? AND provider=?",
                           (mapping["native_session_id"], mapping["provider"])).fetchone()
    sample = store.db.execute("""SELECT id,context_tokens FROM telemetry_samples
        WHERE session_id=? AND provider=? AND context_tokens IS NOT NULL ORDER BY id DESC LIMIT 1""",
                             (mapping["native_session_id"], mapping["provider"])).fetchone()
    return CompactRequest(CompactVerification.REQUESTED, _identity_now(), int(row[0] if row else 0),
                          int(sample["context_tokens"]) if sample else None, int(sample["id"]) if sample else 0)


def invoke_herdr_compact(mapping: sqlite3.Row, request: CompactRequest) -> CompactRequest:
    """Submit one structured request. Completion is proven separately from local evidence."""
    if not herdr_pane_is_idle(mapping):
        return dataclasses.replace(request, state=CompactVerification.REJECTED)
    try:
        result = subprocess.run(["herdr", "agent", "prompt", str(mapping["pane_id"]), "/compact", "--wait", "--until", "idle"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                timeout=30, check=False)
        # Herdr can report agent_prompt_stalled when a very short provider turn
        # reaches idle before its state watcher observes working.  Treat that as
        # an unverified request, never as proof that delivery failed or succeeded.
        return dataclasses.replace(request, state=CompactVerification.ACCEPTED if result.returncode == 0 else CompactVerification.REQUESTED)
    except (OSError, subprocess.TimeoutExpired):
        return dataclasses.replace(request, state=CompactVerification.TIMED_OUT)


def verify_herdr_compact(store: StateStore, mapping: sqlite3.Row, request: CompactRequest) -> CompactVerification:
    """Verify one request from exact identity, provider lifecycle, and numeric telemetry.

    A CLI transport acknowledgement alone is intentionally insufficient.  The
    provider can complete before Herdr's waiter observes a working transition,
    so matching post-request provider evidence is allowed to establish delivery.
    """
    current = store.exact_identity(str(mapping["provider"]), str(mapping["native_session_id"]), str(mapping["transcript_path"]))
    if current is None or current["pane_id"] != mapping["pane_id"]:
        return CompactVerification.IDENTITY_LOST
    requested = request.requested_at.isoformat()
    lifecycle = store.db.execute("""SELECT hook_event_name,lifecycle_source FROM identity_lifecycle
        WHERE provider=? AND native_session_id=? AND observed_at>=? ORDER BY id""",
                                 (mapping["provider"], mapping["native_session_id"], requested)).fetchall()
    provider_lifecycle = any(item["hook_event_name"] == "PostCompact" or
                             (item["hook_event_name"] == "SessionStart" and item["lifecycle_source"] == "compact")
                             for item in lifecycle)
    row = store.db.execute("SELECT compactions FROM sessions WHERE session_id=? AND provider=?",
                           (mapping["native_session_id"], mapping["provider"])).fetchone()
    compaction_seen = row is not None and int(row[0]) > request.before_compactions
    if not provider_lifecycle or not compaction_seen:
        return CompactVerification.TIMED_OUT
    after = store.db.execute("""SELECT context_tokens FROM telemetry_samples
        WHERE session_id=? AND provider=? AND id>? AND context_tokens IS NOT NULL ORDER BY id DESC LIMIT 1""",
                             (mapping["native_session_id"], mapping["provider"], request.before_telemetry_id)).fetchone()
    if request.before_context is None or after is None:
        return CompactVerification.PROVIDER_CONFIRMED
    return CompactVerification.VERIFIED if int(after[0]) < request.before_context else CompactVerification.FAILED


def compact_action_recent(store: StateStore, provider: str, session_id: str, cooldown_seconds: int) -> bool:
    """A verified compact gets one cooldown window; never repeat it blindly."""
    row = store.db.execute("""SELECT timestamp FROM health_events WHERE provider=? AND session_id=?
        AND code='COMPACT_VERIFIED' ORDER BY id DESC LIMIT 1""", (provider, session_id)).fetchone()
    when = iso_to_dt(str(row[0])) if row else None
    return bool(when and (_identity_now() - when).total_seconds() < cooldown_seconds)


@dataclasses.dataclass(frozen=True)
class HealthPolicy:
    watch_pct: float = 0.50
    checkpoint_pct: float = 0.65
    rotation_pct: float = 0.80
    recovery_pct: float = 0.45
    cooldown_seconds: int = 900

    @classmethod
    def from_environment(cls) -> "HealthPolicy":
        raw = os.environ.get("AGENTOPSY_HEALTH_POLICY", "")
        if not raw: return cls()
        try: return cls(**{k: v for k, v in json.loads(raw).items() if k in cls.__dataclass_fields__})
        except (ValueError, TypeError, json.JSONDecodeError): raise ValueError("AGENTOPSY_HEALTH_POLICY must be a JSON object with health thresholds")


def evaluate_live_health(row: sqlite3.Row, policy: HealthPolicy) -> tuple[str, list[tuple[str, str, str, dict[str, Any]]]]:
    context = provider_context_evaluation(row, current=True)
    severity, pct, semantics = context["severity"], context["pct"], context["semantics"]
    if semantics == "N/A": return "UNKNOWN", []
    previous = row["health_state"]
    if row["provider"] == "claude":
        state = "ROTATION_RECOMMENDED" if context["tokens"] >= 200_000 else "CHECKPOINT_RECOMMENDED" if severity == Severity.HIGH else "HEALTHY"
    elif pct >= policy.rotation_pct: state = "ROTATION_RECOMMENDED"
    elif pct >= policy.checkpoint_pct: state = "CHECKPOINT_RECOMMENDED"
    elif pct >= policy.watch_pct: state = "WATCH"
    elif pct < policy.recovery_pct or previous == "HEALTHY": state = "HEALTHY"
    else: state = previous  # hysteresis retains the existing band between recovery and entry thresholds.
    events = []
    if state not in {"HEALTHY", "UNKNOWN"}:
        code = "EXTREME_CONTEXT" if state == "ROTATION_RECOMMENDED" else "HIGH_CONTEXT"
        value = f"~{human_int(context['tokens'])} tokens" if pct is None else f"{pct*100:.1f}%"
        events.append(("high" if state == "ROTATION_RECOMMENDED" else "medium", code, f"Current context {semantics} is {value} ({state.lower().replace('_', ' ')}).", {"context_tokens": context["tokens"], "context_pct": round(pct * 100, 1) if pct is not None else None, "semantics": semantics}))
    if int(row["max_tool_result_chars"] or 0) // 4 >= GIANT_RESULT_TOKENS: events.append(("high", "GIANT_TOOL_RESULT", "A large tool result was observed.", {"tokens_proxy": int(row["max_tool_result_chars"]) // 4}))
    if int(row["repeated_reads"] or 0) >= 4: events.append(("medium", "REPEATED_READ", "A read target has repeated.", {"repeats": row["repeated_reads"]}))
    if int(row["repeated_commands"] or 0) >= 5: events.append(("medium", "COMMAND_REPETITION", "A command has repeated.", {"repeats": row["repeated_commands"]}))
    # Raw compaction count alone is not causal evidence of thrash.  The
    # collector keeps marker/timing telemetry for measured classification.
    # The live collector has no truthful context-velocity or dwell samples yet.
    # Do not emit a compound emergency from fabricated zero-valued lanes; this
    # rule remains available for callers that actually supply independent facts.
    return state, events


@dataclasses.dataclass
class IngestionMetrics:
    bytes_examined: int = 0; bytes_newly_parsed: int = 0; files_unchanged: int = 0; files_advanced: int = 0; files_rescanned: int = 0; parse_errors: int = 0
    touched_sessions: set = dataclasses.field(default_factory=set)
    control_evaluations: int = 0; control_blocked: int = 0; control_fail_safes: int = 0; control_invocations: int = 0; control_verified: int = 0


class IncrementalIngestor:
    def __init__(self, store: StateStore, roots: Optional[list[tuple[Path, str]]] = None, provider: str = "all", event_cooldown: int = 900):
        self.store, self.roots, self.provider, self.event_cooldown = store, roots or discover_live_roots(), provider, event_cooldown

    def scan(self) -> IngestionMetrics:
        metrics = IngestionMetrics()
        candidates = collect_candidates(self.roots, self.provider, lambda path: self.store.cached_provider(path) or classify_jsonl(path))
        with self.store.db:
            for candidate in candidates: self._ingest(candidate, metrics)
            self.store.reconcile_parent_streams()
            # The marker survives every crash/exception because this is inside
            # the same transaction as the replay.  A filtered scan cannot
            # claim a complete rebuild of providers it did not inspect.
            if self.store.v5_rebuild_required() and self.provider == "all" and candidates:
                self.store.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('v5_rebuild_state','complete')")
            self.store.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('last_successful_scan',?)", (dt.datetime.now(dt.timezone.utc).isoformat(),))
        return metrics

    def _ingest(self, candidate: Candidate, metrics: IngestionMetrics) -> None:
        path = candidate.path
        fh = _open_transcript(path, candidate.trusted_root, binary=True)
        if fh is None:
            return
        with fh:
            stat = os.fstat(fh.fileno())
            identity = f"{stat.st_dev}:{stat.st_ino}"; old = self.store.file(path)
            reset = old is not None and (old["identity"] != identity or stat.st_size < old["last_offset"])
            if old and not reset and stat.st_size == old["size"]:
                metrics.files_unchanged += 1; self.store.upsert_file(provider=candidate.provider,path=path,identity=identity,size=stat.st_size,mtime_ns=stat.st_mtime_ns,offset=old["last_offset"],partial=old["partial_line"],session_id=old["session_id"],stream_id=old["stream_id"],status="ok"); return
            if reset:
                self.store.reset_file_session(old); offset, partial = 0, ""; metrics.files_rescanned += 1
            else: offset, partial = (int(old["last_offset"]), str(old["partial_line"])) if old else (0, "")
            fh.seek(offset); chunk = fh.read()
        metrics.bytes_examined += len(chunk); metrics.bytes_newly_parsed += len(chunk)
        text = partial + chunk.decode("utf-8", errors="replace")
        lines = text.splitlines(keepends=True); trailing = ""
        if lines and not lines[-1].endswith(("\n", "\r")): trailing = lines.pop()
        adapter = ADAPTERS[candidate.provider]
        if reset or old is None:
            adapter.begin_transcript(path)
        stream_id = "" if reset else str(old["stream_id"] if old else "")
        native_sid = "" if reset else str(old["session_id"] if old else "")
        line_offset = offset - len(partial.encode("utf-8"))
        for line in lines:
            next_offset = line_offset + len(line.encode("utf-8"))
            if not line.strip():
                line_offset = next_offset
                continue
            try:
                record = json.loads(line)
            except ValueError:
                metrics.parse_errors += 1
                # Before metadata identifies a session, retain the error in scan
                # metrics rather than inventing a path-derived session row.
                if stream_id: self.store.apply_record(candidate.provider, path, {"session_id": native_sid, "stream_id": stream_id, "record_key": f"{path}:{line_offset}"}, malformed=True)
                line_offset = next_offset
                continue
            try:
                data = adapter.parse_record(record, path)
            except (NumericSemanticError, TemporalSemanticError):
                metrics.parse_errors += 1
                if stream_id:
                    self.store.apply_record(candidate.provider, path, {"session_id": native_sid, "stream_id": stream_id, "record_key": f"{path}:{line_offset}"}, malformed=True)
                line_offset = next_offset
                continue
            data["record_key"] = f"{path}:{line_offset}"
            if candidate.provider == "claude":
                data.update({"role": "SUBAGENT" if candidate.is_subagent else "MAIN", "parent_session_id": candidate.parent_session_id if candidate.is_subagent else ""})
            # Codex metadata normally carries the native session ID only once.
            # Later records must stay attached to that file's established ID,
            # rather than falling back to a filename-derived placeholder.
            if stream_id and str(data.get("stream_id") or "") == path.stem:
                data["stream_id"] = stream_id
                data["session_id"] = native_sid or str(data.get("session_id") or path.stem)
            if candidate.provider == "codex" and record.get("type") == "session_meta" and stream_id:
                # A restarted collector may not retain the adapter's local
                # metadata cache.  The persisted stream is still authoritative
                # for an append, so never let later metadata rewrite it.
                if (str(data.get("session_id") or "") != native_sid
                        or str(data.get("stream_id") or "") != stream_id):
                    data["metadata_conflict"] = True
                data["session_id"], data["stream_id"] = native_sid, stream_id
            native_sid = str(data.get("session_id") or native_sid or path.stem)
            stream_id = str(data.get("stream_id") or stream_id or native_sid)
            data["session_id"], data["stream_id"] = native_sid, stream_id
            if candidate.provider == "claude" and isinstance(record.get("sessionId"), str) and record["sessionId"].strip():
                # A moved Claude transcript starts scanning from offset zero;
                # anchor deduplication to its provider-native session identity
                # so the already-observed prefix is not replayed.
                data["record_key"] = f"{native_sid}:{line_offset}"
            if candidate.provider == "claude":
                target_sid = stream_id
                usage_key = str(data.pop("usage_key", ""))
                if usage_key and not self.store.mark_unique(candidate.provider, target_sid, "assistant_usage", usage_key, native_sid):
                    for field in ("input_tokens", "cached_input_tokens", "cache_creation_tokens", "output_tokens", "reasoning_tokens", "model_turns", "peak_context_tokens"):
                        data[field] = 0
                calls = data.pop("tool_call_items", [])
                if calls:
                    data["tool_calls"] = sum(self.store.mark_unique(candidate.provider, target_sid, "tool_call", str(item), native_sid) for item in calls)
                results = data.pop("tool_result_items", [])
                if results:
                    fresh = [chars for item, chars in results if self.store.mark_unique(candidate.provider, target_sid, "tool_result", str(item), native_sid)]
                    data["tool_result_chars"] = sum(fresh)
                    data["max_tool_result_chars"] = max(fresh, default=0)
            elif candidate.provider == "codex":
                usage_key = str(data.pop("usage_key", ""))
                if usage_key and not self.store.mark_unique(candidate.provider, stream_id, "token_snapshot", usage_key, native_sid):
                    data["model_turns"] = 0
            stream_id = self.store.apply_record(candidate.provider, path, data, malformed=bool(data.pop("metadata_conflict", False)))
            line_offset = next_offset
        self.store.upsert_file(provider=candidate.provider,path=path,identity=identity,size=stat.st_size,mtime_ns=stat.st_mtime_ns,offset=stat.st_size,partial=trailing,session_id=native_sid or (old["session_id"] if old else path.stem),stream_id=stream_id or (old["stream_id"] if old else path.stem),status="ok")
        metrics.files_advanced += 1
        if stream_id:
            metrics.touched_sessions.add((candidate.provider, stream_id))
            row = self.store.db.execute("SELECT * FROM sessions WHERE stream_id=? AND provider=?", (stream_id, candidate.provider)).fetchone()
            if row:
                state, events = evaluate_live_health(row, HealthPolicy.from_environment())
                self.store.db.execute("UPDATE sessions SET health_state=? WHERE stream_id=? AND provider=?", (state, stream_id, candidate.provider))
                for severity, code, message, evidence in events: self.store.event(candidate.provider, stream_id, severity, code, message, evidence, cooldown=self.event_cooldown)
                self.store.resolve_inactive_events(candidate.provider, stream_id, {code for _, code, _, _ in events if event_lifecycle(code) == EventLifecycle.ACTIVE_CONDITION})


def run_watch(args: argparse.Namespace) -> int:
    interval = args.watch
    if interval <= 0:
        raise ValueError("--watch must be a positive number of seconds")
    if args.source and any(zipfile.is_zipfile(Path(os.path.expanduser(s))) for s in args.source if Path(os.path.expanduser(s)).exists()):
        raise ValueError("--watch is intended for live directories, not static ZIP archives")
    report_dir = Path(os.path.expanduser(args.report_dir or "~/.local/state/agentopsy"))
    report_dir.mkdir(parents=True, exist_ok=True)
    print(f"Watching session stores every {interval}s. Reports: {report_dir}")
    print("Ctrl-C to stop.")
    try:
        while True:
            sessions, roots, _ = scan_once(args)
            md = render_markdown(sessions, roots, details=args.details)
            (report_dir / "latest.md").write_text(md, encoding="utf-8")
            write_json_report(report_dir / "latest.json", sessions, roots)
            ranked = rank_sessions(sessions)
            high = [s for s in ranked if any(d.severity in {"critical", "high"} for d in s.defects)]
            stamp = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{stamp}] sessions={len(sessions)} high/critical-session-count={len(high)}", flush=True)
            if high:
                top = high[0]
                flags = ",".join(d.code for d in top.defects if d.severity in {"critical", "high"})
                print(f"  worst: {top.provider} {top.session_id} grade={top.grade} score={top.score} flags={flags}", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped.")
        return 0


class Notifier:
    """Optional local notifier; absence of a desktop/Herdr is always harmless."""
    def __init__(self, enabled: bool = True, minimum: str = "medium"):
        self.enabled = enabled and os.environ.get("AGENTOPSY_NOTIFICATIONS", "1").lower() not in {"0", "false", "off"}
        self.minimum = os.environ.get("AGENTOPSY_NOTIFICATION_MIN_SEVERITY", minimum)
        self.providers = {x for x in os.environ.get("AGENTOPSY_NOTIFICATION_PROVIDERS", "").split(",") if x}
        self.sessions = {x for x in os.environ.get("AGENTOPSY_NOTIFICATION_SESSIONS", "").split(",") if x}

    def notify(self, title: str, message: str, severity: str = "medium", provider: str = "", session_id: str = "") -> None:
        if not self.enabled or SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(self.minimum, 2): return
        if self.providers and provider not in self.providers: return
        if self.sessions and session_id not in self.sessions: return
        print(f"Agentopsy: {title}\n{message}", file=sys.stderr)
        if shutil.which("notify-send"):
            try: subprocess.run(["notify-send", "Agentopsy: " + title, message], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            except (OSError, subprocess.SubprocessError): pass


class HerdrAdapter:
    """Passive integration boundary. It never controls or resets an agent."""
    def available(self) -> bool: return shutil.which("herdr") is not None
    def list_agents(self) -> list[dict[str, Any]]: return []  # Native structured mapping is provider/version dependent.
    def identify_session(self, agent: dict[str, Any]) -> str: return str(agent.get("session_id") or "")
    def notify(self, title: str, message: str) -> bool:
        if not self.available(): return False
        try: return subprocess.run(["herdr", "notification", "show", title, message], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode == 0
        except (OSError, subprocess.SubprocessError): return False
    def wait_until_safe(self, _session_id: str) -> bool: return False


CLAUDE_RUNTIME_FORMAT_VERSION = 2
CLAUDE_RUNTIME_INBOX_MAX_BYTES = 16_384
CLAUDE_RUNTIME_STDIN_MAX_BYTES = 65_536

# Versions for which CLAUDE-RUNTIME-01's empirical cross-validation was actually
# performed (statusLine token totals matched /context before and after manual
# /compact; the historical cumulative-total bug was not observed; the model
# context denominator and the auto-compact denominator were shown to be
# intentionally distinct). This set is DELIBERATELY conservative: it must only
# ever be expanded by repeating that empirical validation against a new
# version, never by assuming forward compatibility (">= 2.1.239" is exactly
# the mistake this guards against -- a later release can silently regress the
# semantics this feature depends on). An unvalidated version can still supply
# useful OBSERVED telemetry; it can never be promoted to EXACT.
CLAUDE_RUNTIME_EXACT_VERSIONS = {"2.1.239", "2.1.241"}

# Claude Code 2.1.239 and 2.1.241 have also emitted one empirically observed
# status-line shape that looks arithmetically complete but does not represent
# backed current-usage telemetry: every current-usage component, both totals,
# and used_percentage are zero. This is deliberately a narrow compatibility
# quirk, not a general "zero tokens are unavailable" rule and not an
# assumption about newer versions.
CLAUDE_RUNTIME_ZERO_ONLY_UNAVAILABLE_VERSIONS = {"2.1.239", "2.1.241"}


def _claude_runtime_inbox_dir(state_dir: Optional[str] = None) -> Path:
    return default_state_dir(state_dir) / "claude-runtime"


def _claude_runtime_reject_nonfinite(constant_name: str) -> None:
    # json.loads accepts bare NaN/Infinity/-Infinity literals by default,
    # which would otherwise reach numeric extraction as an out-of-band float.
    # Rejecting at the parse boundary (via parse_constant) means no
    # downstream numeric check ever needs to special-case them.
    raise ValueError(f"non-finite JSON constant {constant_name!r} is not permitted in Claude runtime telemetry")


def _claude_runtime_reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # CR3-04: json.loads's default behavior is last-key-wins for a duplicate
    # object key, which would let a payload smuggle two different values
    # under the same key past anything that only inspects the resulting dict
    # once (e.g. a payload logged/displayed with the first occurrence but
    # parsed with the second). Reject outright instead -- object_pairs_hook
    # is invoked once per JSON object at EVERY nesting depth, so this applies
    # recursively to nested objects (context_window, current_usage, ...) with
    # no extra code.
    seen: set[str] = set()
    result: dict[str, Any] = {}
    for key, val in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON object key {key!r} is not permitted in Claude runtime telemetry")
        seen.add(key)
        result[key] = val
    return result


def _claude_runtime_json_loads(text: str) -> Any:
    """The one JSON parse entry point for anything Claude-runtime-related that
    crosses a trust boundary (bridge stdin, inbox files). Disables NaN/
    Infinity/-Infinity literal acceptance (CR2-01) so a non-finite constant
    can never reach numeric validation as a plausible-looking float, and
    rejects duplicate object keys at every nesting depth (CR3-04) rather than
    silently taking json.loads's default last-key-wins value."""
    return json.loads(text, parse_constant=_claude_runtime_reject_nonfinite, object_pairs_hook=_claude_runtime_reject_duplicate_keys)


# Bridge-generated inbox filenames always match this shape exactly:
# <20-digit zero-padded receipt_ns>-<32 hex char session digest>-<8 hex char nonce>.json
# Cheap to test with a single regex, before any JSON parsing is attempted
# (CR2-08): a name that doesn't match this shape is definitionally not a
# genuine Agentopsy-written observation and never needs its content read.
_CLAUDE_RUNTIME_INBOX_FILENAME_RE = re.compile(r"^(\d{20})-[0-9a-f]{32}-[0-9a-f]{8}\.json$")


def _claude_runtime_inbox_filename_receipt(name: str) -> Optional[int]:
    """Parse the receipt_ns embedded in a bridge-generated filename, or None
    if the name doesn't match the expected shape. Used to cross-check against
    the (also validated) body receipt_ns -- CR2-03: filename and body must
    agree exactly, or the observation is rejected as tampered."""
    m = _CLAUDE_RUNTIME_INBOX_FILENAME_RE.match(name)
    if not m:
        return None
    return int(m.group(1))


# One filename per session would let an older writer's os.replace silently
# destroy a newer sample that arrived first (CR-07): two concurrent statusLine
# invocations for the same session have no ordering guarantee on which
# replaces which. Per-observation filenames, ordered by a trusted local
# receipt embedded in the name, preserve every observation until ingestion
# consumes it -- ingestion then does the ordering, not the filesystem.
def _claude_runtime_inbox_filename(session_id: str, receipt_ns: int) -> str:
    """A safe, collision-resistant, sortable filename derived from session
    identity and a trusted local receipt, never raw path input."""
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
    return f"{receipt_ns:020d}-{digest}-{secrets.token_hex(4)}.json"


# Bounded mailbox: at a 20s default scan interval, a single Claude session
# firing the status line every few seconds still produces well under 100
# samples between scans; 500 gives ample headroom for a slow/paused scan loop
# across many concurrent sessions while keeping a hard ceiling on disk usage
# (each file <= CLAUDE_RUNTIME_INBOX_MAX_BYTES, so the mailbox is bounded to a
# few MB even at the cap).
CLAUDE_RUNTIME_INBOX_MAX_FILES = 500
# A receipt more than this far in the future relative to wall-clock "now" is
# treated as suspicious/tampered rather than trusted to live indefinitely.
CLAUDE_RUNTIME_INBOX_MAX_FUTURE_SKEW_SECONDS = 60


# CR2-01: strict numeric validation for every Claude-runtime telemetry field.
# `type(value) is int` rejects bool (a subclass of int in Python), float,
# numeric strings, and any other int-like-but-not-int value; no int()
# coercion or rounding is ever applied, so 1000000.9 / "44865" / True can
# never quietly become a valid-looking integer. json.loads' own NaN/Infinity
# literal support is disabled at both parse sites (see
# CLAUDE_RUNTIME_JSON_PARSE_KWARGS) so those can never reach this function as
# a float in the first place.
def _claude_runtime_bounded_int(value: Any) -> Optional[int]:
    if type(value) is not int:
        return None
    return value if 0 <= value <= 100_000_000 else None


# used_percentage is Claude Code's own rounded integer percentage (0-100
# inclusive); it is a distinct, narrower range from token counts.
def _claude_runtime_bounded_percentage(value: Any) -> Optional[int]:
    if type(value) is not int:
        return None
    return value if 0 <= value <= 100 else None


def _claude_runtime_name_fingerprint(names: Iterable[str]) -> str:
    """Opaque structural discriminator: names are hashed before the inbox."""
    return hashlib.sha256("\x00".join(sorted(set(names))).encode("utf-8")).hexdigest()


def _claude_statusline_extract(payload: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Whitelist bounded runtime telemetry only. No prompts/transcripts/tool output/source code."""
    if not isinstance(payload, dict):
        return None
    session_id = payload.get("session_id")
    transcript_path = payload.get("transcript_path")
    if not isinstance(session_id, str) or not session_id.strip():
        return None
    if not isinstance(transcript_path, str) or not transcript_path.strip():
        return None
    try:
        canonical_path = _canonical_transcript_path(transcript_path)
    except ValueError:
        return None
    model = payload.get("model") if isinstance(payload.get("model"), dict) else {}
    ctx = payload.get("context_window") if isinstance(payload.get("context_window"), dict) else {}
    current_usage = ctx.get("current_usage") if isinstance(ctx.get("current_usage"), dict) else {}
    # Names only: this is structural evidence, not payload retention.  The
    # bounded bridge inbox carries these names so ingestion can fingerprint a
    # provider shape after the original statusLine has been discarded.
    # Do not retain unknown provider *names*: a field name itself can be
    # sensitive. Keep only the fixed relevant names and one boolean proving a
    # structural extension occurred.
    ctx_fields = sorted(k for k in ctx if k in _CLAUDE_RUNTIME_CONTEXT_FIELDS)
    usage_fields = sorted(k for k in current_usage if k in _CLAUDE_RUNTIME_USAGE_FIELDS)
    unknown_context_names = set(ctx) - _CLAUDE_RUNTIME_CONTEXT_FIELDS
    unknown_usage_names = set(current_usage) - _CLAUDE_RUNTIME_USAGE_FIELDS
    unknown_fields_present = bool(unknown_context_names or unknown_usage_names)
    usage_kind = "object" if isinstance(ctx.get("current_usage"), dict) else "null" if ctx.get("current_usage") is None and "current_usage" in ctx else "missing" if "current_usage" not in ctx else "other"
    _bounded_int = _claude_runtime_bounded_int

    # A present-but-invalid used_percentage is nulled out here, not treated as
    # grounds to discard the whole sample -- CR3-01 makes a directly-valid,
    # reconciling used_percentage a REQUIRED item for EXACT (see
    # _claude_runtime_derive), so an absent-or-invalid value already blocks
    # EXACT on its own; discarding the whole observation would additionally
    # and needlessly throw away still-truthful OBSERVED-tier reported fields.
    used_percentage = _claude_runtime_bounded_percentage(ctx.get("used_percentage"))

    sample = {
        "format_version": CLAUDE_RUNTIME_FORMAT_VERSION,
        "session_id": session_id.strip(),
        "transcript_path": canonical_path,
        "claude_code_version": str(payload.get("version") or "")[:64],
        "model_id": str(model.get("id") or "")[:128],
        "model_display_name": str(model.get("display_name") or "")[:128],
        "context_window_size": _bounded_int(ctx.get("context_window_size")),
        "used_percentage": used_percentage,
        "total_input_tokens": _bounded_int(ctx.get("total_input_tokens")),
        "total_output_tokens": _bounded_int(ctx.get("total_output_tokens")),
        "current_usage": {
            "input_tokens": _bounded_int(current_usage.get("input_tokens")),
            "output_tokens": _bounded_int(current_usage.get("output_tokens")),
            "cache_creation_input_tokens": _bounded_int(current_usage.get("cache_creation_input_tokens")),
            "cache_read_input_tokens": _bounded_int(current_usage.get("cache_read_input_tokens")),
        } if current_usage else None,
        "context_window_fields": ctx_fields,
        "current_usage_fields": usage_fields,
        "current_usage_kind": usage_kind,
        "semantic_unknown_fields_present": unknown_fields_present,
        "semantic_unknown_context_fingerprint": _claude_runtime_name_fingerprint(unknown_context_names),
        "semantic_unknown_usage_fingerprint": _claude_runtime_name_fingerprint(unknown_usage_names),
        # Retained only as an untrusted display hint; latest-wins ordering must
        # never depend on this -- see receipt_ns, generated locally below.
        "observed_at": _identity_now().isoformat(),
    }
    return sample


def claude_statusline_bridge_main(argv: Optional[list[str]] = None, *, stdin: Optional[Any] = None, state_dir: Optional[str] = None) -> int:
    """Status-line bridge entry point: read one JSON payload from stdin, whitelist
    and validate it, atomically write a small per-session inbox file, and return
    quickly. Never opens SQLite. Never raises past this function -- a malformed
    or unreadable payload must not break Claude Code's status-line UI."""
    try:
        source = stdin if stdin is not None else sys.stdin.buffer
        raw = source.read(CLAUDE_RUNTIME_STDIN_MAX_BYTES + 1)
        if raw is None or len(raw) > CLAUDE_RUNTIME_STDIN_MAX_BYTES:
            return 0
        payload = _claude_runtime_json_loads(raw.decode("utf-8"))
        sample = _claude_statusline_extract(payload)
        if sample is None:
            return 0
        # Trusted local receipt: generated here, never taken from the payload.
        # Lives both in the filename (sortable enumeration) and the file body
        # (what the merge actually compares).
        sample["receipt_ns"] = time.time_ns()
        inbox = _claude_runtime_inbox_dir(state_dir)
        if default_state_dir(state_dir).is_symlink() or inbox.is_symlink():
            # CR2-07: best-effort same-user confinement, not a privilege
            # boundary -- refuse to write through a symlinked state-dir/inbox
            # path rather than silently following it.
            return 0
        inbox.mkdir(parents=True, exist_ok=True)
        try: os.chmod(inbox, 0o700)
        except OSError: pass
        name = _claude_runtime_inbox_filename(sample["session_id"], sample["receipt_ns"])
        dest = inbox / name
        text = json.dumps(sample, sort_keys=True)
        if len(text.encode("utf-8")) > CLAUDE_RUNTIME_INBOX_MAX_BYTES:
            return 0
        tmp = inbox / (name + ".tmp-" + secrets.token_hex(8))
        try:
            tmp.write_text(text + "\n", encoding="utf-8")
            try: os.chmod(tmp, 0o600)
            except OSError: pass
            os.replace(tmp, dest)
        finally:
            if tmp.exists():
                try: tmp.unlink()
                except OSError: pass
    except Exception:
        pass
    return 0


def _claude_runtime_inbox_extract(payload: Any, *, max_receipt_ns: Optional[int] = None, filename_receipt_ns: Optional[int] = None) -> Optional[dict[str, Any]]:
    """Whitelist-revalidate the flat shape the bridge itself writes to the inbox.
    The inbox is written by a process this code invokes but does not fully
    control the input of (the bridge's own validation could regress, or a file
    could be tampered with on disk), so this must never trust the file verbatim.
    receipt_ns MUST be present and a plain int: it is the only trusted ordering
    signal, generated by the bridge itself, never derived from the payload's
    own (untrusted) observed_at claim.

    CR2-03: a body receipt_ns beyond max_receipt_ns (a trusted wall-clock
    bound, not an incoming claim) is rejected outright -- it must never
    participate in ordering or be persisted, so a poisoned future receipt can
    never permanently block later genuine observations via latest-wins. When
    filename_receipt_ns is supplied (parsed from a genuine bridge filename
    shape), it must agree with the body's receipt_ns exactly, or the
    observation is treated as tampered and rejected."""
    if not isinstance(payload, dict):
        return None
    session_id = payload.get("session_id")
    transcript_path = payload.get("transcript_path")
    receipt_ns = payload.get("receipt_ns")
    if not isinstance(session_id, str) or not session_id.strip():
        return None
    if not isinstance(transcript_path, str) or not transcript_path.strip():
        return None
    if type(receipt_ns) is not int or receipt_ns < 0:
        return None
    if max_receipt_ns is not None and receipt_ns > max_receipt_ns:
        return None
    if filename_receipt_ns is not None and filename_receipt_ns != receipt_ns:
        return None
    try:
        canonical_path = _canonical_transcript_path(transcript_path)
    except ValueError:
        return None
    current_usage = payload.get("current_usage")
    _bounded_int = _claude_runtime_bounded_int

    # See matching comment in _claude_statusline_extract -- a present-but-
    # invalid used_percentage is nulled out here, not grounds to discard the
    # whole observation; CR3-01's EXACT gate already requires a directly-
    # valid, reconciling used_percentage.
    used_percentage = _claude_runtime_bounded_percentage(payload.get("used_percentage"))
    def safe_names(value: Any) -> list[str]:
        if not isinstance(value, list) or len(value) > 32 or not all(isinstance(x, str) and 0 < len(x) <= 128 for x in value):
            return []
        return sorted(set(value))
    context_window_fields = safe_names(payload.get("context_window_fields"))
    current_usage_fields = safe_names(payload.get("current_usage_fields"))
    usage_kind = payload.get("current_usage_kind")
    if usage_kind not in {"object", "null", "missing", "other"}:
        usage_kind = "object" if isinstance(current_usage, dict) else "null"
    unknown_fields_present = payload.get("semantic_unknown_fields_present")
    if type(unknown_fields_present) is not bool: unknown_fields_present = False
    def safe_fingerprint(value: Any) -> str:
        return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else _claude_runtime_name_fingerprint(())

    return {
        "format_version": CLAUDE_RUNTIME_FORMAT_VERSION,
        "session_id": session_id.strip(),
        "transcript_path": canonical_path,
        "receipt_ns": receipt_ns,
        "claude_code_version": str(payload.get("claude_code_version") or "")[:64],
        "model_id": str(payload.get("model_id") or "")[:128],
        "model_display_name": str(payload.get("model_display_name") or "")[:128],
        "context_window_size": _bounded_int(payload.get("context_window_size")),
        "used_percentage": used_percentage,
        "total_input_tokens": _bounded_int(payload.get("total_input_tokens")),
        "total_output_tokens": _bounded_int(payload.get("total_output_tokens")),
        "current_usage": {
            "input_tokens": _bounded_int(current_usage.get("input_tokens")),
            "output_tokens": _bounded_int(current_usage.get("output_tokens")),
            "cache_creation_input_tokens": _bounded_int(current_usage.get("cache_creation_input_tokens")),
            "cache_read_input_tokens": _bounded_int(current_usage.get("cache_read_input_tokens")),
        } if isinstance(current_usage, dict) else None,
        "context_window_fields": context_window_fields,
        "current_usage_fields": current_usage_fields,
        "current_usage_kind": usage_kind,
        "semantic_unknown_fields_present": unknown_fields_present,
        "semantic_unknown_context_fingerprint": safe_fingerprint(payload.get("semantic_unknown_context_fingerprint")),
        "semantic_unknown_usage_fingerprint": safe_fingerprint(payload.get("semantic_unknown_usage_fingerprint")),
        # Untrusted display hint only -- never used for ordering.
        "observed_at": str(payload.get("observed_at") or "")[:64] or None,
    }


# CR2-08: the scan-work bound is independent of, and set well above, the
# retained-mailbox-size bound (CLAUDE_RUNTIME_INBOX_MAX_FILES). It caps how
# many DIRECTORY ENTRIES one call inspects at all (including junk that costs
# only a filename-shape regex check, never JSON parsing) -- not how many
# valid samples are retained. A same-user flood beyond this bound can delay
# processing across ticks (undefended starvation is possible and is
# documented here rather than pretending otherwise); it can never make one
# tick materialize or parse an unbounded number of entries.
CLAUDE_RUNTIME_INBOX_SCAN_MAX_ENTRIES = 5000


def _read_claude_runtime_inbox(state_dir: Optional[str] = None) -> list[tuple[Path, dict[str, Any]]]:
    """Read and whitelist-revalidate inbox samples, enforcing bounded mailbox
    hygiene (CR-08) and integrity (CR2-03/CR2-07/CR2-08):

    - streams the directory via os.scandir rather than materializing every
      entry up front, and inspects at most CLAUDE_RUNTIME_INBOX_SCAN_MAX_ENTRIES
      entries per call regardless of how many are actually present (bounded
      per-tick work, independent of the smaller retained-sample cap below);
    - a name that doesn't match the genuine bridge-generated filename shape is
      identified and unlinked via a cheap regex check ALONE, before any JSON
      parsing is attempted;
    - symlinked entries (and a symlinked inbox directory itself) are never
      followed, only unlinked -- best-effort same-user confinement, not a
      privilege boundary;
    - oversize/malformed/structurally-invalid files are quarantined (removed)
      immediately rather than skipped forever;
    - a body receipt_ns beyond the trusted wall-clock future-skew bound is
      rejected and can never be persisted or participate in ordering, closing
      off future-receipt poisoning even though mtime skew is also checked;
    - the filename's embedded receipt must agree exactly with the validated
      body receipt_ns, or the observation is treated as tampered;
    - the total RETAINED-VALID count is capped at CLAUDE_RUNTIME_INBOX_MAX_FILES,
      evicting the OLDEST-by-receipt *valid* entries first (applied only after
      validation/quarantine, so a junk burst can never starve genuinely newer
      valid samples by occupying eviction-exempt slots).

    Returns (file_path, sample) pairs ordered oldest-receipt-first so the
    caller can process the whole batch in trusted chronological order."""
    inbox = _claude_runtime_inbox_dir(state_dir)
    samples: list[tuple[Path, dict[str, Any]]] = []
    if default_state_dir(state_dir).is_symlink() or inbox.is_symlink():
        return samples  # CR2-07: never write through or read through a symlinked state-dir/inbox dir
    if not inbox.is_dir():
        return samples
    now = _identity_now()
    now_ns = time.time_ns()
    max_receipt_ns = now_ns + CLAUDE_RUNTIME_INBOX_MAX_FUTURE_SKEW_SECONDS * 1_000_000_000
    candidate_names: list[str] = []
    try:
        with os.scandir(inbox) as it:
            for i, entry in enumerate(it):
                if i >= CLAUDE_RUNTIME_INBOX_SCAN_MAX_ENTRIES:
                    break  # CR2-08: bounded scan work per call, regardless of directory size
                if not entry.name.endswith(".json"):
                    continue
                if _CLAUDE_RUNTIME_INBOX_FILENAME_RE.match(entry.name) is None:
                    # Not a genuine bridge-generated filename shape: cheap to
                    # reject, no JSON parsing needed. Quarantine on sight.
                    try:
                        os.unlink(entry.path)  # os.unlink never follows symlinks
                    except OSError:
                        pass
                    continue
                candidate_names.append(entry.name)
    except OSError:
        return samples
    for name in sorted(candidate_names):
        entry = inbox / name
        filename_receipt_ns = _claude_runtime_inbox_filename_receipt(name)
        try:
            if entry.is_symlink():
                entry.unlink(); continue
            st = entry.lstat()
            if st.st_size > CLAUDE_RUNTIME_INBOX_MAX_BYTES:
                entry.unlink(); continue
            mtime = dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc)
            if (mtime - now).total_seconds() > CLAUDE_RUNTIME_INBOX_MAX_FUTURE_SKEW_SECONDS:
                entry.unlink(); continue
            payload = _claude_runtime_json_loads(entry.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            try: entry.unlink()
            except OSError: pass
            continue
        sample = _claude_runtime_inbox_extract(payload, max_receipt_ns=max_receipt_ns, filename_receipt_ns=filename_receipt_ns)
        if sample is None:
            # Unrecognisable/malformed/structurally-invalid/tampered content
            # (including a future-poisoned or filename-mismatched receipt):
            # quarantine (remove) immediately rather than leaving it to
            # accumulate or retrying it indefinitely.
            try: entry.unlink()
            except OSError: pass
            continue
        samples.append((entry, sample))
    samples.sort(key=lambda item: item[1]["receipt_ns"])
    if len(samples) > CLAUDE_RUNTIME_INBOX_MAX_FILES:
        # Cap AFTER validation/quarantine, not before: capping first would let a
        # burst of junk filenames with high receipt prefixes starve genuinely
        # newer valid samples by occupying eviction-exempt slots. Evict the
        # oldest-by-receipt *valid* entries so junk never outranks real data.
        stale = samples[: len(samples) - CLAUDE_RUNTIME_INBOX_MAX_FILES]
        samples = samples[len(samples) - CLAUDE_RUNTIME_INBOX_MAX_FILES:]
        for entry, _sample in stale:
            try: entry.unlink()
            except OSError: pass
    return samples


def _claude_runtime_meta_key(stream_id: str) -> str:
    return f"claude_runtime:{stream_id}"


def resolve_claude_runtime_sample(store: StateStore, sample: dict[str, Any]) -> tuple[Optional[sqlite3.Row], str]:
    """Exact, non-fuzzy identity resolution: role='MAIN' AND session_id AND
    canonical transcript_path must all match exactly one existing Claude
    session row. No pane, no TTL, no control capability -- this path only
    ever feeds telemetry.

    role='MAIN' is required because Claude's status line empirically reports
    the parent/MAIN session's identity even while a subagent is actively
    running (validated against a captured Claude Code 2.1.239 before/after-
    compaction runtime fixture); without this constraint a SUBAGENT row
    sharing the same session_id/path could be resolved and made exact, which
    v1 must never do.

    Returns (row_or_None, reason) where reason is one of:
    "resolved", "unresolved" (zero matches), "ambiguous" (more than one match)."""
    session_id = str(sample.get("session_id") or "")
    try:
        transcript_path = _canonical_transcript_path(str(sample.get("transcript_path") or ""))
    except ValueError:
        return None, "unresolved"
    if not session_id:
        return None, "unresolved"
    rows = store.db.execute(
        "SELECT * FROM sessions WHERE provider='claude' AND role='MAIN' AND session_id=? AND path=?",
        (session_id, transcript_path),
    ).fetchall()
    if len(rows) == 0:
        return None, "unresolved"
    if len(rows) > 1:
        return None, "ambiguous"
    return rows[0], "resolved"


def _claude_runtime_version_validated(claude_code_version: Any) -> bool:
    """A malformed/missing/unvalidated version can never contribute EXACT
    context telemetry -- only the explicitly, empirically validated set can."""
    return isinstance(claude_code_version, str) and claude_code_version in CLAUDE_RUNTIME_EXACT_VERSIONS


def _claude_runtime_is_zero_only_unavailable_usage(
    sample: dict[str, Any], usage: Any, *, usage_complete: bool,
    total_input_tokens: Optional[int], total_output_tokens: Optional[int],
    used_percentage: Any, window_valid: bool,
) -> bool:
    """Recognise only Claude Code 2.1.239's observed all-zero status-line
    transition. A complete usage object with any nonzero component is outside
    this quirk; zero values are otherwise valid provider values."""
    claude_code_version = sample.get("claude_code_version")
    return (
        type(claude_code_version) is str
        and claude_code_version in CLAUDE_RUNTIME_ZERO_ONLY_UNAVAILABLE_VERSIONS
        and usage_complete
        and window_valid
        and total_input_tokens == 0
        and total_output_tokens == 0
        and type(used_percentage) is int
        and used_percentage == 0
        and all(usage[field] == 0 for field in (
            "input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens",
        ))
    )


def _claude_runtime_bounded_reported_occupancy(current_input_tokens: Optional[int], window: Optional[int]) -> Optional[float]:
    """CR3-02 round-trip safety: the parser rejects a stored occupancy outside
    [0.0, 1.2] and fails the whole snapshot closed. The writer must therefore
    never emit a ratio it computes here that its own reader would reject --
    otherwise a merely-reported (not validated) pair of totals could silently
    discard an entire persisted snapshot on the next read."""
    if current_input_tokens is None or window is None or window <= 0:
        return None
    ratio = current_input_tokens / window
    if not (0.0 <= ratio <= 1.2):
        return None
    return ratio


def _claude_runtime_derive(sample: dict[str, Any]) -> dict[str, Any]:
    """Derive denominator-based facts. CR3-01: current_context_input_tokens
    may only become EXACT when the COMPLETE validated evidence set holds --
    not merely internal self-consistency of the token breakdown:

      1. claude_code_version is explicitly validated (version_validated)
      2. current_usage is complete (usage_complete)
      3. token counters are internally consistent (counters_consistent --
         the sum identity alone; does NOT depend on used_percentage)
      4. context_window_size is directly present and strictly valid
         (window_valid)
      5. used_percentage is directly present and strictly valid
         (percentage_present_and_valid -- absence is NOT sufficient; a
         missing used_percentage must never be treated as "nothing to
         cross-check")
      6. derived input occupancy reconciles with used_percentage
         (percentage_reconciles)

    counters_consistent (item 3) and percentage_reconciles (item 6) are kept
    as SEPARATE facts on purpose: an absent or invalid used_percentage must
    never retroactively make the token-sum identity itself look inconsistent
    (which would wrongly downgrade reported_total_input_tokens, an
    at-most-OBSERVED field, to UNAVAILABLE). Never fabricates the auto-compact
    window.

    MODEL CONTEXT OCCUPANCY NUMERATOR = total_input_tokens
    = input_tokens + cache_creation_input_tokens + cache_read_input_tokens.
    output_tokens is deliberately excluded: Claude Code's own documented
    used_percentage is calculated from input tokens only, so folding
    total_output_tokens into the numerator here would silently diverge from
    the provider's own definition of "context window occupancy"."""
    window = sample.get("context_window_size")
    usage = sample.get("current_usage")
    # CR2-01: type(x) is int strictly -- isinstance(True, int) is True in
    # Python (bool is a subclass of int), so a naive isinstance check here
    # would let {"input_tokens": True, ...} satisfy usage_complete.
    usage_complete = isinstance(usage, dict) and all(type(usage.get(f)) is int for f in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"))
    current_input_tokens = sample.get("total_input_tokens")
    total_output = sample.get("total_output_tokens")
    if type(current_input_tokens) is not int: current_input_tokens = None
    if type(total_output) is not int: total_output = None
    if type(window) is not int: window = None
    window_valid = window is not None and window > 0
    counters_consistent = False
    if usage_complete and current_input_tokens is not None and total_output is not None:
        # Empirical fixture (v0.4.2 probe evidence): total_input_tokens + last
        # output_tokens should equal the sum of the current_usage breakdown.
        # This check validates internal consistency of the reported counters;
        # it does not mean output_tokens enters the occupancy numerator below.
        parts = [usage["input_tokens"], usage["output_tokens"], usage["cache_creation_input_tokens"], usage["cache_read_input_tokens"]]
        counters_consistent = (current_input_tokens + usage["output_tokens"]) == sum(parts)
    occupancy_pct = None
    if counters_consistent and current_input_tokens is not None and window_valid:
        occupancy_pct = current_input_tokens / window  # input tokens only, per Claude Code's used_percentage definition
    # CR3-01 items 5/6: used_percentage must be DIRECTLY present and strictly
    # valid, and must reconcile with the derived occupancy -- absence is
    # explicitly NOT permission to skip this cross-check for EXACT purposes.
    reported_pct = sample.get("used_percentage")
    percentage_present_and_valid = type(reported_pct) is int and 0 <= reported_pct <= 100
    if _claude_runtime_is_zero_only_unavailable_usage(
        sample, usage, usage_complete=usage_complete,
        total_input_tokens=current_input_tokens, total_output_tokens=total_output,
        used_percentage=reported_pct, window_valid=window_valid,
    ):
        # Do not let this known provider/version-specific transition use its
        # synthetically complete zero counters as positive validation evidence.
        # This intentionally matches the evidence strength of current_usage=null
        # without treating arbitrary zero-valued usage as unavailable.
        usage_complete = False
        counters_consistent = False
        occupancy_pct = None
    percentage_reconciles = (
        percentage_present_and_valid
        and occupancy_pct is not None
        and abs(occupancy_pct * 100 - reported_pct) <= 2
    )
    version_validated = _claude_runtime_version_validated(sample.get("claude_code_version"))
    # The complete evidence set required for EXACT (CR3-01, all six items).
    validated = (
        version_validated
        and usage_complete
        and counters_consistent
        and window_valid
        and percentage_present_and_valid
        and percentage_reconciles
    )
    return {
        # Validated current-context INPUT measurement: only set when the full
        # six-item evidence chain holds. This is what may ever be labelled
        # EXACT. Deliberately does not include total_output_tokens.
        "current_context_input_tokens": current_input_tokens if validated else None,
        "model_context_occupancy_pct": occupancy_pct if validated else None,
        # Raw reported totals, retained separately as at-most-OBSERVED evidence
        # even when they cannot be validated as an exact current-context value.
        "reported_total_input_tokens": current_input_tokens,
        "reported_total_output_tokens": total_output,
        "reported_model_context_occupancy_pct": _claude_runtime_bounded_reported_occupancy(current_input_tokens, window),
        "model_context_window_tokens": window if window_valid else None,
        "window_valid": window_valid,
        "usage_complete": usage_complete,
        "counters_consistent": counters_consistent,
        "percentage_present_and_valid": percentage_present_and_valid,
        "percentage_reconciles": percentage_reconciles,
        "version_validated": version_validated,
        "validated": validated,
    }


# CR2-06: a conservative, EXPLICIT combine function over the full
# ProviderCapability enum -- not a bare rank dict, because PROXY and PARTIAL
# are not naturally totally ordered against each other anywhere else in this
# project (PROXY = a documented stand-in quantity for a different metric;
# PARTIAL = the same metric with some fields missing -- genuinely orthogonal
# reduced-fidelity tiers, not comparable in strength). Both are always weaker
# than OBSERVED and stronger than UNAVAILABLE, so that much is a real order;
# only the PROXY-vs-PARTIAL edge has no honest answer. This feature (Claude
# runtime telemetry) never actually produces a PROXY or PARTIAL value itself,
# so that edge is unreachable in practice here -- but _claude_runtime_capability_combine
# must still return a fixed, deterministic, non-raising answer for it rather
# than pretending a total order exists or letting min()/KeyError leak an
# implementation detail. The tie is broken by a fixed precedence
# (PARTIAL before PROXY) documented here as arbitrary-but-fixed, purely so the
# function is total; no code path in this feature relies on that choice.
_CAPABILITY_TIER = {
    ProviderCapability.UNAVAILABLE.value: 0,
    ProviderCapability.PROXY.value: 1,
    ProviderCapability.PARTIAL.value: 1,  # tied with PROXY: no natural order between them
    ProviderCapability.OBSERVED.value: 2,
    ProviderCapability.EXACT.value: 3,
}
# Fixed, arbitrary-but-documented tie-break used ONLY when the two operands
# are PROXY and PARTIAL specifically (same tier, no natural order).
_CAPABILITY_TIE_BREAK_WEAKER = ProviderCapability.PARTIAL.value


def _claude_runtime_capability_combine(a: str, b: str) -> str:
    """The critical invariant a derived capability must never violate: it can
    never be stronger than either operand. Total over every ProviderCapability
    member -- never raises KeyError for a valid enum value; an unrecognized
    string is treated as UNAVAILABLE (fail closed) rather than raising."""
    unavailable = ProviderCapability.UNAVAILABLE.value
    # Normalize any unrecognized string to UNAVAILABLE outright -- fail
    # closed rather than ever returning a value that isn't a real enum member.
    a = a if a in _CAPABILITY_TIER else unavailable
    b = b if b in _CAPABILITY_TIER else unavailable
    rank_a, rank_b = _CAPABILITY_TIER[a], _CAPABILITY_TIER[b]
    if rank_a != rank_b:
        return a if rank_a < rank_b else b
    if rank_a == 1 and {a, b} == {ProviderCapability.PROXY.value, ProviderCapability.PARTIAL.value}:
        return _CAPABILITY_TIE_BREAK_WEAKER
    return a  # equal tier, not the PROXY/PARTIAL edge case (e.g. a == b): either operand is correct


def _claude_runtime_capability(derived: dict[str, Any]) -> dict[str, str]:
    """Capability is a pure function of the evidence facts, and always describes
    the field it is attached to -- a field that is None is never labelled
    anything but UNAVAILABLE, so capability text and value presence never
    disagree with each other.

    Three independently-graded evidence tiers:

    IDENTITY (session_id, transcript_path, model_id, claude_code_version):
      directly reported by a resolved statusLine payload -> EXACT.

    MODEL WINDOW (model_context_window_tokens): context_window_size is a
      directly reported runtime field ("maximum context window size in
      tokens") -- not derived from the historically problematic
      current-context counters, so a valid direct value is EXACT outright.
      Never inferred from model name/table/autoCompactWindow/percentage.

    CURRENT CONTEXT INPUT (current_context_input_tokens): CR3-01 -- EXACT
      requires the COMPLETE evidence set (derived["validated"]): empirically
      validated version, complete usage, internally consistent counters, a
      directly-valid context window, a directly-valid used_percentage, AND
      derived occupancy reconciling with that percentage. Internal
      self-consistency of the token breakdown alone is never sufficient --
      that is exactly the historical semantic-bug class this guards against.
      Complete-but-not-fully-evidenced (e.g. missing/invalid used_percentage,
      or an unvalidated version) -> at most OBSERVED; incomplete/inconsistent
      usage -> UNAVAILABLE.

    MODEL OCCUPANCY (model_context_occupancy_pct / reported_model_context_occupancy_pct):
      a DERIVED value (current-context-input / window) and must never be
      labelled more strongly than its weakest operand -- both EXACT -> EXACT;
      current-context-input OBSERVED + window EXACT -> OBSERVED; either
      operand UNAVAILABLE -> UNAVAILABLE."""
    usage_complete, counters_consistent, version_validated = derived["usage_complete"], derived["counters_consistent"], derived["version_validated"]
    validated = derived.get("validated", False)
    window_cap = ProviderCapability.EXACT.value if derived.get("window_valid") else ProviderCapability.UNAVAILABLE.value
    if validated:
        current_input_cap = ProviderCapability.EXACT.value
    elif usage_complete and counters_consistent:
        current_input_cap = ProviderCapability.OBSERVED.value
    else:
        current_input_cap = ProviderCapability.UNAVAILABLE.value
    validated_occupancy_cap = ProviderCapability.EXACT.value if validated else ProviderCapability.UNAVAILABLE.value
    # Derived occupancy fields: never exceed the weaker of their two operands.
    reported_occupancy_cap = ProviderCapability.OBSERVED.value if (usage_complete and counters_consistent) else ProviderCapability.UNAVAILABLE.value
    validated_occupancy_cap = _claude_runtime_capability_combine(validated_occupancy_cap, window_cap)
    reported_occupancy_cap = _claude_runtime_capability_combine(reported_occupancy_cap, window_cap)
    return {
        "session_id": ProviderCapability.EXACT.value,
        "transcript_path": ProviderCapability.EXACT.value,
        "model_id": ProviderCapability.EXACT.value,
        "claude_code_version": ProviderCapability.EXACT.value,
        "model_context_window_tokens": window_cap,
        "current_context_input_tokens": current_input_cap if current_input_cap == ProviderCapability.EXACT.value else ProviderCapability.UNAVAILABLE.value,
        "model_context_occupancy_pct": validated_occupancy_cap,
        "reported_total_input_tokens": ProviderCapability.OBSERVED.value if (usage_complete and counters_consistent) else ProviderCapability.UNAVAILABLE.value,
        "reported_total_output_tokens": ProviderCapability.OBSERVED.value if isinstance(derived.get("reported_total_output_tokens"), int) else ProviderCapability.UNAVAILABLE.value,
        "reported_model_context_occupancy_pct": reported_occupancy_cap,
        "auto_compact_window_tokens": ProviderCapability.UNAVAILABLE.value,
        "auto_compact_occupancy_pct": ProviderCapability.UNAVAILABLE.value,
    }


def _claude_runtime_valid_optional_str(value: Any, max_len: int = 4096) -> bool:
    return value is None or (isinstance(value, str) and len(value) <= max_len)


def _claude_runtime_valid_optional_int(value: Any) -> bool:
    # CR3-02: a persisted token-count field must satisfy the same bound the
    # live extraction path enforces (_claude_runtime_bounded_int) -- a
    # negative or pathologically oversized value is semantically invalid
    # (never something the writer itself would produce), not just
    # syntactically an int.
    return value is None or _claude_runtime_bounded_int(value) is not None


def _claude_runtime_valid_optional_finite_float(value: Any, *, lo: float = 0.0, hi: float = 1.2) -> bool:
    # CR3-02: occupancy is a stored fraction (0.0-1.0) -- negative is never
    # semantically valid, and 1.2 tolerates the writer's own legitimate
    # near-boundary overflow (current-context tokens can transiently exceed
    # the window right at/before a compaction), while firmly rejecting a
    # pathological value like 1.5. Never NaN/Infinity, always a real float
    # type, never bool/int masquerading as one.
    if value is None:
        return True
    if type(value) is not float:
        return False
    if math.isnan(value) or math.isinf(value):
        return False
    return lo <= value <= hi


def _claude_runtime_valid_capability_value(value: Any) -> bool:
    return isinstance(value, str) and value in _CAPABILITY_TIER


def _claude_runtime_valid_optional_receipt_ns(value: Any) -> bool:
    # CR3-02: regime_started_at shares receipt_ns's shape/semantics (a
    # trusted wall-clock nanosecond timestamp), not a token count -- it must
    # never be run through the 100M token-count bound, and must obey the
    # same non-negative / not-implausibly-future constraints receipt_ns itself
    # is held to elsewhere in this module.
    if value is None:
        return True
    if type(value) is not int or value < 0:
        return False
    return value <= time.time_ns() + CLAUDE_RUNTIME_INBOX_MAX_FUTURE_SKEW_SECONDS * 1_000_000_000


def _claude_runtime_valid_regime(value: Any) -> bool:
    if not (isinstance(value, list) and len(value) == 2):
        return False
    model_id, window = value
    if not _claude_runtime_valid_optional_str(value=model_id, max_len=128):
        return False
    return window is None or (type(window) is int and 0 <= window <= 100_000_000)


def _parse_claude_runtime_snapshot(raw_value: Optional[str]) -> dict[str, Any]:
    """Centralised, STRUCTURALLY EXHAUSTIVE parser for the claude_runtime:*
    service_meta value (CR2-02). Never raises. If ANY field that merge, peak
    max/min, ordering, formatting, capability derivation, regime logic, or
    status rendering later consumes fails validation, the ENTIRE prior
    snapshot is discarded and treated as absent -- partial trust of malformed
    persisted state is exactly the class of bug that let a stray string reach
    `int > str` in a later comparison. A corrupted row can neither crash
    ingestion/status/reset/a daemon tick nor block a new valid observation
    from replacing it (an empty {} never satisfies the older-receipt guard in
    store_claude_runtime_sample, so the next genuine sample always wins)."""
    if not raw_value:
        return {}
    try:
        value = _claude_runtime_json_loads(raw_value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    if not isinstance(value, dict):
        return {}

    # --- identity / bookkeeping ---
    if value.get("format_version") != CLAUDE_RUNTIME_FORMAT_VERSION:
        return {}
    if not isinstance(value.get("stream_id"), str):
        return {}
    if not _claude_runtime_valid_optional_str(value.get("session_id")):
        return {}
    if not _claude_runtime_valid_optional_str(value.get("transcript_path"), max_len=8192):
        return {}
    if not _claude_runtime_valid_optional_str(value.get("claude_code_version"), max_len=64):
        return {}
    if not _claude_runtime_valid_optional_str(value.get("model_id"), max_len=128):
        return {}
    if not _claude_runtime_valid_optional_str(value.get("model_display_name"), max_len=128):
        return {}

    # --- receipt / timestamps: receipt_ns is the only trusted ordering
    # signal and MUST be a plain, non-negative, not-implausibly-future int ---
    receipt_ns = value.get("receipt_ns")
    if type(receipt_ns) is not int or receipt_ns < 0:
        return {}
    if receipt_ns > time.time_ns() + CLAUDE_RUNTIME_INBOX_MAX_FUTURE_SKEW_SECONDS * 1_000_000_000:
        return {}  # CR2-03: a future-poisoned persisted receipt must fail closed too
    # CR3-02: observed_at/last_validated_at, when present, must be usable
    # timestamps per the project's real timestamp parser -- not merely
    # syntactically a string. "not-a-timestamp" must fail closed here rather
    # than being carried forward as a plausible-looking display value.
    for ts_key in ("observed_at", "last_validated_at"):
        ts_value = value.get(ts_key)
        if ts_value is not None and (not isinstance(ts_value, str) or iso_to_dt(ts_value) is None):
            return {}

    # --- latest counters ---
    if not _claude_runtime_valid_optional_int(value.get("current_context_input_tokens")):
        return {}
    if not _claude_runtime_valid_optional_int(value.get("model_context_window_tokens")):
        return {}
    if not _claude_runtime_valid_optional_finite_float(value.get("model_context_occupancy_pct")):
        return {}

    # --- reported (at-most-OBSERVED) counters ---
    if not _claude_runtime_valid_optional_int(value.get("reported_total_input_tokens")):
        return {}
    if not _claude_runtime_valid_optional_int(value.get("reported_total_output_tokens")):
        return {}
    if not _claude_runtime_valid_optional_finite_float(value.get("reported_model_context_occupancy_pct")):
        return {}

    # --- peak counters ---
    if not _claude_runtime_valid_optional_int(value.get("peak_current_context_input_tokens")):
        return {}
    if not _claude_runtime_valid_optional_finite_float(value.get("peak_model_context_occupancy_pct")):
        return {}

    # --- auto-compact fields: CR3-02 REQUIRES these to always be None for
    # v1 -- this feature never emits an auto-compact measurement, so a
    # tampered service_meta snapshot claiming otherwise (e.g.
    # auto_compact_window_tokens=1) must fail closed rather than let a
    # fabricated value silently become populated. ---
    if value.get("auto_compact_window_tokens") is not None:
        return {}
    if value.get("auto_compact_occupancy_pct") is not None:
        return {}
    if value.get("peak_auto_compact_occupancy_pct") is not None:
        return {}

    # --- evidence booleans ---
    for flag_key in ("usage_complete", "counters_consistent", "version_validated"):
        flag_value = value.get(flag_key)
        if flag_value is not None and type(flag_value) is not bool:
            return {}

    # --- regime shape ---
    regime = value.get("regime")
    if regime is not None and not _claude_runtime_valid_regime(regime):
        return {}
    if not _claude_runtime_valid_optional_receipt_ns(value.get("regime_started_at")):
        return {}

    # --- capability map: every value must be an actual ProviderCapability ---
    capability = value.get("capability")
    if capability is not None:
        if not isinstance(capability, dict):
            return {}
        for cap_value in capability.values():
            if not _claude_runtime_valid_capability_value(cap_value):
                return {}

    # --- provenance/integrity notes: bounded list of strings only ---
    notes = value.get("provenance_notes")
    if notes is not None:
        if not (isinstance(notes, list) and len(notes) <= 16 and all(isinstance(n, str) and len(n) <= 2048 for n in notes)):
            return {}

    return value


def store_claude_runtime_sample(store: StateStore, row: sqlite3.Row, sample: dict[str, Any], *, receipt_ns: Optional[int] = None) -> bool:
    """Merge one resolved runtime sample into the bounded per-stream service_meta
    snapshot. Latest-observation-wins uses the caller-supplied trusted receipt
    (never the incoming payload's own observed_at). Peak fields only advance
    within the SAME telemetry regime -- (model_id, model_context_window_tokens)
    -- a regime change resets peaks rather than merging incompatible values."""
    stream_id = str(row["stream_id"])
    key = _claude_runtime_meta_key(stream_id)
    existing_row = store.db.execute("SELECT value FROM service_meta WHERE key=?", (key,)).fetchone()
    existing = _parse_claude_runtime_snapshot(existing_row[0] if existing_row else None)
    receipt_ns = receipt_ns if receipt_ns is not None else time.time_ns()
    # CR3-03: this is the final merge boundary and must be independently safe
    # even when called directly, without going through the normal inbox
    # reader's validation. type(x) is int strictly (never bool -- bool is a
    # subclass of int in Python), non-negative, and within the same trusted
    # wall-clock future-skew bound receipt_ns is held to everywhere else
    # (CR2-03) -- a caller-supplied bool/float/string/negative/future receipt
    # must never be persisted or participate in ordering.
    if type(receipt_ns) is not int or receipt_ns < 0:
        return False
    max_receipt_ns = time.time_ns() + CLAUDE_RUNTIME_INBOX_MAX_FUTURE_SKEW_SECONDS * 1_000_000_000
    if receipt_ns > max_receipt_ns:
        return False
    if isinstance(existing.get("receipt_ns"), int) and receipt_ns <= existing["receipt_ns"]:
        return False  # equal receipt is an inbox crash replay, not new evidence
    derived = _claude_runtime_derive(sample)
    regime = [sample.get("model_id"), derived.get("model_context_window_tokens")]
    existing_regime = existing.get("regime")
    regime_changed = existing_regime is not None and existing_regime != regime
    new_regime = existing_regime is None or regime_changed
    peak_tokens = existing.get("peak_current_context_input_tokens")
    peak_pct = existing.get("peak_model_context_occupancy_pct")
    if new_regime:
        peak_tokens, peak_pct = derived.get("current_context_input_tokens"), derived.get("model_context_occupancy_pct")
    else:
        if isinstance(derived.get("current_context_input_tokens"), int):
            peak_tokens = max(peak_tokens or 0, derived["current_context_input_tokens"])
        if isinstance(derived.get("model_context_occupancy_pct"), float):
            peak_pct = max(peak_pct or 0.0, derived["model_context_occupancy_pct"])
    observed_at = sample.get("observed_at") if isinstance(sample.get("observed_at"), str) else None
    snapshot = {
        "format_version": CLAUDE_RUNTIME_FORMAT_VERSION,
        "receipt_ns": receipt_ns,
        "observed_at": observed_at,
        "session_id": sample.get("session_id"),
        "transcript_path": sample.get("transcript_path"),
        "stream_id": stream_id,
        "claude_code_version": sample.get("claude_code_version"),
        "model_id": sample.get("model_id"),
        "model_display_name": sample.get("model_display_name"),
        "current_context_input_tokens": derived.get("current_context_input_tokens"),
        "peak_current_context_input_tokens": peak_tokens,
        "reported_total_input_tokens": derived.get("reported_total_input_tokens"),
        "reported_total_output_tokens": derived.get("reported_total_output_tokens"),
        "reported_model_context_occupancy_pct": derived.get("reported_model_context_occupancy_pct"),
        "model_context_window_tokens": derived.get("model_context_window_tokens"),
        "model_context_occupancy_pct": derived.get("model_context_occupancy_pct"),
        "peak_model_context_occupancy_pct": peak_pct,
        "auto_compact_window_tokens": None,
        "auto_compact_occupancy_pct": None,
        "peak_auto_compact_occupancy_pct": None,
        "usage_complete": derived.get("usage_complete"),
        "counters_consistent": derived.get("counters_consistent"),
        "version_validated": derived.get("version_validated"),
        "regime": regime,
        "regime_started_at": receipt_ns if new_regime else existing.get("regime_started_at", receipt_ns),
        "last_validated_at": observed_at if derived.get("current_context_input_tokens") is not None else existing.get("last_validated_at"),
        "capability": _claude_runtime_capability(derived),
        "provenance_notes": [
            "current_context_input_tokens, when present, is validated for the session identity "
            "Claude Code reported; Claude's status line does not partition delegated/subagent "
            "consumption, so this value may include work performed by a delegated subagent. It is "
            "total_input_tokens only (input_tokens + cache_creation_input_tokens + "
            "cache_read_input_tokens); total_output_tokens is tracked separately as "
            "reported_total_output_tokens and never enters model_context_occupancy_pct, matching "
            "Claude Code's own documented used_percentage definition (input tokens only).",
            f"EXACT capability requires claude_code_version to be in the empirically validated "
            f"set {sorted(CLAUDE_RUNTIME_EXACT_VERSIONS)}; other versions are at most OBSERVED "
            "even when internally self-consistent. model_context_window_tokens is a directly "
            "reported provider field (not derived from current-context counters) and is EXACT "
            "whenever validly present, independent of claude_code_version. Derived occupancy "
            "fields are never labelled more strongly than their weakest operand.",
        ],
    }
    store.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES(?,?)", (key, json.dumps(snapshot, sort_keys=True)))
    return True


CLAUDE_RUNTIME_INBOX_UNRESOLVED_MAX_AGE_SECONDS = 30 * 60
CLAUDE_RUNTIME_SEMANTIC_MAX_FINGERPRINTS_PER_PROFILE = 16
CLAUDE_RUNTIME_SEMANTIC_STREAM_TTL_SECONDS = 30 * 24 * 60 * 60
CLAUDE_RUNTIME_SEMANTIC_MAX_STREAMS = 2048
_CLAUDE_RUNTIME_CONTEXT_FIELDS = frozenset({"context_window_size", "current_usage", "remaining_percentage", "total_input_tokens", "total_output_tokens", "used_percentage"})
_CLAUDE_RUNTIME_USAGE_FIELDS = frozenset({"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"})


def _claude_runtime_semantic_profile(sample: dict[str, Any]) -> tuple[str, str, str, int]:
    window = sample.get("context_window_size")
    return ("claude", str(sample.get("claude_code_version") or "")[:64], str(sample.get("model_id") or "")[:128], window if _claude_runtime_bounded_int(window) is not None else -1)


def _claude_runtime_semantic_fingerprint(names: list[str], unknown_fingerprint: str) -> tuple[str, str]:
    canonical = ",".join(sorted(set(names)))
    # The opaque unknown-name digest distinguishes provider shapes without
    # persisting those names. It is part of the digest input, never the list.
    return hashlib.sha256((canonical + "\x00unknown:" + unknown_fingerprint).encode("utf-8")).hexdigest(), canonical


def _claude_runtime_semantic_facts(sample: dict[str, Any]) -> dict[str, Any]:
    """Classify orthogonal facts. Invalidity wins only its own counters; it
    does not erase independently useful null/missing/field-shape evidence."""
    raw_ctx_names = sample.get("context_window_fields") if isinstance(sample.get("context_window_fields"), list) else []
    raw_usage_names = sample.get("current_usage_fields") if isinstance(sample.get("current_usage_fields"), list) else []
    ctx_unknown_names = set(raw_ctx_names) - _CLAUDE_RUNTIME_CONTEXT_FIELDS
    usage_unknown_names = set(raw_usage_names) - _CLAUDE_RUNTIME_USAGE_FIELDS
    ctx_names = sorted(set(raw_ctx_names) & _CLAUDE_RUNTIME_CONTEXT_FIELDS)
    usage_names = sorted(set(raw_usage_names) & _CLAUDE_RUNTIME_USAGE_FIELDS)
    kind = sample.get("current_usage_kind") if sample.get("current_usage_kind") in {"object", "null", "missing", "other"} else ("object" if isinstance(sample.get("current_usage"), dict) else "null")
    usage = sample.get("current_usage") if isinstance(sample.get("current_usage"), dict) else {}
    required = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
    usage_complete = kind == "object" and all(_claude_runtime_bounded_int(usage.get(k)) is not None for k in required)
    all_zero = usage_complete and all(usage[k] == 0 for k in required) and sample.get("total_input_tokens") == 0
    nonzero = usage_complete and not all_zero
    window_field_present = "context_window_size" in ctx_names or (not ctx_names and sample.get("context_window_size") is not None)
    window_valid = _claude_runtime_bounded_int(sample.get("context_window_size")) is not None
    numeric_keys = ("context_window_size", "total_input_tokens", "total_output_tokens")
    numeric_invalid = any(k in ctx_names and _claude_runtime_bounded_int(sample.get(k)) is None for k in numeric_keys) or any(k in usage_names and _claude_runtime_bounded_int(usage.get(k)) is None for k in required)
    percentage_present = "used_percentage" in ctx_names or (not ctx_names and sample.get("used_percentage") is not None)
    percentage_valid = _claude_runtime_bounded_percentage(sample.get("used_percentage")) is not None
    operands = (sample.get("total_input_tokens"), usage.get("input_tokens"), usage.get("cache_creation_input_tokens"), usage.get("cache_read_input_tokens"))
    identity_testable = all(_claude_runtime_bounded_int(v) is not None for v in operands)
    identity_pass = identity_testable and operands[0] == operands[1] + operands[2] + operands[3]
    ctx_unknown_fp = sample.get("semantic_unknown_context_fingerprint") if isinstance(sample.get("semantic_unknown_context_fingerprint"), str) else _claude_runtime_name_fingerprint(ctx_unknown_names)
    usage_unknown_fp = sample.get("semantic_unknown_usage_fingerprint") if isinstance(sample.get("semantic_unknown_usage_fingerprint"), str) else _claude_runtime_name_fingerprint(usage_unknown_names)
    unknown = bool(sample.get("semantic_unknown_fields_present")) or bool(ctx_unknown_names or usage_unknown_names)
    state = "NORMAL" if nonzero else "ZERO" if all_zero else "NULL" if kind == "null" else "OTHER"
    return {"complete_nonzero": nonzero, "complete_all_zero": all_zero, "usage_null": kind == "null", "usage_missing": kind == "missing", "partial": kind == "object" and not usage_complete,
            "invalid": numeric_invalid or kind == "other", "identity_testable": identity_testable, "identity_pass": identity_pass,
            "window_present": window_valid, "window_missing": not window_field_present, "window_invalid": window_field_present and not window_valid,
            "numeric_valid": not numeric_invalid, "numeric_invalid": numeric_invalid, "percentage_present": percentage_present,
            "percentage_valid": percentage_valid, "unknown": unknown, "state": state, "ctx_names": ctx_names, "usage_names": usage_names, "ctx_unknown_fp": ctx_unknown_fp, "usage_unknown_fp": usage_unknown_fp,
            "contradiction": (identity_testable and not identity_pass) or numeric_invalid or kind == "other"}


def record_claude_runtime_semantic_evidence(store: StateStore, row: sqlite3.Row, sample: dict[str, Any], receipt_ns: int) -> None:
    """Update durable aggregate evidence. This function has no return value and
    is deliberately never consulted by runtime derivation or qualification."""
    profile = _claude_runtime_semantic_profile(sample); facts = _claude_runtime_semantic_facts(sample)
    now = dt.datetime.fromtimestamp(receipt_ns / 1_000_000_000, dt.timezone.utc).isoformat()
    cols = ("complete_nonzero_count", "complete_all_zero_count", "current_usage_null_count", "current_usage_missing_count", "partial_usage_count", "invalid_count", "counter_identity_testable", "counter_identity_pass", "counter_identity_fail", "window_present_count", "window_missing_count", "window_invalid_count", "numeric_valid_count", "numeric_invalid_count", "percentage_present_count", "percentage_missing_count", "percentage_valid_type_count", "percentage_invalid_type_count", "unknown_field_occurrence_count", "contradiction_count")
    inc = dict.fromkeys(cols, 0)
    inc.update(complete_nonzero_count=int(facts["complete_nonzero"]), complete_all_zero_count=int(facts["complete_all_zero"]), current_usage_null_count=int(facts["usage_null"]), current_usage_missing_count=int(facts["usage_missing"]), partial_usage_count=int(facts["partial"]), invalid_count=int(facts["invalid"]), counter_identity_testable=int(facts["identity_testable"]), counter_identity_pass=int(facts["identity_pass"]), counter_identity_fail=int(facts["identity_testable"] and not facts["identity_pass"]), window_present_count=int(facts["window_present"]), window_missing_count=int(facts["window_missing"]), window_invalid_count=int(facts["window_invalid"]), numeric_valid_count=int(facts["numeric_valid"]), numeric_invalid_count=int(facts["numeric_invalid"]), percentage_present_count=int(facts["percentage_present"]), percentage_missing_count=int(not facts["percentage_present"]), percentage_valid_type_count=int(facts["percentage_present"] and facts["percentage_valid"]), percentage_invalid_type_count=int(facts["percentage_present"] and not facts["percentage_valid"]), unknown_field_occurrence_count=int(facts["unknown"]), contradiction_count=int(facts["contradiction"]))
    names = ["provider", "claude_code_version", "model_id", "model_context_window_tokens", "first_seen", "last_seen", "samples_total"] + list(inc)
    values = list(profile) + [now, now, 1] + [inc[n] for n in inc]
    store.db.execute(f"INSERT INTO claude_runtime_semantic_evidence({','.join(names)}) VALUES({','.join('?' for _ in names)}) ON CONFLICT(provider,claude_code_version,model_id,model_context_window_tokens) DO UPDATE SET last_seen=excluded.last_seen,samples_total=samples_total+1," + ",".join(f"{k}={k}+excluded.{k}" for k in inc), values)
    ctx_fp, ctx_list = _claude_runtime_semantic_fingerprint(facts["ctx_names"], facts["ctx_unknown_fp"]); usage_fp, usage_list = _claude_runtime_semantic_fingerprint(facts["usage_names"], facts["usage_unknown_fp"])
    fp_key = profile + (ctx_fp, usage_fp)
    fp = store.db.execute("SELECT 1 FROM claude_runtime_semantic_fingerprints WHERE provider=? AND claude_code_version=? AND model_id=? AND model_context_window_tokens=? AND context_window_fingerprint=? AND current_usage_fingerprint=?", fp_key).fetchone()
    if fp or store.db.execute("SELECT count(*) FROM claude_runtime_semantic_fingerprints WHERE provider=? AND claude_code_version=? AND model_id=? AND model_context_window_tokens=?", profile).fetchone()[0] < CLAUDE_RUNTIME_SEMANTIC_MAX_FINGERPRINTS_PER_PROFILE:
        store.db.execute("INSERT INTO claude_runtime_semantic_fingerprints(provider,claude_code_version,model_id,model_context_window_tokens,context_window_fingerprint,current_usage_fingerprint,context_window_fields,current_usage_fields,unknown_fields_present,count,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(provider,claude_code_version,model_id,model_context_window_tokens,context_window_fingerprint,current_usage_fingerprint) DO UPDATE SET count=count+1,last_seen=excluded.last_seen", fp_key + (ctx_list, usage_list, int(facts["unknown"]), 1, now, now))
    stream_hash = hashlib.sha256(str(row["stream_id"]).encode("utf-8")).hexdigest()
    prior = store.db.execute("SELECT previous_state,previous_receipt_ns,provider,claude_code_version,model_id,model_context_window_tokens FROM claude_runtime_semantic_streams WHERE stream_hash=?", (stream_hash,)).fetchone()
    if prior is None or tuple(prior[k] for k in ("provider", "claude_code_version", "model_id", "model_context_window_tokens")) != profile:
        store.db.execute("UPDATE claude_runtime_semantic_evidence SET stream_cursor_epochs_seen=stream_cursor_epochs_seen+1 WHERE provider=? AND claude_code_version=? AND model_id=? AND model_context_window_tokens=?", profile)
    else:
        transition = {("NORMAL", "ZERO"): "normal_to_zero", ("NORMAL", "NULL"): "normal_to_null", ("ZERO", "NORMAL"): "zero_to_normal", ("NULL", "NORMAL"): "null_to_normal", ("ZERO", "ZERO"): "zero_to_zero", ("NULL", "NULL"): "null_to_null"}.get((prior["previous_state"], facts["state"]))
        if transition:
            store.db.execute(f"UPDATE claude_runtime_semantic_evidence SET {transition}={transition}+1 WHERE provider=? AND claude_code_version=? AND model_id=? AND model_context_window_tokens=?", profile)
            if transition in {"normal_to_zero", "normal_to_null"}: store.db.execute("UPDATE claude_runtime_semantic_evidence SET transition_without_recovery=transition_without_recovery+1 WHERE provider=? AND claude_code_version=? AND model_id=? AND model_context_window_tokens=?", profile)
            if transition in {"zero_to_normal", "null_to_normal"}:
                prior_profile = tuple(prior[k] for k in ("provider", "claude_code_version", "model_id", "model_context_window_tokens"))
                store.db.execute("UPDATE claude_runtime_semantic_evidence SET transition_without_recovery=MAX(0,transition_without_recovery-1) WHERE provider=? AND claude_code_version=? AND model_id=? AND model_context_window_tokens=?", prior_profile)
                elapsed = max(0, receipt_ns - prior["previous_receipt_ns"]) / 1_000_000_000; bucket = "recovery_le_5s" if elapsed <= 5 else "recovery_le_30s" if elapsed <= 30 else "recovery_le_2m" if elapsed <= 120 else "recovery_gt_2m"
                store.db.execute(f"UPDATE claude_runtime_semantic_evidence SET {bucket}={bucket}+1 WHERE provider=? AND claude_code_version=? AND model_id=? AND model_context_window_tokens=?", profile)
    store.db.execute("INSERT INTO claude_runtime_semantic_streams(stream_hash,previous_state,previous_receipt_ns,provider,claude_code_version,model_id,model_context_window_tokens,last_seen) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(stream_hash) DO UPDATE SET previous_state=excluded.previous_state,previous_receipt_ns=excluded.previous_receipt_ns,provider=excluded.provider,claude_code_version=excluded.claude_code_version,model_id=excluded.model_id,model_context_window_tokens=excluded.model_context_window_tokens,last_seen=excluded.last_seen", (stream_hash, facts["state"], receipt_ns, *profile, now))
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=CLAUDE_RUNTIME_SEMANTIC_STREAM_TTL_SECONDS)).isoformat()
    store.db.execute("DELETE FROM claude_runtime_semantic_streams WHERE last_seen < ?", (cutoff,))
    store.db.execute("DELETE FROM claude_runtime_semantic_streams WHERE stream_hash IN (SELECT stream_hash FROM claude_runtime_semantic_streams ORDER BY last_seen DESC LIMIT -1 OFFSET ?)", (CLAUDE_RUNTIME_SEMANTIC_MAX_STREAMS,))


def ingest_claude_runtime_inbox(store: StateStore, state_dir: Optional[str] = None) -> dict[str, int]:
    """Read the bounded inbox, resolve each sample by exact identity, and merge
    resolved samples into service_meta IN TRUSTED-RECEIPT ORDER (oldest first).
    Processing the whole ordered batch through the same merge function -- rather
    than only ever looking at the newest sample -- is what lets a model/window
    regime change (CR-09) that occurs mid-batch be applied at the right point in
    the sequence. Never writes SQLite from the bridge itself; this is the only
    path that opens the database for runtime telemetry.

    The inbox is a mailbox, not durable history: a resolved sample is deleted
    once merged into service_meta (the durable copy), and an unresolved sample
    -- e.g. the status line fired before the transcript was first discovered --
    is retried on later scans but evicted once stale (using the trusted local
    receipt, never the untrusted payload observed_at), so the directory never
    grows unbounded and a session reset can't resurrect a stale snapshot."""
    metrics = {"samples_read": 0, "resolved": 0, "unresolved": 0, "ambiguous": 0}
    now_ns = time.time_ns()
    stale_ns = CLAUDE_RUNTIME_INBOX_UNRESOLVED_MAX_AGE_SECONDS * 1_000_000_000
    with store.db:
        # Reserve the writer before observing any prior aggregate/cursor state;
        # concurrent service processes serialize deterministically.
        store.db.execute("BEGIN IMMEDIATE")
        for entry, sample in _read_claude_runtime_inbox(state_dir):
            metrics["samples_read"] += 1
            row, reason = resolve_claude_runtime_sample(store, sample)
            if row is None:
                metrics[reason] += 1
                if now_ns - sample["receipt_ns"] > stale_ns:
                    try: entry.unlink()
                    except OSError: pass
                continue
            accepted = store_claude_runtime_sample(store, row, sample, receipt_ns=sample["receipt_ns"])
            # Semantic evidence is durable before the source mailbox entry is
            # removed. It is aggregate-only and cannot influence the snapshot.
            if accepted:
                record_claude_runtime_semantic_evidence(store, row, sample, sample["receipt_ns"])
            metrics["resolved"] += 1
            try: entry.unlink()
            except OSError: pass
    return metrics


def claude_runtime_semantic_evidence(store: StateStore, version: str = "", model: str = "") -> dict[str, Any]:
    where, args = ["provider='claude'"], []
    if version: where.append("claude_code_version=?"); args.append(version)
    if model: where.append("model_id=?"); args.append(model)
    rows = [dict(r) for r in store.db.execute("SELECT * FROM claude_runtime_semantic_evidence WHERE " + " AND ".join(where) + " ORDER BY claude_code_version,model_id,model_context_window_tokens", args).fetchall()]
    return {"provider": "claude", "evidence_only": True, "profiles": rows,
            "limitations": ["Observed semantic evidence does not qualify a version.", "Explicit Claude runtime version qualification remains authoritative.", "No compact association is implemented: no trustworthy structured compact marker is available at ingestion."]}


def render_claude_runtime_semantic_evidence(payload: dict[str, Any]) -> str:
    lines = ["Claude runtime semantic evidence (observed; not a compatibility verdict)", "", "Version  Model  Window  Samples  Cursor epochs  Normal  Zero  Null  Identity"]
    for r in payload["profiles"]:
        window = "unavailable" if r["model_context_window_tokens"] < 0 else str(r["model_context_window_tokens"])
        lines.append(f"{r['claude_code_version'] or '-'}  {r['model_id'] or '-'}  {window}  {r['samples_total']}  {r['stream_cursor_epochs_seen']}  {r['complete_nonzero_count']}  {r['complete_all_zero_count']}  {r['current_usage_null_count']}  {r['counter_identity_pass']}/{r['counter_identity_testable']}")
    if not payload["profiles"]: lines.append("(no semantic evidence recorded)")
    return "\n".join(lines)


HANDOFF_SECTIONS = ("Objective", "Completed", "Current State", "Decisions", "Files Changed", "Verification", "Open Problems", "Do Not Repeat", "Exact Next Action", "Relevant References")

def validate_handoff(project: str) -> dict[str, Any]:
    path = Path(project) / ".ai" / "state" / "HANDOFF.md"
    result = {"path": str(path), "present": path.is_file(), "valid": False, "missing": list(HANDOFF_SECTIONS), "sha256": "", "freshness_seconds": None,
              "rotation_ready": False, "rotation_reason": "A valid handoff is necessary but v0.4.1 does not infer agent idle/safe state or automate rotation."}
    if not path.is_file(): return result
    text = path.read_text(encoding="utf-8", errors="replace")
    result["missing"] = [name for name in HANDOFF_SECTIONS if not re.search(rf"(?mi)^#+\s*{re.escape(name)}\s*$", text)]
    result["valid"] = not result["missing"]
    result["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    result["freshness_seconds"] = max(0, int(time.time() - path.stat().st_mtime))
    return result


def render_health(rows: list[sqlite3.Row]) -> str:
    if not rows: return "No incremental session state yet. Run `agentopsy service once`."
    lines = []
    for row in rows:
        current_pct, peak_pct = row["current_context_pct"], float(row["peak_context_pct"] or 0.0)
        current = f"{float(current_pct)*100:.1f}%" if current_pct is not None else (f"~{human_int(row['current_context_tokens'])} tokens (proxy)" if row["current_context_tokens"] else "N/A")
        peak = f"{peak_pct*100:.1f}%" if peak_pct else (f"~{human_int(row['peak_context_tokens'])} tokens" if row["peak_context_tokens"] else "N/A")
        lines += [row["provider"].title(), f"session: {row['session_id']}", f"stream: {row['stream_id']}", f"role: {row['role']}", f"health: {row['health_state']}", f"current context: {current}", f"peak context: {peak}", f"repeated reads: {row['repeated_reads']}", f"repeated commands: {row['repeated_commands']}", f"last activity: {row['last_activity_at'] or '-'}", ""]
    return "\n".join(lines).rstrip()


def trend_payload(store: StateStore, days: int = 30, provider_filter: str = "all", session_filter: str = "") -> dict[str, Any]:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    result: dict[str, Any] = {"period_days": days, "providers": {}}
    providers = ("claude", "codex") if provider_filter == "all" else (provider_filter,)
    for provider in providers:
        rows = [r for r in store.sessions(provider, session_filter) if r["last_activity_at"] >= cutoff and r["role"] == "MAIN" and int(r["model_turns"] or 0) > 0]
        peaks = [float(r["peak_context_pct"] or 0.0) for r in rows if r["peak_context_pct"]]
        contexts = [provider_context_evaluation(r) for r in rows]
        outcomes = [outcome for row in rows for outcome in stream_compaction_outcomes(store, row)]
        result["providers"][provider] = {"sessions": len(rows), "median_peak_context_pct": statistics.median(peaks) if peaks else None,
            "sessions_over_65pct": sum(x >= .65 for x in peaks), "high_context_sessions": sum(CONTEXT_SEVERITY_RANK[item["severity"]] >= CONTEXT_SEVERITY_RANK[Severity.HIGH] for item in contexts), "context_semantics": "absolute-token proxy" if provider == "claude" else "measured percentage",
            "repeated_read_sessions": sum(int(r["repeated_reads"]) >= 4 for r in rows),
            "compaction_thrash_sessions": sum(any(item["outcome"] == "THRASH" for item in stream_compaction_outcomes(store, row)) for row in rows),
            "tool_output_chars": sum(int(r["tool_result_chars"]) for r in rows), "note": "Context/token values are transcript telemetry or explicit proxies, not billing."}
    return result


def robust_profile(values: list[float], sessions: int, turns: int = 0, tools: int = 0) -> dict[str, Any]:
    """Transcript-free robust calibration facts; hard safety ceilings remain separate."""
    if not values: return {"confidence": "INSUFFICIENT", "samples": 0}
    ordered = sorted(values)
    def q(p: float) -> float: return ordered[min(len(ordered) - 1, round((len(ordered) - 1) * p))]
    median = q(.5); mad = statistics.median(abs(value - median) for value in ordered)
    confidence = "HIGH" if sessions >= 30 and turns >= 2000 and tools >= 1000 and mad <= max(1.0, abs(median) * .25) else "MEDIUM" if sessions >= 10 and turns >= 500 else "LOW" if sessions >= 3 else "INSUFFICIENT"
    return {"confidence": confidence, "samples": len(values), "p50": median, "p75": q(.75), "p90": q(.90), "p95": q(.95), "mad": mad}


CALIBRATION_PROFILE_VERSION = 3
CALIBRATION_METRICS = ("session_duration_seconds", "model_turns", "context_peak_pct", "context_peak_tokens", "tool_output_chars", "max_tool_result_chars", "repeated_reads", "command_repetition")
CALIBRATION_METRIC_SIGNALS = {
    "session_duration_seconds": "WALL_CLOCK_DURATION", "model_turns": "MODEL_TURNS",
    "context_peak_pct": "SESSION_CONTEXT_OCCUPANCY", "context_peak_tokens": "CONTEXT_TOKENS_WINDOW",
    "tool_output_chars": "TOOL_CALLS_RESULTS", "max_tool_result_chars": "TOOL_RESULT_SIZE",
    "repeated_reads": "REPEATED_READS", "command_repetition": "REPEATED_COMMANDS",
}


def calibration_metric_capability(provider: str, metric: str) -> ProviderCapability:
    """Return whether a provider can supply a calibration metric, never a fabricated value."""
    capability = signal_capability(CALIBRATION_METRIC_SIGNALS[metric], provider)
    # Claude's context occupancy is deliberately an absolute-token proxy.  A
    # percentage baseline needs a provider-reported denominator, so it is not
    # applicable even though the broader occupancy signal is useful as a proxy.
    if metric == "context_peak_pct" and capability is not ProviderCapability.EXACT:
        return ProviderCapability.UNAVAILABLE
    return capability


def calibration_profiles(store: StateStore) -> dict[str, Any]:
    rows = [r for r in store.sessions() if r["role"] == "MAIN" and int(r["model_turns"] or 0) > 0]
    profiles: dict[str, Any] = {}
    for provider in ("claude", "codex"):
        subset = [r for r in rows if r["provider"] == provider]
        turns, tools = sum(int(r["model_turns"]) for r in subset), sum(int(r["tool_calls"]) for r in subset)
        durations = [(iso_to_dt(r["last_activity_at"]) - iso_to_dt(r["started_at"])).total_seconds() for r in subset if iso_to_dt(r["started_at"]) and iso_to_dt(r["last_activity_at"]) and iso_to_dt(r["last_activity_at"]) >= iso_to_dt(r["started_at"])]
        metrics = {"session_duration_seconds": durations, "model_turns": [float(r["model_turns"]) for r in subset], "context_peak_pct": [float(r["peak_context_pct"]) for r in subset if r["peak_context_pct"]], "context_peak_tokens": [float(r["peak_context_tokens"]) for r in subset if r["peak_context_tokens"]], "tool_output_chars": [float(r["tool_result_chars"]) for r in subset], "max_tool_result_chars": [float(r["max_tool_result_chars"]) for r in subset], "repeated_reads": [float(r["repeated_reads"]) for r in subset], "command_repetition": [float(r["repeated_commands"]) for r in subset]}
        profile: dict[str, Any] = {}
        for name, values in metrics.items():
            capability = calibration_metric_capability(provider, name)
            if capability is ProviderCapability.UNAVAILABLE:
                profile[name] = {"capability": capability.value, "confidence": "N/A", "samples": 0}
            else:
                profile[name] = {"capability": capability.value, **robust_profile(values, len(values), sum(int(r["model_turns"]) for r in subset if (name != "session_duration_seconds" or r["started_at"] and r["last_activity_at"])), sum(int(r["tool_calls"]) for r in subset))}
        profiles[provider] = profile
    return profiles


def calibration_build(store: StateStore) -> dict[str, Any]:
    payload = {"version": CALIBRATION_PROFILE_VERSION, "schema_version": SCHEMA_VERSION, "built_at": dt.datetime.now(dt.timezone.utc).isoformat(), "profiles": calibration_profiles(store), "population": calibration_build_fingerprint(store), "factory_hard_ceilings_authoritative": True, "adopted": False}
    store.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('calibration_profile',?)", (json.dumps(payload, sort_keys=True),)); store.db.commit()
    return payload


def calibration_status(store: StateStore) -> dict[str, Any]:
    row = store.db.execute("SELECT value FROM service_meta WHERE key='calibration_profile'").fetchone()
    return json.loads(row[0]) if row else {"status": "INSUFFICIENT", "message": "No calibration built yet."}


def calibration_adoptable(store: StateStore, payload: dict[str, Any]) -> bool:
    """Reject hand-written, stale, or incomplete profiles even if they claim HIGH."""
    return calibration_adoption_reason(store, payload) is None


def calibration_adoption_reason(store: StateStore, payload: dict[str, Any]) -> Optional[str]:
    """Return the fail-closed reason a calibration profile cannot be adopted."""
    expected_keys = {"version", "schema_version", "built_at", "profiles", "population", "factory_hard_ceilings_authoritative", "adopted"}
    if not isinstance(payload, dict) or set(payload) != expected_keys: return "Calibration profile structure is malformed."
    if payload.get("version") != CALIBRATION_PROFILE_VERSION or payload.get("schema_version") != SCHEMA_VERSION or not isinstance(payload.get("built_at"), str) or iso_to_dt(payload["built_at"]) is None: return "Calibration profile version or timestamp is invalid."
    if payload.get("factory_hard_ceilings_authoritative") is not True or not isinstance(payload.get("adopted"), bool) or not isinstance(payload.get("population"), dict): return "Calibration profile safety fields are invalid."
    current = calibration_build_fingerprint(store)
    if payload["population"] != current: return "Calibration population fingerprint is stale or malformed."
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict): return "Calibration profiles are malformed."
    expected_profiles = calibration_profiles(store)
    for provider in ("claude", "codex"):
        profile = profiles.get(provider)
        if not isinstance(profile, dict) or set(profile) != set(CALIBRATION_METRICS): return f"{provider.title()} calibration profile is incomplete or malformed."
        for name in CALIBRATION_METRICS:
            metric = profile[name]
            expected = expected_profiles[provider][name]
            if metric != expected: return f"{provider.title()} {name} calibration metric is malformed or does not match current evidence."
            if expected["capability"] == ProviderCapability.UNAVAILABLE.value:
                if set(metric) != {"capability", "confidence", "samples"} or metric["confidence"] != "N/A" or metric["samples"] != 0:
                    return f"{provider.title()} {name} unavailable metric is malformed."
                continue
            if expected["confidence"] in {"INSUFFICIENT", "LOW"}:
                return f"{provider.title()} applicable {name} metric has {expected['confidence']} confidence."
    return None


def calibration_build_fingerprint(store: StateStore) -> dict[str, Any]:
    rows = [r for r in store.sessions() if r["role"] == "MAIN" and int(r["model_turns"] or 0) > 0]
    return {"qualified_main_streams": len(rows), "fingerprint": hashlib.sha256(json.dumps([(r["provider"], r["stream_id"], r["model_turns"], r["last_activity_at"]) for r in rows], sort_keys=True).encode()).hexdigest()}


def insights_payload(store: StateStore, days: int = 30, provider: str = "all") -> dict[str, Any]:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    rows = [r for r in store.sessions(provider) if r["last_activity_at"] >= cutoff and r["role"] == "MAIN" and int(r["model_turns"] or 0) > 0]
    if not rows: return {"period_days": days, "provider": provider, "sessions": 0, "insights": []}
    outcomes = {r["stream_id"]: stream_compaction_outcomes(store, r) for r in rows}
    recurring = {"repeated_reads": sum(int(r["repeated_reads"]) >= 4 for r in rows), "command_repetition": sum(int(r["repeated_commands"]) >= 5 for r in rows), "compaction_thrash": sum(any(item["outcome"] == "THRASH" for item in outcomes[r["stream_id"]]) for r in rows), "high_context": sum(CONTEXT_SEVERITY_RANK[provider_context_evaluation(r)["severity"]] >= CONTEXT_SEVERITY_RANK[Severity.HIGH] for r in rows)}
    weakest = max(recurring, key=recurring.get)
    refill = sum(any(item["outcome"] == "RAPID_REFILL" for item in outcomes[r["stream_id"]]) for r in rows)
    insights = [f"Most recurrent workflow fault: {weakest.replace('_', ' ')} ({recurring[weakest]}/{len(rows)} sessions).", f"Compaction followed by repeated commands occurred in {refill}/{len(rows)} sessions.", "Use bounded reads, checkpoints, and fresh sessions at high context; these are workflow recommendations, not provider cache-expiry claims."]
    return {"period_days": days, "provider": provider, "sessions": len(rows), "recurring_faults": recurring, "weakest_marker": weakest, "compaction_refill_sessions": refill, "insights": insights}


def stale_session_preflight(row: sqlite3.Row, now: Optional[dt.datetime] = None) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc); last = iso_to_dt(row["last_activity_at"])
    idle = (now - last).total_seconds() if last else None
    context = provider_context_evaluation(row, current=True)
    pct = context["pct"]
    warning = bool(idle is not None and idle >= 3600 and CONTEXT_SEVERITY_RANK[context["severity"]] >= CONTEXT_SEVERITY_RANK[Severity.HIGH])
    return {"supported_interception": False, "idle_seconds": idle, "context_pct": pct, "context_tokens": context["tokens"], "context_semantics": context["semantics"], "cache_ratio": (int(row["cached_input_tokens"] or 0) / int(row["input_tokens"])) if int(row["input_tokens"]) else None, "warning": warning, "message": "This session is already large and has been idle for a substantial period. Continuing may require previous context to be processed again. Consider compacting or starting fresh." if warning else "No stale-session preflight warning from observed local facts.", "note": "Current context is used. No provider cache-expiry claim is made."}


def select_main_stream(store: StateStore, provider: str, selector: str) -> sqlite3.Row:
    """Resolve native IDs role-aware: auxiliary streams never obscure a MAIN."""
    token = selector.strip().lower()
    rows = store.sessions(provider, token)
    exact_native = [r for r in rows if r["role"] == "MAIN" and r["session_id"].lower() == token]
    exact_stream = [r for r in rows if r["stream_id"].lower() == token]
    candidates = exact_native or exact_stream or [r for r in rows if r["role"] == "MAIN" and (r["session_id"].lower().startswith(token) or r["stream_id"].lower().startswith(token))]
    unique = {(r["provider"], r["stream_id"]): r for r in candidates}
    if len(unique) != 1:
        raise ValueError("Session selector must match exactly one MAIN/native execution stream")
    return next(iter(unique.values()))


DEFAULT_POLICY = {"version": 1, "notification": {"enabled": True, "minimum_severity": "medium", "cooldown_seconds": 900}}
def policy_show(store: StateStore) -> dict[str, Any]:
    row = store.db.execute("SELECT value FROM service_meta WHERE key='runtime_policy'").fetchone()
    return json.loads(row[0]) if row else dict(DEFAULT_POLICY)
def policy_import(store: StateStore, payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict) or payload.get("version") != 1 or not isinstance(payload.get("notification"), dict): raise ValueError("Invalid policy schema/version")
    notification = payload["notification"]
    if not isinstance(notification.get("enabled"), bool) or notification.get("minimum_severity") not in SEVERITY_ORDER or not isinstance(notification.get("cooldown_seconds"), int) or notification["cooldown_seconds"] < 0: raise ValueError("Invalid notification policy")
    store.db.execute("BEGIN IMMEDIATE")
    try: store.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('runtime_policy',?)", (json.dumps(payload, sort_keys=True),)); store.db.commit()
    except Exception: store.db.rollback(); raise


def guardian_replay(store: StateStore, provider: str = "all") -> list[dict[str, Any]]:
    """Read-only deterministic policy replay; no provider/session mutation."""
    timeline = []
    for row in sorted(store.sessions(provider), key=lambda item: (item["last_activity_at"], item["session_id"])):
        context = provider_context_evaluation(row)
        severity = context["severity"]
        states = [severity.value]
        if severity in {Severity.CRITICAL, Severity.SUPER_CRITICAL, Severity.EMERGENCY}: states.append("WOULD_COMPACT")
        if severity in {Severity.SUPER_CRITICAL, Severity.EMERGENCY}: states.append("WOULD_REQUIRE_HANDOFF")
        if severity == Severity.EMERGENCY: states.append("WOULD_ROTATE")
        outcomes = stream_compaction_outcomes(store, row)
        states.extend(sorted({item["outcome"] for item in outcomes if item["outcome"] in {"RAPID_REFILL", "THRASH"}}))
        timeline.append({"timestamp": row["last_activity_at"], "provider": row["provider"], "session_id": row["session_id"], "stream_id": row["stream_id"], "role": row["role"], "context_semantics": context["semantics"], "states": states, "reason": "Recorded provider-aware context and measured compaction telemetry replayed against policy."})
    return timeline


def service_once(state_dir: Optional[str], provider: str = "all", roots: Optional[list[tuple[Path, str]]] = None, notify: bool = True, auto_act: AutoActMode = AutoActMode.OBSERVE) -> IngestionMetrics:
    store = StateStore(state_dir)
    try:
        notification = policy_show(store)["notification"]
        metrics = IncrementalIngestor(store, roots, provider, event_cooldown=notification["cooldown_seconds"]).scan()
        if store.v5_rebuild_required():
            # A provider-filtered or interrupted replay may have produced some
            # rows, but none are trustworthy as a complete v5 population yet.
            # Do not evaluate health, notify, or attempt control until the
            # durable marker is cleared by a successful all-provider replay.
            store.db.commit()
            return metrics
        if provider in ("all", "claude"):
            ingest_claude_runtime_inbox(store, state_dir)
        notifier = Notifier(notify and notification["enabled"], notification["minimum_severity"])
        # Only notify for sessions touched this tick AND recently active.
        # Without the recency check, a cold start (or any scan that first
        # ingests months of history) would surface a desktop popup for every
        # stale, long-finished session that happens to be over a threshold.
        recent_cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=15)
        for prov, sid in metrics.touched_sessions:
            row = store.db.execute("SELECT * FROM sessions WHERE session_id=? AND provider=?", (sid, prov)).fetchone()
            if row and row["health_state"] in {"CHECKPOINT_RECOMMENDED", "ROTATION_RECOMMENDED"}:
                metrics.control_evaluations += 1
                if int(row["malformed_records"] or 0):
                    fail_safe = fail_safe_control("transcript-integrity uncertainty", provider=prov, session_id=sid, malformed_records=int(row["malformed_records"] or 0))
                    store.event(prov, sid, fail_safe.severity.value.lower(), fail_safe.code, "Control disabled because transcript integrity is uncertain.", fail_safe.evidence)
                    metrics.control_fail_safes += 1
                decision = control_decision_for_live_session(row, auto_act, store)
                if not decision.allowed:
                    metrics.control_blocked += 1
                elif decision.action == "full":
                    # Full mode has no verified rotation/new-session adapter yet;
                    # an allowed decision must still resolve to a blocked, accounted
                    # outcome rather than silently doing nothing.
                    metrics.control_blocked += 1
                elif decision.action == "compact":
                    mapping = exact_identity_for_live_session(store, row)
                    if mapping is None or compact_action_recent(store, prov, sid, notification["cooldown_seconds"]):
                        metrics.control_blocked += 1
                    else:
                        request = invoke_herdr_compact(mapping, compact_request_snapshot(store, mapping))
                        if request.state == CompactVerification.REJECTED:
                            metrics.control_blocked += 1
                        else:
                            # One bounded re-scan admits asynchronous provider hooks and
                            # the compacted transcript record without retrying the action.
                            IncrementalIngestor(store, roots, "codex", event_cooldown=notification["cooldown_seconds"]).scan()
                            verified = verify_herdr_compact(store, mapping, request)
                            if verified == CompactVerification.VERIFIED:
                                metrics.control_invocations += 1
                                metrics.control_verified += 1
                                store.event(prov, sid, "info", "COMPACT_VERIFIED", "Compact request verified from matching provider lifecycle and reduced context.", {"verified": True})
                            else:
                                metrics.control_blocked += 1
            activity = iso_to_dt(row["last_activity_at"]) if row else None
            # last_activity_at is raw provider text (e.g. Codex's "...503Z" vs
            # Claude's own format); parse both sides rather than comparing
            # timestamp strings lexically, which silently mis-sorts across
            # differing fractional-second widths or UTC offset spellings.
            if activity is None or activity < recent_cutoff: continue
            for event in store.db.execute("SELECT * FROM health_events WHERE session_id=? AND provider=? AND resolved_at IS NULL ORDER BY id DESC LIMIT 1", (sid, prov)).fetchall():
                if event["timestamp"] >= (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=3)).isoformat(): notifier.notify(f"{row['provider'].title()} session needs attention", event["message"], event["severity"], row["provider"], row["session_id"])
        store.db.commit()
        return metrics
    finally: store.close()


def service_status_payload() -> dict[str, str]:
    """Report the optional user-systemd unit without reading Agentopsy state."""
    unit = "agentopsyd.service"
    if not shutil.which("systemctl"):
        return {"status": "UNAVAILABLE", "manager": "systemd --user", "unit": unit,
                "detail": "systemctl is not available"}
    try:
        result = subprocess.run(
            ["systemctl", "--user", "show", unit, "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=Result"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return {"status": "UNKNOWN", "manager": "systemd --user", "unit": unit,
                "detail": "unable to query the user service manager"}
    fields = {key: value for line in result.stdout.splitlines() if "=" in line
              for key, value in [line.split("=", 1)]
              if key in {"LoadState", "ActiveState", "SubState", "Result"}}
    load, active = fields.get("LoadState", ""), fields.get("ActiveState", "")
    if load == "not-found": status = "NOT_INSTALLED"
    elif active == "active": status = "ACTIVE"
    elif active == "inactive": status = "INACTIVE"
    elif active == "failed": status = "FAILED"
    else: status = "UNKNOWN"
    payload = {"status": status, "manager": "systemd --user", "unit": unit}
    payload.update({key: value for key, value in fields.items()})
    if result.returncode and status == "UNKNOWN":
        payload["detail"] = "user service manager query failed"
    return payload


def render_service_status(payload: dict[str, str]) -> str:
    labels = (("manager", "Manager"), ("unit", "Unit"), ("LoadState", "Load state"),
              ("ActiveState", "Active state"), ("SubState", "Substate"),
              ("Result", "Result"), ("detail", "Detail"))
    lines = [f"Service status: {payload['status']}"]
    lines.extend(f"{label}: {payload[key]}" for key, label in labels if payload.get(key))
    return "\n".join(lines)


def service_main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="agentopsyd", description="Passive local Agentopsy session-health service.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "once"):
        q = sub.add_parser(name); q.add_argument("--interval", type=int, default=20); q.add_argument("--state-dir"); q.add_argument("--provider", choices=["all", "claude", "codex"], default="all"); q.add_argument("--foreground", action="store_true"); q.add_argument("--no-notify", action="store_true"); q.add_argument("--auto-act", choices=[mode.value for mode in AutoActMode], default=AutoActMode.OBSERVE.value, help="Control mode; defaults to observe and fails closed until a verified adapter is available.")
    status = sub.add_parser("status"); status.add_argument("--state-dir")
    args = parser.parse_args(argv)
    if args.command == "status":
        print(render_service_status(service_status_payload())); return 0
    if args.command == "once":
        m = service_once(args.state_dir, args.provider, notify=not args.no_notify, auto_act=AutoActMode(args.auto_act))
        # touched_sessions is an internal notification-gating detail (raw
        # session IDs); do not print it in the scan summary.
        summary = {k: v for k, v in dataclasses.asdict(m).items() if k != "touched_sessions"}
        print(summary); return 0
    if args.interval <= 0: parser.error("--interval must be positive")
    lock = default_state_dir(args.state_dir) / "agentopsyd.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            pid = int(lock.read_text().strip()); os.kill(pid, 0)
        except (ValueError, ProcessLookupError):
            lock.unlink(missing_ok=True); fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        else:
            parser.error(f"another agentopsyd instance appears to hold {lock}")
    running = True
    def stop(_sig: int, _frame: Any) -> None:
        nonlocal running; running = False
    signal.signal(signal.SIGINT, stop); signal.signal(signal.SIGTERM, stop)
    try:
        os.write(fd, str(os.getpid()).encode())
        while running:
            try:
                m = service_once(args.state_dir, args.provider, notify=not args.no_notify, auto_act=AutoActMode(args.auto_act))
                print(f"sessions scan: advanced={m.files_advanced} unchanged={m.files_unchanged} parsed={human_bytes(m.bytes_newly_parsed)}", flush=True)
            except Exception as e:
                # A transient failure (e.g. a concurrent CLI scan racing on the
                # same state DB) must not take the whole service down.
                print(f"sessions scan failed: {e}", file=sys.stderr, flush=True)
            for _ in range(args.interval * 10):
                if not running: break
                time.sleep(.1)
        return 0
    finally:
        os.close(fd)
        try: lock.unlink()
        except FileNotFoundError: pass


def _codex_hook_command(state_dir: Optional[str]) -> str:
    command = f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} integration hook codex"
    return command + (f" --state-dir {shlex.quote(state_dir)}" if state_dir else "")


def _backup_file(path: Path) -> Optional[Path]:
    if not path.exists(): return None
    backup = path.with_name(path.name + ".agentopsy-backup-" + _identity_now().strftime("%Y%m%d%H%M%S"))
    shutil.copy2(path, backup)
    return backup


def _integration_ownership_path(codex_home: Path) -> Path:
    """Local installer state, intentionally separate from hooks.json/repositories."""
    return codex_home / ".agentopsy-integration.json"


def _read_integration_ownership(codex_home: Path) -> dict[str, Any]:
    path = _integration_ownership_path(codex_home)
    if not path.exists(): return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) and value.get("version") == 1 else {}


def _atomic_write_text(path: Path, text: str, *, mode: Optional[int] = None) -> None:
    """Write-then-replace, optionally with an explicit mode. When mode is
    given, it is applied to the TEMP file before os.replace, not chmod'd onto
    the destination afterward -- chmod-after-replace leaves a window where
    the file briefly exists at the umask-derived mode of a freshly created
    temp file, defeating a caller that needs it private (e.g. 0600) from the
    instant it becomes visible at its final path (CR2-05)."""
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    try:
        temporary.write_text(text, encoding="utf-8")
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists(): temporary.unlink()


def integration_status(codex_home: Path) -> dict[str, Any]:
    config, hooks = codex_home / "config.toml", codex_home / "hooks.json"
    try: payload = json.loads(hooks.read_text(encoding="utf-8")) if hooks.exists() else {}
    except Exception: payload = {}
    commands = [str(item.get("command") or "") for group in payload.get("hooks", {}).get("SessionStart", []) if isinstance(group, dict) for item in group.get("hooks", []) if isinstance(item, dict)]
    config_text = config.read_text(encoding="utf-8") if config.exists() else ""
    return {"provider": "codex", "hooks_enabled": bool(re.search(r"(?m)^hooks\s*=\s*true\s*$", config_text)),
            "agentopsy_hook_installed": any("integration hook codex" in item for item in commands),
            "herdr_hook_present": any("herdr-agent-state.sh" in item for item in commands),
            "configuration": str(config), "hook_file": str(hooks)}


def integration_install_codex(codex_home: Path, state_dir: Optional[str]) -> dict[str, Any]:
    """Explicit installer: preserve existing hooks and back up each edited file."""
    config, hooks = codex_home / "config.toml", codex_home / "hooks.json"
    if not config.exists(): raise ValueError(f"Codex configuration not found: {config}")
    try: payload = json.loads(hooks.read_text(encoding="utf-8")) if hooks.exists() else {}
    except json.JSONDecodeError as exc: raise ValueError("Codex hooks.json is malformed; refusing to modify it") from exc
    if not isinstance(payload, dict): raise ValueError("Codex hooks.json must contain an object; refusing to modify it")
    original = config.read_text(encoding="utf-8")
    match = re.search(r"(?m)^hooks\s*=\s*(true|false)\s*$", original)
    previous = match.group(1) if match else "absent"
    text = re.sub(r"(?m)^hooks\s*=\s*(true|false)\s*$", "hooks = true", original, count=1) if match else original + "\n[features]\nhooks = true\n"
    command = _codex_hook_command(state_dir)
    for event in ("SessionStart", "PreCompact", "PostCompact"):
        groups = payload.setdefault("hooks", {}).setdefault(event, [])
        if not any(command == str(item.get("command") or "") for group in groups if isinstance(group, dict) for item in group.get("hooks", []) if isinstance(item, dict)):
            groups.append({"hooks": [{"type": "command", "command": command, "timeout": 2}]})
    # Validation and full output construction happen before either durable file
    # is touched, so malformed hooks never leave a half-installed config.
    rendered_hooks = json.dumps(payload, indent=2) + "\n"
    existing_ownership = _read_integration_ownership(codex_home)
    ownership = existing_ownership
    if not ownership and previous != "true":
        ownership = {"version": 1, "hooks_feature": {"owned": True, "previous": previous, "installed_config_sha256": hashlib.sha256(text.encode()).hexdigest()}}
    if text != original:
        _backup_file(config); config.write_text(text, encoding="utf-8")
    original_hooks = hooks.read_text(encoding="utf-8") if hooks.exists() else ""
    if rendered_hooks != original_hooks:
        _backup_file(hooks); hooks.write_text(rendered_hooks, encoding="utf-8")
    # Persist first-install ownership only after configuration/hook validation
    # and writes have succeeded.  Reinstalls never rewrite this prior state.
    if ownership and ownership != existing_ownership:
        _atomic_write_text(_integration_ownership_path(codex_home), json.dumps(ownership, sort_keys=True) + "\n")
    return integration_status(codex_home)


def integration_remove_codex(codex_home: Path) -> dict[str, Any]:
    config, hooks = codex_home / "config.toml", codex_home / "hooks.json"
    if not hooks.exists(): return integration_status(codex_home)
    payload = json.loads(hooks.read_text(encoding="utf-8")); ownership = _read_integration_ownership(codex_home); retained = []
    for event in ("SessionStart", "PreCompact", "PostCompact"):
        retained = []
        for group in payload.get("hooks", {}).get(event, []):
            if not isinstance(group, dict): retained.append(group); continue
            entries = [item for item in group.get("hooks", []) if not (isinstance(item, dict) and "integration hook codex" in str(item.get("command") or ""))]
            if entries: retained.append({**group, "hooks": entries})
        payload.setdefault("hooks", {})[event] = retained
    rendered_hooks = json.dumps(payload, indent=2) + "\n"
    original = config.read_text(encoding="utf-8") if config.exists() else ""
    feature = ownership.get("hooks_feature", {}) if isinstance(ownership.get("hooks_feature"), dict) else {}
    restore = feature.get("owned") is True and feature.get("previous") == "false" and feature.get("installed_config_sha256") == hashlib.sha256(original.encode()).hexdigest()
    restored = re.sub(r"(?m)^hooks\s*=\s*true\s*$", "hooks = false", original, count=1) if restore else original
    original_hooks = hooks.read_text(encoding="utf-8")
    if restored != original:
        _backup_file(config); config.write_text(restored, encoding="utf-8")
    if rendered_hooks != original_hooks:
        _backup_file(hooks); hooks.write_text(rendered_hooks, encoding="utf-8")
    ownership_path = _integration_ownership_path(codex_home)
    if ownership_path.exists(): ownership_path.unlink()
    return integration_status(codex_home)


def _claude_settings_path(claude_home: Path) -> Path:
    return claude_home / "settings.json"


def _claude_integration_ownership_path(claude_home: Path) -> Path:
    return claude_home / ".agentopsy-integration.json"


def _claude_integration_pre_image_path(claude_home: Path) -> Path:
    # CR2-04: a PRIVATE, separate artifact holding the original settings.json
    # bytes verbatim -- never embedded in the ownership sidecar, since
    # settings.json can contain sensitive configuration/environment values
    # and the sidecar's contents are not treated as equally sensitive.
    return claude_home / ".agentopsy-integration.settings-preimage"


def _claude_integration_symlinked_paths(claude_home: Path) -> list[Path]:
    # CR3-05: best-effort same-user configuration integrity (not a privilege
    # boundary) -- a symlink at any of the three Claude-integration config
    # paths must be detected BEFORE mutation and before any read that would
    # otherwise silently follow it (read_text/json.loads/hashlib all follow
    # symlinks transparently). os.path.islink never follows the link itself,
    # so this is safe to call unconditionally.
    candidates = [_claude_settings_path(claude_home), _claude_integration_ownership_path(claude_home), _claude_integration_pre_image_path(claude_home)]
    return [p for p in candidates if os.path.islink(p)]


def _read_claude_integration_ownership(claude_home: Path) -> tuple[str, dict[str, Any]]:
    """Read Claude ownership metadata without conflating absent and invalid.

    Callers that mutate configuration must use only the returned mapping from
    the ``VALID`` state.  Status also needs to report a present-but-unusable
    sidecar honestly as a manual-recovery condition, rather than treating it
    like no sidecar was ever installed.
    """
    path = _claude_integration_ownership_path(claude_home)
    if os.path.islink(path):
        return "INVALID", {}  # CR3-05: never follow it
    if not path.exists():
        return "MISSING", {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "INVALID", {}
    if not isinstance(value, dict) or value.get("version") != 1:
        return "INVALID", {}
    feature = value.get("statusline")
    if not isinstance(feature, dict) or feature.get("owned") is not True:
        return "INVALID", {}
    required_strings = ("expected_owned_settings_sha256", "installed_command_sha256")
    if any(not isinstance(feature.get(key), str) or not feature[key] for key in required_strings):
        return "INVALID", {}
    if type(feature.get("original_existed")) is not bool:
        return "INVALID", {}
    return "VALID", value


def _claude_statusline_command(state_dir: Optional[str]) -> str:
    command = f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} runtime bridge claude"
    return command + (f" --state-dir {shlex.quote(state_dir)}" if state_dir else "")


def _claude_statusline_is_agentopsy_owned(current_command: str, ownership: dict[str, Any]) -> bool:
    """CR-05: ownership is proven only by a three-way agreement -- never by a
    substring/text match against the command, which a foreign command could
    trivially spoof (e.g. '/usr/bin/foreign --label "runtime bridge claude"').

    A statusLine is Agentopsy-owned only when:
      1. ownership metadata exists and parses at the expected version, AND
      2. it records an installed_command_sha256, AND
      3. that hash matches sha256(current_command) exactly.

    No ownership metadata means foreign/unknown, full stop, regardless of what
    the command text looks like."""
    feature = ownership.get("statusline") if isinstance(ownership.get("statusline"), dict) else None
    if not feature or not feature.get("owned"):
        return False
    installed_hash = feature.get("installed_command_sha256")
    if not isinstance(installed_hash, str) or not installed_hash:
        return False
    return installed_hash == hashlib.sha256(current_command.encode()).hexdigest()


def claude_integration_status(claude_home: Path) -> dict[str, Any]:
    """CR3-07: `owned`/`agentopsy_statusline_installed`/`foreign_statusline_present`
    keep their existing meaning unchanged (install/remove branch on them) --
    the new `state` field adds an EXPLICIT diagnostic on top, so a caller
    that only wants "is this a healthy, unconflicted install" has one field
    to check rather than needing to know the reconciliation logic below.
    Never raises: every read that could fail (settings, ownership, pre-image)
    is guarded, and a failure degrades to a diagnostic state -- install and
    remove both return this function's result directly, so an exception here
    would surface as a false failure of an otherwise-successful mutation.

    States:
      NOT_INSTALLED               -- no statusLine present at all
      FOREIGN                     -- a statusLine is present but not Agentopsy-owned
      SYMLINK_CONFLICT            -- settings.json/ownership/pre-image is a symlink
      STALE_OR_MALFORMED_OWNERSHIP -- ownership claims owned=True but lacks the
                                      bounded metadata this version requires
      SETTINGS_MISSING_WHILE_OWNED -- ownership says owned, but settings.json
                                      does not exist on disk
      EXTERNAL_EDIT_CONFLICT      -- settings.json exists but its hash no
                                      longer matches the expected-owned hash
      PREIMAGE_MISSING            -- original existed at install time but its
                                      private pre-image file is now missing
      PREIMAGE_CORRUPT            -- the pre-image file exists but fails its
                                      recorded integrity hash
      OWNED_OK                    -- owned, consistent, and (if applicable)
                                      the pre-image is present and verified"""
    settings = _claude_settings_path(claude_home)
    symlinked = _claude_integration_symlinked_paths(claude_home)
    if symlinked:
        return {"provider": "claude", "statusline_present": False,
                "agentopsy_statusline_installed": False, "foreign_statusline_present": False,
                "configuration": str(settings), "owned": False, "state": "SYMLINK_CONFLICT"}
    settings_exists = settings.exists()
    try:
        payload = json.loads(settings.read_text(encoding="utf-8")) if settings_exists else {}
    except Exception:
        payload = {}
    status_line = payload.get("statusLine") if isinstance(payload, dict) else None
    command = str(status_line.get("command") or "") if isinstance(status_line, dict) else ""
    ownership_state, ownership = _read_claude_integration_ownership(claude_home)
    if ownership_state == "INVALID":
        return {"provider": "claude", "statusline_present": status_line is not None,
                "agentopsy_statusline_installed": False,
                "foreign_statusline_present": status_line is not None,
                "configuration": str(settings), "owned": False,
                "state": "STALE_OR_MALFORMED_OWNERSHIP"}
    owned = status_line is not None and _claude_statusline_is_agentopsy_owned(command, ownership)
    result = {"provider": "claude", "statusline_present": status_line is not None,
              "agentopsy_statusline_installed": owned,
              "foreign_statusline_present": status_line is not None and not owned,
              "configuration": str(settings), "owned": owned}
    ownership_feature = ownership.get("statusline", {}) if isinstance(ownership.get("statusline"), dict) else {}
    if not settings_exists and ownership_feature.get("owned"):
        # Ownership metadata claims Agentopsy owns this configuration, but
        # settings.json itself is gone -- this is a conflict, not "nothing
        # was ever installed": must not be reported as ordinary NOT_INSTALLED.
        result["state"] = "SETTINGS_MISSING_WHILE_OWNED"
        return result
    if status_line is None:
        result["state"] = "NOT_INSTALLED"
        return result
    if not owned:
        result["state"] = "FOREIGN"
        return result
    feature = ownership_feature
    expected_hash = feature.get("expected_owned_settings_sha256")
    if not isinstance(expected_hash, str) or not expected_hash:
        result["state"] = "STALE_OR_MALFORMED_OWNERSHIP"
        return result
    try:
        current_hash = hashlib.sha256(settings.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    except OSError:
        result["state"] = "STALE_OR_MALFORMED_OWNERSHIP"
        return result
    if current_hash != expected_hash:
        result["state"] = "EXTERNAL_EDIT_CONFLICT"
        return result
    if feature.get("original_existed"):
        pre_image_path = _claude_integration_pre_image_path(claude_home)
        pre_image_ref = feature.get("pre_image_ref")
        original_sha256 = feature.get("original_sha256")
        if not isinstance(pre_image_ref, str) or pre_image_ref != pre_image_path.name or not pre_image_path.exists():
            result["state"] = "PREIMAGE_MISSING"
            return result
        try:
            pre_image_text = pre_image_path.read_text(encoding="utf-8")
        except OSError:
            result["state"] = "PREIMAGE_MISSING"
            return result
        if not isinstance(original_sha256, str) or hashlib.sha256(pre_image_text.encode("utf-8")).hexdigest() != original_sha256:
            result["state"] = "PREIMAGE_CORRUPT"
            return result
    result["state"] = "OWNED_OK"
    return result


class _ClaudeIntegrationArtifact:
    """One file participating in a transactional multi-file publish. `text`
    is the new content (None means "delete this file", only meaningful if it
    previously existed). `mode`, when given, is applied to the temp file
    before the atomic replace (CR2-05: never chmod-after-replace, which
    leaves a window at the umask-derived mode).

    CR3-06: `legacy_backup` defaults to False -- the Claude integration
    transaction already has its own private, exact pre-image artifact as the
    recovery source, so _publish must NOT also invoke the legacy
    _backup_file() timestamped-copy path for these artifacts; doing so would
    leave a redundant plaintext `settings.json.agentopsy-backup-*` copy
    behind after every successful install/reinstall/remove. Set True only
    for a caller that has no other recovery artifact and genuinely needs the
    legacy safety net (this feature's own callers never do)."""
    __slots__ = ("path", "text", "mode", "legacy_backup")
    def __init__(self, path: Path, text: Optional[str], mode: Optional[int] = None, legacy_backup: bool = False):
        self.path, self.text, self.mode, self.legacy_backup = path, text, mode, legacy_backup


def _claude_integration_transactional_write(claude_home: Path, artifacts: list[_ClaudeIntegrationArtifact]) -> None:
    """CR-06 (generalized to N files for CR2-04's third artifact): independent
    os.replace calls across multiple files cannot be made atomic -- a crash
    between them would leave some updated and others stale. This stages every
    artifact's prospective content (and its prior state, including absence
    and mode) fully in memory first, then publishes in order; if any
    publication after the first fails, every already-published artifact is
    rolled back to its exact prior state (unlinked if it did not exist
    before), so the whole set is either fully updated or fully unchanged from
    the caller's perspective.

    CR3-06: publishing does NOT invoke the legacy _backup_file() timestamped-
    copy mechanism unless an artifact explicitly opts in via legacy_backup --
    the Claude integration's own private pre-image IS the recovery artifact,
    so a redundant plaintext settings.json.agentopsy-backup-* copy must never
    be created as a side effect of install/reinstall/remove."""
    prior: list[tuple[_ClaudeIntegrationArtifact, bool, Optional[str], Optional[int]]] = []
    for art in artifacts:
        existed = art.path.exists()
        before_text = art.path.read_text(encoding="utf-8") if existed else None
        before_mode = art.path.stat().st_mode if existed else None
        prior.append((art, existed, before_text, before_mode))

    def _publish(art: _ClaudeIntegrationArtifact, existed_before: bool) -> None:
        if art.text is None:
            if existed_before: art.path.unlink()
            return
        if existed_before and art.legacy_backup: _backup_file(art.path)
        _atomic_write_text(art.path, art.text, mode=art.mode)

    def _restore(art: _ClaudeIntegrationArtifact, existed_before: bool, mode_before: Optional[int], before_text: Optional[str]) -> None:
        if not existed_before:
            if art.path.exists(): art.path.unlink()
            return
        _atomic_write_text(art.path, before_text, mode=stat.S_IMODE(mode_before) if mode_before is not None else None)

    published: list[tuple[_ClaudeIntegrationArtifact, bool, Optional[str], Optional[int]]] = []
    try:
        for art, existed, before_text, before_mode in prior:
            if art.text != before_text:
                _publish(art, existed)
            published.append((art, existed, before_text, before_mode))
    except Exception as publish_exc:
        failures = []
        for art, existed, before_text, before_mode in published:
            try:
                _restore(art, existed, before_mode, before_text)
            except OSError as restore_exc:
                failures.append(f"{art.path}: {restore_exc}")
        if failures:
            # Do NOT swallow a failed rollback (CR-06): surface it loudly
            # rather than silently leaving a half-published set of artifacts.
            # The private settings pre-image (.agentopsy-integration.settings-
            # preimage) is the recovery artifact for the Claude integration --
            # it is never touched by this rollback failure path itself, so it
            # should still exist on disk for manual recovery when the failed
            # artifact is settings.json.
            raise RuntimeError(
                "Failed to roll back the following artifacts after a failed publish, and "
                "automatic rollback also failed for them: " + "; ".join(failures) +
                ". The private settings pre-image (.agentopsy-integration.settings-preimage), "
                "if present, is the recovery source and must be restored to settings.json "
                "manually before retrying."
            ) from publish_exc
        raise


def claude_integration_install(claude_home: Path, state_dir: Optional[str]) -> dict[str, Any]:
    """Explicit installer: never overwrite a foreign statusLine (CR-05
    ownership check). Validate fully before any write; all artifacts are
    published/rolled back together (CR-06).

    CR2-04: settings.json is allowed to be ABSENT (first install then simply
    means "no statusLine key to preserve, and remove should restore
    absence"). On first install, a PRIVATE byte-exact pre-image of the
    original settings.json is written to a separate artifact -- never
    embedded in the ownership sidecar, since settings.json can hold sensitive
    configuration. The ownership sidecar records only bounded metadata:
    whether the original existed, its SHA-256 and mode, a reference to the
    pre-image file, and the expected-owned-settings/installed-command hashes
    used to verify state on remove. A reinstall NEVER touches the original
    pre-image/metadata -- only the expected-owned-settings hash and the
    installed-command hash are refreshed to describe what was just written.

    CR3-05: refuses before any mutation (and before any read that would
    follow it) if settings.json, the ownership sidecar, or the pre-image is
    itself a symlink -- best-effort same-user configuration integrity, not a
    privilege boundary. Never replaces the symlink with os.replace, never
    follows it to read/hash a target's contents."""
    symlinked = _claude_integration_symlinked_paths(claude_home)
    if symlinked:
        raise ValueError(f"Refusing to install: {', '.join(str(p) for p in symlinked)} is a symlink; resolve this conflict manually before installing.")
    settings = _claude_settings_path(claude_home)
    settings_existed = settings.exists()
    original = settings.read_text(encoding="utf-8") if settings_existed else ""
    try: payload = json.loads(original) if original.strip() else {}
    except json.JSONDecodeError as exc: raise ValueError("Claude settings.json is malformed; refusing to modify it") from exc
    if not isinstance(payload, dict): raise ValueError("Claude settings.json must contain an object; refusing to modify it")
    command = _claude_statusline_command(state_dir)
    existing = payload.get("statusLine")
    existing_command = str(existing.get("command") or "") if isinstance(existing, dict) else ""
    ownership_state, ownership = _read_claude_integration_ownership(claude_home)
    if ownership_state == "INVALID":
        raise ValueError("Claude integration ownership metadata is stale or malformed; refusing to install without manual recovery.")
    if existing is not None and not _claude_statusline_is_agentopsy_owned(existing_command, ownership):
        # Foreign/unknown statusLine: refuse outright, zero mutation. Ownership
        # metadata -- not command text -- is the only thing that can excuse this.
        raise ValueError("A non-Agentopsy statusLine is already configured; refusing to overwrite it. Remove it manually or chain it yourself before installing.")
    new_status_line = {"type": "command", "command": command}
    installed_hash = hashlib.sha256(command.encode()).hexdigest()
    already_owned = existing is not None and _claude_statusline_is_agentopsy_owned(existing_command, ownership)
    if already_owned and existing == new_status_line:
        return claude_integration_status(claude_home)  # idempotent reinstall, no write needed
    new_payload = {**payload, "statusLine": new_status_line}
    rendered = json.dumps(new_payload, indent=2) + "\n"
    # Hash EXACTLY what we are about to publish (the rendered string), never
    # a value re-read from disk afterward -- a re-read could disagree over a
    # trailing-newline/encoding detail and make every future remove refuse.
    expected_owned_settings_sha256 = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    ownership_path = _claude_integration_ownership_path(claude_home)
    pre_image_path = _claude_integration_pre_image_path(claude_home)
    prior_statusline = ownership.get("statusline", {}) if isinstance(ownership.get("statusline"), dict) else {}
    settings_mode = stat.S_IMODE(settings.stat().st_mode) if settings_existed else None
    # CR3-06 fault-recovery ordering: publish the private pre-image (when this
    # is a fresh install writing one) BEFORE settings.json itself, so that if
    # publishing settings then fails, the pre-image -- the sole recovery
    # artifact -- is already durably on disk rather than depending on a
    # same-transaction publish that never got the chance to run.
    settings_artifact = _ClaudeIntegrationArtifact(settings, rendered, mode=settings_mode)
    artifacts: list[_ClaudeIntegrationArtifact] = []
    if already_owned:
        # Reinstall: NEVER replace the original pre-Agentopsy pre-image/
        # metadata -- only the hashes describing the currently-installed
        # Agentopsy configuration change.
        new_ownership = {
            "version": 1,
            "statusline": {
                "owned": True,
                "original_existed": prior_statusline.get("original_existed"),
                "original_sha256": prior_statusline.get("original_sha256"),
                "original_mode": prior_statusline.get("original_mode"),
                "pre_image_ref": prior_statusline.get("pre_image_ref"),
                "expected_owned_settings_sha256": expected_owned_settings_sha256,
                "installed_command_sha256": installed_hash,
            },
        }
        # The pre-image itself is untouched: no artifact for it in this branch.
        artifacts.append(settings_artifact)
    else:
        pre_image_ref = pre_image_path.name
        new_ownership = {
            "version": 1,
            "statusline": {
                "owned": True,
                "original_existed": settings_existed,
                "original_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest() if settings_existed else None,
                "original_mode": stat.S_IMODE(settings.stat().st_mode) if settings_existed else None,
                "pre_image_ref": pre_image_ref if settings_existed else None,
                "expected_owned_settings_sha256": expected_owned_settings_sha256,
                "installed_command_sha256": installed_hash,
            },
        }
        if settings_existed:
            artifacts.append(_ClaudeIntegrationArtifact(pre_image_path, original, mode=0o600))
        artifacts.append(settings_artifact)
    new_ownership_text = json.dumps(new_ownership, sort_keys=True) + "\n"
    artifacts.append(_ClaudeIntegrationArtifact(ownership_path, new_ownership_text, mode=0o600))
    _claude_integration_transactional_write(claude_home, artifacts)
    return claude_integration_status(claude_home)


def claude_integration_remove(claude_home: Path) -> dict[str, Any]:
    """Remove only the Agentopsy-owned statusLine (CR-05 ownership check).

    CR2-04: before restoring anything, verifies THREE things: ownership
    metadata is well-formed and owned, the current statusLine command hash
    matches, and the FULL current settings.json file hash matches the
    expected-owned-settings hash recorded at install/reinstall time. If the
    full-file hash disagrees, the file was edited outside Agentopsy in some
    way beyond just the statusLine (or is byte-different in ANY way, e.g. a
    reformat) -- removal is refused outright, zero mutation, rather than
    restoring a stale pre-image over a legitimate-but-unexpected user change.
    If everything matches, the exact original bytes and mode are restored
    atomically (or the file is removed entirely if it did not originally
    exist), then the ownership sidecar and private pre-image are deleted.

    CR3-05: refuses before any mutation (and before any read/hash that would
    follow it) if settings.json, the ownership sidecar, or the pre-image is
    itself a symlink."""
    symlinked = _claude_integration_symlinked_paths(claude_home)
    if symlinked:
        raise ValueError(f"Refusing to remove: {', '.join(str(p) for p in symlinked)} is a symlink; resolve this conflict manually before removing.")
    settings = _claude_settings_path(claude_home)
    ownership_state, ownership = _read_claude_integration_ownership(claude_home)
    if ownership_state == "INVALID":
        raise ValueError("Claude integration ownership metadata is stale or malformed; refusing destructive removal without manual recovery.")
    feature = ownership.get("statusline", {}) if isinstance(ownership.get("statusline"), dict) else {}
    if not feature.get("owned"):
        return claude_integration_status(claude_home)
    settings_exists = settings.exists()
    current_text = settings.read_text(encoding="utf-8") if settings_exists else ""
    try: payload = json.loads(current_text) if current_text.strip() else {}
    except json.JSONDecodeError:
        raise ValueError("Claude settings.json is malformed; refusing to modify it")
    current = payload.get("statusLine") if isinstance(payload, dict) else None
    current_command = str(current.get("command") or "") if isinstance(current, dict) else ""
    if not _claude_statusline_is_agentopsy_owned(current_command, ownership):
        raise ValueError("The statusLine was modified outside Agentopsy since installation; refusing to remove it destructively.")
    expected_hash = feature.get("expected_owned_settings_sha256")
    current_hash = hashlib.sha256(current_text.encode("utf-8")).hexdigest() if settings_exists else None
    if not isinstance(expected_hash, str) or current_hash != expected_hash:
        # Full-file hash disagreement: treat as an external edit/conflict.
        # Deliberately refuses removal after ANY unowned settings edit rather
        # than restoring a stale full pre-image over legitimate user changes.
        raise ValueError("settings.json does not match Agentopsy's expected owned state (an external edit was made beyond the statusLine); refusing to remove it destructively.")

    original_existed = feature.get("original_existed")
    ownership_path = _claude_integration_ownership_path(claude_home)
    pre_image_path = _claude_integration_pre_image_path(claude_home)
    pre_image_ref = feature.get("pre_image_ref")

    if original_existed:
        original_sha256 = feature.get("original_sha256")
        original_mode = feature.get("original_mode")
        if not isinstance(pre_image_ref, str) or pre_image_ref != pre_image_path.name or not pre_image_path.exists():
            raise ValueError("The original settings.json pre-image is missing; refusing to remove destructively without a byte-exact restoration source.")
        pre_image_text = pre_image_path.read_text(encoding="utf-8")
        if not isinstance(original_sha256, str) or hashlib.sha256(pre_image_text.encode("utf-8")).hexdigest() != original_sha256:
            raise ValueError("The original settings.json pre-image failed integrity verification; refusing to remove destructively.")
        restore_mode = stat.S_IMODE(original_mode) if isinstance(original_mode, int) else None
        artifacts = [
            _ClaudeIntegrationArtifact(settings, pre_image_text, mode=restore_mode),
            _ClaudeIntegrationArtifact(ownership_path, None),
            _ClaudeIntegrationArtifact(pre_image_path, None),
        ]
    else:
        # Original settings.json did not exist: successful remove restores
        # absence, since the current owned file already exactly matched
        # Agentopsy's expected state (verified above).
        artifacts = [
            _ClaudeIntegrationArtifact(settings, None),
            _ClaudeIntegrationArtifact(ownership_path, None),
        ]
        if isinstance(pre_image_ref, str) and pre_image_path.exists():
            artifacts.append(_ClaudeIntegrationArtifact(pre_image_path, None))
    _claude_integration_transactional_write(claude_home, artifacts)
    return claude_integration_status(claude_home)


def live_cli(argv: list[str]) -> Optional[int]:
    if not argv or argv[0] not in {"service", "health", "trends", "service-status", "handoff", "signals", "explain", "calibrate", "insights", "preflight", "policy", "guardian", "integration", "runtime"}: return None
    if argv[0] == "integration":
        parser = argparse.ArgumentParser(prog="agentopsy integration"); parser.add_argument("action", choices=["status", "install", "remove", "hook"]); parser.add_argument("provider", choices=["codex", "claude"]); parser.add_argument("--codex-home", default=os.environ.get("CODEX_HOME", "~/.codex")); parser.add_argument("--claude-home", default=os.environ.get("CLAUDE_CONFIG_DIR", "~/.claude")); parser.add_argument("--state-dir")
        args = parser.parse_args(argv[1:])
        if args.provider == "claude":
            if args.action == "hook": raise ValueError("agentopsy integration hook is only defined for codex")
            home = Path(os.path.expanduser(args.claude_home))
            payload = claude_integration_status(home) if args.action == "status" else claude_integration_install(home, args.state_dir) if args.action == "install" else claude_integration_remove(home)
            print(json.dumps(payload, indent=2)); return 0
        home = Path(os.path.expanduser(args.codex_home))
        if args.action == "hook": return identity_hook_main(args.provider, args.state_dir)
        payload = integration_status(home) if args.action == "status" else integration_install_codex(home, args.state_dir) if args.action == "install" else integration_remove_codex(home)
        print(json.dumps(payload, indent=2)); return 0
    if argv[0] == "runtime":
        if len(argv) >= 3 and argv[1] == "bridge" and argv[2] == "claude":
            parser = argparse.ArgumentParser(prog="agentopsy runtime bridge claude"); parser.add_argument("--state-dir")
            args = parser.parse_args(argv[3:])
            return claude_statusline_bridge_main(state_dir=args.state_dir)
        if len(argv) >= 2 and argv[1] == "status":
            parser = argparse.ArgumentParser(prog="agentopsy runtime status"); parser.add_argument("--state-dir")
            args = parser.parse_args(argv[2:])
            store = StateStore(args.state_dir)
            try:
                rows = store.db.execute("SELECT key,value FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchall()
                snapshots = []
                for r in rows:
                    snap = _parse_claude_runtime_snapshot(r["value"])
                    snapshots.append(snap if snap else {"key": r["key"], "status": "INVALID"})
                print(json.dumps(snapshots, indent=2)); return 0
            finally: store.close()
        if len(argv) >= 3 and argv[1] == "evidence" and argv[2] == "claude":
            parser = argparse.ArgumentParser(prog="agentopsy runtime evidence claude"); parser.add_argument("--state-dir"); parser.add_argument("--version", default=""); parser.add_argument("--model", default=""); parser.add_argument("--json", action="store_true")
            args = parser.parse_args(argv[3:]); store = StateStore(args.state_dir)
            try:
                payload = claude_runtime_semantic_evidence(store, args.version, args.model)
                print(json.dumps(payload, indent=2) if args.json else render_claude_runtime_semantic_evidence(payload)); return 0
            finally: store.close()
        raise ValueError("usage: agentopsy runtime bridge claude | agentopsy runtime status | agentopsy runtime evidence claude")
    if argv[0] == "signals":
        if argv[1:] == ["--help"]:
            print("usage: agentopsy signals\n\nList the local signal registry."); return 0
        if len(argv) != 1:
            raise ValueError("agentopsy signals takes no arguments")
        print(render_signals())
        return 0
    if argv[0] == "explain":
        if argv[1:] == ["--help"]:
            print("usage: agentopsy explain SIGNAL_CODE\n\nExplain one local signal."); return 0
        if len(argv) != 2:
            raise ValueError("usage: agentopsy explain SIGNAL_CODE")
        print(explain_signal(argv[1]))
        return 0
    if argv[0] == "service": return service_main(argv[1:])
    if argv[0] == "service-status":
        parser = argparse.ArgumentParser(prog="agentopsy service-status")
        # Retain the former option for invocation compatibility; operational
        # service state is intentionally independent of the SQLite state path.
        parser.add_argument("--state-dir")
        parser.parse_args(argv[1:])
        print(render_service_status(service_status_payload())); return 0
    if argv[0] == "calibrate":
        parser = argparse.ArgumentParser(prog="agentopsy calibrate"); parser.add_argument("action", choices=["status", "build", "recommend", "adopt", "reset"]); parser.add_argument("--state-dir")
        args = parser.parse_args(argv[1:]); store = StateStore(args.state_dir)
        try:
            if args.action == "build": payload = calibration_build(store)
            elif args.action == "reset": store.db.execute("DELETE FROM service_meta WHERE key='calibration_profile'"); store.db.commit(); payload = {"status": "RESET"}
            else:
                payload = calibration_status(store)
                if args.action == "recommend": payload["recommendation"] = "Review robust P90/P95 baselines; factory hard safety ceilings remain authoritative."
                if args.action == "adopt":
                    reason = calibration_adoption_reason(store, payload)
                    if reason: raise ValueError(f"Calibration cannot be adopted: {reason}")
                    payload["adopted"] = True; store.db.execute("UPDATE service_meta SET value=? WHERE key='calibration_profile'", (json.dumps(payload, sort_keys=True),)); store.db.commit()
            print(json.dumps(payload, indent=2)); return 0
        finally: store.close()
    if argv[0] == "insights":
        parser = argparse.ArgumentParser(prog="agentopsy insights"); parser.add_argument("--state-dir"); parser.add_argument("--days", type=int, default=30); parser.add_argument("--provider", choices=["all", "claude", "codex"], default="all"); parser.add_argument("--json", action="store_true")
        args = parser.parse_args(argv[1:]); store = StateStore(args.state_dir)
        try:
            payload = insights_payload(store, args.days, args.provider)
            print(json.dumps(payload, indent=2) if args.json else "\n".join(payload["insights"]) if payload["insights"] else "No qualifying session-health history yet.")
            return 0
        finally: store.close()
    if argv[0] == "preflight":
        parser = argparse.ArgumentParser(prog="agentopsy preflight"); parser.add_argument("--state-dir"); parser.add_argument("--provider", choices=["claude", "codex"], required=True); parser.add_argument("--session", required=True)
        args = parser.parse_args(argv[1:]); store = StateStore(args.state_dir)
        try:
            row = select_main_stream(store, args.provider, args.session)
            print(json.dumps(stale_session_preflight(row), indent=2)); return 0
        finally: store.close()
    if argv[0] == "policy":
        parser = argparse.ArgumentParser(prog="agentopsy policy"); parser.add_argument("action", choices=["show", "export", "import", "reset"]); parser.add_argument("path", nargs="?"); parser.add_argument("--state-dir")
        args = parser.parse_args(argv[1:]); store = StateStore(args.state_dir)
        try:
            if args.action == "show": print(json.dumps(policy_show(store), indent=2))
            elif args.action == "export":
                if not args.path: raise ValueError("policy export requires a path")
                Path(args.path).write_text(json.dumps(policy_show(store), indent=2), encoding="utf-8")
            elif args.action == "import":
                if not args.path: raise ValueError("policy import requires a path")
                policy_import(store, json.loads(Path(args.path).read_text(encoding="utf-8")))
            else: store.db.execute("DELETE FROM service_meta WHERE key='runtime_policy'"); store.db.commit()
            return 0
        finally: store.close()
    if argv[0] == "guardian":
        parser = argparse.ArgumentParser(prog="agentopsy guardian"); parser.add_argument("action", choices=["replay"]); parser.add_argument("--state-dir"); parser.add_argument("--provider", choices=["all", "claude", "codex"], default="all")
        args = parser.parse_args(argv[1:]); store = StateStore(args.state_dir)
        try:
            for item in guardian_replay(store, args.provider): print(f"{item['timestamp']} {item['provider']}: {' -> '.join(item['states'])}")
            return 0
        finally: store.close()
    parser = argparse.ArgumentParser(prog="agentopsy " + argv[0])
    parser.add_argument("--state-dir"); parser.add_argument("--provider", choices=["all", "claude", "codex"], default="all"); parser.add_argument("--session", default=""); parser.add_argument("--all", action="store_true", help="Show all matching sessions (the default for stored state).")
    if argv[0] == "trends": parser.add_argument("--days", type=int, default=30); parser.add_argument("--json", action="store_true")
    if argv[0] == "handoff": parser.add_argument("project")
    args = parser.parse_args(argv[1:]); store = StateStore(args.state_dir)
    try:
        if argv[0] == "health": print(render_health(store.sessions(args.provider, args.session)))
        elif argv[0] == "trends":
            payload = trend_payload(store, args.days, args.provider, args.session); print(json.dumps(payload, indent=2) if args.json else "\n".join(f"{p.title()}: sessions={v['sessions']} median peak context={v['median_peak_context_pct']} repeated-read sessions={v['repeated_read_sessions']}" for p,v in payload['providers'].items()))
        else: print(json.dumps(validate_handoff(args.project), indent=2))
        return 0
    finally: store.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentopsy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Local forensic session analyser for Claude Code and OpenAI Codex CLI.",
        epilog=textwrap.dedent(
            """
            Selection and output compose cleanly:
              agentopsy --sessions
              agentopsy --summary
              agentopsy --last
              agentopsy --last 3 --summary
              agentopsy --session <SESSION_ID> --summary
              agentopsy --session <ID> --export one-session.md
              agentopsy --last --summary --export latest.md
              agentopsy --summary --export-claude claude.md --export-codex codex.md

            Selection order:
              1. discover/read --source (or live stores)
              2. apply --provider, --project, --since, subagent policy
              3. apply either --session OR --last
              4. render console mode and requested exports from the same selection

            --last N means the N most recent sessions PER selected provider.
            With --provider all, plain --last therefore selects the latest Claude
            session and the latest Codex session when both exist.

            Live stores discovered by default:
              Claude Code: $CLAUDE_CONFIG_DIR/projects or ~/.claude/projects
              Codex CLI:   $CODEX_HOME/sessions and $CODEX_HOME/archived_sessions
                           or ~/.codex/...

            Live v0.6.1 commands:
              service, health, trends, service-status, guardian, calibrate,
              insights, policy, preflight, handoff, signals, explain, integration
            """
        ),
    )
    p.add_argument("--source", action="append", default=[], help="Directory, JSONL file, or ZIP archive. Repeatable. Default: auto-discover live stores.")
    p.add_argument("--provider", choices=["all", "claude", "codex"], default="all", help="Provider filter applied before session selection.")
    p.add_argument("--project", default="", help="Only sessions whose path/CWD contains this text.")
    p.add_argument("--since", default=None, help="Only sessions ending after this point, e.g. 7d, 24h, or an ISO timestamp.")
    p.add_argument("--gap-minutes", type=float, default=DEFAULT_GAP_MINUTES, help="Idle gap that splits activity bursts (default: 30).")

    selectors = p.add_mutually_exclusive_group()
    selectors.add_argument("--session", action="append", default=[], metavar="ID", help="Analyse only this session ID. Exact IDs or unique prefixes accepted. Repeatable.")
    selectors.add_argument("--last", nargs="?", const=1, default=0, type=int, metavar="N", help="Analyse the most recent N sessions per selected provider (default N=1).")

    display = p.add_mutually_exclusive_group()
    display.add_argument("--sessions", action="store_true", help="Print only a minimal date/provider/session-ID list for the current selection.")
    display.add_argument("--summary", action="store_true", help="Print only compact provider totals for the current selection. Also makes Markdown exports summary-only.")

    p.add_argument("--export", "--markdown", dest="export_file", metavar="FILE", help="Write one Markdown report for the current selection. --markdown is kept as a compatibility alias.")
    p.add_argument("--export-claude", metavar="FILE", help="Write the Claude subset of the current selection to one Markdown file.")
    p.add_argument("--export-codex", metavar="FILE", help="Write the Codex subset of the current selection to one Markdown file.")
    p.add_argument("--json", metavar="FILE", help="Write machine-readable JSON for the current selection.")

    p.add_argument("--top", type=int, default=20, help="Rows in the default terminal health ranking (default: 20).")
    p.add_argument("--details", type=int, default=10, help="Detailed sessions in the default terminal/full Markdown report (default: 10).")
    p.add_argument("--all", action="store_true", help="Show every selected session in the default terminal ranking.")
    p.add_argument("--include-subagents", action="store_true", help="List Claude subagent transcripts independently as well as parent aggregates.")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="ANSI colour mode (default: auto; NO_COLOR disables auto).")
    p.add_argument("--no-color", dest="color", action="store_const", const="never", help="Compatibility alias for --color never.")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--watch", type=int, metavar="SECONDS", default=0, help="Legacy polling mode: rescan live stores on this interval and maintain latest.md/latest.json. Intended to be replaced by incremental service mode.")
    p.add_argument("--report-dir", help="Directory for --watch reports (default ~/.local/state/agentopsy).")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p

def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # install.sh symlinks agentopsyd -> agentopsy.py; the pip entry point invokes
    # service_main directly, so route the symlinked invocation the same way.
    if Path(sys.argv[0]).name in {"agentopsyd", "agentopsyd.py"}:
        return service_main(argv)
    if argv and argv[0] in {"service", "health", "trends", "service-status", "handoff", "signals", "explain", "calibrate", "insights", "preflight", "policy", "guardian", "integration", "runtime"}:
        try:
            return live_cli(argv)
        except SystemExit:
            raise
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
    args = build_parser().parse_args(argv)
    try:
        if "--last" in argv and args.last < 1:
            raise ValueError("--last must be at least 1")
        if args.since and parse_relative_time(args.since) is None:
            raise ValueError("--since must be a relative duration (for example 7d) or ISO timestamp")
        if args.watch:
            if args.session or args.last or args.sessions or args.summary or args.export_file or args.export_claude or args.export_codex:
                raise ValueError("--watch is a standalone legacy mode; do not combine it with selection/display/export switches")
            return run_watch(args)

        sessions, roots, _ = scan_once(args)
        sessions = select_sessions(sessions, args.session, args.last)
        if not sessions:
            raise RuntimeError("No sessions remain after applying the requested filters/selection.")

        colour = colour_enabled(args.color)
        if args.sessions:
            print(render_session_list(sessions))
        elif args.summary:
            print(render_summary(sessions))
        else:
            print(render_terminal(sessions, roots, args.top, args.details, colour, args.all))

        notices = export_selected(args, sessions, roots)
        if args.json:
            path = Path(os.path.expanduser(args.json))
            write_json_report(path, sessions, roots)
            notices.append(f"JSON report: {path}")
        if notices:
            print("")
            print("Exports")
            for notice in notices:
                print(f"  - {notice}")
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if getattr(args, "verbose", False):
            raise
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
