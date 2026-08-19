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
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import statistics
import sys
import tempfile
import textwrap
import time
import zipfile
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

VERSION = "0.3.0-dev"
PARSER_VERSION = 1
SCHEMA_VERSION = 1

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

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
}


def c(text: str, colour: str, enabled: bool) -> str:
    return f"{ANSI[colour]}{text}{ANSI['reset']}" if enabled else text


def iso_to_dt(value: Any) -> Optional[dt.datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


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
    notes: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["tool_stats"] = {k: v.to_dict() if isinstance(v, ToolStat) else v for k, v in self.tool_stats.items()}
        d["bursts"] = [b.to_dict() if isinstance(b, Burst) else b for b in self.bursts]
        d["defects"] = [x.to_dict() if isinstance(x, Defect) else x for x in self.defects]
        return d


@dataclasses.dataclass
class Candidate:
    provider: str
    path: Path
    display_path: str
    source_label: str
    is_subagent: bool = False
    parent_session_id: str = ""


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

    def extract_timestamp(self, record: dict[str, Any]) -> str:
        return str(record.get("timestamp") or "")

    def extract_usage(self, record: dict[str, Any]) -> dict[str, Any]:
        return {}

    def extract_tool_event(self, record: dict[str, Any]) -> dict[str, Any]:
        return {}

    def parse_record(self, record: dict[str, Any], path: Path) -> dict[str, Any]:
        return {"session_id": self.identify_session(record, path), "timestamp": self.extract_timestamp(record)}


class ClaudeAdapter(ProviderAdapter):
    name = "claude"

    def identify_session(self, record: dict[str, Any], path: Path) -> str:
        # Claude's transcript filename is the durable session identity used by
        # the forensic parser. Some record-level IDs are stream/request IDs and
        # must not split a single transcript into multiple state sessions.
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
                 "compactions": 0, "read_key": "", "command_key": "", "tool_call_items": [], "tool_result_items": []}
        msg = record.get("message") if isinstance(record.get("message"), dict) else {}
        content = msg.get("content")
        if record.get("type") == "assistant" and isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    event["tool_calls"] += 1
                    event["tool_call_items"].append(str(block.get("id") or ""))
                    name, inp = str(block.get("name") or ""), block.get("input") or {}
                    if name == "Read": event["read_key"] = str(inp.get("file_path") or inp.get("path") or "")
                    if name == "Bash": event["command_key"] = normalise_command(str(inp.get("command") or ""))
        if record.get("type") == "user" and isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    chars = content_len(block.get("content")); event["tool_result_chars"] += chars
                    event["max_tool_result_chars"] = max(event["max_tool_result_chars"], chars)
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
        info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
        total = info.get("total_token_usage") if isinstance(info.get("total_token_usage"), dict) else {}
        last = info.get("last_token_usage") if isinstance(info.get("last_token_usage"), dict) else {}
        window = safe_int(info.get("model_context_window")); current = safe_int(last.get("total_tokens"))
        values.update({"input_tokens": safe_int(total.get("input_tokens")), "cached_input_tokens": safe_int(total.get("cached_input_tokens")),
                       "output_tokens": safe_int(total.get("output_tokens")), "reasoning_tokens": safe_int(total.get("reasoning_output_tokens")),
                       "peak_context_tokens": current, "context_window_tokens": window,
                       "peak_context_pct": current / window if window else 0.0, "model_turns": 1})
        values["usage_key"] = json.dumps((safe_int(total.get("input_tokens")), safe_int(total.get("cached_input_tokens")), safe_int(total.get("output_tokens")), safe_int(total.get("reasoning_output_tokens")), safe_int(total.get("total_tokens")), current, window))
        return values

    def extract_tool_event(self, record: dict[str, Any]) -> dict[str, Any]:
        event = {"tool_calls": 0, "tool_result_chars": 0, "max_tool_result_chars": 0,
                 "compactions": int(record.get("type") == "compacted"), "read_key": "", "command_key": ""}
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
        elif typ in {"function_call_output", "custom_tool_call_output"}:
            chars = len(json_text(payload.get("output") if "output" in payload else payload.get("content")))
            event["tool_result_chars"] = chars; event["max_tool_result_chars"] = chars
        return event

    def parse_record(self, record: dict[str, Any], path: Path) -> dict[str, Any]:
        result = super().parse_record(record, path)
        result.update(self.extract_usage(record)); result.update(self.extract_tool_event(record))
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
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


def classify_jsonl(path: Path) -> Optional[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for _ in range(12):
                line = f.readline()
                if not line:
                    break
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
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


def collect_candidates(roots: list[tuple[Path, str]], provider_filter: str) -> list[Candidate]:
    candidates: list[Candidate] = []
    seen: set[Path] = set()
    for root, label in roots:
        paths = [root] if root.is_file() else root.rglob("*.jsonl")
        for path in paths:
            try:
                rp = path.resolve()
            except OSError:
                rp = path
            if rp in seen:
                continue
            seen.add(rp)
            provider = classify_jsonl(path)
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
            candidates.append(Candidate(provider, path, display, label, is_subagent, parent))
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

    try:
        fh = p.open("r", encoding="utf-8", errors="replace")
    except OSError as e:
        summary.notes.append(f"cannot open: {e}")
        add_defect(summary, "critical", "UNREADABLE_SESSION", f"Cannot read transcript: {e}")
        finalise_grade(summary)
        return summary

    with fh:
        for line in fh:
            summary.event_count += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                summary.malformed_lines += 1
                continue
            ts = iso_to_dt(rec.get("timestamp"))
            if ts:
                timestamps.append(ts)
            typ = rec.get("type")
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
                        except json.JSONDecodeError:
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

    try:
        fh = p.open("r", encoding="utf-8", errors="replace")
    except OSError as e:
        summary.notes.append(f"cannot open: {e}")
        add_defect(summary, "critical", "UNREADABLE_SESSION", f"Cannot read transcript: {e}")
        finalise_grade(summary)
        return summary

    with fh:
        for line in fh:
            summary.event_count += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                summary.malformed_lines += 1
                continue
            ts = iso_to_dt(rec.get("timestamp"))
            if ts:
                timestamps.append(ts)
            typ = rec.get("type")
            payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}

            if typ == "session_meta":
                sid = payload.get("session_id") or payload.get("id")
                if sid:
                    summary.session_id = str(sid)
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
                    summary.token_count_events += 1
                    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
                    total = info.get("total_token_usage") if isinstance(info.get("total_token_usage"), dict) else {}
                    last = info.get("last_token_usage") if isinstance(info.get("last_token_usage"), dict) else {}
                    window = safe_int(info.get("model_context_window"))
                    sig = (
                        safe_int(total.get("input_tokens")), safe_int(total.get("cached_input_tokens")),
                        safe_int(total.get("output_tokens")), safe_int(total.get("reasoning_output_tokens")),
                        safe_int(total.get("total_tokens")), safe_int(last.get("total_tokens")), window,
                    )
                    token_signatures[sig] += 1
                    latest_total_usage = total or latest_total_usage
                    if window:
                        summary.context_window_tokens = max(summary.context_window_tokens, window)
                    last_total = safe_int(last.get("total_tokens"))
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
        summary.reasoning_tokens = safe_int(latest_total_usage.get("reasoning_output_tokens"))
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
                    except json.JSONDecodeError:
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

    if s.compactions >= 3:
        sev = "high" if s.compactions >= 5 else "medium"
        add_defect(s, sev, "COMPACTION_THRASH",
                   f"The session compacted {s.compactions} times.",
                   "Inspect whether compact→re-read→refill cycles are occurring; prefer a durable handoff and fresh chat when compaction repeats.",
                   compactions=s.compactions)
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


class StateStore:
    """Transactional, local-only state. Raw transcript records are never stored."""
    def __init__(self, state_dir: Optional[str] = None):
        self.dir = default_state_dir(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "agentopsy.db"
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def close(self) -> None: self.db.close()

    def _migrate(self) -> None:
        with self.db:
            self.db.execute("CREATE TABLE IF NOT EXISTS service_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            version = self.db.execute("SELECT value FROM service_meta WHERE key='schema_version'").fetchone()
            if version and int(version[0]) > SCHEMA_VERSION:
                raise RuntimeError("state database is newer than this Agentopsy version")
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
            self.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
            self.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('parser_version',?)", (str(PARSER_VERSION),))

    def file(self, path: Path) -> Optional[sqlite3.Row]:
        return self.db.execute("SELECT * FROM files WHERE path=?", (str(path),)).fetchone()

    def reset_file_session(self, row: sqlite3.Row) -> None:
        if row["session_id"]:
            self.db.execute("DELETE FROM sessions WHERE session_id=? AND provider=?", (row["session_id"], row["provider"]))
            self.db.execute("DELETE FROM occurrences WHERE session_id=? AND provider=?", (row["session_id"], row["provider"]))
            self.db.execute("DELETE FROM record_dedup WHERE session_id=? AND provider=?", (row["session_id"], row["provider"]))

    def upsert_file(self, *, provider: str, path: Path, identity: str, size: int, mtime_ns: int, offset: int, partial: str, session_id: str, status: str) -> None:
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        self.db.execute("""INSERT INTO files(provider,path,identity,size,mtime_ns,last_offset,partial_line,session_id,first_seen,last_seen,parser_version,status)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET provider=excluded.provider,identity=excluded.identity,size=excluded.size,mtime_ns=excluded.mtime_ns,last_offset=excluded.last_offset,partial_line=excluded.partial_line,session_id=excluded.session_id,last_seen=excluded.last_seen,parser_version=excluded.parser_version,status=excluded.status""",
            (provider, str(path), identity, size, mtime_ns, offset, partial, session_id, now, now, PARSER_VERSION, status))

    def apply_record(self, provider: str, path: Path, data: dict[str, Any], malformed: bool = False) -> str:
        sid = str(data.get("session_id") or path.stem)
        ts = str(data.get("timestamp") or "")
        row = self.db.execute("SELECT * FROM sessions WHERE session_id=? AND provider=?", (sid, provider)).fetchone()
        if row is None:
            self.db.execute("INSERT INTO sessions(session_id,provider,project,path,started_at,last_activity_at,health_since) VALUES(?,?,?,?,?,?,?)", (sid, provider, str(data.get("project") or ""), str(path), ts, ts, dt.datetime.now(dt.timezone.utc).isoformat()))
        # Codex token snapshots are cumulative; append-only Claude values are additive.
        cumulative = provider == "codex" and data.get("input_tokens") is not None
        set_parts, args = [], []
        for field in ("project", "model", "effort", "version"):
            if data.get(field): set_parts.append(f"{field}=?"); args.append(str(data[field]))
        if ts:
            set_parts.append("last_activity_at=?"); args.append(ts)
            set_parts.append("started_at=CASE WHEN started_at='' THEN ? ELSE started_at END"); args.append(ts)
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
            args.extend([sid, provider]); self.db.execute(f"UPDATE sessions SET {','.join(set_parts)} WHERE session_id=? AND provider=?", args)
        for kind, key in (("read", data.get("read_key")), ("command", data.get("command_key"))):
            if key:
                digest = sha1_text(str(key)); self.db.execute("INSERT INTO occurrences(session_id,provider,kind,key_hash,count) VALUES(?,?,?,?,1) ON CONFLICT(session_id,provider,kind,key_hash) DO UPDATE SET count=count+1", (sid, provider, kind, digest))
                col = "repeated_reads" if kind == "read" else "repeated_commands"
                self.db.execute(f"UPDATE sessions SET {col}=(SELECT COALESCE(MAX(count),0) FROM occurrences WHERE session_id=? AND provider=? AND kind=?) WHERE session_id=? AND provider=?", (sid, provider, kind, sid, provider))
        return sid

    def mark_unique(self, provider: str, sid: str, kind: str, key: str) -> bool:
        if not key: return True
        cur = self.db.execute("INSERT OR IGNORE INTO record_dedup(session_id,provider,kind,key_hash) VALUES(?,?,?,?)", (sid, provider, kind, sha1_text(key)))
        return cur.rowcount == 1

    def sessions(self, provider: str = "all", session: str = "") -> list[sqlite3.Row]:
        sql, args = "SELECT * FROM sessions", []
        where = []
        if provider != "all": where.append("provider=?"); args.append(provider)
        if session: where.append("session_id LIKE ?"); args.append(session + "%")
        if where: sql += " WHERE " + " AND ".join(where)
        return self.db.execute(sql + " ORDER BY last_activity_at DESC", args).fetchall()

    def event(self, provider: str, sid: str, severity: str, code: str, message: str, evidence: dict[str, Any], cooldown: int = 900) -> None:
        now = dt.datetime.now(dt.timezone.utc); previous = self.db.execute("SELECT timestamp FROM health_events WHERE session_id=? AND provider=? AND code=? AND resolved_at IS NULL ORDER BY id DESC LIMIT 1", (sid, provider, code)).fetchone()
        if previous and (now - iso_to_dt(previous[0])).total_seconds() < cooldown: return
        self.db.execute("INSERT INTO health_events(timestamp,session_id,provider,severity,code,message,evidence) VALUES(?,?,?,?,?,?,?)", (now.isoformat(), sid, provider, severity, code, message, json.dumps(evidence, sort_keys=True)))


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
    pct = float(row["peak_context_pct"] or 0.0)
    if row["provider"] == "claude" and not pct:
        # Claude does not reliably report a window denominator; use a documented provisional 250k reference only for policy bands.
        pct = min(1.0, int(row["peak_context_tokens"] or 0) / 250_000)
    previous = row["health_state"]
    if pct >= policy.rotation_pct: state = "ROTATION_RECOMMENDED"
    elif pct >= policy.checkpoint_pct: state = "CHECKPOINT_RECOMMENDED"
    elif pct >= policy.watch_pct: state = "WATCH"
    elif pct < policy.recovery_pct or previous == "HEALTHY": state = "HEALTHY"
    else: state = previous  # hysteresis retains the existing band between recovery and entry thresholds.
    events = []
    if state != "HEALTHY": events.append(("high" if state == "ROTATION_RECOMMENDED" else "medium", "HIGH_CONTEXT" if state != "ROTATION_RECOMMENDED" else "EXTREME_CONTEXT", f"Context occupancy proxy is {pct*100:.1f}% ({state.lower().replace('_', ' ')}).", {"context_pct": round(pct * 100, 1)}))
    if int(row["max_tool_result_chars"] or 0) // 4 >= GIANT_RESULT_TOKENS: events.append(("high", "GIANT_TOOL_RESULT", "A large tool result was observed.", {"tokens_proxy": int(row["max_tool_result_chars"]) // 4}))
    if int(row["repeated_reads"] or 0) >= 4: events.append(("medium", "REPEATED_READ", "A read target has repeated.", {"repeats": row["repeated_reads"]}))
    if int(row["repeated_commands"] or 0) >= 5: events.append(("medium", "COMMAND_REPETITION", "A command has repeated.", {"repeats": row["repeated_commands"]}))
    if int(row["compactions"] or 0) >= 3: events.append(("medium", "COMPACTION_THRASH", "Repeated compactions were observed.", {"compactions": row["compactions"]}))
    return state, events


@dataclasses.dataclass
class IngestionMetrics:
    bytes_examined: int = 0; bytes_newly_parsed: int = 0; files_unchanged: int = 0; files_advanced: int = 0; files_rescanned: int = 0; parse_errors: int = 0


class IncrementalIngestor:
    def __init__(self, store: StateStore, roots: Optional[list[tuple[Path, str]]] = None, provider: str = "all"):
        self.store, self.roots, self.provider = store, roots or discover_live_roots(), provider

    def scan(self) -> IngestionMetrics:
        metrics = IngestionMetrics()
        candidates = collect_candidates(self.roots, self.provider)
        with self.store.db:
            for candidate in candidates: self._ingest(candidate, metrics)
            self.store.db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('last_successful_scan',?)", (dt.datetime.now(dt.timezone.utc).isoformat(),))
        return metrics

    def _ingest(self, candidate: Candidate, metrics: IngestionMetrics) -> None:
        path = candidate.path; stat = path.stat(); identity = f"{stat.st_dev}:{stat.st_ino}"; old = self.store.file(path)
        reset = old is not None and (old["identity"] != identity or stat.st_size < old["last_offset"])
        if old and not reset and stat.st_size == old["size"]:
            metrics.files_unchanged += 1; self.store.upsert_file(provider=candidate.provider,path=path,identity=identity,size=stat.st_size,mtime_ns=stat.st_mtime_ns,offset=old["last_offset"],partial=old["partial_line"],session_id=old["session_id"],status="ok"); return
        if reset:
            self.store.reset_file_session(old); offset, partial = 0, ""; metrics.files_rescanned += 1
        else: offset, partial = (int(old["last_offset"]), str(old["partial_line"])) if old else (0, "")
        with path.open("rb") as f:
            f.seek(offset); chunk = f.read()
        metrics.bytes_examined += len(chunk); metrics.bytes_newly_parsed += len(chunk)
        text = partial + chunk.decode("utf-8", errors="replace")
        lines = text.splitlines(keepends=True); trailing = ""
        if lines and not lines[-1].endswith(("\n", "\r")): trailing = lines.pop()
        adapter = ADAPTERS[candidate.provider]; sid = "" if reset else str(old["session_id"] if old else "")
        for line in lines:
            if not line.strip(): continue
            try:
                data = adapter.parse_record(json.loads(line), path)
                # Codex metadata normally carries the native session ID only once.
                # Later records must stay attached to that file's established ID,
                # rather than falling back to a filename-derived placeholder.
                if sid and str(data.get("session_id") or "") == path.stem:
                    data["session_id"] = sid
                if candidate.provider == "claude":
                    target_sid = str(data.get("session_id") or sid or path.stem)
                    usage_key = str(data.pop("usage_key", ""))
                    if usage_key and not self.store.mark_unique(candidate.provider, target_sid, "assistant_usage", usage_key):
                        for field in ("input_tokens", "cached_input_tokens", "cache_creation_tokens", "output_tokens", "reasoning_tokens", "model_turns", "peak_context_tokens"):
                            data[field] = 0
                    calls = data.pop("tool_call_items", [])
                    if calls:
                        data["tool_calls"] = sum(self.store.mark_unique(candidate.provider, target_sid, "tool_call", str(item)) for item in calls)
                    results = data.pop("tool_result_items", [])
                    if results:
                        fresh = [chars for item, chars in results if self.store.mark_unique(candidate.provider, target_sid, "tool_result", str(item))]
                        data["tool_result_chars"] = sum(fresh)
                        data["max_tool_result_chars"] = max(fresh, default=0)
                elif candidate.provider == "codex":
                    usage_key = str(data.pop("usage_key", ""))
                    if usage_key and not self.store.mark_unique(candidate.provider, str(data.get("session_id") or sid or path.stem), "token_snapshot", usage_key):
                        data["model_turns"] = 0
                sid = self.store.apply_record(candidate.provider, path, data)
            except json.JSONDecodeError:
                metrics.parse_errors += 1
                # Before metadata identifies a session, retain the error in scan
                # metrics rather than inventing a path-derived session row.
                if sid: self.store.apply_record(candidate.provider, path, {"session_id": sid}, malformed=True)
        self.store.upsert_file(provider=candidate.provider,path=path,identity=identity,size=stat.st_size,mtime_ns=stat.st_mtime_ns,offset=stat.st_size,partial=trailing,session_id=sid or (old["session_id"] if old else path.stem),status="ok")
        metrics.files_advanced += 1
        if sid:
            row = self.store.db.execute("SELECT * FROM sessions WHERE session_id=? AND provider=?", (sid, candidate.provider)).fetchone()
            if row:
                state, events = evaluate_live_health(row, HealthPolicy.from_environment())
                self.store.db.execute("UPDATE sessions SET health_state=? WHERE session_id=? AND provider=?", (state, sid, candidate.provider))
                for severity, code, message, evidence in events: self.store.event(candidate.provider, sid, severity, code, message, evidence)


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


HANDOFF_SECTIONS = ("Objective", "Completed", "Current State", "Decisions", "Files Changed", "Verification", "Open Problems", "Do Not Repeat", "Exact Next Action", "Relevant References")

def validate_handoff(project: str) -> dict[str, Any]:
    path = Path(project) / ".ai" / "state" / "HANDOFF.md"
    result = {"path": str(path), "present": path.is_file(), "valid": False, "missing": list(HANDOFF_SECTIONS), "sha256": "", "freshness_seconds": None,
              "rotation_ready": False, "rotation_reason": "A valid handoff is necessary but v0.3 does not infer agent idle/safe state or automate rotation."}
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
        pct = float(row["peak_context_pct"] or 0.0)
        context = f"{pct*100:.1f}%" if pct else (f"~{human_int(row['peak_context_tokens'])} tokens" if row["peak_context_tokens"] else "unknown")
        lines += [row["provider"].title(), f"session: {row['session_id']}", f"health: {row['health_state']}", f"context: {context}", f"peak context: {context}", f"large reads: {row['repeated_reads']}", f"repeated commands: {row['repeated_commands']}", f"last activity: {row['last_activity_at'] or '-'}", ""]
    return "\n".join(lines).rstrip()


def trend_payload(store: StateStore, days: int = 30) -> dict[str, Any]:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    result: dict[str, Any] = {"period_days": days, "providers": {}}
    for provider in ("claude", "codex"):
        rows = store.db.execute("SELECT * FROM sessions WHERE provider=? AND last_activity_at>=?", (provider, cutoff)).fetchall()
        peaks = [float(r["peak_context_pct"] or 0.0) for r in rows if r["peak_context_pct"]]
        result["providers"][provider] = {"sessions": len(rows), "median_peak_context_pct": statistics.median(peaks) if peaks else None,
            "sessions_over_65pct": sum(x >= .65 for x in peaks), "repeated_read_sessions": sum(int(r["repeated_reads"]) >= 4 for r in rows),
            "compaction_thrash_sessions": sum(int(r["compactions"]) >= 3 for r in rows),
            "tool_output_chars": sum(int(r["tool_result_chars"]) for r in rows), "note": "Context/token values are transcript telemetry or explicit proxies, not billing."}
    return result


def service_once(state_dir: Optional[str], provider: str = "all", roots: Optional[list[tuple[Path, str]]] = None, notify: bool = True) -> IngestionMetrics:
    store = StateStore(state_dir)
    try:
        metrics = IncrementalIngestor(store, roots, provider).scan()
        notifier = Notifier(notify)
        for row in store.sessions(provider):
            for event in store.db.execute("SELECT * FROM health_events WHERE session_id=? AND provider=? AND resolved_at IS NULL ORDER BY id DESC LIMIT 1", (row["session_id"], row["provider"])).fetchall():
                if event["timestamp"] >= (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=3)).isoformat(): notifier.notify(f"{row['provider'].title()} session needs attention", event["message"], event["severity"], row["provider"], row["session_id"])
        return metrics
    finally: store.close()


def service_main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="agentopsyd", description="Passive local Agentopsy session-health service.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "once"):
        q = sub.add_parser(name); q.add_argument("--interval", type=int, default=20); q.add_argument("--state-dir"); q.add_argument("--provider", choices=["all", "claude", "codex"], default="all"); q.add_argument("--foreground", action="store_true"); q.add_argument("--no-notify", action="store_true")
    status = sub.add_parser("status"); status.add_argument("--state-dir")
    args = parser.parse_args(argv)
    if args.command == "status":
        store = StateStore(args.state_dir)
        try:
            print(render_health(store.sessions())); return 0
        finally: store.close()
    if args.command == "once":
        m = service_once(args.state_dir, args.provider, notify=not args.no_notify); print(dataclasses.asdict(m)); return 0
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
            m = service_once(args.state_dir, args.provider, notify=not args.no_notify)
            print(f"sessions scan: advanced={m.files_advanced} unchanged={m.files_unchanged} parsed={human_bytes(m.bytes_newly_parsed)}", flush=True)
            for _ in range(args.interval * 10):
                if not running: break
                time.sleep(.1)
        return 0
    finally:
        os.close(fd)
        try: lock.unlink()
        except FileNotFoundError: pass


def live_cli(argv: list[str]) -> Optional[int]:
    if not argv or argv[0] not in {"service", "health", "trends", "service-status", "handoff"}: return None
    if argv[0] == "service": return service_main(argv[1:])
    parser = argparse.ArgumentParser(prog="agentopsy " + argv[0])
    parser.add_argument("--state-dir"); parser.add_argument("--provider", choices=["all", "claude", "codex"], default="all"); parser.add_argument("--session", default=""); parser.add_argument("--all", action="store_true", help="Show all matching sessions (the default for stored state).")
    if argv[0] == "trends": parser.add_argument("--days", type=int, default=30); parser.add_argument("--json", action="store_true")
    if argv[0] == "handoff": parser.add_argument("project")
    args = parser.parse_args(argv[1:]); store = StateStore(args.state_dir)
    try:
        if argv[0] in {"health", "service-status"}: print(render_health(store.sessions(args.provider, args.session)))
        elif argv[0] == "trends":
            payload = trend_payload(store, args.days); print(json.dumps(payload, indent=2) if args.json else "\n".join(f"{p.title()}: sessions={v['sessions']} median peak context={v['median_peak_context_pct']} repeated-read sessions={v['repeated_read_sessions']}" for p,v in payload['providers'].items()))
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
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colours in terminal output.")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--watch", type=int, metavar="SECONDS", default=0, help="Legacy polling mode: rescan live stores on this interval and maintain latest.md/latest.json. Intended to be replaced by incremental service mode.")
    p.add_argument("--report-dir", help="Directory for --watch reports (default ~/.local/state/agentopsy).")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p

def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    live_result = live_cli(argv)
    if live_result is not None:
        return live_result
    args = build_parser().parse_args(argv)
    try:
        if args.watch:
            if args.session or args.last or args.sessions or args.summary or args.export_file or args.export_claude or args.export_codex:
                raise ValueError("--watch is a standalone legacy mode; do not combine it with selection/display/export switches")
            return run_watch(args)

        sessions, roots, _ = scan_once(args)
        sessions = select_sessions(sessions, args.session, args.last)
        if not sessions:
            raise RuntimeError("No sessions remain after applying the requested filters/selection.")

        colour = sys.stdout.isatty() and not args.no_color
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
