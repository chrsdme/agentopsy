import importlib.util
import json
import os
import re
import sqlite3
import stat
import contextlib
import io
import tempfile
import unittest
import sys
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("asa", HERE / "agentopsy.py")
asa = importlib.util.module_from_spec(spec)
sys.modules["asa"] = asa
spec.loader.exec_module(asa)


class SchemaMigrationTests(unittest.TestCase):
    def make_v1_state(self, state: Path) -> Path:
        state.mkdir()
        db_path = state / "agentopsy.db"
        db = sqlite3.connect(db_path)
        db.executescript("""
            CREATE TABLE service_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE files (id INTEGER PRIMARY KEY, provider TEXT NOT NULL, path TEXT NOT NULL UNIQUE,
              identity TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, mtime_ns INTEGER NOT NULL DEFAULT 0,
              last_offset INTEGER NOT NULL DEFAULT 0, partial_line TEXT NOT NULL DEFAULT '', session_id TEXT NOT NULL DEFAULT '',
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, parser_version INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'ok');
            CREATE TABLE sessions (session_id TEXT NOT NULL, provider TEXT NOT NULL, project TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '',
              started_at TEXT NOT NULL DEFAULT '', last_activity_at TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', effort TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
              model_turns INTEGER NOT NULL DEFAULT 0, tool_calls INTEGER NOT NULL DEFAULT 0, tool_result_chars INTEGER NOT NULL DEFAULT 0,
              max_tool_result_chars INTEGER NOT NULL DEFAULT 0, input_tokens INTEGER NOT NULL DEFAULT 0, cached_input_tokens INTEGER NOT NULL DEFAULT 0,
              cache_creation_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, reasoning_tokens INTEGER NOT NULL DEFAULT 0,
              peak_context_tokens INTEGER NOT NULL DEFAULT 0, context_window_tokens INTEGER NOT NULL DEFAULT 0, peak_context_pct REAL NOT NULL DEFAULT 0,
              compactions INTEGER NOT NULL DEFAULT 0, repeated_reads INTEGER NOT NULL DEFAULT 0, repeated_commands INTEGER NOT NULL DEFAULT 0,
              malformed_records INTEGER NOT NULL DEFAULT 0, health_state TEXT NOT NULL DEFAULT 'HEALTHY', health_since TEXT NOT NULL DEFAULT '',
              PRIMARY KEY(session_id, provider));
        """)
        db.execute("INSERT INTO service_meta VALUES('schema_version', '1')")
        db.execute("INSERT INTO files(provider,path,identity,session_id,first_seen,last_seen,parser_version) VALUES(?,?,?,?,?,?,?)", ("codex", "/tmp/old.jsonl", "inode:1", "old-session", "a", "b", 1))
        db.execute("INSERT INTO sessions(session_id,provider,project,path) VALUES(?,?,?,?)", ("old-session", "codex", "project", "/tmp/old.jsonl"))
        db.commit()
        db.close()
        return db_path

    def test_v1_state_migrates_idempotently_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            self.make_v1_state(state)
            store = asa.StateStore(str(state))
            self.assertEqual(store.db.execute("SELECT value FROM service_meta WHERE key='schema_version'").fetchone()[0], str(asa.SCHEMA_VERSION))
            self.assertIsNone(store.file(Path("/tmp/old.jsonl")))
            self.assertEqual(store.sessions("codex"), [])
            self.assertFalse(store.v5_rebuild_required())
            self.assertEqual({row[0] for row in store.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'guardian_%'")}, {"guardian_events", "guardian_event_lanes"})
            self.assertIsNotNone(store.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='telemetry_samples'").fetchone())
            store.close()
            reopened = asa.StateStore(str(state))
            self.assertFalse(reopened.v5_rebuild_required())
            self.assertEqual(reopened.db.execute("SELECT count(*) FROM guardian_events").fetchone()[0], 0)
            reopened.close()

    def test_failed_migration_rolls_back_without_advancing_schema_version(self):
        class FailingV2Store(asa.StateStore):
            def _migration_steps(self):
                def fail():
                    self.db.execute("CREATE TABLE failed_migration_marker (id INTEGER)")
                    raise sqlite3.OperationalError("injected migration failure")
                return ((2, fail),)

        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            self.make_v1_state(state)
            connections = []
            original_connect = asa.sqlite3.connect
            class TrackingConnection(sqlite3.Connection):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs); self.closed_for_test = False; connections.append(self)
                def close(self):
                    self.closed_for_test = True
                    return super().close()
            def tracked_connect(*args, **kwargs):
                kwargs["factory"] = TrackingConnection
                return original_connect(*args, **kwargs)
            asa.sqlite3.connect = tracked_connect
            try:
                with self.assertRaisesRegex(sqlite3.OperationalError, "injected migration failure"):
                    FailingV2Store(str(state))
            finally:
                asa.sqlite3.connect = original_connect
            self.assertEqual(len(connections), 1)
            self.assertTrue(connections[0].closed_for_test)
            db = sqlite3.connect(state / "agentopsy.db")
            self.assertEqual(db.execute("SELECT value FROM service_meta WHERE key='schema_version'").fetchone()[0], "1")
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='failed_migration_marker'").fetchone())
            self.assertEqual(db.execute("SELECT session_id FROM sessions").fetchone()[0], "old-session")
            db.close()

    def test_successful_state_store_initialization_remains_usable_and_closable(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            self.assertEqual(store.db.execute("SELECT 1").fetchone()[0], 1)
            store.close()
            store.close()

    def test_current_state_store_opens_while_another_writer_is_active(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            initial = asa.StateStore(str(state)); initial.close()
            holder = sqlite3.connect(state / "agentopsy.db")
            try:
                holder.execute("BEGIN IMMEDIATE")
                contender = asa.StateStore(str(state))
                contender.close()
            finally:
                holder.rollback(); holder.close()

    def test_guardian_dimensions_are_independent_and_evidence_is_transcript_free(self):
        event = asa.GuardianEvent("CONTEXT_HIGH", asa.Severity.CRITICAL, (asa.ImpactLane.CONTEXT_PRESSURE, asa.ImpactLane.TOOL_OUTPUT), asa.ActionSafety.ADVISE_ONLY, {"context_pct": 0.91})
        self.assertEqual(event.action_safety, asa.ActionSafety.ADVISE_ONLY)
        with self.assertRaises(ValueError):
            asa.GuardianEvent("BAD", asa.Severity.HIGH, (asa.ImpactLane.INTEGRITY,), asa.ActionSafety.ACTION_BLOCKED, {"transcript": "secret body"})


class SignalRegistryTests(unittest.TestCase):
    def test_registry_is_versioned_and_covers_both_provider_specific_families(self):
        self.assertEqual(asa.SIGNAL_REGISTRY_VERSION, 1)
        self.assertEqual(len(asa.SIGNALS_BY_CODE), len(asa.SIGNAL_REGISTRY))
        self.assertIn("CLAUDE_CACHE_CREATE", asa.SIGNALS_BY_CODE)
        self.assertIn("CODEX_COMPACTIONS", asa.SIGNALS_BY_CODE)
        self.assertEqual(asa.signal_capability("SESSION_CONTEXT_OCCUPANCY", "codex"), asa.ProviderCapability.EXACT)

    def test_unavailable_signal_is_absent_not_zero_or_bad(self):
        self.assertIsNone(asa.signal_value_or_unavailable("CLAUDE_CACHE_CREATE", "codex", 0))
        self.assertEqual(asa.signal_value_or_unavailable("CLAUDE_CACHE_CREATE", "claude", 0), 0)

    def test_signals_and_explain_cli_are_local_and_descriptive(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(asa.main(["signals"]), 0)
        self.assertIn("SESSION_CONTEXT_OCCUPANCY | PROXY | EXACT", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(asa.main(["explain", "SESSION_CONTEXT_OCCUPANCY"]), 0)
        text = output.getvalue()
        for heading in ("What it means:", "How it is measured:", "Why it matters:", "Expected impact:", "Corrective action:", "Alternative action:", "Provider limitations:"):
            self.assertIn(heading, text)


class MarkerScoringTests(unittest.TestCase):
    def test_unavailable_markers_are_na_and_excluded_from_efficiency(self):
        summary = asa.SessionSummary("claude", "scorecard", "/tmp/a", "test")
        asa.finalise_grade(summary)
        scores = {marker.code: marker for marker in summary.marker_scores}
        self.assertEqual(scores["COMPACTION_HEALTH"].score, None)
        self.assertEqual(scores["INSTRUCTION_OVERHEAD"].percent, None)
        self.assertEqual(summary.overall_efficiency_score, 100)
        self.assertIsNone(summary.lane_scores[asa.ImpactLane.COMPACTION_HEALTH.value])

    def test_context_emergency_floor_survives_high_overall_efficiency(self):
        summary = asa.SessionSummary("codex", "scorecard", "/tmp/a", "test")
        asa.add_defect(summary, "critical", "CODEX_CONTEXT_CRITICAL", "Critical context", "Start fresh")
        asa.add_defect(summary, "medium", "GIANT_TOOL_RESULT", "Large output", "Bound the output")
        asa.finalise_grade(summary)
        scores = {marker.code: marker for marker in summary.marker_scores}
        self.assertEqual(summary.overall_efficiency_score, 85)
        self.assertEqual(scores["CONTEXT_PRESSURE"].score, 1)
        self.assertEqual(scores["CONTEXT_PRESSURE"].severity, asa.Severity.EMERGENCY)
        self.assertEqual(summary.effective_severity, asa.Severity.EMERGENCY)
        self.assertEqual(summary.worst_indicators[0], "CONTEXT_PRESSURE")
        self.assertEqual(summary.corrective_opportunities, ["Start fresh", "Bound the output"])

    def test_scorecard_is_serialised_and_rendered_with_required_fields(self):
        summary = asa.SessionSummary("codex", "scorecard", "/tmp/a", "test")
        asa.finalise_grade(summary)
        payload = summary.to_dict()
        self.assertEqual(payload["overall_efficiency_score"], 100)
        self.assertEqual(payload["effective_severity"], "SAFE")
        self.assertEqual(payload["trend"], "UNKNOWN")
        self.assertIn("lane_scores", payload)
        self.assertIn("marker_scores", payload)
        self.assertEqual(payload["marker_scores"][0]["percent"], 100)
        terminal = "\n".join(asa.render_terminal_detail(summary, colour=False))
        markdown = "\n".join(asa.render_markdown_detail(summary))
        self.assertIn("efficiency=100/100", terminal)
        self.assertIn("Marker scorecard", markdown)


class SeverityPolicyTests(unittest.TestCase):
    def test_factory_context_bands_and_accessible_status(self):
        cases = [(0.55, asa.Severity.SAFE), (.551, asa.Severity.LIGHT), (.651, asa.Severity.HIGH), (.751, asa.Severity.CRITICAL), (.851, asa.Severity.SUPER_CRITICAL), (.901, asa.Severity.EMERGENCY)]
        for pct, expected in cases:
            self.assertEqual(asa.context_severity(pct), expected)
        self.assertEqual(asa.context_status_text(asa.Severity.SAFE), "SESSION HEALTHY")
        self.assertIn("EMERGENCY", asa.context_status_text(asa.Severity.EMERGENCY))

    def test_behavioural_policy_compounds_related_context_risks(self):
        severities = asa.behavioural_severity({"context_velocity": .07, "high_context_dwell": 1000, "rolling_tool_output": 300_000})
        self.assertEqual(severities["context_velocity"], asa.Severity.CRITICAL)
        self.assertEqual(severities["compound_context_pressure"], asa.Severity.EMERGENCY)
        self.assertEqual(asa.behavioural_severity({})["command_repetition"], asa.Severity.SAFE)

    def test_live_health_does_not_claim_unmeasured_compound_context_pressure(self):
        row = {"provider": "codex", "peak_context_pct": .7, "peak_context_tokens": 0, "health_state": "HEALTHY", "max_tool_result_chars": 0, "repeated_reads": 0, "repeated_commands": 0, "compactions": 0}
        _state, events = asa.evaluate_live_health(row, asa.HealthPolicy())
        self.assertNotIn("COMPOUND_CONTEXT_PRESSURE", [code for _severity, code, _message, _evidence in events])

    def test_colour_modes_and_no_color(self):
        class Tty:
            def isatty(self): return True
        self.assertTrue(asa.colour_enabled("always", Tty(), {"NO_COLOR": "1"}))
        self.assertFalse(asa.colour_enabled("auto", Tty(), {"NO_COLOR": "1"}))
        self.assertFalse(asa.colour_enabled("never", Tty(), {}))
        self.assertEqual(asa.build_parser().parse_args(["--color", "always"]).color, "always")
        self.assertEqual(asa.build_parser().parse_args(["--no-color"]).color, "never")


class CausalRiskTests(unittest.TestCase):
    def test_light_indicators_promote_with_explainable_causal_path(self):
        summary = asa.SessionSummary("codex", "risk", "/tmp/a", "test", peak_context_pct=.60)
        summary.repeated_reads = [("path:range", 2)]
        asa.finalise_grade(summary)
        risk = summary.causal_risk
        self.assertEqual(risk.current_severity, asa.Severity.LIGHT)
        self.assertEqual(risk.effective_severity, asa.Severity.HIGH)
        self.assertEqual(risk.trend, "DETERIORATING")
        self.assertEqual(risk.predicted_next_risk_state, asa.Severity.HIGH)
        self.assertIn(asa.ImpactLane.REPETITION, risk.contributing_lanes)
        self.assertTrue(risk.explanations)

    def test_compaction_refetch_path_is_critical_and_serialised(self):
        summary = asa.SessionSummary("codex", "risk", "/tmp/a", "test", compactions=1, post_compact_repeats=2)
        asa.finalise_grade(summary)
        self.assertEqual(summary.causal_risk.effective_severity, asa.Severity.CRITICAL)
        self.assertEqual(summary.causal_risk.trend, "RAPIDLY_DETERIORATING")
        self.assertEqual(summary.to_dict()["causal_risk"]["predicted_next_risk_state"], "CRITICAL")


class CalibrationTests(unittest.TestCase):
    def populate_adoptable_calibration(self, store):
        now = asa.dt.datetime.now(asa.dt.timezone.utc)
        for provider in ("claude", "codex"):
            for index in range(30):
                timestamp = (now + asa.dt.timedelta(seconds=index + 1)).isoformat()
                store.db.execute("""INSERT INTO sessions(session_id,provider,stream_id,role,started_at,last_activity_at,model_turns,tool_calls,tool_result_chars,max_tool_result_chars,peak_context_tokens,peak_context_pct,repeated_reads,repeated_commands)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (f"{provider}-{index}", provider, f"{provider}-{index}", "MAIN", now.isoformat(), timestamp, 70, 34, 100, 10, 1000, .5 if provider == "codex" else 0, 1, 1))
        store.db.commit()

    def test_calibration_adoption_skips_unavailable_claude_percentage_only(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state")); self.populate_adoptable_calibration(store)
            payload = asa.calibration_build(store)
            claude_pct = payload["profiles"]["claude"]["context_peak_pct"]
            self.assertEqual(claude_pct, {"capability": "UNAVAILABLE", "confidence": "N/A", "samples": 0})
            self.assertNotIn("p50", claude_pct)
            self.assertTrue(asa.calibration_adoptable(store, payload))
            store.close()

    def test_calibration_rejects_low_confidence_applicable_metrics_and_stale_or_fabricated_profiles(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state")); self.populate_adoptable_calibration(store)
            payload = asa.calibration_build(store)
            for provider, metric in (("claude", "model_turns"), ("codex", "context_peak_pct")):
                for confidence in ("LOW", "INSUFFICIENT"):
                    altered = json.loads(json.dumps(payload)); altered["profiles"][provider][metric]["confidence"] = confidence
                    self.assertFalse(asa.calibration_adoptable(store, altered))
            stale = json.loads(json.dumps(payload)); stale["population"]["fingerprint"] = "stale"
            self.assertFalse(asa.calibration_adoptable(store, stale))
            fabricated = json.loads(json.dumps(payload)); fabricated["profiles"]["claude"]["context_peak_pct"] = {"capability": "UNAVAILABLE", "confidence": "HIGH", "samples": 1}
            self.assertFalse(asa.calibration_adoptable(store, fabricated))
            store.close()

    def test_runtime_and_package_versions_match(self):
        match = re.search(r'^version\s*=\s*"([^"]+)"$', (HERE / "pyproject.toml").read_text(encoding="utf-8"), re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), asa.VERSION)

    def test_robust_profile_reports_quantiles_confidence_and_stability(self):
        low = asa.robust_profile([1, 2, 3], 3)
        self.assertEqual(low["confidence"], "LOW")
        unstable = asa.robust_profile(list(range(30)), 30, 2000, 1000)
        self.assertEqual(unstable["confidence"], "MEDIUM")
        stable = asa.robust_profile([10] * 30, 30, 2000, 1000)
        self.assertEqual(stable["confidence"], "HIGH")
        self.assertEqual(stable["p95"], 10)

    def test_calibration_commands_are_reviewable_before_adoption(self):
        with tempfile.TemporaryDirectory() as td:
            state = str(Path(td) / "state")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(asa.main(["calibrate", "status", "--state-dir", state]), 0)
                self.assertEqual(asa.main(["calibrate", "build", "--state-dir", state]), 0)
            store = asa.StateStore(state)
            profile = asa.calibration_status(store)
            self.assertTrue(profile["factory_hard_ceilings_authoritative"])
            self.assertFalse(profile["adopted"])
            store.close()
            with contextlib.redirect_stdout(output):
                self.assertEqual(asa.main(["calibrate", "recommend", "--state-dir", state]), 0)
                self.assertEqual(asa.main(["calibrate", "adopt", "--state-dir", state]), 2)
                self.assertEqual(asa.main(["calibrate", "reset", "--state-dir", state]), 0)


class InsightsTests(unittest.TestCase):
    def test_insights_are_session_health_only_and_filterable(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            now = asa.dt.datetime.now(asa.dt.timezone.utc).isoformat()
            for provider in ("codex", "claude"):
                store.db.execute("INSERT INTO sessions(session_id,provider,last_activity_at,model_turns,tool_calls,repeated_reads,repeated_commands,compactions,peak_context_pct) VALUES(?,?,?,?,?,?,?,?,?)", (provider, provider, now, 10, 2, 5, 0, 1, .7))
            store.db.commit()
            payload = asa.insights_payload(store, 7, "codex")
            self.assertEqual(payload["sessions"], 1)
            self.assertEqual(payload["weakest_marker"], "repeated_reads")
            self.assertNotIn("project", " ".join(payload["insights"]).lower())
            store.close()


class PreflightTests(unittest.TestCase):
    def test_stale_high_context_warning_is_advisory_not_expiry_claim(self):
        row = {"last_activity_at": (asa.dt.datetime.now(asa.dt.timezone.utc) - asa.dt.timedelta(hours=3)).isoformat(), "peak_context_pct": .8, "peak_context_tokens": 0, "cached_input_tokens": 10, "input_tokens": 20}
        warning = asa.stale_session_preflight(row)
        self.assertTrue(warning["warning"])
        self.assertFalse(warning["supported_interception"])
        self.assertIn("No provider cache-expiry claim", warning["note"])
        self.assertIn("starting fresh", warning["message"])


class PolicyTests(unittest.TestCase):
    def test_policy_import_is_validated_and_transactional(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            self.assertEqual(asa.policy_show(store)["version"], 1)
            valid = {"version": 1, "notification": {"enabled": False, "minimum_severity": "high", "cooldown_seconds": 60}}
            asa.policy_import(store, valid)
            self.assertFalse(asa.policy_show(store)["notification"]["enabled"])
            with self.assertRaises(ValueError):
                asa.policy_import(store, {"version": 2, "notification": {}})
            with self.assertRaises(ValueError):
                asa.policy_import(store, {"version": 1, "notification": {"enabled": True, "minimum_severity": "medium", "cooldown_seconds": -1}})
            self.assertFalse(asa.policy_show(store)["notification"]["enabled"])
            store.close()

    def test_persisted_cooldown_changes_live_event_cadence(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"
            root.mkdir(); path = root / "rollout.jsonl"
            now = asa.dt.datetime.now(asa.dt.timezone.utc).isoformat()
            meta = {"type": "session_meta", "timestamp": now, "payload": {"session_id": "cooldown"}}
            def token(total): return {"type": "event_msg", "timestamp": now, "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": total, "total_tokens": total}, "last_token_usage": {"total_tokens": total}, "model_context_window": 100}}}
            path.write_text("\n".join(json.dumps(item) for item in (meta, token(90))) + "\n")
            store = asa.StateStore(str(state))
            asa.policy_import(store, {"version": 1, "notification": {"enabled": True, "minimum_severity": "medium", "cooldown_seconds": 3600}})
            store.close()
            asa.service_once(str(state), roots=[(root, "test")], notify=False)
            path.write_text(path.read_text() + json.dumps(token(91)) + "\n")
            asa.service_once(str(state), roots=[(root, "test")], notify=False)
            store = asa.StateStore(str(state))
            self.assertEqual(store.db.execute("SELECT count(*) FROM health_events WHERE session_id='cooldown' AND code='EXTREME_CONTEXT'").fetchone()[0], 1)
            asa.policy_import(store, {"version": 1, "notification": {"enabled": True, "minimum_severity": "medium", "cooldown_seconds": 0}})
            store.close()
            path.write_text(path.read_text() + json.dumps(token(92)) + "\n")
            asa.service_once(str(state), roots=[(root, "test")], notify=False)
            store = asa.StateStore(str(state))
            self.assertEqual(store.db.execute("SELECT count(*) FROM health_events WHERE session_id='cooldown' AND code='EXTREME_CONTEXT'").fetchone()[0], 2)
            store.close()


class ReplayTests(unittest.TestCase):
    def test_replay_is_deterministic_and_only_emits_would_actions(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            store.db.execute("INSERT INTO sessions(session_id,provider,last_activity_at,peak_context_pct,compactions,repeated_commands) VALUES(?,?,?,?,?,?)", ("r1", "codex", "2026-01-01T00:00:00+00:00", .92, 1, 2))
            store.db.commit()
            first = asa.guardian_replay(store)
            self.assertEqual(first, asa.guardian_replay(store))
            self.assertIn("WOULD_COMPACT", first[0]["states"])
            self.assertIn("WOULD_ROTATE", first[0]["states"])
            self.assertNotIn("RAPID_REFILL", first[0]["states"])
            store.close()

    def test_replaying_seen_file_offsets_does_not_duplicate_command_effects(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"; root.mkdir()
            command = {"type": "response_item", "timestamp": "2026-08-27T12:00:01Z", "payload": {"type": "function_call", "name": "exec_command", "arguments": '{"cmd":"echo repeat"}'}}
            records = [
                {"type": "session_meta", "timestamp": "2026-08-27T12:00:00Z", "payload": {"session_id": "native", "id": "stream"}},
                command, command,
            ]
            path = root / "rollout.jsonl"; path.write_text("\n".join(json.dumps(record) for record in records) + "\n")
            store = asa.StateStore(str(state)); ingestor = asa.IncrementalIngestor(store, [(root, "test")])
            try:
                ingestor.scan()
                store.db.execute("UPDATE files SET size=0,last_offset=0 WHERE path=?", (str(path),)); store.db.commit()
                ingestor.scan()
                self.assertEqual(store.sessions("codex")[0]["repeated_commands"], 2)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(command) + "\n")
                ingestor.scan()
                self.assertEqual(store.sessions("codex")[0]["repeated_commands"], 3)
            finally:
                store.close()


class ControlModeTests(unittest.TestCase):
    def test_observe_and_missing_safety_preconditions_never_act(self):
        observe = asa.evaluate_control_request(asa.AutoActMode.OBSERVE, exact_provider=True, exact_session=True, exact_harness=True, capability=asa.ProviderCapability.EXACT, safe_idle_boundary=True, active_critical_operation=False, integrity_ok=True)
        self.assertFalse(observe.allowed)
        blocked = asa.evaluate_control_request(asa.AutoActMode.COMPACT, exact_provider=True, exact_session=True, exact_harness=True, capability=asa.ProviderCapability.UNAVAILABLE, safe_idle_boundary=True, active_critical_operation=False, integrity_ok=True)
        self.assertFalse(blocked.allowed)
        permitted = asa.evaluate_control_request(asa.AutoActMode.COMPACT, exact_provider=True, exact_session=True, exact_harness=True, capability=asa.ProviderCapability.EXACT, safe_idle_boundary=True, active_critical_operation=False, integrity_ok=True)
        self.assertTrue(permitted.allowed)
        self.assertEqual(permitted.action, "compact")

    def test_service_cli_routes_each_auto_act_mode_to_live_fail_closed_control(self):
        seen_modes = []
        original = asa.evaluate_control_request

        def tracked(mode, **kwargs):
            seen_modes.append(mode)
            return original(mode, **kwargs)

        asa.evaluate_control_request = tracked
        try:
            for mode in asa.AutoActMode:
                with tempfile.TemporaryDirectory() as td:
                    root, state = Path(td) / "sessions", Path(td) / "state"
                    root.mkdir()
                    now = asa.dt.datetime.now(asa.dt.timezone.utc).isoformat()
                    records = [
                        {"type": "session_meta", "timestamp": now, "payload": {"session_id": f"{mode.value}-session"}},
                        {"type": "event_msg", "timestamp": now, "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 90, "total_tokens": 90}, "last_token_usage": {"total_tokens": 90}, "model_context_window": 100}}},
                    ]
                    (root / f"rollout-{mode.value}.jsonl").write_text("\n".join(json.dumps(item) for item in records) + "\n")
                    output = io.StringIO()
                    previous_codex_home = os.environ.get("CODEX_HOME")
                    previous_claude_config = os.environ.get("CLAUDE_CONFIG_DIR")
                    os.environ["CODEX_HOME"] = td
                    os.environ["CLAUDE_CONFIG_DIR"] = td
                    try:
                        with contextlib.redirect_stdout(output):
                            self.assertEqual(asa.main(["service", "once", "--state-dir", str(state), "--no-notify", "--auto-act", mode.value]), 0)
                    finally:
                        if previous_codex_home is None: os.environ.pop("CODEX_HOME", None)
                        else: os.environ["CODEX_HOME"] = previous_codex_home
                        if previous_claude_config is None: os.environ.pop("CLAUDE_CONFIG_DIR", None)
                        else: os.environ["CLAUDE_CONFIG_DIR"] = previous_claude_config
                    self.assertIn("'control_evaluations': 1", output.getvalue())
                    self.assertIn("'control_blocked': 1", output.getvalue())
        finally:
            asa.evaluate_control_request = original
        self.assertEqual(seen_modes, list(asa.AutoActMode))

    def test_live_integrity_uncertainty_reaches_fail_safe_without_provider_action(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"
            root.mkdir()
            now = asa.dt.datetime.now(asa.dt.timezone.utc).isoformat()
            records = [
                {"type": "session_meta", "timestamp": now, "payload": {"session_id": "unsafe"}},
                {"type": "event_msg", "timestamp": now, "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 90, "total_tokens": 90}, "last_token_usage": {"total_tokens": 90}, "model_context_window": 100}}},
            ]
            (root / "rollout-unsafe.jsonl").write_text("\n".join(json.dumps(item) for item in records) + "\n{malformed}\n")
            metrics = asa.service_once(str(state), roots=[(root, "test")], notify=False, auto_act=asa.AutoActMode.FULL)
            self.assertEqual((metrics.control_evaluations, metrics.control_blocked, metrics.control_fail_safes), (1, 1, 1))
            store = asa.StateStore(str(state))
            self.assertEqual(store.db.execute("SELECT code FROM health_events WHERE session_id='unsafe' AND provider='codex' ORDER BY id DESC LIMIT 1").fetchone()[0], "CONTROL_FAIL_SAFE")
            store.close()

    def test_full_mode_with_exact_mapping_is_accounted_as_blocked_not_silently_dropped(self):
        """No rotation/new-session adapter exists yet, so an allowed 'full' decision
        must still resolve to an accounted blocked outcome rather than falling
        through every branch and leaving the evaluation unaccounted for."""
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"
            root.mkdir()
            transcript = root / "rollout-full.jsonl"
            now = asa._identity_now().isoformat()
            records = [
                {"type": "session_meta", "timestamp": now, "payload": {"session_id": "full-session"}},
                {"type": "event_msg", "timestamp": now, "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 90, "total_tokens": 90}, "last_token_usage": {"total_tokens": 90}, "model_context_window": 100}}},
            ]
            transcript.write_text("\n".join(json.dumps(item) for item in records) + "\n")

            store = asa.StateStore(str(state))
            store.register_identity("codex", "full-session", str(transcript), "w:p1", "startup")
            store.db.commit(); store.close()

            original_socket = asa._socket_request
            asa._socket_request = lambda *a, **k: {"result": {"agents": [{"agent": "codex", "pane_id": "w:p1", "agent_status": "idle", "agent_session": {"value": "full-session"}}]}}
            try:
                metrics = asa.service_once(str(state), roots=[(root, "test")], notify=False, auto_act=asa.AutoActMode.FULL)
            finally:
                asa._socket_request = original_socket

            self.assertEqual(metrics.control_evaluations, 1)
            self.assertEqual(metrics.control_blocked, 1)
            self.assertEqual(metrics.control_verified, 0)
            self.assertEqual(metrics.control_invocations, 0)


class ControlAdapterTests(unittest.TestCase):
    def test_unestablished_adapters_are_explicitly_unavailable(self):
        adapters = {adapter.provider: adapter for adapter in asa.control_adapters()}
        self.assertEqual(adapters["codex"].capability("compact"), asa.ProviderCapability.UNAVAILABLE)
        self.assertEqual(adapters["claude"].capability("safe_idle"), asa.ProviderCapability.UNAVAILABLE)
        self.assertEqual(adapters["herdr"].harness, "integration")

    def test_live_control_stays_blocked_without_native_session_mapping(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            store.db.execute("INSERT INTO sessions(session_id,provider,health_state) VALUES(?,?,?)", ("transcript-only", "codex", "ROTATION_RECOMMENDED"))
            store.db.commit()
            original = asa.control_adapters
            asa.control_adapters = lambda: (asa.ControlAdapter("codex", "native", {"compact": asa.ProviderCapability.EXACT}),)
            try:
                row = store.db.execute("SELECT * FROM sessions WHERE session_id=? AND provider=?", ("transcript-only", "codex")).fetchone()
                decision = asa.control_decision_for_live_session(row, asa.AutoActMode.COMPACT)
            finally:
                asa.control_adapters = original
                store.close()
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.action, None)


class IdentityBridgeTests(unittest.TestCase):
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))

    def test_exact_registration_duplicate_and_stale_mapping(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "sessions" / "a.jsonl")
            store.register_identity("codex", "s1", path, "w:p1", "startup")
            store.register_identity("codex", "s1", path, "w:p1", "resume")
            self.assertEqual(store.db.execute("SELECT count(*) FROM identity_mappings").fetchone()[0], 1)
            self.assertEqual(store.exact_identity("codex", "s1", path)["confidence"], "EXACT")
            expired = asa._identity_now() + asa.dt.timedelta(seconds=asa.IDENTITY_TTL_SECONDS + 1)
            self.assertIsNone(store.exact_identity("codex", "s1", path, now=expired)); store.close()

    def test_pane_reuse_transcript_replacement_and_restart_invalidate(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); one, two = str(Path(td) / "one.jsonl"), str(Path(td) / "two.jsonl")
            store.register_identity("codex", "old", one, "w:p1", "startup")
            store.register_identity("codex", "new", two, "w:p1", "resume")
            self.assertIsNone(store.exact_identity("codex", "old", one))
            self.assertIsNotNone(store.exact_identity("codex", "new", two))
            store.invalidate_identity("codex", "new", pane_id="w:p1")
            self.assertIsNone(store.exact_identity("codex", "new", two)); store.close()

    def test_lifecycle_malformed_and_missing_herdr_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s.jsonl")
            self.assertFalse(asa.identity_hook_payload({"hook_event_name": "SessionStart", "session_id": "s", "transcript_path": path}, state_dir=str(Path(td) / "state"), environ={}))
            self.assertFalse(asa.identity_hook_payload({"hook_event_name": "SessionStart", "session_id": "s", "transcript_path": "relative"}, state_dir=str(Path(td) / "state"), environ={}))
            store = self._store(td); store.record_identity_lifecycle("codex", "s", "PreCompact"); store.record_identity_lifecycle("codex", "s", "PostCompact"); store.db.commit()
            self.assertEqual(store.db.execute("SELECT count(*) FROM identity_lifecycle WHERE native_session_id='s'").fetchone()[0], 2); store.close()

    def test_wrong_pane_and_herdr_restart_block_idle_gate(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s.jsonl"); store.register_identity("codex", "s", path, "w:p1")
            mapping = store.exact_identity("codex", "s", path); original = asa._socket_request
            asa._socket_request = lambda *a, **k: {"result": {"agents": [{"agent": "codex", "pane_id": "w:wrong", "agent_status": "idle", "agent_session": {"value": "s"}}]}}
            try: self.assertFalse(asa.herdr_pane_is_idle(mapping))
            finally: asa._socket_request = original
            self.assertFalse(asa.herdr_pane_is_idle(mapping, socket_path=str(Path(td) / "missing.sock"))); store.close()

    def test_exact_join_rejects_ambiguous_and_mismatched_provider(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s.jsonl"); store.register_identity("codex", "s", path, "w:p1")
            with self.assertRaises(ValueError): store.register_identity("claude", "s", path, "w:p1")
            now = asa._identity_now().isoformat(); later = (asa._identity_now() + asa.dt.timedelta(minutes=1)).isoformat()
            store.db.execute("INSERT INTO identity_mappings(provider,native_session_id,transcript_path,pane_id,observed_at,expires_at,confidence,active) VALUES(?,?,?,?,?,?,?,1)", ("codex", "s", asa._canonical_transcript_path(path), "w:p2", now, later, "EXACT"))
            self.assertIsNone(store.exact_identity("codex", "s", path)); store.close()

    def test_hook_registration_and_config_install_are_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / "config.toml").write_text("[features]\nhooks = false\n")
            (root / "hooks.json").write_text(json.dumps({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "bash herdr-agent-state.sh"}]}]}}))
            first = asa.integration_install_codex(root, str(root / "state")); second = asa.integration_install_codex(root, str(root / "state"))
            self.assertTrue(first["hooks_enabled"] and second["agentopsy_hook_installed"] and second["herdr_hook_present"])
            installed = json.loads((root / "hooks.json").read_text())
            self.assertTrue(all(installed["hooks"][event] for event in ("SessionStart", "PreCompact", "PostCompact")))
            removed = asa.integration_remove_codex(root); self.assertFalse(removed["agentopsy_hook_installed"]); self.assertTrue(removed["herdr_hook_present"])
            final = json.loads((root / "hooks.json").read_text())
            self.assertFalse(any("integration hook codex" in str(item.get("command") or "") for event in final["hooks"].values() for group in event for item in group.get("hooks", []) if isinstance(item, dict)))

    def test_integration_false_flag_ownership_survives_reinstall_and_restores(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); config, hooks = root / "config.toml", root / "hooks.json"
            config.write_text("[features]\nhooks = false\n"); hooks.write_text(json.dumps({"hooks": {}}))
            asa.integration_install_codex(root, str(root / "state")); first_hooks = json.loads(hooks.read_text())
            ownership = json.loads((root / ".agentopsy-integration.json").read_text())
            asa.integration_install_codex(root, str(root / "state")); second_hooks = json.loads(hooks.read_text())
            self.assertEqual(first_hooks, second_hooks)
            self.assertEqual(json.loads((root / ".agentopsy-integration.json").read_text()), ownership)
            self.assertEqual(ownership["hooks_feature"]["previous"], "false")
            asa.integration_remove_codex(root)
            self.assertIn("hooks = false", config.read_text()); self.assertFalse((root / ".agentopsy-integration.json").exists())

    def test_integration_true_flag_is_not_owned_or_changed_on_remove(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); config, hooks = root / "config.toml", root / "hooks.json"
            config.write_text("[features]\nhooks = true\n"); hooks.write_text(json.dumps({"hooks": {}}))
            asa.integration_install_codex(root, str(root / "state")); first_hooks = json.loads(hooks.read_text())
            asa.integration_install_codex(root, str(root / "state"))
            self.assertEqual(json.loads(hooks.read_text()), first_hooks); self.assertFalse((root / ".agentopsy-integration.json").exists())
            asa.integration_remove_codex(root)
            self.assertIn("hooks = true", config.read_text())

    def test_integration_preserves_unrelated_hooks_across_reinstall_and_remove(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); config, hooks = root / "config.toml", root / "hooks.json"
            config.write_text("[features]\nhooks = false\n")
            unrelated = {"hooks": {event: [{"hooks": [{"type": "command", "command": f"herdr-{event}"}]}] for event in ("SessionStart", "PreCompact", "PostCompact")}}
            hooks.write_text(json.dumps(unrelated))
            asa.integration_install_codex(root, None); asa.integration_install_codex(root, None); asa.integration_remove_codex(root)
            final = json.loads(hooks.read_text())
            self.assertEqual(final["hooks"], unrelated["hooks"]); self.assertIn("hooks = false", config.read_text())

    def test_integration_external_post_install_change_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); config, hooks = root / "config.toml", root / "hooks.json"
            config.write_text("[features]\nhooks = false\n"); hooks.write_text(json.dumps({"hooks": {}}))
            asa.integration_install_codex(root, None)
            config.write_text("[features]\nhooks = true\n# externally changed\n")
            asa.integration_remove_codex(root)
            self.assertEqual(config.read_text(), "[features]\nhooks = true\n# externally changed\n")


class CompactVerificationTests(unittest.TestCase):
    def _mapping_and_request(self, td):
        store = asa.StateStore(str(Path(td) / "state")); path = str(Path(td) / "s.jsonl")
        store.register_identity("codex", "s", path, "w:p1")
        store.db.execute("INSERT INTO sessions(session_id,provider,compactions) VALUES(?,?,0)", ("s", "codex"))
        store.db.execute("INSERT INTO telemetry_samples(timestamp,session_id,provider,turn_index,context_tokens,context_pct,tool_output_chars,read_hash,command_hash,content_hash,cached_input_tokens,instruction_chars,compaction) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (asa._identity_now().isoformat(), "s", "codex", 1, 100, 0.5, 0, "", "", "", None, None, 0))
        store.db.commit()
        mapping = store.exact_identity("codex", "s", path)
        return store, mapping, asa.compact_request_snapshot(store, mapping)

    def _provider_compact(self, store, *, after_context=40, lifecycle=True):
        if lifecycle: store.record_identity_lifecycle("codex", "s", "PostCompact")
        store.db.execute("UPDATE sessions SET compactions=1 WHERE session_id='s' AND provider='codex'")
        store.db.execute("INSERT INTO telemetry_samples(timestamp,session_id,provider,turn_index,context_tokens,context_pct,tool_output_chars,read_hash,command_hash,content_hash,cached_input_tokens,instruction_chars,compaction) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (asa._identity_now().isoformat(), "s", "codex", 2, after_context, 0.2, 0, "", "", "", None, None, 1))
        store.db.commit()

    def test_async_provider_evidence_verifies_after_non_success_transport(self):
        with tempfile.TemporaryDirectory() as td:
            store, mapping, request = self._mapping_and_request(td)
            self._provider_compact(store)
            request = asa.dataclasses.replace(request, state=asa.CompactVerification.TIMED_OUT)
            self.assertEqual(asa.verify_herdr_compact(store, mapping, request), asa.CompactVerification.VERIFIED)
            store.close()

    def test_transport_ack_without_provider_confirmation_times_out(self):
        with tempfile.TemporaryDirectory() as td:
            store, mapping, request = self._mapping_and_request(td)
            request = asa.dataclasses.replace(request, state=asa.CompactVerification.ACCEPTED)
            self.assertEqual(asa.verify_herdr_compact(store, mapping, request), asa.CompactVerification.TIMED_OUT)
            store.close()

    def test_compact_verification_rejects_wrong_identity_missing_event_and_no_reduction(self):
        with tempfile.TemporaryDirectory() as td:
            store, mapping, request = self._mapping_and_request(td)
            self._provider_compact(store, lifecycle=False)
            self.assertEqual(asa.verify_herdr_compact(store, mapping, request), asa.CompactVerification.TIMED_OUT)
            store.db.execute("DELETE FROM telemetry_samples WHERE session_id='s' AND id>?", (request.before_telemetry_id,))
            store.db.execute("UPDATE sessions SET compactions=0 WHERE session_id='s'")
            self._provider_compact(store, after_context=100)
            self.assertEqual(asa.verify_herdr_compact(store, mapping, request), asa.CompactVerification.FAILED)
            store.register_identity("codex", "other", str(Path(td) / "other.jsonl"), "w:p1")
            self.assertEqual(asa.verify_herdr_compact(store, mapping, request), asa.CompactVerification.IDENTITY_LOST)
            store.close()

    def test_service_once_compact_path_verifies_once_then_cooldown_blocks_repeat(self):
        """End-to-end wiring: service_once must reach COMPACT_VERIFIED only via
        exact identity + Herdr idle re-query + async provider lifecycle evidence,
        and a second immediate tick must be blocked by cooldown, not re-invoked."""
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"
            root.mkdir()
            transcript = root / "rollout-compact.jsonl"
            now = asa._identity_now().isoformat()
            records = [
                {"type": "session_meta", "timestamp": now, "payload": {"session_id": "compact-session"}},
                {"type": "event_msg", "timestamp": now, "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 90, "total_tokens": 90}, "last_token_usage": {"total_tokens": 90}, "model_context_window": 100}}},
            ]
            transcript.write_text("\n".join(json.dumps(item) for item in records) + "\n")

            store = asa.StateStore(str(state))
            store.register_identity("codex", "compact-session", str(transcript), "w:p1", "startup")
            store.db.commit()
            store.close()

            original_socket, original_run = asa._socket_request, asa.subprocess.run

            def fake_socket(socket_path, method, params, timeout=0.5):
                if method == "agent.list":
                    return {"result": {"agents": [{"agent": "codex", "pane_id": "w:p1", "agent_status": "idle", "agent_session": {"value": "compact-session"}}]}}
                return {"result": {}}

            def fake_run(cmd, **kwargs):
                # Simulate the provider emitting PostCompact + a smaller context
                # sample asynchronously, exactly as a real async hook delivery would,
                # before verification re-queries state.
                live_store = asa.StateStore(str(state))
                live_store.record_identity_lifecycle("codex", "compact-session", "PostCompact")
                live_store.db.execute("UPDATE sessions SET compactions=compactions+1 WHERE session_id='compact-session' AND provider='codex'")
                live_store.db.execute("""INSERT INTO telemetry_samples(timestamp,session_id,provider,turn_index,context_tokens,context_pct,tool_output_chars,read_hash,command_hash,content_hash,cached_input_tokens,instruction_chars,compaction)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (asa._identity_now().isoformat(), "compact-session", "codex", 2, 10, 0.1, 0, "", "", "", None, None, 1))
                live_store.db.commit(); live_store.close()
                return asa.subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            asa._socket_request, asa.subprocess.run = fake_socket, fake_run
            try:
                metrics = asa.service_once(str(state), roots=[(root, "test")], notify=False, auto_act=asa.AutoActMode.COMPACT)
            finally:
                asa._socket_request, asa.subprocess.run = original_socket, original_run

            self.assertEqual(metrics.control_verified, 1)
            self.assertEqual(metrics.control_invocations, 1)
            store = asa.StateStore(str(state))
            self.assertEqual(store.db.execute("SELECT code FROM health_events WHERE session_id='compact-session' AND provider='codex' ORDER BY id DESC LIMIT 1").fetchone()[0], "COMPACT_VERIFIED")
            store.close()

            # A second tick within the cooldown window must not invoke Herdr again.
            invoked = []
            asa._socket_request, asa.subprocess.run = fake_socket, (lambda cmd, **kwargs: invoked.append(cmd) or asa.subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""))
            try:
                metrics2 = asa.service_once(str(state), roots=[(root, "test")], notify=False, auto_act=asa.AutoActMode.COMPACT)
            finally:
                asa._socket_request, asa.subprocess.run = original_socket, original_run
            self.assertEqual(metrics2.control_verified, 0)
            self.assertEqual(invoked, [])


class CompactionTests(unittest.TestCase):
    def test_observed_compaction_outcomes_are_explainable(self):
        effective = asa.classify_compaction(100, 30, 50, 0, 1)
        self.assertEqual(effective["outcome"], "EFFECTIVE")
        refill = asa.classify_compaction(100, 30, 95, 0, 1)
        self.assertEqual(refill["outcome"], "RAPID_REFILL")
        self.assertEqual(asa.classify_compaction(100, 70, None, 3, 5, compaction_window_seconds=300)["outcome"], "THRASH")

    def test_missing_before_sample_is_unknown_not_ineffective(self):
        self.assertEqual(asa.classify_compaction(0, 0, None, 0, 1)["outcome"], "UNKNOWN")

    def test_effective_spaced_compactions_are_not_thrash_due_to_count_alone(self):
        result = asa.classify_compaction(1000, 100, 150, 0, 5, compaction_window_seconds=7200)
        self.assertEqual(result["outcome"], "EFFECTIVE")

    def test_frequent_rapid_refill_is_thrash(self):
        result = asa.classify_compaction(1000, 100, 950, 0, 5, compaction_window_seconds=300)
        self.assertEqual(result["outcome"], "THRASH")


class RotationTests(unittest.TestCase):
    def test_rotation_blocks_without_verified_handoff_or_adapter(self):
        with tempfile.TemporaryDirectory() as td:
            plan = asa.rotation_plan(td, safe_to_act=True, adapter_capability=asa.ProviderCapability.UNAVAILABLE)
            self.assertEqual(plan["action_safety"], asa.ActionSafety.ACTION_BLOCKED.value)
            self.assertIsNone(plan["action"])


class FailSafeTests(unittest.TestCase):
    def test_integrity_failure_blocks_control_without_transcript_evidence(self):
        event = asa.fail_safe_control("parser uncertainty", provider="codex", session_id="s", malformed_records=11)
        self.assertEqual(event.action_safety, asa.ActionSafety.ACTION_BLOCKED)
        self.assertEqual(event.severity, asa.Severity.SUPER_CRITICAL)
        self.assertEqual(event.evidence, {"malformed_records": 11, "control_disabled": True})


class InstallerTests(unittest.TestCase):
    def test_installer_accepts_required_flags_and_shell_syntax(self):
        script = (HERE / "install.sh").read_text()
        for flag in ("--update", "--service", "--no-service"):
            self.assertIn(flag, script)
        result = subprocess.run(["sh", "-n", str(HERE / "install.sh")], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class AnalyzerTests(unittest.TestCase):
    def test_classify_claude(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.jsonl"
            p.write_text(json.dumps({"type": "mode", "mode": "normal", "sessionId": "x"}) + "\n")
            self.assertEqual(asa.classify_jsonl(p), "claude")

    def test_classify_codex(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.jsonl"
            p.write_text(json.dumps({"type": "session_meta", "payload": {"session_id": "x"}}) + "\n")
            self.assertEqual(asa.classify_jsonl(p), "codex")

    def test_claude_deduplicates_stream_records_and_flags_long_gap(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "abc.jsonl"
            usage = {
                "input_tokens": 2,
                "cache_creation_input_tokens": 1000,
                "cache_read_input_tokens": 160000,
                "output_tokens": 100,
                "iterations": [{
                    "type": "message",
                    "input_tokens": 2,
                    "cache_creation_input_tokens": 1000,
                    "cache_read_input_tokens": 160000,
                    "output_tokens": 100,
                }],
            }
            rows = [
                {"type": "assistant", "timestamp": "2026-01-01T00:00:00Z", "requestId": "r1", "message": {"id": "m1", "model": "claude-test", "usage": usage, "content": [{"type": "text", "text": "x"}]}},
                {"type": "assistant", "timestamp": "2026-01-01T00:00:01Z", "requestId": "r1", "message": {"id": "m1", "model": "claude-test", "usage": usage, "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/tmp/a"}}]}},
                {"type": "user", "timestamp": "2026-01-01T00:00:02Z", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": "x" * 20000}]}},
                {"type": "user", "timestamp": "2026-01-05T00:00:00Z", "message": {"content": "back"}},
            ]
            p.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
            c = asa.Candidate("claude", p, p.name, "test")
            s = asa.parse_claude(c, 30)
            self.assertEqual(s.model_turns, 1)
            self.assertGreater(s.max_idle_gap_seconds, 72 * 3600)
            self.assertIn("LONG_GAP_REUSE", {d.code for d in s.defects})
            self.assertEqual(s.tool_calls, 1)

    def test_codex_uses_last_usage_for_context_not_cumulative(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rollout-x.jsonl"
            rows = [
                {"timestamp": "2026-01-01T00:00:00Z", "type": "session_meta", "payload": {"session_id": "x", "cwd": "/tmp/p", "cli_version": "1"}},
                {"timestamp": "2026-01-01T00:00:01Z", "type": "event_msg", "payload": {"type": "token_count", "info": {
                    "total_token_usage": {"input_tokens": 500000, "cached_input_tokens": 400000, "output_tokens": 10000, "reasoning_output_tokens": 1000, "total_tokens": 510000},
                    "last_token_usage": {"input_tokens": 180000, "cached_input_tokens": 160000, "output_tokens": 1000, "reasoning_output_tokens": 100, "total_tokens": 181000},
                    "model_context_window": 200000,
                }}},
            ]
            p.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
            c = asa.Candidate("codex", p, p.name, "test")
            s = asa.parse_codex(c, 30)
            self.assertEqual(s.logged_processed_tokens, 510000)
            self.assertAlmostEqual(s.peak_context_pct, 181000 / 200000)
            self.assertIn("CODEX_CONTEXT_CRITICAL", {d.code for d in s.defects})


class IncrementalServiceTests(unittest.TestCase):
    def test_provider_timestamp_requires_aware_iso_and_normalizes_to_utc(self):
        reference = asa.dt.datetime(2026, 8, 27, 12, 0, tzinfo=asa.dt.timezone.utc)
        self.assertEqual(
            asa.normalise_provider_timestamp("2026-08-27T13:30:00+01:30", now=reference),
            "2026-08-27T12:00:00Z",
        )
        for value in ("not-a-timestamp", "2026-08-27T12:00:00", 1, 1.0, True, "", float("nan")):
            with self.subTest(value=repr(value)):
                with self.assertRaises(asa.TemporalSemanticError):
                    asa.normalise_provider_timestamp(value, now=reference)
        with self.assertRaises(asa.TemporalSemanticError):
            asa.normalise_provider_timestamp("2026-08-27T12:01:01Z", now=reference)
        for adapter in (asa.ClaudeAdapter(), asa.CodexAdapter()):
            with self.subTest(adapter=adapter.name):
                with self.assertRaises(asa.TemporalSemanticError):
                    adapter.parse_record({"timestamp": "not-a-timestamp"}, Path("session.jsonl"))

    def test_incremental_ingestion_rejects_bad_timestamps_and_keeps_neighbors(self):
        for timestamp in ("not-a-timestamp", "2026-08-27T12:00:01", 1):
            with self.subTest(timestamp=repr(timestamp)), tempfile.TemporaryDirectory() as td:
                root, state = Path(td) / "sessions", Path(td) / "state"
                root.mkdir(); path = root / "rollout.jsonl"
                meta = {"type": "session_meta", "timestamp": "2026-08-27T12:00:00Z", "payload": {"session_id": "native", "id": "stream"}}
                bad = {"type": "event_msg", "timestamp": timestamp, "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 1, "total_tokens": 1}, "last_token_usage": {"total_tokens": 1}, "model_context_window": 100}}}
                suffix = {"type": "event_msg", "timestamp": "2026-08-27T12:00:02Z", "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 2, "total_tokens": 2}, "last_token_usage": {"total_tokens": 2}, "model_context_window": 100}}}
                path.write_text("\n".join(json.dumps(row) for row in (meta, bad, suffix)) + "\n")
                summary = asa.parse_codex(asa.Candidate("codex", path, path.name, "test"), 30)
                self.assertEqual((summary.malformed_lines, summary.input_tokens), (1, 2))
                store = asa.StateStore(str(state))
                try:
                    self.assertEqual(asa.IncrementalIngestor(store, [(root, "test")]).scan().parse_errors, 1)
                    row = store.sessions("codex")[0]
                    self.assertEqual((row["started_at"], row["last_activity_at"], row["input_tokens"]), ("2026-08-27T12:00:00Z", "2026-08-27T12:00:02Z", 2))
                    self.assertEqual(asa.IncrementalIngestor(store, [(root, "test")]).scan().files_unchanged, 1)
                finally:
                    store.close()

    def test_state_store_prevents_future_or_late_past_timestamp_poisoning(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            try:
                path = Path(td) / "rollout.jsonl"
                store.apply_record("codex", path, {"session_id": "s", "stream_id": "s", "timestamp": "2026-08-27T12:00:00Z"})
                store.apply_record("codex", path, {"session_id": "s", "stream_id": "s", "timestamp": "2000-01-01T00:00:00Z", "input_tokens": 25, "peak_context_tokens": 25})
                store.apply_record("codex", path, {"session_id": "s", "stream_id": "s", "timestamp": "2999-01-01T00:00:00Z", "input_tokens": 50, "peak_context_tokens": 50})
                row = store.sessions("codex")[0]
                self.assertEqual(row["last_activity_at"], "2026-08-27T12:00:00Z")
                self.assertEqual((row["input_tokens"], row["peak_context_tokens"]), (25, 0))
                self.assertEqual(store.db.execute("SELECT COUNT(*) FROM telemetry_samples").fetchone()[0], 0)
            finally:
                store.close()

    def test_codex_token_count_numeric_contract_rejects_hostile_values(self):
        invalid_cases = {
            "negative": ({"input_tokens": -1}, {"total_tokens": -1}, 100),
            "integral-float": ({"input_tokens": 1.0}, {"total_tokens": 1.0}, 100),
            "fractional": ({"input_tokens": 1.5}, {"total_tokens": 1.5}, 100),
            "string": ({"input_tokens": "1"}, {"total_tokens": "1"}, 100),
            "empty-string": ({"input_tokens": ""}, {"total_tokens": ""}, 100),
            "null": ({"input_tokens": None}, {"total_tokens": None}, 100),
            "true": ({"input_tokens": True}, {"total_tokens": True}, 100),
            "false": ({"input_tokens": False}, {"total_tokens": False}, 100),
            "nan": ({"input_tokens": float("nan")}, {"total_tokens": float("nan")}, 100),
            "infinity": ({"input_tokens": float("inf")}, {"total_tokens": float("inf")}, 100),
            "negative-infinity": ({"input_tokens": -float("inf")}, {"total_tokens": -float("inf")}, 100),
            "int64-overflow": ({"input_tokens": asa.SQLITE_INT64_MAX + 1}, {"total_tokens": 1}, 100),
            "zero-window": ({"input_tokens": 1}, {"total_tokens": 1}, 0),
            "negative-window": ({"input_tokens": 1}, {"total_tokens": 1}, -1),
            "context-exceeds-window": ({"input_tokens": 1}, {"total_tokens": 101}, 100),
        }
        for name, (total, last, window) in invalid_cases.items():
            with self.subTest(name=name):
                record = {
                    "type": "event_msg", "payload": {"type": "token_count", "info": {
                        "total_token_usage": total, "last_token_usage": last, "model_context_window": window,
                    }},
                }
                with self.assertRaises(asa.NumericSemanticError):
                    asa.CodexAdapter().extract_usage(record)

    def test_sqlite_integer_bounds_are_explicit(self):
        self.assertEqual(asa.require_int(asa.SQLITE_INT64_MIN, "storage"), asa.SQLITE_INT64_MIN)
        self.assertEqual(asa.require_int(asa.SQLITE_INT64_MAX, "storage"), asa.SQLITE_INT64_MAX)
        for value in (asa.SQLITE_INT64_MIN - 1, asa.SQLITE_INT64_MAX + 1):
            with self.subTest(value=value):
                with self.assertRaises(asa.NumericSemanticError):
                    asa.require_int(value, "storage")

    def test_incremental_ingestion_rejects_invalid_numeric_record_without_poisoning(self):
        invalid = {"type": "event_msg", "timestamp": "2026-08-27T12:00:01Z", "payload": {"type": "token_count", "info": {
            "total_token_usage": {"input_tokens": asa.SQLITE_INT64_MAX + 1},
            "last_token_usage": {"total_tokens": 1}, "model_context_window": 100,
        }}}
        valid = {"type": "event_msg", "timestamp": "2026-08-27T12:00:02Z", "payload": {"type": "token_count", "info": {
            "total_token_usage": {"input_tokens": 10, "total_tokens": 10},
            "last_token_usage": {"total_tokens": 10}, "model_context_window": 100,
        }}}
        meta = {"type": "session_meta", "timestamp": "2026-08-27T12:00:00Z", "payload": {"session_id": "native", "id": "stream"}}
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"
            root.mkdir(); path = root / "rollout.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in (meta, invalid, valid)) + "\n")
            summary = asa.parse_codex(asa.Candidate("codex", path, path.name, "test"), 30)
            self.assertEqual((summary.malformed_lines, summary.input_tokens, summary.peak_context_tokens), (1, 10, 10))
            store = asa.StateStore(str(state))
            try:
                first = asa.IncrementalIngestor(store, [(root, "test")]).scan()
                self.assertEqual(first.parse_errors, 1)
                self.assertEqual(store.sessions("codex")[0]["input_tokens"], 10)
                self.assertEqual([row[0] for row in store.db.execute("SELECT context_tokens FROM telemetry_samples")], [10])
                self.assertEqual(asa.IncrementalIngestor(store, [(root, "test")]).scan().files_unchanged, 1)
            finally:
                store.close()

    def test_codex_token_count_accepts_sqlite_int64_upper_boundary(self):
        record = {"type": "event_msg", "payload": {"type": "token_count", "info": {
            "total_token_usage": {"input_tokens": asa.SQLITE_INT64_MAX},
            "last_token_usage": {"total_tokens": 1}, "model_context_window": 100,
        }}}
        self.assertEqual(asa.CodexAdapter().extract_usage(record)["input_tokens"], asa.SQLITE_INT64_MAX)

    def test_classification_skips_pathological_integer_and_keeps_sibling(self):
        """A hostile JSON literal must not prevent discovery of a good file."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bad.jsonl").write_text(
                '{"type":"session_meta","payload":{"n":' + "9" * 10_000 + "}}\n"
            )
            (root / "good.jsonl").write_text(
                json.dumps({"type": "session_meta", "payload": {"session_id": "good"}}) + "\n"
            )
            candidates = asa.collect_candidates([(root, "test")], "all")
            self.assertEqual([(candidate.provider, candidate.path.name) for candidate in candidates], [("codex", "good.jsonl")])

    def test_classification_preserves_ordinary_integer_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, integer in (("small", "42"), ("bounded", "9" * 1_000)):
                with self.subTest(name=name):
                    path = root / f"{name}.jsonl"
                    path.write_text(
                        '{"type":"session_meta","payload":{"session_id":"s","n":' + integer + "}}\n"
                    )
                    self.assertEqual(asa.classify_jsonl(path), "codex")

    def test_incremental_ingestion_skips_pathological_integer_and_keeps_neighbors(self):
        with tempfile.TemporaryDirectory() as td:
            for provider in ("claude", "codex"):
                with self.subTest(provider=provider):
                    root, state = Path(td) / provider, Path(td) / f"{provider}-state"
                    root.mkdir()
                    if provider == "claude":
                        prefix = {
                            "type": "assistant", "timestamp": "2026-08-27T12:00:00Z", "sessionId": "claude-native",
                            "message": {"usage": {"input_tokens": 1, "output_tokens": 1}},
                        }
                        suffix = {
                            "type": "assistant", "timestamp": "2026-08-27T12:00:02Z", "sessionId": "claude-native",
                            "message": {"usage": {"input_tokens": 2, "output_tokens": 1}},
                        }
                    else:
                        prefix = {"type": "session_meta", "timestamp": "2026-08-27T12:00:00Z", "payload": {"session_id": "codex-native", "cwd": "/project"}}
                        suffix = {
                            "type": "event_msg", "timestamp": "2026-08-27T12:00:02Z",
                            "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 2, "total_tokens": 2}, "last_token_usage": {"total_tokens": 2}, "model_context_window": 100}},
                        }
                    path = root / f"{provider}.jsonl"
                    path.write_text(
                        json.dumps(prefix) + "\n" + '{"type":"late","n":' + "9" * 10_000 + "}\n" + json.dumps(suffix) + "\n"
                    )
                    candidate = asa.Candidate(provider, path, path.name, "test")
                    summary = (asa.parse_claude if provider == "claude" else asa.parse_codex)(candidate, 30)
                    self.assertEqual(summary.malformed_lines, 1)
                    self.assertEqual(summary.end, "2026-08-27T12:00:02+00:00")
                    store = asa.StateStore(str(state))
                    try:
                        ingestor = asa.IncrementalIngestor(store, [(root, "test")])
                        first = ingestor.scan()
                        self.assertEqual(first.parse_errors, 1)
                        row = store.sessions(provider)[0]
                        self.assertEqual(row["started_at"], "2026-08-27T12:00:00Z")
                        self.assertEqual(row["last_activity_at"], "2026-08-27T12:00:02Z")
                        self.assertEqual(store.file(path)["last_offset"], path.stat().st_size)
                        second = ingestor.scan()
                        self.assertEqual(second.files_unchanged, 1)
                        self.assertEqual(store.sessions(provider)[0]["last_activity_at"], "2026-08-27T12:00:02Z")
                    finally:
                        store.close()

    def test_service_status_reports_user_service_states_without_opening_state(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            original_which, original_run = asa.shutil.which, asa.subprocess.run
            responses = iter([
                subprocess.CompletedProcess([], 0, "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n", ""),
                subprocess.CompletedProcess([], 0, "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\n", ""),
                subprocess.CompletedProcess([], 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=success\n", ""),
                subprocess.CompletedProcess([], 0, "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\n", ""),
                subprocess.CompletedProcess([], 1, "", "unavailable"),
                subprocess.CompletedProcess([], 0, "unexpected output\n", ""),
            ])
            asa.shutil.which = lambda name: "/usr/bin/systemctl" if name == "systemctl" else None
            asa.subprocess.run = lambda *args, **kwargs: next(responses)
            try:
                for expected in ("ACTIVE", "INACTIVE", "NOT_INSTALLED", "FAILED", "UNKNOWN", "UNKNOWN"):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(asa.main(["service-status", "--state-dir", str(state)]), 0)
                    self.assertIn(f"Service status: {expected}", output.getvalue())
                self.assertFalse(state.exists())
            finally:
                asa.shutil.which, asa.subprocess.run = original_which, original_run

    def test_service_status_is_operational_not_health_and_handles_no_manager(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            health = io.StringIO()
            with contextlib.redirect_stdout(health):
                self.assertEqual(asa.main(["health", "--state-dir", str(state)]), 0)
            original_which = asa.shutil.which
            asa.shutil.which = lambda _name: None
            try:
                service_status = io.StringIO()
                with contextlib.redirect_stdout(service_status):
                    self.assertEqual(asa.main(["service-status", "--state-dir", str(state)]), 0)
                self.assertIn("Service status: UNAVAILABLE", service_status.getvalue())
                self.assertNotEqual(service_status.getvalue(), health.getvalue())
                daemon_status = io.StringIO()
                with contextlib.redirect_stdout(daemon_status):
                    self.assertEqual(asa.service_main(["status", "--state-dir", str(state)]), 0)
                self.assertIn("Service status: UNAVAILABLE", daemon_status.getvalue())
            finally:
                asa.shutil.which = original_which

    def test_agentopsyd_symlink_dispatches_to_service_cli(self):
        """Exercise argv[0]-based service dispatch through a real executable."""
        with tempfile.TemporaryDirectory() as td:
            link = Path(td) / "agentopsyd"
            link.symlink_to(HERE / "agentopsy.py")
            result = subprocess.run([str(link), "--help"], text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage: agentopsyd", result.stdout)
            self.assertIn("{run,once,status}", result.stdout)
            self.assertNotIn("Local forensic session analyser", result.stdout)

    def test_incremental_append_partial_recovery_and_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"
            root.mkdir(); p = root / "rollout-a.jsonl"
            first = {"timestamp": "2026-01-01T00:00:00Z", "type": "session_meta", "payload": {"session_id": "s1", "cwd": "/project"}}
            p.write_text(json.dumps(first) + "\n")
            store = asa.StateStore(str(state)); ingestor = asa.IncrementalIngestor(store, [(root, "test")])
            one = ingestor.scan(); self.assertGreater(one.bytes_newly_parsed, 0)
            two = ingestor.scan(); self.assertEqual(two.bytes_newly_parsed, 0); self.assertEqual(two.files_unchanged, 1)
            appended = {"timestamp": "2026-01-01T00:00:01Z", "type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 9, "cached_input_tokens": 2, "output_tokens": 1}, "last_token_usage": {"total_tokens": 60}, "model_context_window": 100}}}
            raw = json.dumps(appended); p.write_text(p.read_text() + raw[:20])
            partial = ingestor.scan(); self.assertEqual(partial.parse_errors, 0); self.assertEqual(store.sessions()[0]["input_tokens"], 0)
            p.write_text(p.read_text() + raw[20:] + "\n")
            completed = ingestor.scan(); self.assertLess(completed.bytes_newly_parsed, p.stat().st_size); self.assertEqual(store.sessions()[0]["input_tokens"], 9)
            self.assertEqual(len(store.sessions()), 1)
            self.assertEqual(store.sessions()[0]["session_id"], "s1")
            p.unlink(); p.write_text(json.dumps(first) + "\n")
            replaced = ingestor.scan(); self.assertEqual(replaced.files_rescanned, 1)
            store.close()

    def test_unchanged_scan_does_not_reread_file_bytes(self):
        # ROADMAP.md documents that a normal tick reads zero bytes for unchanged
        # sessions. classify_jsonl() currently reopens and re-reads the first
        # lines of every candidate file on every scan, including unchanged
        # ones; this is not reflected in IngestionMetrics. This test documents
        # the current (undesired) behavior so a future fix can flip the
        # assertion instead of silently regressing again.
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"
            root.mkdir(); p = root / "rollout-a.jsonl"
            first = {"timestamp": "2026-01-01T00:00:00Z", "type": "session_meta", "payload": {"session_id": "s1", "cwd": "/project"}}
            p.write_text(json.dumps(first) + "\n")
            store = asa.StateStore(str(state)); ingestor = asa.IncrementalIngestor(store, [(root, "test")])
            ingestor.scan()
            calls = []
            original = asa.classify_jsonl
            asa.classify_jsonl = lambda path, _orig=original: (calls.append(path), _orig(path))[1]
            try:
                unchanged = ingestor.scan()
                self.assertEqual(unchanged.bytes_newly_parsed, 0)
                self.assertEqual(unchanged.files_unchanged, 1)
                self.assertEqual(calls, [])
            finally:
                asa.classify_jsonl = original
            store.close()

    def test_rolling_telemetry_is_bounded_and_reports_time_and_turn_windows(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            start = asa.dt.datetime(2026, 1, 1, tzinfo=asa.dt.timezone.utc)
            with store.db:
                for i in range(60):
                    store.apply_record("codex", Path("/tmp/s.jsonl"), {"session_id": "s", "timestamp": (start + asa.dt.timedelta(minutes=i)).isoformat(), "input_tokens": i, "cached_input_tokens": i // 2, "output_tokens": i, "model_turns": 1, "peak_context_tokens": 100 + i, "peak_context_pct": .5 + i / 1000, "tool_result_chars": i, "read_key": f"file:{i % 3}", "command_key": f"cmd:{i % 2}", "content_key": f"result-{i % 2}", "compactions": int(i == 30)})
            telemetry = store.rolling_telemetry("codex", "s", start + asa.dt.timedelta(minutes=59))
            self.assertEqual(telemetry["last_10_turns"]["samples"], 10)
            self.assertEqual(telemetry["last_10_turns"]["context_growth_tokens"], 9.0)
            self.assertEqual(telemetry["last_5m"]["context_growth_tokens"], 5.0)
            self.assertEqual(telemetry["compaction_snapshots"], 1)
            self.assertEqual(telemetry["context_refill_after_compaction"], 29)
            self.assertEqual(telemetry["last_10_turns"]["cache_reuse_change"], 4)
            self.assertIsNone(telemetry["last_10_turns"]["advisor_subagent_amplification"])
            row = store.db.execute("SELECT read_hash,command_hash,content_hash FROM telemetry_samples WHERE read_hash!='' OR command_hash!='' LIMIT 1").fetchone()
            self.assertTrue(row["read_hash"] and row["command_hash"] and row["content_hash"])
            for i in range(260):
                store.apply_record("codex", Path("/tmp/s.jsonl"), {"session_id": "s", "timestamp": (start + asa.dt.timedelta(minutes=60 + i)).isoformat(), "tool_result_chars": 1})
            self.assertEqual(store.db.execute("SELECT count(*) FROM telemetry_samples WHERE session_id='s'").fetchone()[0], 250)
            store.close()

    def test_unchanged_scale_scan_uses_cached_provider_without_opening_transcripts(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"
            root.mkdir()
            for i in range(40):
                (root / f"rollout-{i}.jsonl").write_text(json.dumps({"type": "session_meta", "payload": {"session_id": f"s{i}"}}) + "\n")
            store = asa.StateStore(str(state)); ingestor = asa.IncrementalIngestor(store, [(root, "test")])
            ingestor.scan()
            calls, original = [], asa.classify_jsonl
            asa.classify_jsonl = lambda path: calls.append(path) or original(path)
            try:
                metrics = ingestor.scan()
            finally:
                asa.classify_jsonl = original
            self.assertEqual(calls, [])
            self.assertEqual((metrics.files_unchanged, metrics.bytes_newly_parsed), (40, 0))
            store.close()

    def test_provider_cache_invalidates_on_parser_or_file_change(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"
            root.mkdir(); path = root / "rollout.jsonl"
            path.write_text(json.dumps({"type": "session_meta", "payload": {"session_id": "s"}}) + "\n")
            store = asa.StateStore(str(state)); asa.IncrementalIngestor(store, [(root, "test")]).scan()
            self.assertEqual(store.cached_provider(path), "codex")
            path.write_text(path.read_text() + "\n")
            self.assertIsNone(store.cached_provider(path))
            store.close()

    def test_codex_response_item_id_is_not_a_session_id(self):
        adapter = asa.CodexAdapter()
        path = Path("rollout-real.jsonl")
        self.assertEqual(adapter.identify_session({"type": "response_item", "payload": {"id": "item-123"}}, path), path.stem)

    def test_claude_streamed_assistant_records_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "projects"; root.mkdir(); p = root / "c.jsonl"
            row = {"type": "assistant", "timestamp": "2026-01-01T00:00:00Z", "sessionId": "c", "message": {"id": "m1", "usage": {"input_tokens": 2, "output_tokens": 1}, "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {}}]}}
            p.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n")
            store = asa.StateStore(str(Path(td) / "state")); asa.IncrementalIngestor(store, [(root, "test")]).scan()
            session = store.sessions("claude")[0]
            self.assertEqual((session["model_turns"], session["input_tokens"], session["tool_calls"]), (1, 2, 1))
            store.close()

    def test_claude_usage_iterations_are_one_model_turn(self):
        value = asa.ClaudeAdapter().extract_usage({"type": "assistant", "message": {"usage": {"iterations": [{"input_tokens": 1}, {"input_tokens": 2}]}}})
        self.assertEqual((value["model_turns"], value["input_tokens"]), (1, 3))

    def test_health_event_cooldown_and_disabled_notifications(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            store.event("codex", "s", "high", "HIGH_CONTEXT", "high", {}, cooldown=3600)
            store.event("codex", "s", "high", "HIGH_CONTEXT", "high", {}, cooldown=3600)
            self.assertEqual(store.db.execute("select count(*) from health_events").fetchone()[0], 1)
            self.assertFalse(asa.Notifier(False).enabled)
            store.close()

    def test_resolve_multiple_unresolved_health_events_uses_unique_resolution_times(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))

            # Reproduce the production failure mode: the same state condition
            # remains active beyond its cooldown and creates several unresolved
            # health-event observations for one provider/stream/code.
            for i in range(4):
                store.event(
                    "claude",
                    "stream-1",
                    "medium",
                    "HIGH_CONTEXT",
                    "high context",
                    {"observation": i},
                    cooldown=0,
                )

            unresolved = store.db.execute(
                """SELECT id,resolved_at FROM health_events
                   WHERE provider=? AND stream_id=? AND code=?
                     AND resolved_at IS NULL
                   ORDER BY id""",
                ("claude", "stream-1", "HIGH_CONTEXT"),
            ).fetchall()
            self.assertEqual(len(unresolved), 4)

            store.resolve_inactive_events("claude", "stream-1", set())

            rows = store.db.execute(
                """SELECT resolved_at FROM health_events
                   WHERE provider=? AND stream_id=? AND code=?
                   ORDER BY id""",
                ("claude", "stream-1", "HIGH_CONTEXT"),
            ).fetchall()

            resolved = [row["resolved_at"] for row in rows]
            self.assertEqual(len(resolved), 4)
            self.assertTrue(all(resolved))
            self.assertEqual(len(set(resolved)), 4)

            remaining = store.db.execute(
                """SELECT COUNT(*) FROM health_events
                   WHERE provider=? AND stream_id=? AND code=?
                     AND resolved_at IS NULL""",
                ("claude", "stream-1", "HIGH_CONTEXT"),
            ).fetchone()[0]
            self.assertEqual(remaining, 0)

            self.assertEqual(
                store.db.execute("PRAGMA integrity_check").fetchone()[0],
                "ok",
            )
            self.assertEqual(
                store.db.execute("PRAGMA foreign_key_check").fetchall(),
                [],
            )
            store.close()

    def test_cold_start_does_not_notify_for_stale_sessions(self):
        # A fresh state DB ingesting months-old transcripts must not fire a
        # desktop notification for every historical session that happens to
        # already be over a health threshold -- only sessions active in the
        # last few minutes should notify.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "sessions"; root.mkdir(); p = root / "rollout-old.jsonl"
            old_ts = "2020-01-01T00:00:00.000Z"
            meta = {"type": "session_meta", "timestamp": old_ts, "payload": {"session_id": "old", "cwd": "/x"}}
            giant = {"type": "response_item", "timestamp": old_ts, "payload": {"type": "function_call_output", "output": "x" * 1_100_000}}
            p.write_text(json.dumps(meta) + "\n" + json.dumps(giant) + "\n")
            calls = []
            original_notify = asa.Notifier.notify
            asa.Notifier.notify = lambda self, t, msg, sev="medium", prov="", sid="": calls.append((prov, sid, sev))
            try:
                asa.service_once(str(Path(td) / "state"), roots=[(root, "test")])
            finally:
                asa.Notifier.notify = original_notify
            self.assertEqual(calls, [])

    def test_codex_duplicate_token_snapshots_are_one_model_turn(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "sessions"; root.mkdir(); p = root / "rollout-c.jsonl"
            meta = {"type": "session_meta", "payload": {"session_id": "c"}}
            token = {"type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 10, "total_tokens": 10}, "last_token_usage": {"total_tokens": 10}, "model_context_window": 100}}}
            p.write_text("\n".join(json.dumps(x) for x in (meta, token, token)) + "\n")
            store = asa.StateStore(str(Path(td) / "state")); asa.IncrementalIngestor(store, [(root, "test")]).scan()
            self.assertEqual(store.sessions("codex")[0]["model_turns"], 1)
            store.close()

    def test_malformed_claude_and_health_transition(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "projects"; root.mkdir(); p = root / "c.jsonl"
            p.write_text('{broken}\n' + json.dumps({"type": "assistant", "timestamp": "2026-01-01T00:00:00Z", "sessionId": "c", "message": {"usage": {"input_tokens": 1, "cache_read_input_tokens": 210000}}}) + "\n")
            store = asa.StateStore(str(Path(td) / "state")); result = asa.IncrementalIngestor(store, [(root, "test")]).scan()
            self.assertEqual(result.parse_errors, 1); row = store.sessions("claude")[0]
            self.assertEqual(row["health_state"], "ROTATION_RECOMMENDED")
            store.close()

    def test_handoff_contract_and_empty_trends(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "project"; handoff = project / ".ai" / "state" / "HANDOFF.md"
            handoff.parent.mkdir(parents=True)
            handoff.write_text("\n".join("## " + item for item in asa.HANDOFF_SECTIONS))
            self.assertTrue(asa.validate_handoff(str(project))["valid"])
            store = asa.StateStore(str(Path(td) / "state"))
            self.assertEqual(asa.trend_payload(store, 7)["providers"]["claude"]["sessions"], 0)
            store.close()


class SelectionAndOutputTests(unittest.TestCase):
    def make_summary(self, provider, sid, end, *, start="", turns=0, total=0, cached=0, input_tokens=0, output=0, peak_pct=0.0):
        return asa.SessionSummary(
            provider=provider,
            session_id=sid,
            path=f"/{provider}/{sid}.jsonl",
            source="test",
            start=start,
            end=end,
            model_turns=turns,
            logged_processed_tokens=total,
            cached_input_tokens=cached,
            input_tokens=input_tokens,
            output_tokens=output,
            peak_context_pct=peak_pct,
        )

    def test_last_selects_latest_per_provider(self):
        sessions = [
            self.make_summary("claude", "c-old", "2026-01-01T00:00:00+00:00"),
            self.make_summary("claude", "c-new", "2026-01-03T00:00:00+00:00"),
            self.make_summary("codex", "x-old", "2026-01-01T00:00:00+00:00"),
            self.make_summary("codex", "x-new", "2026-01-04T00:00:00+00:00"),
        ]
        selected = asa.select_sessions(sessions, [], 1)
        self.assertEqual({s.session_id for s in selected}, {"c-new", "x-new"})

    def test_last_json_keeps_distinct_codex_streams_with_one_native_session(self):
        with tempfile.TemporaryDirectory() as td:
            root, report = Path(td) / "sessions", Path(td) / "last.json"
            root.mkdir()
            parent = {"type": "session_meta", "timestamp": "2026-08-29T10:00:00Z", "payload": {"session_id": "native", "id": "parent-stream"}}
            child = {"type": "session_meta", "timestamp": "2026-08-29T10:01:00Z", "payload": {"session_id": "native", "id": "child-stream", "thread_source": "subagent", "parent_thread_id": "native"}}
            (root / "parent.jsonl").write_text(json.dumps(parent) + "\n")
            (root / "child.jsonl").write_text(json.dumps(child) + "\n")
            self.assertEqual(asa.main(["--source", str(root), "--provider", "codex", "--last", "2", "--json", str(report)]), 0)
            payload = json.loads(report.read_text())
            rows = payload["sessions"]
            self.assertEqual([row["session_id"] for row in rows], ["native", "native"])
            self.assertEqual([row["stream_id"] for row in rows], ["child-stream", "parent-stream"])
            self.assertEqual([row["role"] for row in rows], ["SUBAGENT", "MAIN"])

    def test_last_one_json_keeps_newest_stream_identity(self):
        sessions = [
            self.make_summary("codex", "native", "2026-08-29T10:00:00+00:00"),
            self.make_summary("codex", "native", "2026-08-29T10:01:00+00:00"),
        ]
        sessions[0].stream_id, sessions[1].stream_id = "older-stream", "newer-stream"
        selected = asa.select_sessions(sessions, [], 1)
        self.assertEqual([item.stream_id for item in selected], ["newer-stream"])

    def test_json_stream_identity_defaults_to_native_session(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.json"
            sessions = [
                self.make_summary("codex", "native-one", "2026-08-29T10:00:00+00:00"),
                self.make_summary("codex", "native-two", "2026-08-29T10:01:00+00:00"),
            ]
            asa.write_json_report(report, sessions, [])
            rows = json.loads(report.read_text())["sessions"]
            self.assertEqual([(row["session_id"], row["stream_id"]) for row in rows], [
                ("native-one", "native-one"),
                ("native-two", "native-two"),
            ])

    def test_session_accepts_unique_prefix(self):
        sessions = [
            self.make_summary("claude", "abcdef01-1111", "2026-01-01T00:00:00+00:00"),
            self.make_summary("codex", "12345678-2222", "2026-01-02T00:00:00+00:00"),
        ]
        selected = asa.select_sessions(sessions, ["abcdef"], 0)
        self.assertEqual([s.session_id for s in selected], ["abcdef01-1111"])

    def test_session_ambiguous_prefix_fails(self):
        sessions = [
            self.make_summary("claude", "abcdef01-1111", "2026-01-01T00:00:00+00:00"),
            self.make_summary("claude", "abcdef02-2222", "2026-01-02T00:00:00+00:00"),
        ]
        with self.assertRaises(ValueError):
            asa.select_sessions(sessions, ["abcdef"], 0)

    def test_summary_is_provider_numbered(self):
        sessions = [
            self.make_summary("claude", "c1", "2026-01-01T19:10:00+00:00", start="2026-01-01T15:30:00+00:00", turns=12, total=1000, cached=900),
            self.make_summary("codex", "x1", "2026-01-02T19:10:00+00:00", start="2026-01-02T15:30:00+00:00", total=2000, cached=1500, input_tokens=1900, output=100, peak_pct=0.75),
        ]
        text = asa.render_summary(sessions)
        self.assertIn("1. Claude — 2026-01-01 15:30–19:10 UTC", text)
        self.assertIn("2. Codex — 2026-01-02 15:30–19:10 UTC", text)
        self.assertIn("12 unique model iterations", text)
        self.assertIn("highest context occupancy: 75.0%", text)

    def test_summary_multiple_sessions_keeps_plain_heading(self):
        sessions = [
            self.make_summary("claude", "c1", "2026-01-01T19:10:00+00:00", start="2026-01-01T15:30:00+00:00"),
            self.make_summary("claude", "c2", "2026-01-02T19:10:00+00:00", start="2026-01-02T15:30:00+00:00"),
        ]
        text = asa.render_summary(sessions)
        self.assertIn("1. Claude\n────────────────────────────────────────────────\n2 sessions", text)
        self.assertNotIn("1. Claude —", text)

    def test_summary_cross_date_span_shows_both_dates(self):
        session = self.make_summary(
            "claude",
            "cross-date",
            "2026-08-19T01:10:00+00:00",
            start="2026-08-18T23:30:00+00:00",
        )
        text = asa.render_summary([session])
        self.assertIn("1. Claude — 2026-08-18 23:30 UTC–2026-08-19 01:10 UTC", text)

    def test_session_list_contains_only_copy_friendly_core_fields(self):
        s = self.make_summary("claude", "abc-123", "2026-01-01T12:00:00+00:00")
        text = asa.render_session_list([s])
        self.assertIn("claude", text)
        self.assertIn("abc-123", text)
        self.assertIn("2026-01-01", text)

    def test_summary_export_is_summary_only(self):
        s = self.make_summary("claude", "abc-123", "2026-01-01T12:00:00+00:00", start="2026-01-01T11:00:00+00:00", turns=2)
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "summary.md"
            asa.write_markdown_export(str(target), [s], [], True, 10)
            text = target.read_text()
            self.assertIn("# Agentopsy Summary", text)
            self.assertIn("1. Claude — 2026-01-01 11:00–12:00 UTC", text)
            self.assertNotIn("Session health ranking", text)

class V041RegressionTests(unittest.TestCase):
    def make_v4_rebuild_state(self, state):
        SchemaMigrationTests().make_v1_state(state)
        db = sqlite3.connect(state / "agentopsy.db")
        db.executescript("""
          CREATE TABLE health_events (id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,session_id TEXT NOT NULL,provider TEXT NOT NULL,severity TEXT NOT NULL,code TEXT NOT NULL,message TEXT NOT NULL,evidence TEXT NOT NULL DEFAULT '{}',resolved_at TEXT);
          CREATE TABLE occurrences (session_id TEXT NOT NULL,provider TEXT NOT NULL,kind TEXT NOT NULL,key_hash TEXT NOT NULL,count INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(session_id,provider,kind,key_hash));
          CREATE TABLE record_dedup (session_id TEXT NOT NULL,provider TEXT NOT NULL,kind TEXT NOT NULL,key_hash TEXT NOT NULL,PRIMARY KEY(session_id,provider,kind,key_hash));
          CREATE TABLE guardian_events (id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,session_id TEXT NOT NULL,provider TEXT NOT NULL,severity TEXT NOT NULL,action_safety TEXT NOT NULL,code TEXT NOT NULL,evidence TEXT NOT NULL DEFAULT '{}',resolved_at TEXT);
          CREATE TABLE guardian_event_lanes (event_id INTEGER NOT NULL,lane TEXT NOT NULL,PRIMARY KEY(event_id,lane));
          CREATE TABLE telemetry_samples (id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,session_id TEXT NOT NULL,provider TEXT NOT NULL,turn_index INTEGER NOT NULL,context_tokens INTEGER,context_pct REAL,tool_output_chars INTEGER NOT NULL DEFAULT 0,read_hash TEXT NOT NULL DEFAULT '',command_hash TEXT NOT NULL DEFAULT '',content_hash TEXT NOT NULL DEFAULT '',cached_input_tokens INTEGER,instruction_chars INTEGER,compaction INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE identity_mappings (id INTEGER PRIMARY KEY,provider TEXT NOT NULL,native_session_id TEXT NOT NULL,transcript_path TEXT NOT NULL,pane_id TEXT NOT NULL,lifecycle_source TEXT NOT NULL DEFAULT '',observed_at TEXT NOT NULL,expires_at TEXT NOT NULL,confidence TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
          CREATE TABLE identity_lifecycle (id INTEGER PRIMARY KEY,provider TEXT NOT NULL,native_session_id TEXT NOT NULL,hook_event_name TEXT NOT NULL,lifecycle_source TEXT NOT NULL DEFAULT '',observed_at TEXT NOT NULL);
        """)
        db.execute("UPDATE service_meta SET value='4' WHERE key='schema_version'")
        db.execute("INSERT INTO service_meta VALUES('calibration_profile','{\"adopted\":true}')")
        db.commit(); db.close()

    def test_v4_rebuild_replays_streams_and_invalidates_derived_state(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "roots", Path(td) / "state"; root.mkdir(); self.make_v4_rebuild_state(state)
            now = "2026-08-21T10:00:00Z"
            def codex(path, stream, guardian=False):
                meta = {"id": stream, "session_id": "conversation", "thread_source": "subagent" if guardian else "user", "parent_thread_id": "conversation" if guardian else "", "source": {"subagent": {"other": "guardian"}} if guardian else {}}
                usage = {"type": "event_msg", "timestamp": now, "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 25, "total_tokens": 25}, "last_token_usage": {"total_tokens": 25}, "model_context_window": 100}}}
                path.write_text(json.dumps({"type": "session_meta", "timestamp": now, "payload": meta}) + "\n" + json.dumps(usage) + "\n")
            codex(root / "main.jsonl", "main-rollout"); codex(root / "guardian.jsonl", "guardian-rollout", True)
            subdir = root / "parent" / "subagents"; subdir.mkdir(parents=True)
            (subdir / "child.jsonl").write_text(json.dumps({"type":"assistant","timestamp":now,"sessionId":"child","message":{"usage":{"input_tokens":1}}}) + "\n")
            store = asa.StateStore(str(state))
            self.assertTrue(store.v5_rebuild_required()); self.assertEqual(store.sessions(), [])
            self.assertIsNone(store.file(Path("/tmp/old.jsonl")))
            self.assertIsNone(store.db.execute("SELECT value FROM service_meta WHERE key='calibration_profile'").fetchone())
            first = asa.IncrementalIngestor(store, [(root, "test")]).scan()
            rows = store.db.execute("SELECT stream_id,role,parent_stream_id,current_context_tokens FROM sessions ORDER BY stream_id").fetchall()
            self.assertEqual(first.files_advanced, 3); self.assertFalse(store.v5_rebuild_required())
            self.assertEqual([(r["stream_id"], r["role"]) for r in rows], [("child", "SUBAGENT"), ("guardian-rollout", "GUARDIAN"), ("main-rollout", "MAIN")])
            guardian = next(r for r in rows if r["stream_id"] == "guardian-rollout")
            self.assertEqual(guardian["parent_stream_id"], "main-rollout"); self.assertEqual(guardian["current_context_tokens"], 25)
            second = asa.IncrementalIngestor(store, [(root, "test")]).scan()
            self.assertEqual((second.bytes_newly_parsed, second.files_advanced), (0, 0))
            store.close()

    def test_incomplete_rebuild_marker_remains_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"; self.make_v4_rebuild_state(state)
            store = asa.StateStore(str(state))
            self.assertTrue(store.v5_rebuild_required()); self.assertEqual(store.sessions(), [])
            asa.IncrementalIngestor(store, [], "codex").scan()
            self.assertTrue(store.v5_rebuild_required())
            store.close()

    def test_codex_rollouts_with_one_conversation_remain_separate_streams(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "sessions", Path(td) / "state"; root.mkdir()
            now = "2026-08-21T10:00:00Z"
            def write(name, rollout, role):
                payload = {"id": rollout, "session_id": "conversation", "thread_source": "subagent" if role else "user", "parent_thread_id": "conversation" if role else "", "source": {"subagent": {"other": "guardian"}} if role else {}}
                (root / name).write_text(json.dumps({"type": "session_meta", "timestamp": now, "payload": payload}) + "\n" + json.dumps({"type": "event_msg", "timestamp": now, "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 10, "total_tokens": 10}, "last_token_usage": {"total_tokens": 10}, "model_context_window": 100}}}) + "\n")
            write("main.jsonl", "main-rollout", False); write("review.jsonl", "review-rollout", True)
            store = asa.StateStore(str(state)); asa.IncrementalIngestor(store, [(root, "test")]).scan()
            rows = store.db.execute("SELECT session_id,stream_id,role FROM sessions ORDER BY stream_id").fetchall()
            self.assertEqual([(r["session_id"], r["stream_id"], r["role"]) for r in rows], [("conversation", "main-rollout", "MAIN"), ("conversation", "review-rollout", "GUARDIAN")])
            store.close()

    def test_health_renders_latest_context_separately_from_peak(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            self.addCleanup(store.close)
            with store.db:
                store.apply_record("codex", Path("/tmp/current.jsonl"), {"session_id": "s", "stream_id": "s", "timestamp": "2026-08-21T10:00:00Z", "peak_context_tokens": 90, "peak_context_pct": .9})
                store.apply_record("codex", Path("/tmp/current.jsonl"), {"session_id": "s", "stream_id": "s", "timestamp": "2026-08-21T10:01:00Z", "peak_context_tokens": 20, "peak_context_pct": .2})
            text = asa.render_health(store.sessions("codex"))
            self.assertIn("current context: 20.0%", text); self.assertIn("peak context: 90.0%", text)

    def test_recovered_health_and_guardian_events_are_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            with store.db:
                store.apply_record("codex", Path("/tmp/recovery.jsonl"), {"session_id": "s", "stream_id": "s", "timestamp": "2026-08-21T10:00:00Z", "peak_context_tokens": 90, "peak_context_pct": .9})
                row = store.sessions("codex")[0]; state, events = asa.evaluate_live_health(row, asa.HealthPolicy())
                for severity, code, message, evidence in events: store.event("codex", "s", severity, code, message, evidence)
                store.apply_record("codex", Path("/tmp/recovery.jsonl"), {"session_id": "s", "stream_id": "s", "timestamp": "2026-08-21T10:01:00Z", "peak_context_tokens": 20, "peak_context_pct": .2})
                row = store.sessions("codex")[0]; state, events = asa.evaluate_live_health(row, asa.HealthPolicy())
                store.resolve_inactive_events("codex", "s", {code for _, code, _, _ in events})
            self.assertEqual(state, "HEALTHY")
            self.assertEqual(store.db.execute("SELECT count(*) FROM health_events WHERE resolved_at IS NULL").fetchone()[0], 0)
            self.assertEqual(store.db.execute("SELECT count(*) FROM guardian_events WHERE resolved_at IS NULL").fetchone()[0], 0)
            store.close()

    def test_active_context_events_stay_unresolved_until_their_condition_recovers(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            with store.db:
                store.event("codex", "s", "medium", "HIGH_CONTEXT", "high", {"context_pct": 70})
                store.event("codex", "s", "high", "EXTREME_CONTEXT", "extreme", {"context_pct": 90})
                store.resolve_inactive_events("codex", "s", {"HIGH_CONTEXT", "EXTREME_CONTEXT"})
            self.assertEqual(store.db.execute("SELECT count(*) FROM health_events WHERE resolved_at IS NULL").fetchone()[0], 2)
            self.assertEqual(store.db.execute("SELECT count(*) FROM guardian_events WHERE resolved_at IS NULL").fetchone()[0], 2)
            with store.db: store.resolve_inactive_events("codex", "s", set())
            self.assertEqual(store.db.execute("SELECT count(*) FROM health_events WHERE resolved_at IS NULL").fetchone()[0], 0)
            self.assertEqual(store.db.execute("SELECT count(*) FROM guardian_events WHERE resolved_at IS NULL").fetchone()[0], 0)
            store.close()

    def test_occurrence_events_are_historical_idempotent_and_not_active(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            with store.db:
                store.event("codex", "s", "high", "GIANT_TOOL_RESULT", "large", {"tokens_proxy": 10293})
                store.event("codex", "s", "medium", "COMMAND_REPETITION", "repeat", {"repeats": 6})
                # A no-op evaluation sees the same cumulative aggregate facts.
                store.event("codex", "s", "high", "GIANT_TOOL_RESULT", "large", {"tokens_proxy": 10293})
                store.event("codex", "s", "medium", "COMMAND_REPETITION", "repeat", {"repeats": 6})
            for table in ("health_events", "guardian_events"):
                self.assertEqual(store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 2)
                self.assertEqual(store.db.execute(f"SELECT count(*) FROM {table} WHERE resolved_at IS NULL").fetchone()[0], 0)
                self.assertEqual({r[0] for r in store.db.execute(f"SELECT code FROM {table}")}, {"GIANT_TOOL_RESULT", "COMMAND_REPETITION"})
            store.close()

    def test_healthy_stream_preserves_historical_events_but_only_active_codes_remain_open(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            with store.db:
                store.apply_record("codex", Path("/tmp/lifecycle.jsonl"), {"session_id":"s", "stream_id":"s", "timestamp":"2026-08-21T10:00:00Z", "peak_context_tokens":20, "peak_context_pct":.2})
                # Simulate legacy unresolved historical evidence, then reevaluate.
                store.db.execute("INSERT INTO health_events(timestamp,session_id,provider,stream_id,severity,code,message,evidence) VALUES(?,?,?,?,?,?,?,?)", ("2026-08-21T10:00:00Z","s","codex","s","high","GIANT_TOOL_RESULT","large",'{"tokens_proxy":10293}'))
                store.db.execute("INSERT INTO guardian_events(timestamp,session_id,provider,stream_id,severity,action_safety,code,evidence) VALUES(?,?,?,?,?,?,?,?)", ("2026-08-21T10:00:00Z","s","codex","s","high","ADVISE_ONLY","GIANT_TOOL_RESULT",'{"tokens_proxy":10293}'))
                store.resolve_inactive_events("codex", "s", set())
            self.assertEqual(store.sessions("codex")[0]["health_state"], "HEALTHY")
            self.assertEqual(store.db.execute("SELECT count(*) FROM health_events WHERE code='GIANT_TOOL_RESULT' AND resolved_at IS NOT NULL").fetchone()[0], 1)
            self.assertEqual(store.db.execute("SELECT count(*) FROM guardian_events WHERE code='GIANT_TOOL_RESULT' AND resolved_at IS NOT NULL").fetchone()[0], 1)
            self.assertEqual(store.db.execute("SELECT count(*) FROM health_events WHERE resolved_at IS NULL").fetchone()[0], 0)
            store.close()

    def test_claude_context_is_absolute_proxy_in_replay_and_insights(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            with store.db:
                store.apply_record("claude", Path("/tmp/claude.jsonl"), {"session_id": "c", "stream_id": "c", "timestamp": asa.dt.datetime.now(asa.dt.timezone.utc).isoformat(), "model_turns": 1, "peak_context_tokens": 400000})
            item = asa.guardian_replay(store, "claude")[0]
            self.assertEqual(item["states"][0], "EMERGENCY"); self.assertEqual(item["context_semantics"], "absolute-token proxy")
            self.assertEqual(asa.insights_payload(store, provider="claude")["recurring_faults"]["high_context"], 1)
            store.close()

    def test_measured_compaction_metrics_do_not_use_counter_proxies(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state")); now = asa.dt.datetime.now(asa.dt.timezone.utc).isoformat()
            with store.db:
                store.apply_record("codex", Path("/tmp/compact.jsonl"), {"session_id":"s", "stream_id":"s", "timestamp":now, "model_turns":1, "peak_context_tokens":1000, "peak_context_pct":.5})
                for index, tokens, marker in ((1, 1000, 0), (2, 100, 1), (3, 150, 0)):
                    store.db.execute("INSERT INTO telemetry_samples(timestamp,session_id,provider,stream_id,turn_index,context_tokens,context_pct,tool_output_chars,read_hash,command_hash,content_hash,compaction) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (now,"s","codex","s",index,tokens,.5,0,"","","",marker))
            outcome = asa.stream_compaction_outcomes(store, store.sessions("codex")[0])[0]
            self.assertEqual(outcome["outcome"], "EFFECTIVE")
            self.assertEqual(asa.insights_payload(store, provider="codex")["compaction_refill_sessions"], 0)
            self.assertEqual(asa.classify_compaction(1000, 100, 950, 0, 1)["outcome"], "RAPID_REFILL")
            self.assertEqual(asa.classify_compaction(1000, 900, 950, 2, 5, compaction_window_seconds=300)["outcome"], "THRASH")
            store.close()

    def test_preflight_native_main_ignores_guardian_and_uses_current_context(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"; store = asa.StateStore(str(state)); now = "2026-08-21T10:00:00Z"
            with store.db:
                store.apply_record("codex", Path("/tmp/main.jsonl"), {"session_id":"native", "stream_id":"main", "role":"MAIN", "timestamp":now, "peak_context_tokens":181000, "peak_context_pct":.603, "model_turns":1})
                store.apply_record("codex", Path("/tmp/main.jsonl"), {"session_id":"native", "stream_id":"main", "role":"MAIN", "timestamp":"2026-08-21T10:01:00Z", "peak_context_tokens":100000, "peak_context_pct":.333})
                store.apply_record("codex", Path("/tmp/guardian.jsonl"), {"session_id":"native", "stream_id":"guardian", "role":"GUARDIAN", "timestamp":now, "peak_context_tokens":10, "peak_context_pct":.1})
            selected = asa.select_main_stream(store, "codex", "native")
            self.assertEqual(selected["stream_id"], "main"); self.assertAlmostEqual(asa.stale_session_preflight(selected)["context_pct"], .333)
            store.close()

    def test_fabricated_calibration_profile_cannot_be_adopted(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"; store = asa.StateStore(str(state)); store.close()
            fabricated = {"version": 2, "schema_version": asa.SCHEMA_VERSION, "population": {"qualified_main_streams": 0, "fingerprint": "forged"}, "profiles": {provider: {"session_duration_seconds": {"confidence":"HIGH", "samples":1}} for provider in ("claude", "codex")}}
            db = sqlite3.connect(state / "agentopsy.db"); db.execute("INSERT OR REPLACE INTO service_meta(key,value) VALUES('calibration_profile',?)", (json.dumps(fabricated),)); db.commit(); db.close()
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(asa.main(["calibrate", "adopt", "--state-dir", str(state)]), 2)

    def test_help_and_selector_validation(self):
        self.assertEqual(asa.main(["signals", "--help"]), 0)
        self.assertEqual(asa.main(["explain", "--help"]), 0)
        self.assertEqual(asa.main(["--last", "0"]), 2)
        self.assertEqual(asa.main(["--since", "not-a-time"]), 2)

    def test_malformed_hook_install_is_atomic(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); config, hooks = home / "config.toml", home / "hooks.json"
            config.write_text("[features]\nhooks = false\n"); hooks.write_text("{")
            before, hooks_before = config.read_bytes(), hooks.read_bytes()
            with self.assertRaises(ValueError): asa.integration_install_codex(home, None)
            self.assertEqual(config.read_bytes(), before); self.assertEqual(hooks.read_bytes(), hooks_before)
            self.assertFalse((home / ".agentopsy-integration.json").exists())


def _sample_statusline_payload(session_id="s1", transcript_path=None, **overrides):
    payload = {
        "version": "2.1.239", "session_id": session_id,
        "transcript_path": transcript_path,
        "model": {"id": "claude-sonnet-5", "display_name": "Sonnet 5"},
        "context_window": {
            "context_window_size": 1000000, "used_percentage": 4, "remaining_percentage": 96,
            "total_input_tokens": 44865, "total_output_tokens": 7,
            "current_usage": {"input_tokens": 2, "output_tokens": 7, "cache_creation_input_tokens": 9196, "cache_read_input_tokens": 35667},
        },
    }
    payload.update(overrides)
    return payload


class ClaudeRuntimeStrictNumericTypeTests(unittest.TestCase):
    """CR2-01: no int()/round() coercion anywhere in Claude runtime telemetry
    validation. type(value) is int strictly -- float, bool (a subclass of
    int), numeric strings, negative-where-impossible, and pathological
    out-of-range values must all be rejected, never silently truncated."""
    def _bridge_extract(self, **ctx_overrides):
        payload = _sample_statusline_payload(transcript_path="/tmp/s1.jsonl")
        payload["context_window"].update(ctx_overrides)
        return asa._claude_statusline_extract(payload)

    def test_float_context_window_size_rejected_not_truncated(self):
        sample = self._bridge_extract(context_window_size=1000000.9)
        self.assertIsNone(sample["context_window_size"])

    def test_float_total_input_tokens_rejected_not_truncated(self):
        sample = self._bridge_extract(total_input_tokens=44865.9)
        self.assertIsNone(sample["total_input_tokens"])

    def test_bool_true_rejected_as_token_count(self):
        sample = self._bridge_extract(total_input_tokens=True)
        self.assertIsNone(sample["total_input_tokens"])

    def test_bool_false_rejected_as_token_count(self):
        sample = self._bridge_extract(total_input_tokens=False)
        self.assertIsNone(sample["total_input_tokens"])

    def test_numeric_string_rejected(self):
        sample = self._bridge_extract(total_input_tokens="44865")
        self.assertIsNone(sample["total_input_tokens"])

    def test_negative_value_rejected(self):
        sample = self._bridge_extract(total_input_tokens=-1)
        self.assertIsNone(sample["total_input_tokens"])

    def test_extreme_out_of_range_value_rejected(self):
        sample = self._bridge_extract(total_input_tokens=10**18)
        self.assertIsNone(sample["total_input_tokens"])

    def test_bool_used_percentage_rejected(self):
        sample = self._bridge_extract(used_percentage=True)
        self.assertIsNone(sample["used_percentage"])

    def test_used_percentage_out_of_0_100_range_rejected(self):
        sample = self._bridge_extract(used_percentage=150)
        self.assertIsNone(sample["used_percentage"])

    def test_used_percentage_absent_leaves_sample_valid(self):
        payload = _sample_statusline_payload(transcript_path="/tmp/s1.jsonl")
        del payload["context_window"]["used_percentage"]
        sample = asa._claude_statusline_extract(payload)
        self.assertIsNotNone(sample)
        self.assertIsNone(sample["used_percentage"])

    def test_out_of_range_used_percentage_cannot_smuggle_inconsistent_sample_to_exact(self):
        # CR3-01: a present-but-invalid used_percentage must never let
        # current_context_input_tokens reach EXACT -- the field is nulled at
        # extraction, but the sample itself is not discarded (its other
        # OBSERVED-tier reported fields remain truthful); the EXACT gate in
        # _claude_runtime_derive is what actually blocks this, since a
        # missing/invalid used_percentage fails "directly present and valid".
        sample = _claude_runtime_sample("s1", "/tmp/s1.jsonl")
        payload = _sample_statusline_payload(transcript_path="/tmp/s1.jsonl")
        payload["context_window"]["used_percentage"] = 150
        extracted = asa._claude_statusline_extract(payload)
        self.assertIsNotNone(extracted)
        self.assertIsNone(extracted["used_percentage"])
        derived = asa._claude_runtime_derive(extracted)
        cap = asa._claude_runtime_capability(derived)
        self.assertNotEqual(cap["current_context_input_tokens"], "EXACT")

    def test_float_used_percentage_rejected(self):
        sample = self._bridge_extract(used_percentage=4.5)
        self.assertIsNone(sample["used_percentage"])

    def test_current_usage_field_bool_rejected(self):
        payload = _sample_statusline_payload(transcript_path="/tmp/s1.jsonl")
        payload["context_window"]["current_usage"]["input_tokens"] = True
        sample = asa._claude_statusline_extract(payload)
        self.assertIsNone(sample["current_usage"]["input_tokens"])

    def test_current_usage_field_float_rejected(self):
        payload = _sample_statusline_payload(transcript_path="/tmp/s1.jsonl")
        payload["context_window"]["current_usage"]["cache_read_input_tokens"] = 35667.5
        sample = asa._claude_statusline_extract(payload)
        self.assertIsNone(sample["current_usage"]["cache_read_input_tokens"])

    def test_inbox_extract_float_context_window_size_rejected(self):
        sample = asa._claude_runtime_inbox_extract({
            "session_id": "s1", "transcript_path": "/tmp/s1.jsonl", "receipt_ns": 1,
            "context_window_size": 1000000.9,
        })
        self.assertIsNone(sample["context_window_size"])

    def test_inbox_extract_bool_receipt_ns_rejected(self):
        sample = asa._claude_runtime_inbox_extract({
            "session_id": "s1", "transcript_path": "/tmp/s1.jsonl", "receipt_ns": True,
        })
        self.assertIsNone(sample)  # receipt_ns is load-bearing; bool must reject the whole sample

    def test_inbox_extract_float_receipt_ns_rejected(self):
        sample = asa._claude_runtime_inbox_extract({
            "session_id": "s1", "transcript_path": "/tmp/s1.jsonl", "receipt_ns": 123.5,
        })
        self.assertIsNone(sample)

    def test_derive_rejects_bool_in_current_usage_for_usage_complete(self):
        # isinstance(True, int) is True -- a naive isinstance check would
        # have let bool satisfy "usage_complete". type(x) is int must not.
        sample = {"total_input_tokens": 44865, "total_output_tokens": 7, "context_window_size": 1000000,
                  "claude_code_version": "2.1.239",
                  "current_usage": {"input_tokens": True, "output_tokens": 7, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 44758}}
        derived = asa._claude_runtime_derive(sample)
        self.assertFalse(derived["usage_complete"])

    def test_validated_empirical_v2_1_239_fixture_still_passes(self):
        sample = _claude_runtime_sample("s1", "/tmp/s1.jsonl")
        derived = asa._claude_runtime_derive(sample)
        cap = asa._claude_runtime_capability(derived)
        self.assertEqual(derived["current_context_input_tokens"], 44865)
        self.assertEqual(cap["current_context_input_tokens"], "EXACT")

    def test_bare_nan_json_constant_rejected_at_parse_boundary(self):
        with self.assertRaises(ValueError):
            asa._claude_runtime_json_loads('{"total_input_tokens": NaN}')

    def test_bare_infinity_json_constant_rejected_at_parse_boundary(self):
        with self.assertRaises(ValueError):
            asa._claude_runtime_json_loads('{"total_input_tokens": Infinity}')

    def test_bridge_main_does_not_crash_or_write_on_nan_payload(self):
        with tempfile.TemporaryDirectory() as td:
            rc = asa.claude_statusline_bridge_main(stdin=io.BytesIO(b'{"session_id":"s1","transcript_path":"/tmp/s1.jsonl","context_window":{"total_input_tokens":NaN}}'), state_dir=td)
            self.assertEqual(rc, 0)
            self.assertEqual(list((Path(td) / "claude-runtime").glob("*.json")), [])

    # --- CR3-04: duplicate JSON object keys must be rejected, not last-key-wins ---

    def test_duplicate_key_at_top_level_is_rejected(self):
        with self.assertRaises(ValueError):
            asa._claude_runtime_json_loads('{"session_id":"a","session_id":"b"}')

    def test_duplicate_key_in_context_window_is_rejected(self):
        with self.assertRaises(ValueError):
            asa._claude_runtime_json_loads(
                '{"context_window":{"used_percentage":150,"used_percentage":4}}'
            )

    def test_duplicate_key_in_current_usage_is_rejected(self):
        with self.assertRaises(ValueError):
            asa._claude_runtime_json_loads(
                '{"context_window":{"current_usage":{"input_tokens":1,"input_tokens":2}}}'
            )

    def test_byte_size_limit_still_enforced_alongside_duplicate_key_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            huge = b'{"session_id":"' + b"x" * (asa.CLAUDE_RUNTIME_STDIN_MAX_BYTES + 100) + b'"}'
            rc = asa.claude_statusline_bridge_main(stdin=io.BytesIO(huge), state_dir=td)
            self.assertEqual(rc, 0)
            self.assertEqual(list((Path(td) / "claude-runtime").glob("*.json")), [])

    def test_top_level_object_requirement_still_enforced(self):
        # A syntactically valid top-level array must still fail whitelist
        # extraction downstream, not be treated as a valid payload shape.
        sample = asa._claude_statusline_extract(asa._claude_runtime_json_loads("[1,2,3]"))
        self.assertIsNone(sample)

    def test_bridge_writes_no_inbox_file_on_duplicate_key_input(self):
        with tempfile.TemporaryDirectory() as td:
            payload = b'{"session_id":"s1","transcript_path":"/tmp/s1.jsonl","context_window":{"used_percentage":150,"used_percentage":4}}'
            rc = asa.claude_statusline_bridge_main(stdin=io.BytesIO(payload), state_dir=td)
            self.assertEqual(rc, 0)
            self.assertEqual(list((Path(td) / "claude-runtime").glob("*.json")), [])

    def test_inbox_reader_quarantines_duplicate_key_file_without_crashing(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            receipt_ns = asa.time.time_ns()
            name = asa._claude_runtime_inbox_filename("s1", receipt_ns)
            (inbox / name).write_text('{"session_id":"s1","transcript_path":"/tmp/s1.jsonl","receipt_ns":%d,"used_percentage":150,"used_percentage":4}' % receipt_ns)
            samples = asa._read_claude_runtime_inbox(td)
            self.assertEqual(samples, [])
            self.assertFalse((inbox / name).exists())  # quarantined, not left forever


class ClaudeRuntimeCompleteEvidenceTests(unittest.TestCase):
    """CR3-01: current_context_input_tokens may only become EXACT when the
    COMPLETE evidence set holds -- validated version, complete usage,
    internally consistent counters, a directly-valid context window, a
    directly-valid used_percentage, AND derived occupancy reconciling with
    it. Internal self-consistency of the token breakdown alone must never be
    enough. Full bridge -> inbox -> ingest path, not just the derive/
    capability unit level."""
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))

    def _seed_session(self, store, session_id, path, role="MAIN"):
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, "claude", session_id, role, path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
        store.db.commit()

    def _run_end_to_end(self, td, payload):
        path = str(Path(td) / "s1.jsonl")
        store = self._store(td)
        self._seed_session(store, "s1", path)
        rc = asa.claude_statusline_bridge_main(stdin=io.BytesIO(json.dumps(payload).encode()), state_dir=td)
        self.assertEqual(rc, 0)
        for entry, sample in asa._read_claude_runtime_inbox(td):
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertEqual(reason, "resolved")
            asa.store_claude_runtime_sample(store, row, sample)
        store.db.commit()
        snapshot = asa._parse_claude_runtime_snapshot(
            store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0]
        )
        store.close()
        return snapshot

    def _valid_payload(self, path, **ctx_overrides):
        ctx = {
            "context_window_size": 1000000, "used_percentage": 4,
            "total_input_tokens": 44865, "total_output_tokens": 7,
            "current_usage": {"input_tokens": 7, "output_tokens": 7, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 44758},
        }
        ctx.update(ctx_overrides)
        return {"session_id": "s1", "transcript_path": path, "version": "2.1.239",
                "model": {"id": "claude-sonnet-5", "display_name": "Sonnet 5"}, "context_window": ctx}

    def test_complete_valid_2_1_239_fixture_reaches_exact_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            snapshot = self._run_end_to_end(td, self._valid_payload(path))
            self.assertEqual(snapshot["current_context_input_tokens"], 44865)
            self.assertEqual(snapshot["capability"]["current_context_input_tokens"], "EXACT")

    def test_actually_captured_2_1_239_statusline_shape_reaches_exact(self):
        # Built from a real Claude Code 2.1.239 statusline JSON payload
        # captured for this feature (used_percentage confirmed to be a plain
        # JSON integer in the genuine payload, not a float) -- not just a
        # synthetic fixture this test file constructs itself.
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = {
                "session_id": "s1", "transcript_path": path, "version": "2.1.239",
                "model": {"id": "claude-sonnet-5", "display_name": "Sonnet 5"},
                "context_window": {
                    "context_window_size": 1000000, "used_percentage": 4,
                    "total_input_tokens": 42245, "total_output_tokens": 6,
                    "current_usage": {"input_tokens": 2, "output_tokens": 6, "cache_creation_input_tokens": 42243, "cache_read_input_tokens": 0},
                },
            }
            snapshot = self._run_end_to_end(td, payload)
            self.assertEqual(snapshot["current_context_input_tokens"], 42245)
            self.assertEqual(snapshot["capability"]["current_context_input_tokens"], "EXACT")

    def test_missing_window_never_reaches_exact_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = self._valid_payload(path)
            del payload["context_window"]["context_window_size"]
            snapshot = self._run_end_to_end(td, payload)
            self.assertIsNone(snapshot["current_context_input_tokens"])
            self.assertNotEqual(snapshot["capability"]["current_context_input_tokens"], "EXACT")

    def test_invalid_window_forms_never_reach_exact_end_to_end(self):
        for bad_window in (True, "1000000", -1, 0, 1000000.9, 10**18):
            with tempfile.TemporaryDirectory() as td:
                path = str(Path(td) / "s1.jsonl")
                payload = self._valid_payload(path, context_window_size=bad_window)
                snapshot = self._run_end_to_end(td, payload)
                self.assertIsNone(snapshot["current_context_input_tokens"], msg=f"window={bad_window!r}")
                self.assertNotEqual(snapshot["capability"]["current_context_input_tokens"], "EXACT", msg=f"window={bad_window!r}")

    def test_missing_percentage_never_reaches_exact_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = self._valid_payload(path)
            del payload["context_window"]["used_percentage"]
            snapshot = self._run_end_to_end(td, payload)
            self.assertIsNone(snapshot["current_context_input_tokens"])
            self.assertNotEqual(snapshot["capability"]["current_context_input_tokens"], "EXACT")

    def test_invalid_percentage_forms_never_reach_exact_end_to_end(self):
        for bad_pct in (True, False, "4", -1, 150, 4.5):
            with tempfile.TemporaryDirectory() as td:
                path = str(Path(td) / "s1.jsonl")
                payload = self._valid_payload(path, used_percentage=bad_pct)
                snapshot = self._run_end_to_end(td, payload)
                self.assertIsNone(snapshot["current_context_input_tokens"], msg=f"used_percentage={bad_pct!r}")
                self.assertNotEqual(snapshot["capability"]["current_context_input_tokens"], "EXACT", msg=f"used_percentage={bad_pct!r}")

    def test_percentage_not_reconciling_with_derived_occupancy_never_reaches_exact(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            # 4% is within tolerance of 44865/1000000=4.4865%; 50% is not.
            payload = self._valid_payload(path, used_percentage=50)
            snapshot = self._run_end_to_end(td, payload)
            self.assertIsNone(snapshot["current_context_input_tokens"])
            self.assertNotEqual(snapshot["capability"]["current_context_input_tokens"], "EXACT")

    def test_internally_consistent_but_incomplete_evidence_never_reaches_exact(self):
        # CR3-01's core regression case: token breakdown is internally
        # consistent (counters_consistent True) but window/percentage are
        # missing -- must NOT be EXACT merely because the breakdown sums.
        # current_context_input_tokens is never OBSERVED-labelled (capability
        # text must never disagree with value presence: the value is None
        # unless the complete evidence set holds), so this must fall all the
        # way to UNAVAILABLE, not just short of EXACT.
        derived = asa._claude_runtime_derive({
            "total_input_tokens": 44865, "total_output_tokens": 7, "claude_code_version": "2.1.239",
            "current_usage": {"input_tokens": 7, "output_tokens": 7, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 44758},
            # context_window_size and used_percentage both absent
        })
        self.assertTrue(derived["counters_consistent"])
        self.assertFalse(derived["validated"])
        self.assertIsNone(derived["current_context_input_tokens"])
        cap = asa._claude_runtime_capability(derived)
        self.assertNotEqual(cap["current_context_input_tokens"], "EXACT")
        self.assertEqual(cap["current_context_input_tokens"], "UNAVAILABLE")
        # But the raw reported total is still truthfully OBSERVED.
        self.assertEqual(cap["reported_total_input_tokens"], "OBSERVED")

    def test_reported_total_input_tokens_stays_observed_when_percentage_missing(self):
        # A missing used_percentage must not drag counters_consistent to
        # False and wrongly downgrade the at-most-OBSERVED reported field.
        derived = asa._claude_runtime_derive(_claude_runtime_sample("s1", "/tmp/s1.jsonl", used_percentage=None))
        self.assertTrue(derived["counters_consistent"])
        cap = asa._claude_runtime_capability(derived)
        self.assertEqual(cap["reported_total_input_tokens"], "OBSERVED")


class ClaudeRuntimeBridgeTests(unittest.TestCase):
    def _bridge(self, payload_bytes, state_dir):
        return asa.claude_statusline_bridge_main(stdin=io.BytesIO(payload_bytes), state_dir=state_dir)

    def test_valid_payload_writes_bounded_whitelisted_inbox_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            rc = self._bridge(json.dumps(_sample_statusline_payload(transcript_path=path)).encode(), td)
            self.assertEqual(rc, 0)
            files = list((Path(td) / "claude-runtime").glob("*.json"))
            self.assertEqual(len(files), 1)
            data = json.loads(files[0].read_text())
            self.assertEqual(data["session_id"], "s1")
            self.assertEqual(set(data.keys()), {"format_version", "session_id", "transcript_path", "claude_code_version",
                "model_id", "model_display_name", "context_window_size", "used_percentage", "total_input_tokens",
                "total_output_tokens", "current_usage", "context_window_fields", "current_usage_fields", "current_usage_kind",
                "semantic_unknown_fields_present", "semantic_unknown_context_fingerprint", "semantic_unknown_usage_fingerprint", "observed_at", "receipt_ns"})
            self.assertIsInstance(data["receipt_ns"], int)

    def test_documented_remaining_percentage_is_structurally_known_but_not_consumed(self):
        payload = _sample_statusline_payload(transcript_path="/tmp/s1.jsonl")
        sample = asa._claude_statusline_extract(payload)
        self.assertFalse(sample["semantic_unknown_fields_present"])
        self.assertIn("remaining_percentage", sample["context_window_fields"])
        self.assertNotIn("remaining_percentage", sample)  # structural recognition only

    def test_remaining_percentage_is_optional_but_future_context_fields_remain_unknown(self):
        payload = _sample_statusline_payload(transcript_path="/tmp/s1.jsonl")
        payload["context_window"].pop("remaining_percentage")
        self.assertFalse(asa._claude_statusline_extract(payload)["semantic_unknown_fields_present"])
        payload["context_window"]["future_context_field"] = "must-not-persist"
        sample = asa._claude_statusline_extract(payload)
        self.assertTrue(sample["semantic_unknown_fields_present"])
        self.assertNotIn("future_context_field", str(sample))
        self.assertNotIn("must-not-persist", str(sample))

    def test_missing_optional_fields_still_produce_a_sample(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = {"version": "2.1.239", "session_id": "s1", "transcript_path": path}
            rc = self._bridge(json.dumps(payload).encode(), td)
            self.assertEqual(rc, 0)
            files = list((Path(td) / "claude-runtime").glob("*.json"))
            self.assertEqual(len(files), 1)
            data = json.loads(files[0].read_text())
            self.assertIsNone(data["context_window_size"])

    def test_malformed_json_does_not_raise_or_write(self):
        with tempfile.TemporaryDirectory() as td:
            rc = self._bridge(b"{not json", td)
            self.assertEqual(rc, 0)
            self.assertFalse((Path(td) / "claude-runtime").exists())

    def test_unknown_model_is_persisted_as_reported(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = _sample_statusline_payload(transcript_path=path, model={"id": "future-model-x", "display_name": "Future X"})
            self._bridge(json.dumps(payload).encode(), td)
            data = json.loads(next((Path(td) / "claude-runtime").glob("*.json")).read_text())
            self.assertEqual(data["model_id"], "future-model-x")

    def test_missing_session_id_or_transcript_path_produces_no_file(self):
        with tempfile.TemporaryDirectory() as td:
            self._bridge(json.dumps({"version": "x", "session_id": "s1"}).encode(), td)
            self.assertFalse((Path(td) / "claude-runtime").exists())
            self._bridge(json.dumps({"version": "x", "transcript_path": str(Path(td) / "a.jsonl")}).encode(), td)
            self.assertFalse((Path(td) / "claude-runtime").exists())

    def test_relative_transcript_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            self._bridge(json.dumps(_sample_statusline_payload(transcript_path="relative/path.jsonl")).encode(), td)
            self.assertFalse((Path(td) / "claude-runtime").exists())

    def test_never_writes_sqlite(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            self._bridge(json.dumps(_sample_statusline_payload(transcript_path=path)).encode(), td)
            self.assertFalse((Path(td) / "agentopsy.db").exists())

    def test_atomic_inbox_write_leaves_no_tmp_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            self._bridge(json.dumps(_sample_statusline_payload(transcript_path=path)).encode(), td)
            tmp_files = list((Path(td) / "claude-runtime").glob("*.tmp-*"))
            self.assertEqual(tmp_files, [])

    def test_session_id_cannot_escape_inbox_directory(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = _sample_statusline_payload(session_id="../../etc/passwd", transcript_path=path)
            self._bridge(json.dumps(payload).encode(), td)
            files = list((Path(td) / "claude-runtime").glob("*"))
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0].parent.samefile(Path(td) / "claude-runtime"))
            self.assertFalse((Path(td) / "etc").exists())

    def test_oversized_stdin_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = _sample_statusline_payload(transcript_path=path, model={"id": "x" * 200_000, "display_name": "y"})
            self._bridge(json.dumps(payload).encode(), td)
            self.assertFalse((Path(td) / "claude-runtime").exists())

    def test_unexpected_json_keys_are_discarded(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = _sample_statusline_payload(transcript_path=path)
            payload["prompt"] = "the user's secret prompt"
            payload["system_prompt"] = "leaked system text"
            payload["tool_output"] = "some tool result"
            self._bridge(json.dumps(payload).encode(), td)
            data = json.loads(next((Path(td) / "claude-runtime").glob("*.json")).read_text())
            self.assertNotIn("prompt", data); self.assertNotIn("system_prompt", data); self.assertNotIn("tool_output", data)

    def test_no_prompt_transcript_or_tool_content_ever_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = _sample_statusline_payload(transcript_path=path)
            payload["context_window"]["transcript_body"] = "leaked"
            self._bridge(json.dumps(payload).encode(), td)
            data = json.loads(next((Path(td) / "claude-runtime").glob("*.json")).read_text())
            self.assertNotIn("transcript_body", str(data))

    def test_current_usage_null_after_compact_accepted_without_fabricating_zero(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            payload = _sample_statusline_payload(transcript_path=path)
            payload["context_window"]["current_usage"] = None
            self._bridge(json.dumps(payload).encode(), td)
            data = json.loads(next((Path(td) / "claude-runtime").glob("*.json")).read_text())
            self.assertIsNone(data["current_usage"])


class ClaudeRuntimeResolverTests(unittest.TestCase):
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))

    def _seed_session(self, store, session_id, path, role="MAIN"):
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, "claude", session_id, role, path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
        store.db.commit()

    def test_exact_identity_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertEqual(reason, "resolved"); self.assertEqual(row["session_id"], "s1"); store.close()

    def test_same_session_id_wrong_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", str(Path(td) / "other.jsonl"))
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertIsNone(row); self.assertEqual(reason, "unresolved"); store.close()

    def test_right_path_wrong_session_id_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("wrong-session", path)
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertIsNone(row); self.assertEqual(reason, "unresolved"); store.close()

    def test_ambiguous_match_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl")
            store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
                ("s1", "claude", "s1", "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
            store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
                ("s1", "claude", "s1-dup", "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
            store.db.commit()
            sample = _claude_runtime_sample("s1", path)
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertIsNone(row); self.assertEqual(reason, "ambiguous"); store.close()

    def test_zero_matches_unresolved(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td)
            sample = _claude_runtime_sample("nope", str(Path(td) / "nope.jsonl"))
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertIsNone(row); self.assertEqual(reason, "unresolved"); store.close()

    # CR-03: exact runtime resolution must require role='MAIN'. Claude's status
    # line empirically reports the parent/MAIN identity even while a subagent
    # is running, so any row sharing that identity but tagged SUBAGENT must
    # never be resolved -- resolving it would make a SUBAGENT exact, which v1
    # must never do.
    def test_sole_matching_subagent_row_is_unresolved(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path, role="SUBAGENT")
            sample = _claude_runtime_sample("s1", path)
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertIsNone(row); self.assertEqual(reason, "unresolved"); store.close()

    def test_matching_main_resolves(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path, role="MAIN")
            sample = _claude_runtime_sample("s1", path)
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertEqual(reason, "resolved"); self.assertEqual(row["role"], "MAIN"); store.close()

    def test_matching_main_and_subagent_resolves_main_only(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl")
            store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
                ("s1", "claude", "s1", "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
            store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
                ("s1", "claude", "s1-sub", "SUBAGENT", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
            store.db.commit()
            sample = _claude_runtime_sample("s1", path)
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertEqual(reason, "resolved"); self.assertEqual(row["stream_id"], "s1"); self.assertEqual(row["role"], "MAIN"); store.close()

    def test_parent_id_with_subagent_transcript_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); main_path = str(Path(td) / "main.jsonl"); sub_path = str(Path(td) / "sub.jsonl")
            self._seed_session(store, "parent-id", main_path, role="MAIN")
            store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
                ("parent-id", "claude", "sub-stream", "SUBAGENT", sub_path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
            store.db.commit()
            sample = _claude_runtime_sample("parent-id", sub_path)  # correct session_id, but the SUBAGENT's own path
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertIsNone(row); self.assertEqual(reason, "unresolved"); store.close()

    def test_correct_path_but_subagent_role_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path, role="SUBAGENT")
            sample = _claude_runtime_sample("s1", path)  # exact session_id + exact path, but role is SUBAGENT
            row, reason = asa.resolve_claude_runtime_sample(store, sample)
            self.assertIsNone(row); self.assertEqual(reason, "unresolved"); store.close()

    def test_runtime_evidence_grants_no_control_identity(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            self.assertEqual(store.db.execute("SELECT count(*) FROM identity_mappings").fetchone()[0], 0)
            store.close()

    def test_historical_session_without_runtime_evidence_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            before = dict(store.db.execute("SELECT * FROM sessions WHERE session_id='s1'").fetchone())
            self.assertEqual(store.db.execute("SELECT count(*) FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchone()[0], 0)
            after = dict(store.db.execute("SELECT * FROM sessions WHERE session_id='s1'").fetchone())
            self.assertEqual(before, after); store.close()

    def test_transcript_ingestion_after_runtime_observation_cannot_clobber_it(self):
        with tempfile.TemporaryDirectory() as td:
            projects = Path(td) / "projects"; projects.mkdir()
            path = projects / "s1.jsonl"
            path.write_text('{"type":"assistant","uuid":"u1","timestamp":"2026-08-21T20:00:00Z","message":{"model":"claude-sonnet-5","id":"m1","usage":{"input_tokens":10,"output_tokens":5}}}\n')
            store = self._store(td)
            self._seed_session(store, "s1", str(path.resolve()))
            sample = _claude_runtime_sample("s1", str(path.resolve()))
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample); store.db.commit()
            before = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            ingestor = asa.IncrementalIngestor(store, [(projects, "claude")], "claude")
            ingestor.scan()
            after = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(before, after); store.close()

    def test_duplicate_observation_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path, observed_at="2026-08-21T20:05:00+00:00")
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            self.assertEqual(store.db.execute("SELECT count(*) FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchone()[0], 1)
            store.close()

    def test_older_observation_cannot_replace_newer_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            newer = _claude_runtime_sample("s1", path, total_input_tokens=90000)
            older = _claude_runtime_sample("s1", path, total_input_tokens=10000)
            row, _ = asa.resolve_claude_runtime_sample(store, newer)
            asa.store_claude_runtime_sample(store, row, newer, receipt_ns=2000)
            asa.store_claude_runtime_sample(store, row, older, receipt_ns=1000)  # earlier trusted receipt
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["current_context_input_tokens"], 90000); store.close()

    def test_untrusted_payload_observed_at_cannot_reorder_observations(self):
        """CR-07: an incoming observed_at claim must never participate in
        latest-wins -- only the caller-supplied trusted receipt does."""
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            # attacker/regressed-client claims a far-future observed_at, but its
            # trusted receipt is genuinely earlier.
            fake_future = _claude_runtime_sample("s1", path, total_input_tokens=10000, observed_at="2099-01-01T00:00:00+00:00")
            real_later = _claude_runtime_sample("s1", path, total_input_tokens=90000, observed_at="2026-08-21T20:00:00+00:00")
            row, _ = asa.resolve_claude_runtime_sample(store, fake_future)
            asa.store_claude_runtime_sample(store, row, fake_future, receipt_ns=1000)
            asa.store_claude_runtime_sample(store, row, real_later, receipt_ns=2000)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["current_context_input_tokens"], 90000); store.close()

    def test_peaks_update_monotonically_under_same_window(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            low = _claude_runtime_sample("s1", path, total_input_tokens=10000)
            high = _claude_runtime_sample("s1", path, total_input_tokens=90000)
            lower_again = _claude_runtime_sample("s1", path, total_input_tokens=20000)
            for i, sample in enumerate((low, high, lower_again)):
                row, _ = asa.resolve_claude_runtime_sample(store, sample)
                asa.store_claude_runtime_sample(store, row, sample, receipt_ns=1000 + i)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["current_context_input_tokens"], 20000)
            self.assertEqual(snap["peak_current_context_input_tokens"], 90000); store.close()

    def test_internally_inconsistent_counters_downgrade_datum(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)
            sample["current_usage"]["input_tokens"] = 99999999  # breaks the sum vs total_input_tokens check
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertFalse(snap["counters_consistent"])
            self.assertIsNone(snap["current_context_input_tokens"])
            self.assertEqual(snap["capability"]["current_context_input_tokens"], "UNAVAILABLE"); store.close()

    def test_cumulative_bug_regression_fixture_post_compact_is_not_blindly_accumulated(self):
        """v0.4.x historical bug shape: status-line reported ever-growing cumulative
        totals across turns even after /compact. A post-compact sample must be
        accepted as its own current snapshot, not merged additively with the pre-compact one."""
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            pre_compact = _claude_runtime_sample("s1", path, observed_at="2026-08-21T20:05:00+00:00", total_input_tokens=42245,
                current_usage={"input_tokens": 2, "output_tokens": 6, "cache_creation_input_tokens": 42243, "cache_read_input_tokens": 0})
            post_compact = _claude_runtime_sample("s1", path, observed_at="2026-08-21T20:10:00+00:00", total_input_tokens=44865,
                current_usage={"input_tokens": 2, "output_tokens": 7, "cache_creation_input_tokens": 9196, "cache_read_input_tokens": 35667})
            for sample in (pre_compact, post_compact):
                row, _ = asa.resolve_claude_runtime_sample(store, sample)
                asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            # current reflects the latest observation, not pre+post summed together
            self.assertEqual(snap["current_context_input_tokens"], 44865)
            self.assertNotEqual(snap["current_context_input_tokens"], 42245 + 44865)
            store.close()

    def test_reset_file_session_evicts_runtime_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample); store.db.commit()
            self.assertEqual(store.db.execute("SELECT count(*) FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchone()[0], 1)
            row = store.db.execute("SELECT * FROM sessions WHERE session_id='s1'").fetchone()
            store.reset_file_session(row); store.db.commit()
            self.assertEqual(store.db.execute("SELECT count(*) FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchone()[0], 0)
            store.close()

    def test_ingest_claude_runtime_inbox_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            payload = json.dumps(_sample_statusline_payload(transcript_path=path)).encode()
            asa.claude_statusline_bridge_main(stdin=io.BytesIO(payload), state_dir=td)
            metrics = asa.ingest_claude_runtime_inbox(store, td)
            self.assertEqual(metrics, {"samples_read": 1, "resolved": 1, "unresolved": 0, "ambiguous": 0})
            self.assertEqual(store.db.execute("SELECT count(*) FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchone()[0], 1)
            store.close()

    def test_inbox_reader_rejects_untrusted_content_beyond_the_whitelist(self):
        """The inbox is written by a process this code invokes but does not fully
        control the input of; a tampered or regressed file must still be
        whitelist-revalidated, not trusted verbatim."""
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            receipt_ns = asa.time.time_ns()
            malicious = {"session_id": "s1", "transcript_path": path, "receipt_ns": receipt_ns, "prompt": "the user's secret prompt",
                         "tool_output": "leaked tool result", "total_input_tokens": "not-an-int",
                         "extra_unexpected_field": {"nested": "junk"}}
            # CR2-03: filename must correspond to the body receipt_ns exactly,
            # or the observation is rejected as tampered -- use the genuine
            # bridge filename shape so the whitelist-vs-tampering distinction
            # this test is actually about isn't masked by the (separate)
            # filename/body correspondence check.
            (inbox / asa._claude_runtime_inbox_filename("s1", receipt_ns)).write_text(json.dumps(malicious))
            metrics = asa.ingest_claude_runtime_inbox(store, td)  # must not raise
            self.assertEqual(metrics["resolved"], 1)
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertNotIn("prompt", str(snap)); self.assertNotIn("tool_output", str(snap)); self.assertNotIn("extra_unexpected_field", str(snap))
            self.assertIsNone(snap["current_context_input_tokens"])  # non-integer total_input_tokens is bounded away, not coerced
            store.close()

    def test_resolved_inbox_file_is_consumed(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            payload = json.dumps(_sample_statusline_payload(transcript_path=path)).encode()
            asa.claude_statusline_bridge_main(stdin=io.BytesIO(payload), state_dir=td)
            self.assertEqual(len(list((Path(td) / "claude-runtime").glob("*.json"))), 1)
            asa.ingest_claude_runtime_inbox(store, td)
            self.assertEqual(list((Path(td) / "claude-runtime").glob("*.json")), [])
            store.close()

    def test_reset_after_ingest_is_not_resurrected_by_stale_inbox_file(self):
        """Regression: a resolved sample must be removed from the inbox, or a
        session reset (which clears the service_meta snapshot) would see it
        silently reappear on the very next scan from the leftover file."""
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            payload = json.dumps(_sample_statusline_payload(transcript_path=path)).encode()
            asa.claude_statusline_bridge_main(stdin=io.BytesIO(payload), state_dir=td)
            asa.ingest_claude_runtime_inbox(store, td)
            self.assertEqual(store.db.execute("SELECT count(*) FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchone()[0], 1)
            row = store.db.execute("SELECT * FROM sessions WHERE session_id='s1'").fetchone()
            store.reset_file_session(row); store.db.commit()
            self.assertEqual(store.db.execute("SELECT count(*) FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchone()[0], 0)
            self._seed_session(store, "s1", path)  # transcript reappears with a fresh row
            asa.ingest_claude_runtime_inbox(store, td)  # must not resurrect from a leftover inbox file
            self.assertEqual(store.db.execute("SELECT count(*) FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchone()[0], 0)
            store.close()

    def test_unresolved_sample_is_retried_then_evicted_when_stale(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td)  # no matching session row yet
            payload = json.dumps(_sample_statusline_payload(transcript_path=path)).encode()
            asa.claude_statusline_bridge_main(stdin=io.BytesIO(payload), state_dir=td)
            metrics = asa.ingest_claude_runtime_inbox(store, td)
            self.assertEqual(metrics["unresolved"], 1)
            self.assertEqual(len(list((Path(td) / "claude-runtime").glob("*.json"))), 1)  # retried, not evicted yet
            stale_file = next((Path(td) / "claude-runtime").glob("*.json"))
            stale = json.loads(stale_file.read_text())
            # Staleness uses the TRUSTED receipt (body + filename), never the
            # untrusted observed_at claim -- mutate the receipt itself.
            old_receipt_ns = asa.time.time_ns() - int((asa.CLAUDE_RUNTIME_INBOX_UNRESOLVED_MAX_AGE_SECONDS + 60) * 1e9)
            stale["receipt_ns"] = old_receipt_ns
            renamed = stale_file.with_name(asa._claude_runtime_inbox_filename("s1", old_receipt_ns))
            stale_file.write_text(json.dumps(stale))
            stale_file.rename(renamed)
            metrics = asa.ingest_claude_runtime_inbox(store, td)
            self.assertEqual(metrics["unresolved"], 1)
            self.assertEqual(list((Path(td) / "claude-runtime").glob("*.json")), [])  # now evicted
            store.close()

    def test_future_dated_receipt_is_evicted_not_trusted_indefinitely(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            payload = json.dumps(_sample_statusline_payload(transcript_path=path)).encode()
            asa.claude_statusline_bridge_main(stdin=io.BytesIO(payload), state_dir=td)
            entry = next((Path(td) / "claude-runtime").glob("*.json"))
            future_ns = asa.time.time_ns() + int((asa.CLAUDE_RUNTIME_INBOX_MAX_FUTURE_SKEW_SECONDS + 3600) * 1e9)
            future_time = future_ns / 1e9
            os.utime(entry, (future_time, future_time))
            metrics = asa.ingest_claude_runtime_inbox(store, td)
            self.assertEqual(metrics["samples_read"], 0)  # quarantined before being counted as a sample
            self.assertEqual(list((Path(td) / "claude-runtime").glob("*.json")), [])
            store.close()

    def test_inbox_file_count_is_bounded_evicting_oldest_first(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td)
            base = asa.time.time_ns()
            for i in range(asa.CLAUDE_RUNTIME_INBOX_MAX_FILES + 10):
                receipt = base + i
                sample = {"session_id": f"s{i}", "transcript_path": str(Path(td) / f"s{i}.jsonl"), "receipt_ns": receipt}
                (inbox / asa._claude_runtime_inbox_filename(f"s{i}", receipt)).write_text(json.dumps(sample))
            samples = asa._read_claude_runtime_inbox(td)
            self.assertLessEqual(len(list(inbox.glob("*.json"))), asa.CLAUDE_RUNTIME_INBOX_MAX_FILES)
            # the newest (highest-i) entries must survive eviction, not the oldest
            surviving_ids = {s["session_id"] for _, s in samples}
            self.assertIn(f"s{asa.CLAUDE_RUNTIME_INBOX_MAX_FILES + 9}", surviving_ids)
            self.assertNotIn("s0", surviving_ids)
            store.close()

    def test_malformed_burst_with_high_receipt_prefixes_cannot_starve_valid_older_samples(self):
        # Regression: capping-by-count must happen AFTER malformed/junk entries
        # are quarantined, not before -- otherwise a burst of junk filenames
        # with high receipt prefixes occupies eviction-exempt slots and a
        # genuinely valid, real sample gets evicted purely by lexical bad luck.
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td)
            base = asa.time.time_ns()
            valid_receipt = base
            valid_sample = {"session_id": "svalid", "transcript_path": str(Path(td) / "svalid.jsonl"), "receipt_ns": valid_receipt}
            (inbox / asa._claude_runtime_inbox_filename("svalid", valid_receipt)).write_text(json.dumps(valid_sample))
            for i in range(asa.CLAUDE_RUNTIME_INBOX_MAX_FILES + 50):
                receipt = base + 1 + i  # all sort AFTER the valid sample
                (inbox / asa._claude_runtime_inbox_filename(f"junk{i}", receipt)).write_text("{not valid json")
            samples = asa._read_claude_runtime_inbox(td)
            surviving_ids = {s["session_id"] for _, s in samples}
            self.assertIn("svalid", surviving_ids)
            store.close()

    def test_symlinked_inbox_entry_is_never_followed(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            secret = Path(td) / "outside-secret.json"
            secret.write_text(json.dumps({"session_id": "s1", "transcript_path": str(Path(td) / "s1.jsonl"), "receipt_ns": asa.time.time_ns()}))
            link = inbox / asa._claude_runtime_inbox_filename("s1", asa.time.time_ns())
            os.symlink(secret, link)
            store = self._store(td)
            samples = asa._read_claude_runtime_inbox(td)
            self.assertEqual(samples, [])
            self.assertFalse(link.exists())  # quarantined, not followed
            self.assertTrue(secret.exists())  # the target itself is untouched
            store.close()

    def test_used_percentage_disagreement_beyond_tolerance_downgrades_occupancy(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            # counters are internally self-consistent (sum matches total_input_tokens)
            # but used_percentage disagrees with the true 90% occupancy by far more
            # than rounding tolerance -- this datum must be downgraded, not trusted.
            sample = _claude_runtime_sample("s1", path, context_window_size=1000000, total_input_tokens=900000,
                current_usage={"input_tokens": 2, "output_tokens": 7, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 899898},
                used_percentage=4)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertIsNone(snap["model_context_occupancy_pct"])
            self.assertEqual(snap["capability"]["model_context_occupancy_pct"], "UNAVAILABLE")
            store.close()


def _claude_runtime_sample(session_id, transcript_path, **overrides):
    total_input_tokens = overrides.get("total_input_tokens", 44865)
    # Keep current_usage internally consistent with total_input_tokens by default
    # (total_input_tokens == input_tokens + cache_creation_input_tokens +
    # cache_read_input_tokens), matching the empirical CLAUDE-RUNTIME-01 evidence
    # shape, unless the caller supplies its own current_usage to deliberately
    # test inconsistency.
    default_usage = {"input_tokens": 2, "output_tokens": 7, "cache_creation_input_tokens": 100, "cache_read_input_tokens": total_input_tokens - 102}
    window = overrides.get("context_window_size", 1000000)
    sample = {
        "format_version": 1, "session_id": session_id, "transcript_path": transcript_path,
        "claude_code_version": "2.1.239", "model_id": "claude-sonnet-5", "model_display_name": "Sonnet 5",
        "context_window_size": 1000000, "used_percentage": round(total_input_tokens / window * 100), "total_input_tokens": total_input_tokens, "total_output_tokens": 7,
        "current_usage": default_usage,
        "observed_at": asa._identity_now().isoformat(),
    }
    sample.update(overrides)
    if "current_usage" not in overrides and "total_input_tokens" in overrides:
        sample["current_usage"] = default_usage
    if "used_percentage" not in overrides and ("total_input_tokens" in overrides or "context_window_size" in overrides):
        sample["used_percentage"] = round(total_input_tokens / window * 100)
    return sample


class ClaudeRuntimeOccupancySemanticsTests(unittest.TestCase):
    """Post-Codex-review semantic corrections: occupancy numerator is
    total_input_tokens only (Claude Code's documented used_percentage
    definition explicitly excludes output_tokens), current_context_tokens was
    renamed to current_context_input_tokens to remove the ambiguity, and
    model_context_window_tokens is EXACT when directly and validly reported
    -- independent of claude_code_version -- since it is not derived from the
    historically problematic current-context counters. Derived occupancy
    fields must never exceed the weaker of their two operands."""
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))
    def _seed_session(self, store, session_id, path, role="MAIN"):
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, "claude", session_id, role, path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
        store.db.commit()

    def test_total_output_tokens_does_not_enter_occupancy_calculation(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path, total_output_tokens=999999)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertAlmostEqual(snap["model_context_occupancy_pct"], 44865 / 1000000)
            self.assertEqual(snap["reported_total_output_tokens"], 999999)
            store.close()

    def test_validated_empirical_fixture_occupancy_is_exactly_0_044865(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)  # 44865 / 1000000, total_output_tokens=7
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["current_context_input_tokens"], 44865)
            self.assertEqual(snap["model_context_occupancy_pct"], 0.044865)
            self.assertEqual(snap["capability"]["model_context_occupancy_pct"], "EXACT")
            store.close()

    def test_changing_output_tokens_alone_does_not_change_occupancy(self):
        with tempfile.TemporaryDirectory() as td:
            path1 = str(Path(td) / "s1.jsonl"); path2 = str(Path(td) / "s2.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path1); self._seed_session(store, "s2", path2)
            sample_a = _claude_runtime_sample("s1", path1, total_output_tokens=7)
            sample_b = _claude_runtime_sample("s2", path2, total_output_tokens=50000)
            row_a, _ = asa.resolve_claude_runtime_sample(store, sample_a)
            row_b, _ = asa.resolve_claude_runtime_sample(store, sample_b)
            asa.store_claude_runtime_sample(store, row_a, sample_a)
            asa.store_claude_runtime_sample(store, row_b, sample_b)
            store.db.commit()
            snap_a = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            snap_b = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s2"),)).fetchone()[0])
            self.assertEqual(snap_a["model_context_occupancy_pct"], snap_b["model_context_occupancy_pct"])
            store.close()

    def test_current_context_input_tokens_name_is_unambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertNotIn("current_context_tokens", snap)
            self.assertIn("current_context_input_tokens", snap)
            self.assertNotIn("current_context_tokens", snap["capability"])
            self.assertIn("current_context_input_tokens", snap["capability"])
            store.close()

    def test_directly_reported_valid_window_is_exact(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            # Deliberately unvalidated version -- window EXACT must not depend on it.
            sample = _claude_runtime_sample("s1", path, claude_code_version="9.9.9")
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["model_context_window_tokens"], 1000000)
            self.assertEqual(snap["capability"]["model_context_window_tokens"], "EXACT")
            store.close()

    def test_missing_invalid_window_is_unavailable(self):
        sample = {"session_id": "s1", "transcript_path": "/tmp/s1.jsonl", "claude_code_version": "2.1.239",
                   "model_id": "claude-sonnet-5", "context_window_size": None, "total_input_tokens": 44865,
                   "total_output_tokens": 7, "current_usage": {"input_tokens": 2, "output_tokens": 7, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 44763}}
        derived = asa._claude_runtime_derive(sample)
        cap = asa._claude_runtime_capability(derived)
        self.assertIsNone(derived["model_context_window_tokens"])
        self.assertEqual(cap["model_context_window_tokens"], "UNAVAILABLE")

    def test_no_model_name_fallback_creates_an_exact_window(self):
        derived = asa._claude_runtime_derive({"model_id": "claude-opus-5", "context_window_size": None, "current_usage": None, "total_input_tokens": None, "total_output_tokens": None, "claude_code_version": "2.1.239"})
        cap = asa._claude_runtime_capability(derived)
        self.assertIsNone(derived["model_context_window_tokens"])
        self.assertEqual(cap["model_context_window_tokens"], "UNAVAILABLE")

    def test_validated_current_input_plus_exact_window_is_exact_occupancy(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)  # validated version, complete/consistent usage
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["capability"]["current_context_input_tokens"], "EXACT")
            self.assertEqual(snap["capability"]["model_context_window_tokens"], "EXACT")
            self.assertEqual(snap["capability"]["model_context_occupancy_pct"], "EXACT")
            store.close()

    def test_unvalidated_observed_current_input_plus_exact_window_is_observed_occupancy(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path, claude_code_version="9.9.9")  # window still valid, version not validated
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["capability"]["current_context_input_tokens"], "UNAVAILABLE")  # never OBSERVED-labelled if value is None
            self.assertEqual(snap["capability"]["reported_total_input_tokens"], "OBSERVED")
            self.assertEqual(snap["capability"]["model_context_window_tokens"], "EXACT")
            self.assertEqual(snap["capability"]["reported_model_context_occupancy_pct"], "OBSERVED")
            store.close()

    def test_derived_capability_never_exceeds_weakest_operand(self):
        # EXACT window + UNAVAILABLE current-context-input (incomplete usage) -> occupancy UNAVAILABLE, not EXACT.
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path, current_usage=None)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["capability"]["model_context_window_tokens"], "EXACT")
            self.assertEqual(snap["capability"]["model_context_occupancy_pct"], "UNAVAILABLE")
            self.assertEqual(snap["capability"]["reported_model_context_occupancy_pct"], "UNAVAILABLE")
            store.close()


class ClaudeRuntimeVersionEvidenceTests(unittest.TestCase):
    """CR-01: EXACT must be gated on an explicitly, empirically validated
    Claude Code version -- never on internal self-consistency alone, and never
    via an open-ended '>= known-good' comparison (a later release can regress
    the semantics this feature depends on)."""
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))

    def _seed_session(self, store, session_id, path):
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, "claude", session_id, "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
        store.db.commit()

    def _snapshot(self, td, sample):
        store = self._store(td); path = sample["transcript_path"]; self._seed_session(store, sample["session_id"], path)
        row, _ = asa.resolve_claude_runtime_sample(store, sample)
        asa.store_claude_runtime_sample(store, row, sample)
        store.db.commit()
        snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key(sample["session_id"]),)).fetchone()[0])
        store.close()
        return snap

    def test_qualified_versions_with_complete_consistent_sample_are_exact(self):
        for version in ("2.1.239", "2.1.241"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as td:
                self.assertIn(version, asa.CLAUDE_RUNTIME_EXACT_VERSIONS)
                sample = _claude_runtime_sample("s1", str(Path(td) / "s1.jsonl"), claude_code_version=version)
                snap = self._snapshot(td, sample)
                self.assertEqual(snap["capability"]["current_context_input_tokens"], "EXACT")
                self.assertEqual(snap["capability"]["model_context_occupancy_pct"], "EXACT")
                self.assertIsNotNone(snap["current_context_input_tokens"])

    def test_2_1_240_is_not_qualified(self):
        self.assertNotIn("2.1.240", asa.CLAUDE_RUNTIME_EXACT_VERSIONS)
        self.assertNotIn("2.1.240", asa.CLAUDE_RUNTIME_ZERO_ONLY_UNAVAILABLE_VERSIONS)

    def test_arbitrary_future_version_same_values_is_observed_not_exact(self):
        with tempfile.TemporaryDirectory() as td:
            future_version = "99.99.99"
            self.assertNotIn(future_version, asa.CLAUDE_RUNTIME_EXACT_VERSIONS)
            sample = _claude_runtime_sample("s1", str(Path(td) / "s1.jsonl"), claude_code_version=future_version)
            snap = self._snapshot(td, sample)
            # the VALIDATED fields never reach EXACT for an unvalidated version...
            self.assertNotEqual(snap["capability"]["current_context_input_tokens"], "EXACT")
            self.assertNotEqual(snap["capability"]["model_context_occupancy_pct"], "EXACT")
            self.assertIsNone(snap["current_context_input_tokens"])
            # ...but the raw REPORTED fields are still retained, at OBSERVED,
            # never labelled as a validated current-context measurement.
            self.assertEqual(snap["capability"]["reported_total_input_tokens"], "OBSERVED")
            self.assertEqual(snap["capability"]["reported_model_context_occupancy_pct"], "OBSERVED")
            self.assertIsNotNone(snap["reported_total_input_tokens"])

    def test_historically_older_version_mutually_consistent_values_not_exact(self):
        with tempfile.TemporaryDirectory() as td:
            older_version = "2.0.0"
            self.assertNotIn(older_version, asa.CLAUDE_RUNTIME_EXACT_VERSIONS)
            # Perfectly self-consistent counters -- this is precisely the shape
            # that a naive "consistency implies correctness" policy would wrongly
            # promote. It must not, no matter how clean the arithmetic is.
            sample = _claude_runtime_sample("s1", str(Path(td) / "s1.jsonl"), claude_code_version=older_version)
            snap = self._snapshot(td, sample)
            self.assertNotEqual(snap["capability"]["current_context_input_tokens"], "EXACT")
            self.assertTrue(snap["counters_consistent"])  # arithmetic was fine
            self.assertFalse(snap["version_validated"])   # but the version wasn't

    def test_missing_version_is_not_exact(self):
        with tempfile.TemporaryDirectory() as td:
            sample = _claude_runtime_sample("s1", str(Path(td) / "s1.jsonl"), claude_code_version="")
            snap = self._snapshot(td, sample)
            self.assertNotEqual(snap["capability"]["current_context_input_tokens"], "EXACT")

    def test_malformed_version_is_not_exact(self):
        with tempfile.TemporaryDirectory() as td:
            sample = _claude_runtime_sample("s1", str(Path(td) / "s1.jsonl"), claude_code_version={"not": "a string"})
            snap = self._snapshot(td, sample)
            self.assertNotEqual(snap["capability"]["current_context_input_tokens"], "EXACT")

    def test_identity_fields_remain_exact_regardless_of_version(self):
        """session_id/transcript_path exactness does not depend on context-counter
        semantics, so an unvalidated version does not downgrade them."""
        with tempfile.TemporaryDirectory() as td:
            sample = _claude_runtime_sample("s1", str(Path(td) / "s1.jsonl"), claude_code_version="0.0.1-unknown")
            snap = self._snapshot(td, sample)
            self.assertEqual(snap["capability"]["session_id"], "EXACT")
            self.assertEqual(snap["capability"]["transcript_path"], "EXACT")

    def test_cumulative_bug_regression_is_not_circular(self):
        """Strengthened regression: proves EXACT depends on the explicit version
        policy, not merely on arithmetic self-consistency. A test that only
        checked total_input + output == sum(current_usage) would be circular --
        it proves arithmetic, not semantic current-context correctness. This
        constructs the SAME internally-consistent counter shape twice, varying
        only claude_code_version, and asserts the version is what decides EXACT."""
        with tempfile.TemporaryDirectory() as td_a, tempfile.TemporaryDirectory() as td_b:
            unvalidated = _claude_runtime_sample("s1", str(Path(td_a) / "s1.jsonl"), claude_code_version="1.0.0-hypothetical")
            validated = _claude_runtime_sample("s1", str(Path(td_b) / "s1.jsonl"), claude_code_version="2.1.239")
            snap_unvalidated = self._snapshot(td_a, unvalidated)
            snap_validated = self._snapshot(td_b, validated)
            # both samples are equally self-consistent arithmetically, and report
            # identically-shaped raw totals...
            self.assertTrue(snap_unvalidated["counters_consistent"])
            self.assertTrue(snap_validated["counters_consistent"])
            self.assertEqual(snap_unvalidated["reported_total_input_tokens"], snap_validated["reported_total_input_tokens"])
            # ...yet only the empirically validated version can reach a validated
            # current_context_input_tokens/EXACT; the unvalidated one is withheld
            # (None) rather than surfaced as if it were current-context truth.
            self.assertEqual(snap_validated["current_context_input_tokens"], 44865)
            self.assertEqual(snap_validated["capability"]["current_context_input_tokens"], "EXACT")
            self.assertIsNone(snap_unvalidated["current_context_input_tokens"])
            self.assertNotEqual(snap_unvalidated["capability"]["current_context_input_tokens"], "EXACT")

    def test_sanitized_historical_bug_shaped_fixture_cannot_acquire_exact_via_self_consistency_alone(self):
        """A self-consistent sample whose version is NOT in the validated set
        must never reach EXACT, regardless of how clean its arithmetic is --
        this is the general form of the historical cumulative-bug concern: an
        unvalidated provider version being trusted merely because its own
        numbers agree with each other."""
        with tempfile.TemporaryDirectory() as td:
            hypothetical_regressed_version = "3.0.0-regressed"
            sample = _claude_runtime_sample("s1", str(Path(td) / "s1.jsonl"), claude_code_version=hypothetical_regressed_version,
                total_input_tokens=44865, current_usage={"input_tokens": 2, "output_tokens": 7, "cache_creation_input_tokens": 9196, "cache_read_input_tokens": 35667})
            snap = self._snapshot(td, sample)
            self.assertTrue(snap["counters_consistent"])
            self.assertNotEqual(snap["capability"]["current_context_input_tokens"], "EXACT")
            self.assertEqual(snap["capability"]["current_context_input_tokens"], "UNAVAILABLE")
            self.assertEqual(snap["capability"]["reported_total_input_tokens"], "OBSERVED")


class ClaudeRuntimeNullUsageTests(unittest.TestCase):
    """CR-02: current_usage=null must never be promoted to EXACT, and must
    never be silently coerced into zero counters that look validated."""
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))

    def _seed_session(self, store, session_id, path):
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, "claude", session_id, "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
        store.db.commit()

    def test_end_to_end_ingest_with_null_current_usage_never_produces_exact(self):
        """End-to-end through the real bridge + inbox reader + ingest path, not
        just direct dict construction -- proves the whole pipeline preserves
        the null distinction, not only one function in isolation."""
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            payload = _sample_statusline_payload(transcript_path=path)
            payload["context_window"]["current_usage"] = None  # e.g. immediately after /compact
            bridge_payload = json.dumps(payload).encode()
            asa.claude_statusline_bridge_main(stdin=io.BytesIO(bridge_payload), state_dir=td)
            metrics = asa.ingest_claude_runtime_inbox(store, td)
            self.assertEqual(metrics["resolved"], 1)
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertIsNone(snap["current_context_input_tokens"])
            self.assertIsNone(snap["model_context_occupancy_pct"])
            self.assertEqual(snap["capability"]["current_context_input_tokens"], "UNAVAILABLE")
            self.assertEqual(snap["capability"]["model_context_occupancy_pct"], "UNAVAILABLE")
            self.assertFalse(snap["usage_complete"])
            store.close()

    def test_null_current_usage_does_not_fabricate_zero_counters(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path, current_usage=None)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertIsNone(snap["current_context_input_tokens"])  # never 0
            self.assertFalse(snap["counters_consistent"])
            store.close()

    def test_stale_exact_value_not_silently_shown_as_current_after_null_observation(self):
        """A prior validated observation followed by a null-usage observation
        must not leave the old EXACT value looking like the current one."""
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            first = _claude_runtime_sample("s1", path, total_input_tokens=44865)
            row, _ = asa.resolve_claude_runtime_sample(store, first)
            asa.store_claude_runtime_sample(store, row, first, receipt_ns=1000)
            store.db.commit()
            snap1 = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap1["current_context_input_tokens"], 44865)
            self.assertEqual(snap1["last_validated_at"], first["observed_at"])
            second = _claude_runtime_sample("s1", path, current_usage=None)
            row, _ = asa.resolve_claude_runtime_sample(store, second)
            asa.store_claude_runtime_sample(store, row, second, receipt_ns=2000)
            store.db.commit()
            snap2 = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            # the LATEST current_context_input_tokens must reflect the null observation, not the stale exact one
            self.assertIsNone(snap2["current_context_input_tokens"])
            self.assertEqual(snap2["capability"]["current_context_input_tokens"], "UNAVAILABLE")
            # the prior validated timestamp is preserved separately, distinctly labelled
            self.assertEqual(snap2["last_validated_at"], first["observed_at"])
            self.assertNotEqual(snap2.get("last_validated_at"), snap2.get("observed_at"))
            store.close()

    def test_post_compact_null_usage_recovers_on_first_complete_api_response(self):
        """Claude 2.1.239 emits null usage immediately after /compact, then
        restores a complete usage object with the first subsequent response.
        The transitional observation must remain unavailable without poisoning
        the stream's later EXACT promotion."""
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            post_compact = _sample_statusline_payload(transcript_path=path)
            post_compact["context_window"].update({
                "total_input_tokens": 0, "total_output_tokens": 0,
                "used_percentage": 0, "current_usage": None,
            })
            asa.claude_statusline_bridge_main(stdin=io.BytesIO(json.dumps(post_compact).encode()), state_dir=td)
            self.assertEqual(asa.ingest_claude_runtime_inbox(store, td)["resolved"], 1)
            null_snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertIsNone(null_snap["current_context_input_tokens"])
            self.assertIsNone(null_snap["model_context_occupancy_pct"])
            self.assertEqual(null_snap["capability"]["current_context_input_tokens"], "UNAVAILABLE")
            self.assertEqual(null_snap["capability"]["model_context_occupancy_pct"], "UNAVAILABLE")
            self.assertFalse(null_snap["usage_complete"])
            self.assertFalse(null_snap["counters_consistent"])
            self.assertIsNone(null_snap["last_validated_at"])
            self.assertEqual(null_snap["model_context_window_tokens"], 1000000)
            self.assertEqual(null_snap["capability"]["model_context_window_tokens"], "EXACT")

            first_response = _sample_statusline_payload(transcript_path=path)
            first_response["context_window"].update({
                "context_window_size": 1000000, "used_percentage": 5,
                "total_input_tokens": 46856, "total_output_tokens": 246,
                "current_usage": {
                    "input_tokens": 2, "output_tokens": 246,
                    "cache_creation_input_tokens": 46854, "cache_read_input_tokens": 0,
                },
            })
            asa.claude_statusline_bridge_main(stdin=io.BytesIO(json.dumps(first_response).encode()), state_dir=td)
            self.assertEqual(asa.ingest_claude_runtime_inbox(store, td)["resolved"], 1)
            recovered = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(recovered["current_context_input_tokens"], 46856)
            self.assertEqual(recovered["model_context_occupancy_pct"], 0.046856)
            self.assertEqual(recovered["capability"]["current_context_input_tokens"], "EXACT")
            self.assertEqual(recovered["capability"]["model_context_occupancy_pct"], "EXACT")
            self.assertEqual(recovered["reported_model_context_occupancy_pct"], 0.046856)
            self.assertNotEqual(recovered["model_context_occupancy_pct"], (46856 + 246) / 1000000)
            self.assertTrue(recovered["usage_complete"])
            self.assertTrue(recovered["counters_consistent"])
            self.assertIsNotNone(recovered["last_validated_at"])
            store.close()

    def test_zero_shape_classification_through_bridge_and_snapshot(self):
        """Keep the A-D diagnostic matrix for every qualified zero-only version."""
        zero_usage = {
            "input_tokens": 0, "output_tokens": 0,
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
        }
        variants = {
            "A": {"current_usage": zero_usage, "used_percentage": 0,
                  "total_output_tokens": 0,
                  "exact": False, "usage_complete": False, "counters_consistent": False,
                  "reported_input_cap": "UNAVAILABLE", "reported_occupancy_cap": "UNAVAILABLE"},
            "B": {"current_usage": zero_usage, "used_percentage": None,
                  "total_output_tokens": 0,
                  "exact": False, "usage_complete": True, "counters_consistent": True,
                  "reported_input_cap": "OBSERVED", "reported_occupancy_cap": "OBSERVED"},
            "C": {"current_usage": None, "used_percentage": 0,
                  "total_output_tokens": 0,
                  "exact": False, "usage_complete": False, "counters_consistent": False,
                  "reported_input_cap": "UNAVAILABLE", "reported_occupancy_cap": "UNAVAILABLE"},
            "D": {"current_usage": None, "used_percentage": None,
                  "total_output_tokens": 0,
                  "exact": False, "usage_complete": False, "counters_consistent": False,
                  "reported_input_cap": "UNAVAILABLE", "reported_occupancy_cap": "UNAVAILABLE"},
        }
        for version in ("2.1.239", "2.1.241"):
            for name, expected in variants.items():
                with self.subTest(version=version, variant=name), tempfile.TemporaryDirectory() as td:
                    path = str(Path(td) / "s1.jsonl")
                    store = self._store(td); self._seed_session(store, "s1", path)
                    payload = _sample_statusline_payload(transcript_path=path)
                    payload["version"] = version
                    payload["context_window"].update({
                        "total_input_tokens": 0, "total_output_tokens": expected["total_output_tokens"],
                        "used_percentage": expected["used_percentage"],
                        "current_usage": expected["current_usage"],
                    })
                    if name in {"C", "D"}:
                        del payload["context_window"]["current_usage"]
                    asa.claude_statusline_bridge_main(stdin=io.BytesIO(json.dumps(payload).encode()), state_dir=td)
                    self.assertEqual(asa.ingest_claude_runtime_inbox(store, td)["resolved"], 1)
                    snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
                    self.assertEqual(snap["reported_total_input_tokens"], 0)
                    self.assertEqual(snap["reported_total_output_tokens"], expected["total_output_tokens"])
                    self.assertEqual(snap["reported_model_context_occupancy_pct"], 0.0)
                    self.assertEqual(snap["current_context_input_tokens"], 0 if expected["exact"] else None)
                    self.assertEqual(snap["model_context_occupancy_pct"], 0.0 if expected["exact"] else None)
                    self.assertEqual(snap["usage_complete"], expected["usage_complete"])
                    self.assertEqual(snap["counters_consistent"], expected["counters_consistent"])
                    if expected["exact"]:
                        self.assertIsNotNone(snap["last_validated_at"])
                    else:
                        self.assertIsNone(snap["last_validated_at"])
                    self.assertEqual(snap["capability"]["current_context_input_tokens"], "EXACT" if expected["exact"] else "UNAVAILABLE")
                    self.assertEqual(snap["capability"]["model_context_occupancy_pct"], "EXACT" if expected["exact"] else "UNAVAILABLE")
                    self.assertEqual(snap["capability"]["reported_total_input_tokens"], expected["reported_input_cap"])
                    self.assertEqual(snap["capability"]["reported_model_context_occupancy_pct"], expected["reported_occupancy_cap"])
                    if name == "A":
                        self.assertIsNone(snap["peak_current_context_input_tokens"])
                        self.assertIsNone(snap["peak_model_context_occupancy_pct"])
                        self.assertEqual(snap["model_context_window_tokens"], 1000000)
                        self.assertEqual(snap["capability"]["model_context_window_tokens"], "EXACT")
                    store.close()

    def test_zero_only_transition_recovers_to_exact_for_qualified_versions(self):
        zero_usage = {
            "input_tokens": 0, "output_tokens": 0,
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
        }
        recoveries = {
            "2.1.239": (46856, 246, 5, {"input_tokens": 2, "output_tokens": 246,
                                         "cache_creation_input_tokens": 46854, "cache_read_input_tokens": 0}),
            "2.1.241": (41802, 13, 4, {"input_tokens": 2, "output_tokens": 13,
                                         "cache_creation_input_tokens": 41800, "cache_read_input_tokens": 0}),
        }
        for version, (input_total, output_total, used_percentage, current_usage) in recoveries.items():
            with self.subTest(version=version), tempfile.TemporaryDirectory() as td:
                path = str(Path(td) / "s1.jsonl")
                store = self._store(td); self._seed_session(store, "s1", path)
                transition = _claude_runtime_sample("s1", path, claude_code_version=version,
                    total_input_tokens=0, total_output_tokens=0, used_percentage=0, current_usage=zero_usage)
                row, _ = asa.resolve_claude_runtime_sample(store, transition)
                asa.store_claude_runtime_sample(store, row, transition, receipt_ns=1000)
                store.db.commit()
                transitional = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
                self.assertIsNone(transitional["current_context_input_tokens"])
                self.assertIsNone(transitional["model_context_occupancy_pct"])
                self.assertFalse(transitional["usage_complete"])
                self.assertFalse(transitional["counters_consistent"])
                self.assertEqual(transitional["capability"]["current_context_input_tokens"], "UNAVAILABLE")
                self.assertEqual(transitional["capability"]["model_context_occupancy_pct"], "UNAVAILABLE")
                recovery = _claude_runtime_sample("s1", path, claude_code_version=version,
                    total_input_tokens=input_total, total_output_tokens=output_total,
                    used_percentage=used_percentage, current_usage=current_usage)
                asa.store_claude_runtime_sample(store, row, recovery, receipt_ns=2000)
                store.db.commit()
                snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
                self.assertEqual(snap["current_context_input_tokens"], input_total)
                self.assertEqual(snap["model_context_occupancy_pct"], input_total / 1000000)
                self.assertEqual(snap["capability"]["current_context_input_tokens"], "EXACT")
                self.assertEqual(snap["capability"]["model_context_occupancy_pct"], "EXACT")
                self.assertTrue(snap["usage_complete"])
                self.assertTrue(snap["counters_consistent"])
                store.close()

    def test_zero_only_guard_does_not_reject_a_nonzero_usage_component(self):
        """The affected sentinel is all four usage components plus both
        totals at zero; a valid output-only response remains EXACT."""
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            payload = _sample_statusline_payload(transcript_path=path)
            payload["context_window"].update({
                "total_input_tokens": 0, "total_output_tokens": 1, "used_percentage": 0,
                "current_usage": {
                    "input_tokens": 0, "output_tokens": 1,
                    "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
                },
            })
            asa.claude_statusline_bridge_main(stdin=io.BytesIO(json.dumps(payload).encode()), state_dir=td)
            self.assertEqual(asa.ingest_claude_runtime_inbox(store, td)["resolved"], 1)
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["current_context_input_tokens"], 0)
            self.assertEqual(snap["model_context_occupancy_pct"], 0.0)
            self.assertTrue(snap["usage_complete"])
            self.assertTrue(snap["counters_consistent"])
            self.assertEqual(snap["capability"]["current_context_input_tokens"], "EXACT")
            self.assertEqual(snap["capability"]["model_context_occupancy_pct"], "EXACT")
            store.close()


class ClaudeRuntimeRegimeTests(unittest.TestCase):
    """CR-09: peaks must reset whenever EITHER model_id OR
    model_context_window_tokens changes -- a model change under the same
    window size is still a new telemetry regime, not a continuation."""
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))

    def _seed_session(self, store, session_id, path):
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, "claude", session_id, "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
        store.db.commit()

    def _run(self, td, samples):
        path = str(Path(td) / "s1.jsonl")
        store = self._store(td); self._seed_session(store, "s1", path)
        for i, sample in enumerate(samples):
            sample["transcript_path"] = path; sample["session_id"] = "s1"
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample, receipt_ns=1000 + i)
        store.db.commit()
        snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
        store.close()
        return snap

    def test_same_model_same_window_peak_continuity(self):
        with tempfile.TemporaryDirectory() as td:
            low = _claude_runtime_sample("s1", "x", model_id="claude-sonnet-5", context_window_size=1000000, total_input_tokens=10000)
            high = _claude_runtime_sample("s1", "x", model_id="claude-sonnet-5", context_window_size=1000000, total_input_tokens=90000)
            snap = self._run(td, [low, high])
            self.assertEqual(snap["peak_current_context_input_tokens"], 90000)
            self.assertEqual(snap["regime"], ["claude-sonnet-5", 1000000])

    def test_same_model_new_window_resets_regime(self):
        with tempfile.TemporaryDirectory() as td:
            first = _claude_runtime_sample("s1", "x", model_id="claude-sonnet-5", context_window_size=1000000, total_input_tokens=900000)
            second = _claude_runtime_sample("s1", "x", model_id="claude-sonnet-5", context_window_size=200000, total_input_tokens=10000)
            snap = self._run(td, [first, second])
            self.assertEqual(snap["regime"], ["claude-sonnet-5", 200000])
            self.assertAlmostEqual(snap["peak_model_context_occupancy_pct"], 0.05)  # not the old 0.9

    def test_new_model_same_window_resets_regime(self):
        """A model change under the SAME window is still a new regime -- two
        different models both happening to report a 1M window must not have
        their peaks merged just because the denominator numbers match."""
        with tempfile.TemporaryDirectory() as td:
            first = _claude_runtime_sample("s1", "x", model_id="claude-sonnet-5", context_window_size=1000000, total_input_tokens=900000)
            second = _claude_runtime_sample("s1", "x", model_id="claude-opus-5", context_window_size=1000000, total_input_tokens=10000)
            snap = self._run(td, [first, second])
            self.assertEqual(snap["regime"], ["claude-opus-5", 1000000])
            self.assertAlmostEqual(snap["peak_model_context_occupancy_pct"], 0.01)  # not the old 0.9

    def test_new_model_new_window_resets_regime(self):
        with tempfile.TemporaryDirectory() as td:
            first = _claude_runtime_sample("s1", "x", model_id="claude-sonnet-5", context_window_size=1000000, total_input_tokens=900000)
            second = _claude_runtime_sample("s1", "x", model_id="claude-opus-5", context_window_size=200000, total_input_tokens=10000)
            snap = self._run(td, [first, second])
            self.assertEqual(snap["regime"], ["claude-opus-5", 200000])
            self.assertAlmostEqual(snap["peak_model_context_occupancy_pct"], 0.05)

    def test_regime_change_mid_batch_applies_at_correct_point(self):
        """CR-07 x CR-09: processing the whole ordered batch (not just the
        newest sample) means a regime change occurring mid-batch is applied
        at the right point in the sequence."""
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            s1 = _claude_runtime_sample("s1", path, model_id="claude-sonnet-5", context_window_size=1000000, total_input_tokens=900000)
            s2 = _claude_runtime_sample("s1", path, model_id="claude-opus-5", context_window_size=1000000, total_input_tokens=5000)  # regime change here
            s3 = _claude_runtime_sample("s1", path, model_id="claude-opus-5", context_window_size=1000000, total_input_tokens=50000)
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            for i, sample in enumerate([s1, s2, s3]):
                sample["receipt_ns"] = 1000 + i
                (inbox / asa._claude_runtime_inbox_filename("s1", sample["receipt_ns"])).write_text(json.dumps(sample))
            asa.ingest_claude_runtime_inbox(store, td)
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            store.close()
            self.assertEqual(snap["regime"], ["claude-opus-5", 1000000])
            self.assertEqual(snap["peak_current_context_input_tokens"], 50000)  # peak only within the opus regime (s2, s3), not s1's 900000


class ClaudeRuntimeMalformedStateTests(unittest.TestCase):
    """CR-04: no malformed claude_runtime:* service_meta value may crash
    ingestion, status, reset, or a normal daemon tick."""
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))

    def _seed_session(self, store, session_id, path):
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, "claude", session_id, "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
        store.db.commit()

    def test_truncated_json_does_not_crash_parser(self):
        self.assertEqual(asa._parse_claude_runtime_snapshot('{"stream_id": "s1", "format_v'), {})

    def test_wrong_type_does_not_crash_parser(self):
        self.assertEqual(asa._parse_claude_runtime_snapshot(json.dumps(["not", "an", "object"])), {})

    def test_wrong_format_version_does_not_crash_parser(self):
        self.assertEqual(asa._parse_claude_runtime_snapshot(json.dumps({"format_version": 999, "stream_id": "s1"})), {})

    def test_missing_required_field_does_not_crash_parser(self):
        self.assertEqual(asa._parse_claude_runtime_snapshot(json.dumps({"format_version": asa.CLAUDE_RUNTIME_FORMAT_VERSION})), {})

    def test_none_value_does_not_crash_parser(self):
        self.assertEqual(asa._parse_claude_runtime_snapshot(None), {})

    def test_ingest_over_malformed_existing_row_replaces_it_safely(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            store.db.execute("INSERT INTO service_meta(key,value) VALUES(?,?)", (asa._claude_runtime_meta_key("s1"), "{not valid json"))
            store.db.commit()
            sample = _claude_runtime_sample("s1", path)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)  # must not raise
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            # The point of this test is that malformed prior state didn't block
            # the merge -- not the specific numeric value, which depends on the
            # fixture's Claude version being in the validated set.
            self.assertTrue(snap["usage_complete"])
            self.assertTrue(snap["version_validated"])
            self.assertIsNotNone(snap["current_context_input_tokens"])
            store.close()

    def test_runtime_status_cli_does_not_crash_on_malformed_row(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td)
            store.db.execute("INSERT INTO service_meta(key,value) VALUES(?,?)", (asa._claude_runtime_meta_key("s1"), "{not valid json"))
            store.db.commit(); store.close()
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = asa.main(["runtime", "status", "--state-dir", str(Path(td) / "state")])
            self.assertEqual(rc, 0)
            payload = json.loads(out.getvalue())
            self.assertEqual(len(payload), 1)
            self.assertEqual(payload[0]["status"], "INVALID")

    def test_reset_file_session_does_not_parse_and_is_safe_over_malformed_row(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = self._store(td); self._seed_session(store, "s1", path)
            store.db.execute("INSERT INTO service_meta(key,value) VALUES(?,?)", (asa._claude_runtime_meta_key("s1"), "{not valid json"))
            store.db.commit()
            row = store.db.execute("SELECT * FROM sessions WHERE session_id='s1'").fetchone()
            store.reset_file_session(row)  # must not raise
            store.db.commit()
            self.assertEqual(store.db.execute("SELECT count(*) FROM service_meta WHERE key LIKE 'claude_runtime:%'").fetchone()[0], 0)
            store.close()


class ClaudeCapabilityTests(unittest.TestCase):
    def test_historical_claude_session_context_peak_pct_stays_unavailable(self):
        self.assertEqual(asa.calibration_metric_capability("claude", "context_peak_pct"), asa.ProviderCapability.UNAVAILABLE)

    def test_claude_calibration_capability_not_globally_promoted(self):
        # Runtime evidence acquisition must not change the static, provider-level
        # calibration capability registry -- that remains a later, separate integration.
        self.assertEqual(asa.calibration_metric_capability("claude", "context_peak_pct"), asa.ProviderCapability.UNAVAILABLE)
        self.assertEqual(asa.signal_capability("SESSION_CONTEXT_OCCUPANCY", "claude"), asa.ProviderCapability.PROXY)


class ClaudeStatuslineInstallerTests(unittest.TestCase):
    def _preimage(self, home): return home / ".agentopsy-integration.settings-preimage"
    def _ownership(self, home): return home / ".agentopsy-integration.json"

    def test_no_existing_statusline_installs_transactionally(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); home.mkdir(exist_ok=True); (home / "settings.json").write_text("{}\n")
            status = asa.claude_integration_install(home, None)
            self.assertTrue(status["agentopsy_statusline_installed"])
            payload = json.loads((home / "settings.json").read_text())
            self.assertIn("runtime bridge claude", payload["statusLine"]["command"])

    def test_reinstall_over_owned_statusline_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            first = asa.claude_integration_install(home, None)
            before = (home / "settings.json").read_text()
            second = asa.claude_integration_install(home, None)
            after = (home / "settings.json").read_text()
            self.assertEqual(before, after)
            self.assertTrue(first["agentopsy_statusline_installed"] and second["agentopsy_statusline_installed"])

    def test_reinstall_with_changed_state_dir_refreshes_ownership_hash(self):
        # Regression: an owned reinstall that changes the command (e.g. a
        # different --state-dir) must publish a fresh installed_command_sha256
        # for the NEW command, or ownership verification immediately considers
        # the just-installed statusLine foreign and orphans it.
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            asa.claude_integration_install(home, "/tmp/state-a")
            status_a = asa.claude_integration_status(home)
            self.assertTrue(status_a["agentopsy_statusline_installed"])
            asa.claude_integration_install(home, "/tmp/state-b")
            status_b = asa.claude_integration_status(home)
            self.assertTrue(status_b["agentopsy_statusline_installed"])
            self.assertFalse(status_b.get("foreign_statusline_present", False))
            removed = asa.claude_integration_remove(home)
            self.assertFalse(removed["agentopsy_statusline_installed"])

    def test_foreign_statusline_refused_with_zero_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            original = json.dumps({"statusLine": {"type": "command", "command": "/usr/bin/my-foreign-probe.py"}})
            (home / "settings.json").write_text(original)
            with self.assertRaises(ValueError):
                asa.claude_integration_install(home, None)
            self.assertEqual((home / "settings.json").read_text(), original)
            self.assertFalse((home / ".agentopsy-integration.json").exists())

    def test_remove_only_agentopsy_owned_and_restores_prior_absence(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            asa.claude_integration_install(home, None)
            removed = asa.claude_integration_remove(home)
            self.assertFalse(removed["agentopsy_statusline_installed"])
            payload = json.loads((home / "settings.json").read_text())
            self.assertNotIn("statusLine", payload)
            self.assertFalse(self._ownership(home).exists())
            self.assertFalse(self._preimage(home).exists())

    def test_remove_restores_prior_foreign_value_if_we_had_wrapped_none(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text(json.dumps({"other": "kept"}))
            asa.claude_integration_install(home, None)
            removed = asa.claude_integration_remove(home)
            payload = json.loads((home / "settings.json").read_text())
            self.assertEqual(payload.get("other"), "kept")
            self.assertNotIn("statusLine", payload)

    def test_external_edit_after_install_is_detected_and_refused(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            asa.claude_integration_install(home, None)
            payload = json.loads((home / "settings.json").read_text())
            payload["statusLine"]["command"] = "/usr/bin/someone-else-edited-this.py"
            edited = json.dumps(payload)
            (home / "settings.json").write_text(edited)
            with self.assertRaises(ValueError):
                asa.claude_integration_remove(home)
            self.assertEqual((home / "settings.json").read_text(), edited)

    def test_malformed_settings_fails_before_any_write(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); before = "{not json"
            (home / "settings.json").write_text(before)
            with self.assertRaises(ValueError):
                asa.claude_integration_install(home, None)
            self.assertEqual((home / "settings.json").read_text(), before)
            self.assertFalse((home / ".agentopsy-integration.json").exists())

    def test_exact_codex_spoof_command_containing_marker_text_is_not_overwritten(self):
        """CR-05: ownership must never be substring-based. A foreign command that
        happens to CONTAIN the text 'runtime bridge claude' (e.g. as a --label
        argument) must still be treated as foreign, because no ownership
        metadata backs it."""
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            spoof_command = '/usr/bin/foreign --label "runtime bridge claude"'
            original = json.dumps({"statusLine": {"type": "command", "command": spoof_command}})
            (home / "settings.json").write_text(original)
            status = asa.claude_integration_status(home)
            self.assertFalse(status["agentopsy_statusline_installed"])
            self.assertTrue(status["foreign_statusline_present"])
            with self.assertRaises(ValueError):
                asa.claude_integration_install(home, None)
            self.assertEqual((home / "settings.json").read_text(), original)
            self.assertFalse((home / ".agentopsy-integration.json").exists())

    def test_ownership_file_alone_without_matching_hash_is_not_sufficient(self):
        """A stray/stale ownership file whose hash does not match the CURRENT
        settings value must not grant ownership -- all three facts must agree."""
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            foreign_command = "/usr/bin/genuinely-foreign-tool"
            (home / "settings.json").write_text(json.dumps({"statusLine": {"type": "command", "command": foreign_command}}))
            stale_ownership = {"version": 1, "statusline": {"owned": True, "previous": None, "installed_command_sha256": "0" * 64}}
            (home / ".agentopsy-integration.json").write_text(json.dumps(stale_ownership))
            status = asa.claude_integration_status(home)
            self.assertFalse(status["agentopsy_statusline_installed"])
            with self.assertRaises(ValueError):
                asa.claude_integration_install(home, None)

    def test_install_fault_after_settings_write_restores_settings_exactly(self):
        """CR-06: inject a failure between the settings write and the ownership
        publish. Settings must be restored byte-for-byte to their prior state,
        and no ownership/pre-image file must be left behind."""
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); before = json.dumps({"kept": "value"})
            (home / "settings.json").write_text(before)
            original_atomic_write = asa._atomic_write_text
            call_count = {"n": 0}
            def faulty_write(path, text, mode=None):
                call_count["n"] += 1
                if call_count["n"] == 3:  # the ownership sidecar's publish (after settings, pre-image)
                    raise OSError("simulated crash between settings and ownership writes")
                return original_atomic_write(path, text, mode=mode)
            asa._atomic_write_text = faulty_write
            try:
                with self.assertRaises(OSError):
                    asa.claude_integration_install(home, None)
            finally:
                asa._atomic_write_text = original_atomic_write
            self.assertEqual((home / "settings.json").read_text(), before)
            self.assertFalse(self._ownership(home).exists())
            self.assertFalse(self._preimage(home).exists())

    def test_rollback_failure_is_raised_loudly_not_swallowed(self):
        """CR-06: if the automatic rollback of settings.json itself fails (e.g.
        disk full -- plausibly the same condition that broke the original
        publish), that must never be silently swallowed. A silent swallow would
        leave settings.json holding the NEW content while ownership was never
        published: a half-installed state with no signal to the caller."""
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); before = json.dumps({"kept": "value"})
            (home / "settings.json").write_text(before)
            original_atomic_write = asa._atomic_write_text
            call_count = {"n": 0}
            def faulty_write(path, text, mode=None):
                call_count["n"] += 1
                if call_count["n"] == 3:  # ownership publish (after settings, pre-image)
                    raise OSError("simulated crash on ownership publish")
                if call_count["n"] == 4:  # rollback of settings
                    raise OSError("simulated crash during rollback of settings")
                return original_atomic_write(path, text, mode=mode)
            asa._atomic_write_text = faulty_write
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    asa.claude_integration_install(home, None)
                self.assertIn(str(home / "settings.json"), str(ctx.exception))
                self.assertIsInstance(ctx.exception.__cause__, OSError)
            finally:
                asa._atomic_write_text = original_atomic_write

    def test_install_fault_before_any_write_leaves_both_files_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); before = json.dumps({"kept": "value"})
            (home / "settings.json").write_text(before)
            original_atomic_write = asa._atomic_write_text
            def always_fail(path, text, mode=None):
                raise OSError("simulated crash on first write")
            asa._atomic_write_text = always_fail
            try:
                with self.assertRaises(OSError):
                    asa.claude_integration_install(home, None)
            finally:
                asa._atomic_write_text = original_atomic_write
            self.assertEqual((home / "settings.json").read_text(), before)
            self.assertFalse(self._ownership(home).exists())
            self.assertFalse(self._preimage(home).exists())

    def test_remove_fault_after_settings_write_restores_both_files(self):
        """CR-06: inject a failure during remove, after settings is rewritten but
        before the ownership file is deleted. Both artifacts must end in their
        ORIGINAL (pre-remove, i.e. installed) state -- not partially removed."""
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            asa.claude_integration_install(home, None)
            installed_settings = (home / "settings.json").read_text()
            installed_ownership = (home / ".agentopsy-integration.json").read_text()
            ownership_path = home / ".agentopsy-integration.json"
            original_unlink = Path.unlink
            def faulty_unlink(self, *a, **k):
                if self == ownership_path:
                    raise OSError("simulated crash deleting the ownership sidecar")
                return original_unlink(self, *a, **k)
            Path.unlink = faulty_unlink
            try:
                with self.assertRaises(OSError):
                    asa.claude_integration_remove(home)
            finally:
                Path.unlink = original_unlink
            self.assertEqual((home / "settings.json").read_text(), installed_settings)
            self.assertTrue((home / ".agentopsy-integration.json").exists())
            self.assertEqual((home / ".agentopsy-integration.json").read_text(), installed_ownership)

    def test_install_preserves_settings_file_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); settings = home / "settings.json"; settings.write_text("{}\n")
            os.chmod(settings, 0o600)
            asa.claude_integration_install(home, None)
            self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o600)

    def test_install_preserves_other_settings_keys(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text(json.dumps({"model": "sonnet", "permissions": {"defaultMode": "auto"}}))
            asa.claude_integration_install(home, None)
            payload = json.loads((home / "settings.json").read_text())
            self.assertEqual(payload["model"], "sonnet")
            self.assertEqual(payload["permissions"]["defaultMode"], "auto")

    def test_cli_integration_status_install_remove_claude(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = asa.main(["integration", "status", "claude", "--claude-home", str(home)])
            self.assertEqual(rc, 0)
            self.assertFalse(json.loads(out.getvalue())["agentopsy_statusline_installed"])
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = asa.main(["integration", "install", "claude", "--claude-home", str(home)])
            self.assertEqual(rc, 0)
            self.assertTrue(json.loads(out.getvalue())["agentopsy_statusline_installed"])
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = asa.main(["integration", "remove", "claude", "--claude-home", str(home)])
            self.assertEqual(rc, 0)
            self.assertFalse(json.loads(out.getvalue())["agentopsy_statusline_installed"])

    # --- CR2-04: byte-exact installer restoration ---

    def test_A_oddly_formatted_original_settings_restored_byte_exact_after_reinstall(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            original = '{"other":{"z":1},"spaced" : [ 1,2 ]}'
            (home / "settings.json").write_text(original)
            asa.claude_integration_install(home, "/tmp/state-a")
            asa.claude_integration_install(home, "/tmp/state-b")
            asa.claude_integration_remove(home)
            self.assertEqual((home / "settings.json").read_text(), original)

    def test_B_byte_exact_restoration_with_non_default_mode(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            original = '{"other":{"z":1},"spaced" : [ 1,2 ]}'
            settings = home / "settings.json"; settings.write_text(original)
            os.chmod(settings, 0o640)
            asa.claude_integration_install(home, "/tmp/state-a")
            asa.claude_integration_install(home, "/tmp/state-b")
            asa.claude_integration_remove(home)
            self.assertEqual(settings.read_text(), original)
            self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o640)

    def test_C_absent_original_stays_absent_after_install_reinstall_remove(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)  # no settings.json at all
            asa.claude_integration_install(home, "/tmp/state-a")
            asa.claude_integration_install(home, "/tmp/state-b")
            asa.claude_integration_remove(home)
            self.assertFalse((home / "settings.json").exists())
            self.assertFalse(self._ownership(home).exists())
            self.assertFalse(self._preimage(home).exists())

    def test_D_external_edit_to_unrelated_key_refuses_removal_and_preserves_edit(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"other": "original"}')
            asa.claude_integration_install(home, None)
            payload = json.loads((home / "settings.json").read_text())
            payload["other"] = "edited-by-someone-else"
            edited = json.dumps(payload)
            (home / "settings.json").write_text(edited)
            with self.assertRaises(ValueError):
                asa.claude_integration_remove(home)
            self.assertEqual((home / "settings.json").read_text(), edited)
            self.assertTrue(self._ownership(home).exists())

    def test_E_external_formatting_only_change_refuses_removal(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"other": "original"}')
            asa.claude_integration_install(home, None)
            payload = json.loads((home / "settings.json").read_text())
            reformatted = json.dumps(payload, indent=4)  # semantically identical, byte-different
            self.assertNotEqual(reformatted, (home / "settings.json").read_text())
            (home / "settings.json").write_text(reformatted)
            with self.assertRaises(ValueError):
                asa.claude_integration_remove(home)
            self.assertEqual((home / "settings.json").read_text(), reformatted)

    def test_F_reinstall_preserves_the_first_original_backup(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            original = json.dumps({"marker": "the-very-first-original"})
            (home / "settings.json").write_text(original)
            asa.claude_integration_install(home, "/tmp/state-a")
            first_ownership = json.loads(self._ownership(home).read_text())
            asa.claude_integration_install(home, "/tmp/state-b")
            second_ownership = json.loads(self._ownership(home).read_text())
            self.assertEqual(first_ownership["statusline"]["original_sha256"], second_ownership["statusline"]["original_sha256"])
            self.assertEqual(first_ownership["statusline"]["pre_image_ref"], second_ownership["statusline"]["pre_image_ref"])
            self.assertEqual(self._preimage(home).read_text(), original)
            asa.claude_integration_remove(home)
            self.assertEqual((home / "settings.json").read_text(), original)

    def test_G_private_backup_mode_is_0600(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"k": "v"}')
            asa.claude_integration_install(home, None)
            self.assertEqual(stat.S_IMODE(self._preimage(home).stat().st_mode), 0o600)

    def test_H_ownership_mode_is_0600(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"k": "v"}')
            asa.claude_integration_install(home, None)
            self.assertEqual(stat.S_IMODE(self._ownership(home).stat().st_mode), 0o600)

    def test_H_ownership_mode_is_0600_even_when_settings_absent(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            asa.claude_integration_install(home, None)
            self.assertEqual(stat.S_IMODE(self._ownership(home).stat().st_mode), 0o600)

    def test_I_fault_during_preimage_publication_leaves_nothing_behind(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); before = json.dumps({"kept": "value"})
            (home / "settings.json").write_text(before)
            original_atomic_write = asa._atomic_write_text
            call_count = {"n": 0}
            def faulty_write(path, text, mode=None):
                call_count["n"] += 1
                if call_count["n"] == 2:  # the pre-image publish (after settings)
                    raise OSError("simulated crash during pre-image write")
                return original_atomic_write(path, text, mode=mode)
            asa._atomic_write_text = faulty_write
            try:
                with self.assertRaises(OSError):
                    asa.claude_integration_install(home, None)
            finally:
                asa._atomic_write_text = original_atomic_write
            self.assertEqual((home / "settings.json").read_text(), before)
            self.assertFalse(self._ownership(home).exists())
            self.assertFalse(self._preimage(home).exists())

    def test_I_fault_during_remove_restoration_of_settings_fails_loudly(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); before = json.dumps({"kept": "value"})
            (home / "settings.json").write_text(before)
            asa.claude_integration_install(home, None)
            original_atomic_write = asa._atomic_write_text
            def always_fail(path, text, mode=None):
                raise OSError("simulated crash restoring settings.json")
            asa._atomic_write_text = always_fail
            try:
                # The settings artifact is first in publish order, so this
                # fails before anything is published and there is nothing to
                # roll back -- the raw OSError propagates unwrapped. Pinned
                # to OSError specifically (not a broad Exception) so a
                # signature mismatch in the monkeypatch (which would raise
                # TypeError instead) cannot silently pass this assertion.
                with self.assertRaises(OSError):
                    asa.claude_integration_remove(home)
            finally:
                asa._atomic_write_text = original_atomic_write
            # Recovery material (pre-image/ownership) must still exist -- never
            # silently claim success or destroy the only restoration source.
            self.assertTrue(self._preimage(home).exists())

    def test_missing_preimage_refuses_removal_rather_than_silently_succeeding(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"k": "v"}')
            asa.claude_integration_install(home, None)
            self._preimage(home).unlink()  # simulate lost/corrupted recovery material
            with self.assertRaises(ValueError):
                asa.claude_integration_remove(home)

    def test_tampered_preimage_fails_integrity_check_and_refuses_removal(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"k": "v"}')
            asa.claude_integration_install(home, None)
            self._preimage(home).write_text('{"k": "TAMPERED"}')
            with self.assertRaises(ValueError):
                asa.claude_integration_remove(home)

    def test_original_settings_bytes_never_appear_in_status_output(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            secret_marker = "super-secret-env-value-xyz123"
            (home / "settings.json").write_text(json.dumps({"env": {"SECRET": secret_marker}}))
            asa.claude_integration_install(home, None)
            status = asa.claude_integration_status(home)
            self.assertNotIn(secret_marker, json.dumps(status))

    # --- CR3-05: symlinked config paths must be rejected before mutation ---

    def test_symlinked_settings_refuses_install_target_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            real_target = home.parent / "real-settings-target.json"
            real_target.write_text('{"real": "content"}')
            os.symlink(real_target, home / "settings.json")
            with self.assertRaises(ValueError):
                asa.claude_integration_install(home, None)
            self.assertTrue((home / "settings.json").is_symlink())
            self.assertEqual(real_target.read_text(), '{"real": "content"}')
            self.assertFalse(self._ownership(home).exists())

    def test_symlinked_ownership_sidecar_refuses_install(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            real_target = home.parent / "real-ownership-target.json"
            real_target.write_text('{"fake": "ownership"}')
            os.symlink(real_target, self._ownership(home))
            with self.assertRaises(ValueError):
                asa.claude_integration_install(home, None)
            self.assertTrue(self._ownership(home).is_symlink())
            self.assertEqual(real_target.read_text(), '{"fake": "ownership"}')

    def test_symlinked_preimage_refuses_install(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            real_target = home.parent / "real-preimage-target"
            real_target.write_text("fake preimage")
            os.symlink(real_target, self._preimage(home))
            with self.assertRaises(ValueError):
                asa.claude_integration_install(home, None)
            self.assertTrue(self._preimage(home).is_symlink())
            self.assertEqual(real_target.read_text(), "fake preimage")

    def test_symlinked_settings_refuses_remove(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            asa.claude_integration_install(home, None)
            real_target = home.parent / "real-settings-target-2.json"
            real_target.write_text((home / "settings.json").read_text())
            (home / "settings.json").unlink()
            os.symlink(real_target, home / "settings.json")
            with self.assertRaises(ValueError):
                asa.claude_integration_remove(home)
            self.assertTrue((home / "settings.json").is_symlink())

    def test_symlink_conflict_reported_by_status(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            real_target = home.parent / "real-settings-target-3.json"
            real_target.write_text("{}")
            os.symlink(real_target, home / "settings.json")
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "SYMLINK_CONFLICT")
            self.assertFalse(status["owned"])

    # --- CR3-06: no redundant plaintext timestamped settings backups ---

    def test_no_legacy_backup_after_install_reinstall_remove_lifecycle(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            (home / "settings.json").write_text('{"other":{"z":1},"spaced" : [ 1,2 ]}')
            asa.claude_integration_install(home, "/tmp/state-a")
            asa.claude_integration_install(home, "/tmp/state-b")
            asa.claude_integration_remove(home)
            leftovers = list(home.glob("settings.json.agentopsy-backup-*"))
            self.assertEqual(leftovers, [])
            self.assertEqual(sorted(p.name for p in home.iterdir()), ["settings.json"])

    def test_no_legacy_backup_after_install_only(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"a": 1}')
            asa.claude_integration_install(home, None)
            self.assertEqual(list(home.glob("settings.json.agentopsy-backup-*")), [])
            self.assertEqual(list(home.glob(".agentopsy-integration.json.agentopsy-backup-*")), [])

    def test_fault_recovery_still_retains_private_preimage_not_legacy_backup(self):
        # Fault recovery must still work via the private pre-image; it must
        # NOT rely on (or produce) a legacy _backup_file copy to do so. Fault
        # injected on the SECOND artifact publish (ownership removal, after
        # settings restoration succeeds) so the settings rollback path itself
        # is exercised (which is where a legacy backup would previously have
        # been created).
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); before = json.dumps({"kept": "value"})
            (home / "settings.json").write_text(before)
            asa.claude_integration_install(home, None)
            original_atomic_write = asa._atomic_write_text
            call_count = [0]
            def faulty_write(path, text, mode=None):
                call_count[0] += 1
                raise OSError("simulated crash restoring settings.json")
            asa._atomic_write_text = faulty_write
            try:
                with self.assertRaises(OSError):
                    asa.claude_integration_remove(home)
            finally:
                asa._atomic_write_text = original_atomic_write
            self.assertTrue(self._preimage(home).exists())
            self.assertEqual(list(home.glob("settings.json.agentopsy-backup-*")), [])

    # --- CR3-07: status must report recovery/conflict states truthfully ---

    def test_status_owned_ok_after_clean_install(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            asa.claude_integration_install(home, None)
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "OWNED_OK")

    def test_status_owned_ok_after_install_with_no_prior_settings_file(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)  # no settings.json written -- original_existed=False path
            asa.claude_integration_install(home, None)
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "OWNED_OK")

    def test_status_not_installed_when_absent(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "NOT_INSTALLED")

    def test_status_foreign_when_unowned_statusline_present(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            (home / "settings.json").write_text(json.dumps({"statusLine": {"type": "command", "command": "/usr/bin/foreign"}}))
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "FOREIGN")

    def test_status_preimage_missing_after_deletion_does_not_report_healthy(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"k": "v"}')
            asa.claude_integration_install(home, None)
            self._preimage(home).unlink()
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "PREIMAGE_MISSING")
            self.assertNotEqual(status["state"], "OWNED_OK")
            with self.assertRaises(ValueError):
                asa.claude_integration_remove(home)  # removal must still refuse

    def test_status_preimage_corrupt_after_tampering_does_not_report_healthy(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"k": "v"}')
            asa.claude_integration_install(home, None)
            self._preimage(home).write_text('{"k": "TAMPERED"}')
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "PREIMAGE_CORRUPT")
            with self.assertRaises(ValueError):
                asa.claude_integration_remove(home)

    def test_status_settings_missing_while_owned_after_external_deletion(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text('{"k": "v"}')
            asa.claude_integration_install(home, None)
            (home / "settings.json").unlink()
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "SETTINGS_MISSING_WHILE_OWNED")

    def test_status_external_edit_conflict_after_settings_change(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            asa.claude_integration_install(home, None)
            data = json.loads((home / "settings.json").read_text())
            data["externallyAdded"] = True
            (home / "settings.json").write_text(json.dumps(data))
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "EXTERNAL_EDIT_CONFLICT")

    def test_status_stale_or_malformed_ownership_when_missing_expected_hash(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            asa.claude_integration_install(home, None)
            ownership = json.loads(self._ownership(home).read_text())
            del ownership["statusline"]["expected_owned_settings_sha256"]
            self._ownership(home).write_text(json.dumps(ownership))
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "STALE_OR_MALFORMED_OWNERSHIP")

    def test_status_malformed_ownership_sidecar_is_stale_without_mutation(self):
        """CR3-07 Codex reproduction: invalid sidecar is not "missing"."""
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); secret_marker = "sidecar-status-secret"
            (home / "settings.json").write_text(json.dumps({"env": {"SECRET": secret_marker}}))
            asa.claude_integration_install(home, None)
            settings_before = (home / "settings.json").read_bytes()
            self._ownership(home).write_text("{not-json")
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "STALE_OR_MALFORMED_OWNERSHIP")
            self.assertFalse(status["owned"])
            self.assertNotIn(secret_marker, json.dumps(status))
            self.assertEqual((home / "settings.json").read_bytes(), settings_before)
            self.assertEqual(self._ownership(home).read_text(), "{not-json")
            with self.assertRaises(ValueError):
                asa.claude_integration_install(home, None)
            with self.assertRaises(ValueError):
                asa.claude_integration_remove(home)

    def test_status_structurally_invalid_ownership_sidecar_is_stale(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td); (home / "settings.json").write_text("{}\n")
            asa.claude_integration_install(home, None)
            self._ownership(home).write_text(json.dumps({"version": 1, "statusline": []}))
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "STALE_OR_MALFORMED_OWNERSHIP")
            self.assertFalse(status["owned"])

    def test_status_never_exposes_preimage_contents_in_conflict_states(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            secret_marker = "super-secret-conflict-value-xyz"
            (home / "settings.json").write_text(json.dumps({"env": {"SECRET": secret_marker}}))
            asa.claude_integration_install(home, None)
            self._preimage(home).write_text('{"env": {"SECRET": "%s-TAMPERED"}}' % secret_marker)
            status = asa.claude_integration_status(home)
            self.assertEqual(status["state"], "PREIMAGE_CORRUPT")
            self.assertNotIn(secret_marker, json.dumps(status))


class ClaudeRuntimeSnapshotValidationTests(unittest.TestCase):
    """CR2-02: the centralized parser must be structurally exhaustive -- ANY
    field later consumed by merge/max/min/ordering/formatting/capability
    derivation/regime logic/status rendering that fails validation discards
    the ENTIRE prior snapshot (fail closed), never partially trusts it."""

    def test_codex_reproduction_exact_case_does_not_crash_and_is_discarded(self):
        raw = json.dumps({
            "format_version": 2, "stream_id": "stream",
            "regime": ["m", 1000000],
            "peak_current_context_input_tokens": "bad",
            "receipt_ns": 1,
        })
        snap = asa._parse_claude_runtime_snapshot(raw)
        self.assertEqual(snap, {})

    def test_codex_reproduction_does_not_crash_downstream_merge(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = asa.StateStore(str(Path(td) / "state"))
            store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
                ("s1", "claude", "s1", "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
            store.db.execute("INSERT INTO service_meta(key,value) VALUES(?,?)", (asa._claude_runtime_meta_key("s1"), json.dumps({
                "format_version": 2, "stream_id": "s1",
                "regime": ["m", 1000000],
                "peak_current_context_input_tokens": "bad",
                "receipt_ns": 1,
            })))
            store.db.commit()
            sample = _claude_runtime_sample("s1", path)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)  # must not raise int > str
            store.db.commit()
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["current_context_input_tokens"], 44865)  # replacement succeeded, not just "didn't crash"
            store.close()

    def test_writer_never_emits_reported_occupancy_its_own_parser_rejects(self):
        # CR3-02 round-trip safety regression: total_input_tokens > 1.2x window
        # is a merely-reported (not validated) pair -- the writer must never
        # compute reported_model_context_occupancy_pct outside the [0.0, 1.2]
        # bound its own parser enforces, or a truthful-but-large report would
        # discard the entire persisted snapshot on the very next read.
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = asa.StateStore(str(Path(td) / "state"))
            store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
                ("s1", "claude", "s1", "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
            store.db.commit()
            sample = _claude_runtime_sample("s1", path, context_window_size=1000, total_input_tokens=2000,
                current_usage={"input_tokens": 2, "output_tokens": 7, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 1898},
                used_percentage=None)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            raw = store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0]
            snap = asa._parse_claude_runtime_snapshot(raw)
            self.assertNotEqual(snap, {})  # must not be discarded by its own writer's output
            store.close()

    def test_writer_output_always_round_trips_through_parser_for_valid_fixture(self):
        # Generic drift guard: any sample the writer accepts as store-worthy
        # must parse back non-empty through the real parser, independent of
        # occupancy edge cases -- catches future writer/validator disagreement
        # in one test rather than one field at a time.
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "s1.jsonl")
            store = asa.StateStore(str(Path(td) / "state"))
            store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
                ("s1", "claude", "s1", "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
            store.db.commit()
            sample = _claude_runtime_sample("s1", path)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample)
            store.db.commit()
            raw = store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0]
            snap = asa._parse_claude_runtime_snapshot(raw)
            self.assertNotEqual(snap, {})
            store.close()

    def _valid_snapshot(self, **overrides):
        base = {
            "format_version": 2, "stream_id": "s1", "session_id": "s1", "transcript_path": "/tmp/s1.jsonl",
            "receipt_ns": 100, "observed_at": "2026-08-21T20:00:00Z", "last_validated_at": "2026-08-21T20:00:00Z",
            "claude_code_version": "2.1.239", "model_id": "claude-sonnet-5", "model_display_name": "Sonnet 5",
            "current_context_input_tokens": 44865, "peak_current_context_input_tokens": 44865,
            "reported_total_input_tokens": 44865, "reported_total_output_tokens": 7,
            "reported_model_context_occupancy_pct": 0.044865,
            "model_context_window_tokens": 1000000, "model_context_occupancy_pct": 0.044865,
            "peak_model_context_occupancy_pct": 0.044865,
            "auto_compact_window_tokens": None, "auto_compact_occupancy_pct": None, "peak_auto_compact_occupancy_pct": None,
            "usage_complete": True, "counters_consistent": True, "version_validated": True,
            "regime": ["claude-sonnet-5", 1000000], "regime_started_at": 100,
            "capability": {"session_id": "EXACT"}, "provenance_notes": ["a note"],
        }
        base.update(overrides)
        return base

    def test_valid_snapshot_survives_validation(self):
        raw = json.dumps(self._valid_snapshot())
        snap = asa._parse_claude_runtime_snapshot(raw)
        self.assertNotEqual(snap, {})
        self.assertEqual(snap["stream_id"], "s1")

    def test_bad_receipt_ns_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(receipt_ns="not-an-int"))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_negative_receipt_ns_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(receipt_ns=-5))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_future_poisoned_receipt_ns_discards_whole_snapshot(self):
        far_future = asa.time.time_ns() + 10**18
        raw = json.dumps(self._valid_snapshot(receipt_ns=far_future))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_model_id_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(model_id=12345))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_claude_code_version_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(claude_code_version=["not", "a", "string"]))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_regime_shape_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(regime=["only-one-element"]))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_regime_window_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(regime=["m", "not-an-int"]))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_regime_started_at_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(regime_started_at="bad"))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_latest_counter_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(current_context_input_tokens="bad"))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_reported_counter_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(reported_total_input_tokens="bad"))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_peak_counter_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(peak_current_context_input_tokens="bad"))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_non_finite_occupancy_float_discards_whole_snapshot(self):
        raw = '{"format_version": 2, "stream_id": "s1", "receipt_ns": 1, "model_context_occupancy_pct": NaN}'
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_infinite_occupancy_float_discards_whole_snapshot(self):
        raw = '{"format_version": 2, "stream_id": "s1", "receipt_ns": 1, "model_context_occupancy_pct": Infinity}'
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_int_masquerading_as_occupancy_float_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(model_context_occupancy_pct=1))  # int, not float
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_out_of_range_occupancy_float_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(model_context_occupancy_pct=99.0))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_capability_map_value_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(capability={"session_id": "TOTALLY_MADE_UP"}))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_capability_map_non_dict_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(capability=["not", "a", "dict"]))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_evidence_flag_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(usage_complete="yes"))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_provenance_notes_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(provenance_notes="not a list"))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_provenance_notes_element_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(provenance_notes=[123]))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_observed_at_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(observed_at=12345))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_session_id_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(session_id=999))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_bad_transcript_path_type_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(transcript_path=999))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_daemon_tick_does_not_crash_on_malformed_row(self):
        with tempfile.TemporaryDirectory() as td:
            store = asa.StateStore(str(Path(td) / "state"))
            store.db.execute("INSERT INTO service_meta(key,value) VALUES(?,?)", (
                asa._claude_runtime_meta_key("s1"),
                json.dumps({"format_version": 2, "stream_id": "s1", "regime": ["m", 1000000], "peak_current_context_input_tokens": "bad", "receipt_ns": 1}),
            ))
            store.db.commit()
            with contextlib.redirect_stdout(io.StringIO()):
                metrics = asa.service_once(str(Path(td) / "svc-state"), "claude", roots=[], notify=False)
            self.assertEqual(metrics.parse_errors, 0)
            store.close()

    # --- CR3-02: exact Codex reproductions, semantics/range enforcement ---

    def test_cr3_negative_current_context_input_tokens_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(current_context_input_tokens=-1))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_huge_reported_total_input_tokens_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(reported_total_input_tokens=10**18))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_huge_reported_total_output_tokens_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(reported_total_output_tokens=10**18))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_auto_compact_window_tokens_populated_discards_whole_snapshot(self):
        # v1 explicitly REQUIRES auto_compact_window_tokens to stay None --
        # a tampered snapshot must never let it become populated.
        raw = json.dumps(self._valid_snapshot(auto_compact_window_tokens=1))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_auto_compact_occupancy_pct_populated_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(auto_compact_occupancy_pct=0.5))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_peak_auto_compact_occupancy_pct_populated_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(peak_auto_compact_occupancy_pct=0.5))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_occupancy_over_one_point_two_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(model_context_occupancy_pct=1.5))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_negative_occupancy_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(model_context_occupancy_pct=-0.1))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_nan_occupancy_discards_whole_snapshot(self):
        raw = '{"format_version": 2, "stream_id": "s1", "receipt_ns": 100, "model_context_occupancy_pct": NaN}'
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_infinity_occupancy_discards_whole_snapshot(self):
        raw = '{"format_version": 2, "stream_id": "s1", "receipt_ns": 100, "model_context_occupancy_pct": Infinity}'
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_observed_at_not_a_timestamp_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(observed_at="not-a-timestamp"))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_last_validated_at_not_a_timestamp_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(last_validated_at="not-a-timestamp"))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_regime_started_at_huge_nanosecond_value_still_valid(self):
        # regime_started_at shares receipt_ns's shape (nanosecond timestamp),
        # not the 100M token-count bound -- a genuine large receipt-shaped
        # value here must NOT be rejected as an oversized token count.
        genuine_receipt = asa.time.time_ns()
        raw = json.dumps(self._valid_snapshot(receipt_ns=genuine_receipt, regime_started_at=genuine_receipt))
        self.assertNotEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_regime_started_at_future_poisoned_discards_whole_snapshot(self):
        far_future = asa.time.time_ns() + 10**18
        raw = json.dumps(self._valid_snapshot(regime_started_at=far_future))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_regime_started_at_negative_discards_whole_snapshot(self):
        raw = json.dumps(self._valid_snapshot(regime_started_at=-1))
        self.assertEqual(asa._parse_claude_runtime_snapshot(raw), {})

    def test_cr3_all_codex_repro_cases_fail_closed_without_crashing(self):
        cases = [
            self._valid_snapshot(current_context_input_tokens=-1),
            self._valid_snapshot(reported_total_input_tokens=10**18),
            self._valid_snapshot(auto_compact_window_tokens=1),
            self._valid_snapshot(model_context_occupancy_pct=1.5),
            self._valid_snapshot(observed_at="not-a-timestamp"),
        ]
        for case in cases:
            snap = asa._parse_claude_runtime_snapshot(json.dumps(case))
            self.assertEqual(snap, {})


class ClaudeRuntimeReceiptIntegrityTests(unittest.TestCase):
    """CR2-03: a persisted/incoming receipt_ns beyond a trusted wall-clock
    future bound must never participate in ordering, must never be written to
    service_meta, and must never block later genuine observations. Filename
    and body receipt must agree exactly."""
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))
    def _seed_session(self, store, session_id, path):
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, "claude", session_id, "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
        store.db.commit()

    def test_future_receipt_ns_1e18_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td); self._seed_session(store, "s1", str(Path(td) / "s1.jsonl"))
            poisoned_receipt = asa.time.time_ns() + 10**18
            sample = {"session_id": "s1", "transcript_path": str(Path(td) / "s1.jsonl"), "receipt_ns": poisoned_receipt}
            (inbox / asa._claude_runtime_inbox_filename("s1", poisoned_receipt)).write_text(json.dumps(sample))
            samples = asa._read_claude_runtime_inbox(td)
            self.assertEqual(samples, [])
            store.close()

    def test_genuine_next_observation_becomes_latest_after_poisoned_one_evicted(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            poisoned_receipt = asa.time.time_ns() + 10**18
            poisoned = {"session_id": "s1", "transcript_path": path, "receipt_ns": poisoned_receipt}
            (inbox / asa._claude_runtime_inbox_filename("s1", poisoned_receipt)).write_text(json.dumps(poisoned))
            genuine_sample = _claude_runtime_sample("s1", path)
            genuine_receipt = asa.time.time_ns()
            genuine_sample["receipt_ns"] = genuine_receipt
            (inbox / asa._claude_runtime_inbox_filename("s1", genuine_receipt)).write_text(json.dumps(genuine_sample))
            metrics = asa.ingest_claude_runtime_inbox(store, td)
            self.assertEqual(metrics["resolved"], 1)
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["receipt_ns"], genuine_receipt)
            store.close()

    def test_filename_receipt_mismatch_with_body_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td); self._seed_session(store, "s1", str(Path(td) / "s1.jsonl"))
            body_receipt = 5000
            filename_receipt = 6000  # deliberately different from the body
            sample = {"session_id": "s1", "transcript_path": str(Path(td) / "s1.jsonl"), "receipt_ns": body_receipt}
            (inbox / asa._claude_runtime_inbox_filename("s1", filename_receipt)).write_text(json.dumps(sample))
            samples = asa._read_claude_runtime_inbox(td)
            self.assertEqual(samples, [])
            store.close()

    def test_future_mtime_still_rejected_as_before(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td); self._seed_session(store, "s1", str(Path(td) / "s1.jsonl"))
            receipt = asa.time.time_ns()
            sample = {"session_id": "s1", "transcript_path": str(Path(td) / "s1.jsonl"), "receipt_ns": receipt}
            entry = inbox / asa._claude_runtime_inbox_filename("s1", receipt)
            entry.write_text(json.dumps(sample))
            far_future_epoch = asa.time.time() + 3600
            os.utime(entry, (far_future_epoch, far_future_epoch))
            samples = asa._read_claude_runtime_inbox(td)
            self.assertEqual(samples, [])
            store.close()

    def test_future_body_receipt_with_normal_mtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td); self._seed_session(store, "s1", str(Path(td) / "s1.jsonl"))
            poisoned_receipt = asa.time.time_ns() + 10**18
            sample = {"session_id": "s1", "transcript_path": str(Path(td) / "s1.jsonl"), "receipt_ns": poisoned_receipt}
            entry = inbox / asa._claude_runtime_inbox_filename("s1", poisoned_receipt)
            entry.write_text(json.dumps(sample))  # mtime is "now" (normal), receipt in body is poisoned
            samples = asa._read_claude_runtime_inbox(td)
            self.assertEqual(samples, [])
            store.close()

    def test_malicious_observed_at_cannot_reorder_a_normal_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            older = _claude_runtime_sample("s1", path, total_input_tokens=1000)
            older["receipt_ns"] = 1000
            older["observed_at"] = "2099-01-01T00:00:00Z"  # forged far-future claim, must not matter
            newer = _claude_runtime_sample("s1", path, total_input_tokens=2000)
            newer["receipt_ns"] = 2000
            newer["observed_at"] = "2000-01-01T00:00:00Z"  # forged far-past claim, must not matter either
            (inbox / asa._claude_runtime_inbox_filename("s1", 1000)).write_text(json.dumps(older))
            (inbox / asa._claude_runtime_inbox_filename("s1", 2000)).write_text(json.dumps(newer))
            metrics = asa.ingest_claude_runtime_inbox(store, td)
            self.assertEqual(metrics["resolved"], 2)
            snap = json.loads(store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()[0])
            self.assertEqual(snap["receipt_ns"], 2000)  # receipt order wins, not observed_at claims
            store.close()

    def test_store_directly_rejects_future_poisoned_receipt(self):
        # Belt-and-suspenders: even if a poisoned receipt reached the store
        # by a path other than the inbox reader, it must never be persisted.
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            poisoned_receipt = asa.time.time_ns() + 10**18
            asa.store_claude_runtime_sample(store, row, sample, receipt_ns=poisoned_receipt)
            store.db.commit()
            existing = store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()
            self.assertIsNone(existing)
            store.close()

    # --- CR3-03: store_claude_runtime_sample must be independently safe as
    # the final merge boundary, even called directly without the inbox reader ---

    def _assert_direct_store_rejects(self, receipt_ns):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample, receipt_ns=receipt_ns)
            store.db.commit()
            existing = store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()
            self.assertIsNone(existing, msg=f"receipt_ns={receipt_ns!r}")
            store.close()

    def test_direct_store_rejects_bool_true_receipt_ns(self):
        self._assert_direct_store_rejects(True)

    def test_direct_store_rejects_bool_false_receipt_ns(self):
        self._assert_direct_store_rejects(False)

    def test_direct_store_rejects_float_receipt_ns(self):
        self._assert_direct_store_rejects(123.5)

    def test_direct_store_rejects_string_receipt_ns(self):
        self._assert_direct_store_rejects("123")

    def test_direct_store_rejects_negative_receipt_ns(self):
        self._assert_direct_store_rejects(-1)

    def test_direct_store_accepts_valid_receipt_ns(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)
            row, _ = asa.resolve_claude_runtime_sample(store, sample)
            asa.store_claude_runtime_sample(store, row, sample, receipt_ns=asa.time.time_ns())
            store.db.commit()
            existing = store.db.execute("SELECT value FROM service_meta WHERE key=?", (asa._claude_runtime_meta_key("s1"),)).fetchone()
            self.assertIsNotNone(existing)
            store.close()


class ClaudeRuntimeCapabilityCombineTests(unittest.TestCase):
    """CR2-06: the minimum-capability helper must define behavior for EVERY
    ProviderCapability member, including PROXY/PARTIAL, and never raise
    KeyError. The critical invariant: derived capability is never stronger
    than either operand."""
    ALL = [c.value for c in asa.ProviderCapability]

    def test_all_enum_pairs_defined_no_keyerror(self):
        for a in self.ALL:
            for b in self.ALL:
                result = asa._claude_runtime_capability_combine(a, b)
                self.assertIn(result, self.ALL)

    def test_never_stronger_than_either_operand(self):
        for a in self.ALL:
            for b in self.ALL:
                result = asa._claude_runtime_capability_combine(a, b)
                rank_result = asa._CAPABILITY_TIER[result]
                self.assertLessEqual(rank_result, asa._CAPABILITY_TIER[a])
                self.assertLessEqual(rank_result, asa._CAPABILITY_TIER[b])

    def test_exact_and_exact_is_exact(self):
        self.assertEqual(asa._claude_runtime_capability_combine("EXACT", "EXACT"), "EXACT")

    def test_exact_and_observed_is_observed(self):
        self.assertEqual(asa._claude_runtime_capability_combine("EXACT", "OBSERVED"), "OBSERVED")

    def test_exact_and_unavailable_is_unavailable(self):
        self.assertEqual(asa._claude_runtime_capability_combine("EXACT", "UNAVAILABLE"), "UNAVAILABLE")

    def test_observed_and_unavailable_is_unavailable(self):
        self.assertEqual(asa._claude_runtime_capability_combine("OBSERVED", "UNAVAILABLE"), "UNAVAILABLE")

    def test_proxy_and_partial_returns_a_fixed_deterministic_answer(self):
        result_ab = asa._claude_runtime_capability_combine("PROXY", "PARTIAL")
        result_ba = asa._claude_runtime_capability_combine("PARTIAL", "PROXY")
        self.assertEqual(result_ab, result_ba)  # deterministic regardless of argument order
        self.assertIn(result_ab, {"PROXY", "PARTIAL"})

    def test_proxy_and_observed_is_proxy(self):
        self.assertEqual(asa._claude_runtime_capability_combine("PROXY", "OBSERVED"), "PROXY")

    def test_partial_and_observed_is_partial(self):
        self.assertEqual(asa._claude_runtime_capability_combine("PARTIAL", "OBSERVED"), "PARTIAL")

    def test_unrecognized_string_treated_as_unavailable(self):
        self.assertEqual(asa._claude_runtime_capability_combine("NOT_A_REAL_CAPABILITY", "EXACT"), "UNAVAILABLE")

    def test_unrecognized_string_does_not_raise(self):
        try:
            asa._claude_runtime_capability_combine("garbage", "also garbage")
        except KeyError:
            self.fail("_claude_runtime_capability_combine raised KeyError for a non-enum string")


class ClaudeRuntimeSymlinkHardeningTests(unittest.TestCase):
    """CR2-07: best-effort same-user confinement for the runtime inbox --
    reject a symlinked inbox directory, reject symlink inbox entries, never
    follow a symlink sample file."""
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))

    def test_symlinked_inbox_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            real_target = Path(td) / "elsewhere"; real_target.mkdir()
            secret = real_target / "secret.json"
            secret.write_text(json.dumps({"session_id": "s1", "transcript_path": str(Path(td) / "s1.jsonl"), "receipt_ns": 1}))
            inbox_link = Path(td) / "state" / "claude-runtime"
            inbox_link.parent.mkdir(parents=True)
            os.symlink(real_target, inbox_link)
            samples = asa._read_claude_runtime_inbox(str(Path(td) / "state"))
            self.assertEqual(samples, [])

    def test_bridge_refuses_to_write_through_symlinked_inbox_directory(self):
        with tempfile.TemporaryDirectory() as td:
            real_target = Path(td) / "elsewhere"; real_target.mkdir()
            state = Path(td) / "state"; state.mkdir()
            os.symlink(real_target, state / "claude-runtime")
            path = str(Path(td) / "s1.jsonl")
            rc = asa.claude_statusline_bridge_main(stdin=io.BytesIO(json.dumps(_sample_statusline_payload(transcript_path=path)).encode()), state_dir=str(state))
            self.assertEqual(rc, 0)
            self.assertEqual(list(real_target.glob("*.json")), [])

    def test_symlinked_inbox_entry_within_a_real_directory_is_never_followed(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            secret = Path(td) / "outside-secret.json"
            secret.write_text(json.dumps({"session_id": "s1", "transcript_path": str(Path(td) / "s1.jsonl"), "receipt_ns": asa.time.time_ns()}))
            receipt_ns = asa.time.time_ns()
            link = inbox / asa._claude_runtime_inbox_filename("s1", receipt_ns)
            os.symlink(secret, link)
            samples = asa._read_claude_runtime_inbox(td)
            self.assertEqual(samples, [])
            self.assertFalse(link.exists())  # the link itself was unlinked, target untouched
            self.assertTrue(secret.exists())

    def test_symlinked_state_dir_itself_is_rejected_by_reader(self):
        # The parent state-dir being a symlink (not just the claude-runtime
        # leaf) must also be refused -- a symlinked state-dir would otherwise
        # let a real inbox subdirectory be written through silently.
        with tempfile.TemporaryDirectory() as td:
            real_target = Path(td) / "elsewhere-state"
            (real_target / "claude-runtime").mkdir(parents=True)
            secret = real_target / "claude-runtime" / "secret.json"
            secret.write_text(json.dumps({"session_id": "s1", "transcript_path": str(Path(td) / "s1.jsonl"), "receipt_ns": 1}))
            state_link = Path(td) / "state"
            os.symlink(real_target, state_link)
            samples = asa._read_claude_runtime_inbox(str(state_link))
            self.assertEqual(samples, [])

    def test_bridge_refuses_to_write_through_symlinked_state_dir(self):
        with tempfile.TemporaryDirectory() as td:
            real_target = Path(td) / "elsewhere-state"; real_target.mkdir()
            state_link = Path(td) / "state"
            os.symlink(real_target, state_link)
            path = str(Path(td) / "s1.jsonl")
            rc = asa.claude_statusline_bridge_main(stdin=io.BytesIO(json.dumps(_sample_statusline_payload(transcript_path=path)).encode()), state_dir=str(state_link))
            self.assertEqual(rc, 0)
            self.assertFalse((real_target / "claude-runtime").exists())


class ClaudeRuntimeInboxScanBoundTests(unittest.TestCase):
    """CR2-08: scan work is bounded per call (CLAUDE_RUNTIME_INBOX_SCAN_MAX_ENTRIES),
    independent of and set above the retained-mailbox-size bound; a junk flood
    beyond the scan bound cannot force one tick to process everything, and
    ordinary valid observations still get through under normal conditions."""
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))
    def _seed_session(self, store, session_id, path):
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, "claude", session_id, "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z"))
        store.db.commit()

    def test_junk_flood_beyond_scan_max_does_not_process_everything_in_one_tick(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            flood_size = asa.CLAUDE_RUNTIME_INBOX_SCAN_MAX_ENTRIES + 500
            for i in range(flood_size):
                (inbox / f"junk-{i}.json").write_text("{not valid json")
            store = self._store(td)
            asa._read_claude_runtime_inbox(td)
            remaining = len(list(inbox.glob("*.json")))
            # Bounded work per call: at most CLAUDE_RUNTIME_INBOX_SCAN_MAX_ENTRIES
            # junk names were even looked at, so some junk must remain after one call.
            self.assertGreater(remaining, 0)
            store.close()

    def test_ordinary_valid_observation_is_processed_under_normal_conditions(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td); path = str(Path(td) / "s1.jsonl"); self._seed_session(store, "s1", path)
            sample = _claude_runtime_sample("s1", path)
            receipt_ns = asa.time.time_ns()
            sample["receipt_ns"] = receipt_ns
            (inbox / asa._claude_runtime_inbox_filename("s1", receipt_ns)).write_text(json.dumps(sample))
            samples = asa._read_claude_runtime_inbox(td)
            self.assertEqual(len(samples), 1)
            self.assertEqual(samples[0][1]["session_id"], "s1")
            store.close()

    def test_repeated_ticks_make_bounded_progress_cleaning_up_a_flood(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            flood_size = asa.CLAUDE_RUNTIME_INBOX_SCAN_MAX_ENTRIES + 200
            for i in range(flood_size):
                (inbox / f"junk-{i}.json").write_text("{not valid json")
            store = self._store(td)
            asa._read_claude_runtime_inbox(td)
            after_first = len(list(inbox.glob("*.json")))
            asa._read_claude_runtime_inbox(td)
            after_second = len(list(inbox.glob("*.json")))
            self.assertLess(after_second, after_first)  # progress was made, not stuck
            store.close()

    def test_scan_max_is_set_above_retained_mailbox_cap(self):
        self.assertGreater(asa.CLAUDE_RUNTIME_INBOX_SCAN_MAX_ENTRIES, asa.CLAUDE_RUNTIME_INBOX_MAX_FILES)

    def test_malformed_burst_still_cannot_starve_valid_older_sample_within_scan_bound(self):
        # This must keep passing alongside the new scan bound: validation/
        # quarantine still happens before the retained-count cap, within
        # whatever the scan bound allowed it to see.
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "claude-runtime"; inbox.mkdir(parents=True)
            store = self._store(td)
            base = asa.time.time_ns()
            valid_receipt = base
            valid_sample = {"session_id": "svalid", "transcript_path": str(Path(td) / "svalid.jsonl"), "receipt_ns": valid_receipt}
            (inbox / asa._claude_runtime_inbox_filename("svalid", valid_receipt)).write_text(json.dumps(valid_sample))
            for i in range(asa.CLAUDE_RUNTIME_INBOX_MAX_FILES + 50):
                receipt = base + 1 + i
                (inbox / asa._claude_runtime_inbox_filename(f"junk{i}", receipt)).write_text("{not valid json")
            samples = asa._read_claude_runtime_inbox(td)
            surviving_ids = {s["session_id"] for _, s in samples}
            self.assertIn("svalid", surviving_ids)
            store.close()


class V042RuntimeRegressionTests(unittest.TestCase):
    """Confirm the whole v0.4.2 suite's assumptions still hold with runtime telemetry wired in."""
    def test_service_once_with_claude_provider_does_not_error_on_empty_inbox(self):
        with tempfile.TemporaryDirectory() as td:
            with contextlib.redirect_stdout(io.StringIO()):
                metrics = asa.service_once(str(Path(td) / "state"), "claude", roots=[], notify=False)
            self.assertEqual(metrics.parse_errors, 0)


class ClaudeRuntimeSemanticEvidenceTests(unittest.TestCase):
    def _store(self, td): return asa.StateStore(str(Path(td) / "state"))
    def _row(self, store, td, stream="stream-1"):
        path = str(Path(td) / f"{stream}.jsonl")
        store.db.execute("INSERT INTO sessions(session_id,provider,stream_id,role,path,started_at,last_activity_at) VALUES(?,?,?,?,?,?,?)", (stream, "claude", stream, "MAIN", path, "2026-08-21T20:00:00Z", "2026-08-21T20:00:00Z")); store.db.commit()
        return store.db.execute("SELECT * FROM sessions WHERE provider='claude' AND stream_id=?", (stream,)).fetchone(), path

    def test_aggregate_unknown_version_and_profile_separation(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); row, path = self._row(store, td)
            a = _claude_runtime_sample("stream-1", path, claude_code_version="2.1.242")
            b = _claude_runtime_sample("stream-1", path, claude_code_version="2.1.242", model_id="claude-haiku-4.5", context_window_size=200000)
            asa.record_claude_runtime_semantic_evidence(store, row, a, asa.time.time_ns()); asa.record_claude_runtime_semantic_evidence(store, row, b, asa.time.time_ns() + 1)
            rows = store.db.execute("SELECT * FROM claude_runtime_semantic_evidence ORDER BY model_id").fetchall()
            self.assertEqual(len(rows), 2); self.assertNotIn("2.1.242", asa.CLAUDE_RUNTIME_EXACT_VERSIONS)
            self.assertEqual(rows[1]["complete_nonzero_count"], 1); self.assertEqual(rows[1]["counter_identity_pass"], 1)
            store.close()

    def test_zero_null_recovery_transitions_and_privacy(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); row, path = self._row(store, td); base = asa.time.time_ns()
            normal = _claude_runtime_sample("stream-1", path, context_window_fields=["context_window_size", "current_usage", "total_input_tokens", "used_percentage"], current_usage_fields=["input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"], current_usage_kind="object")
            zero = _claude_runtime_sample("stream-1", path, total_input_tokens=0, total_output_tokens=0, used_percentage=0, current_usage={"input_tokens":0,"output_tokens":0,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}, context_window_fields=["context_window_size", "current_usage", "total_input_tokens"], current_usage_fields=["input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"], current_usage_kind="object")
            null = _claude_runtime_sample("stream-1", path, current_usage=None, current_usage_kind="null", context_window_fields=["current_usage"], current_usage_fields=[])
            for i, sample in enumerate((normal, zero, normal, null, normal)): asa.record_claude_runtime_semantic_evidence(store, row, sample, base + i * 1_000_000_000)
            evidence = store.db.execute("SELECT * FROM claude_runtime_semantic_evidence").fetchone()
            self.assertEqual((evidence["normal_to_zero"], evidence["zero_to_normal"], evidence["normal_to_null"], evidence["null_to_normal"]), (1, 1, 1, 1))
            persisted = " ".join(str(x) for r in store.db.execute("SELECT * FROM claude_runtime_semantic_evidence").fetchall() for x in r)
            persisted += " " + " ".join(str(x) for r in store.db.execute("SELECT * FROM claude_runtime_semantic_fingerprints").fetchall() for x in r)
            for secret in ("stream-1", path, "prompt text", "tool output", "assistant response"): self.assertNotIn(secret, persisted)
            store.close()

    def test_fingerprint_bound_and_cli_json(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); row, path = self._row(store, td); base = asa.time.time_ns()
            for i in range(asa.CLAUDE_RUNTIME_SEMANTIC_MAX_FINGERPRINTS_PER_PROFILE + 3):
                sample = _claude_runtime_sample("stream-1", path, context_window_fields=["context_window_size", f"future_{i}"], current_usage_fields=[], current_usage_kind="missing")
                asa.record_claude_runtime_semantic_evidence(store, row, sample, base + i)
            self.assertEqual(store.db.execute("SELECT count(*) FROM claude_runtime_semantic_fingerprints").fetchone()[0], asa.CLAUDE_RUNTIME_SEMANTIC_MAX_FINGERPRINTS_PER_PROFILE)
            payload = asa.claude_runtime_semantic_evidence(store)
            self.assertTrue(payload["evidence_only"]); self.assertIn("Samples", asa.render_claude_runtime_semantic_evidence(payload))
            store.close()

    def test_v5_copy_upgrade_is_idempotent_and_cli_json_is_read_only(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"; state.mkdir(); db = sqlite3.connect(state / "agentopsy.db")
            db.execute("CREATE TABLE service_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO service_meta VALUES('schema_version','5')"); db.commit(); db.close()
            store = asa.StateStore(str(state)); self.assertEqual(store.db.execute("SELECT value FROM service_meta WHERE key='schema_version'").fetchone()[0], "6"); store.close()
            out = io.StringIO()
            with contextlib.redirect_stdout(out): self.assertEqual(asa.live_cli(["runtime", "evidence", "claude", "--state-dir", str(state), "--json"]), 0)
            self.assertTrue(json.loads(out.getvalue())["evidence_only"])

    def test_replay_receipt_is_not_counted_twice_after_pre_unlink_crash_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); row, path = self._row(store, td); sample = _claude_runtime_sample("stream-1", path); receipt = asa.time.time_ns()
            with store.db:
                self.assertTrue(asa.store_claude_runtime_sample(store, row, sample, receipt_ns=receipt)); asa.record_claude_runtime_semantic_evidence(store, row, sample, receipt)
            # Simulate process death before unlink: the identical inbox file is retried.
            with store.db:
                self.assertFalse(asa.store_claude_runtime_sample(store, row, sample, receipt_ns=receipt))
            self.assertEqual(store.db.execute("SELECT samples_total FROM claude_runtime_semantic_evidence").fetchone()[0], 1); store.close()

    def test_profile_boundary_reseeds_transition_cursor(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); row, path = self._row(store, td); base = asa.time.time_ns()
            zero_usage = {"input_tokens":0,"output_tokens":0,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}
            # Version, model, and window changes each deliberately reseed.
            cases = [({"claude_code_version":"2.1.242"}), ({"model_id":"claude-haiku-4.5", "context_window_size":200000}), ({"context_window_size":200000})]
            for i, change in enumerate(cases):
                asa.record_claude_runtime_semantic_evidence(store, row, _claude_runtime_sample("stream-1", path), base + i * 10)
                asa.record_claude_runtime_semantic_evidence(store, row, _claude_runtime_sample("stream-1", path, **change, total_input_tokens=0, total_output_tokens=0, used_percentage=0, current_usage=zero_usage), base + i * 10 + 1)
            self.assertEqual(store.db.execute("SELECT sum(normal_to_zero) FROM claude_runtime_semantic_evidence").fetchone()[0], 0)
            store.close()

    def test_unknown_names_are_opaque_but_fingerprint_discriminating_and_stable(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); row, path = self._row(store, td); base = asa.time.time_ns()
            def sample(names): return _claude_runtime_sample("stream-1", path, context_window_fields=["context_window_size", *names], current_usage_fields=[])
            asa.record_claude_runtime_semantic_evidence(store, row, sample(["future_a"]), base)
            asa.record_claude_runtime_semantic_evidence(store, row, sample(["future_b"]), base + 1)
            asa.record_claude_runtime_semantic_evidence(store, row, sample(["future_b", "future_a"]), base + 2)
            asa.record_claude_runtime_semantic_evidence(store, row, sample(["future_a", "future_b"]), base + 3)
            fps = store.db.execute("SELECT context_window_fingerprint,count,context_window_fields FROM claude_runtime_semantic_fingerprints ORDER BY context_window_fingerprint").fetchall()
            self.assertEqual(len(fps), 3); self.assertIn(2, [r["count"] for r in fps])
            persisted = " ".join(str(x) for r in fps for x in r)
            for secret in ("future_a", "future_b"): self.assertNotIn(secret, persisted)
            store.close()

    def test_cursor_epoch_count_is_explicitly_not_distinct_stream_count_after_eviction(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); row, path = self._row(store, td); sample = _claude_runtime_sample("stream-1", path); base = asa.time.time_ns()
            asa.record_claude_runtime_semantic_evidence(store, row, sample, base)
            store.db.execute("DELETE FROM claude_runtime_semantic_streams")
            asa.record_claude_runtime_semantic_evidence(store, row, sample, base + 1)
            self.assertEqual(store.db.execute("SELECT stream_cursor_epochs_seen FROM claude_runtime_semantic_evidence").fetchone()[0], 2); store.close()

    def test_qualified_zero_shape_is_journaled_before_capability_guard(self):
        with tempfile.TemporaryDirectory() as td:
            store = self._store(td); row, path = self._row(store, td)
            zero = _claude_runtime_sample("stream-1", path, claude_code_version="2.1.241", total_input_tokens=0, total_output_tokens=0, used_percentage=0, current_usage={"input_tokens":0,"output_tokens":0,"cache_creation_input_tokens":0,"cache_read_input_tokens":0})
            asa.record_claude_runtime_semantic_evidence(store, row, zero, asa.time.time_ns())
            self.assertEqual(store.db.execute("SELECT complete_all_zero_count FROM claude_runtime_semantic_evidence").fetchone()[0], 1)
            derived = asa._claude_runtime_derive(zero); self.assertFalse(derived["usage_complete"]); self.assertIsNone(derived["current_context_input_tokens"])
            store.close()

    def test_two_independent_sqlite_connections_preserve_counts_and_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            store1 = self._store(td); row1, path = self._row(store1, td); store2 = asa.StateStore(str(Path(td) / "state"))
            row2 = store2.db.execute("SELECT * FROM sessions WHERE provider='claude' AND stream_id='stream-1'").fetchone(); base = asa.time.time_ns()
            with store1.db:
                store1.db.execute("BEGIN IMMEDIATE"); asa.record_claude_runtime_semantic_evidence(store1, row1, _claude_runtime_sample("stream-1", path), base)
            with store2.db:
                store2.db.execute("BEGIN IMMEDIATE"); asa.record_claude_runtime_semantic_evidence(store2, row2, _claude_runtime_sample("stream-1", path), base + 1)
            self.assertEqual(store1.db.execute("SELECT samples_total FROM claude_runtime_semantic_evidence").fetchone()[0], 2)
            self.assertEqual(store1.db.execute("PRAGMA integrity_check").fetchone()[0], "ok"); self.assertEqual(store1.db.execute("PRAGMA foreign_key_check").fetchall(), [])
            store2.close(); store1.close()


if __name__ == "__main__":
    unittest.main()
