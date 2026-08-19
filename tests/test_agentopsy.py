import importlib.util
import json
import os
import sqlite3
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
            self.assertEqual(store.file(Path("/tmp/old.jsonl"))["session_id"], "old-session")
            self.assertEqual(store.sessions("codex")[0]["project"], "project")
            self.assertEqual({row[0] for row in store.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'guardian_%'")}, {"guardian_events", "guardian_event_lanes"})
            self.assertIsNotNone(store.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='telemetry_samples'").fetchone())
            store.close()
            reopened = asa.StateStore(str(state))
            self.assertEqual(reopened.sessions("codex")[0]["session_id"], "old-session")
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
            with self.assertRaisesRegex(sqlite3.OperationalError, "injected migration failure"):
                FailingV2Store(str(state))
            db = sqlite3.connect(state / "agentopsy.db")
            self.assertEqual(db.execute("SELECT value FROM service_meta WHERE key='schema_version'").fetchone()[0], "1")
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='failed_migration_marker'").fetchone())
            self.assertEqual(db.execute("SELECT session_id FROM sessions").fetchone()[0], "old-session")
            db.close()

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
                self.assertEqual(asa.main(["calibrate", "adopt", "--state-dir", state]), 0)
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
            self.assertIn("RAPID_REFILL", first[0]["states"])
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


if __name__ == "__main__":
    unittest.main()
