import importlib.util
import json
import tempfile
import unittest
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("asa", HERE / "agentopsy.py")
asa = importlib.util.module_from_spec(spec)
sys.modules["asa"] = asa
spec.loader.exec_module(asa)


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

    def test_codex_response_item_id_is_not_a_session_id(self):
        adapter = asa.CodexAdapter()
        path = Path("rollout-real.jsonl")
        self.assertEqual(adapter.identify_session({"type": "response_item", "payload": {"id": "item-123"}}, path), path.stem)

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
