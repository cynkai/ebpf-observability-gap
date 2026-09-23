"""규칙 판정 회귀 테스트. 저장소의 샘플·실제 로그로 돌린다 (LLM은 부르지 않는다)."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import eval as ev  # noqa: E402
import gapfind as g  # noqa: E402


def segs(reports, key):
    """{key: [(상태, 시작 HH:MM:SS), ...]} 중 OBS를 뺀 목록."""
    r = next(r for r in reports if r.key == key)
    return [(s["state"], g.hms(s["wins"][0].start)) for s in r.segs if s["state"] != "OBS"]


# ---------- 파싱 ----------

def test_parse_ts_nanoseconds():
    assert g.parse_ts("2026-09-23T08:25:03.088428000Z") == pytest.approx(
        g.parse_ts("2026-09-23T08:25:03.088428Z"))


def test_tetragon_procfs_and_exit_are_ignored():
    base = {"node_name": "n", "time": "2026-09-23T10:00:00Z"}
    procfs = {"process_exec": {"process": {"binary": "/usr/bin/dockerd", "flags": "procFS"}}, **base}
    exit_ = {"process_exit": {"process": {"binary": "/bin/cat"}}, **base}
    exec_ = {"process_exec": {"process": {"binary": "/bin/cat", "flags": "execve"}}, **base}
    assert g.parse_line(procfs) is None
    assert g.parse_line(exit_) is None
    assert g.parse_line(exec_).proc == "cat"


def test_falco_metrics_snapshot_is_heartbeat_with_drop_delta():
    d = {"rule": g.FALCO_METRICS_RULE, "hostname": "h", "time": "2026-09-23T10:00:00Z",
         "output_fields": {"scap.n_drops": 120, "scap.n_drops_prev": 100,
                           "falco.start_ts": 1, "scap.n_evts": 5000}}
    ev_ = g.parse_line(d)
    assert (ev_.proc, ev_.drops, ev_.meta["n_evts"]) == ("falco-metrics", 20, 5000)


# ---------- 판정 ----------

def test_sample_planted_gaps():
    reports = g.analyze(g.load("sample.jsonl"), 10, 0.7)
    assert segs(reports, "node-1/tetragon") == [
        ("QUIET", "10:02:00"), ("LOST", "10:05:00"), ("SUSP", "10:07:30"), ("SUSP", "10:09:00")]


def test_falco_pause_is_delayed_and_restart_is_lost():
    reports = g.analyze(g.load("real/falco_outage.jsonl"), 10, 0.7)
    assert segs(reports, "node-a/falco") == [
        ("DELAYED", "09:17:20"), ("LOST", "09:18:40"), ("QUIET", "09:19:10")]
    assert segs(reports, "node-b/falco") == []


def test_tetragon_heartbeat_settles_all_three():
    reports = g.analyze(g.load(["real/tetragon_hb.jsonl", "real/tetragon_hb_heartbeat.jsonl"]), 10, 0.7)
    assert segs(reports, "tg-node/tetragon") == [
        ("QUIET", "09:46:00"), ("DELAYED", "09:47:20"), ("LOST", "09:48:40")]


def test_exact_gap_bounds_come_from_heartbeats():
    reports = g.analyze(g.load("real/falco_outage.jsonl"), 10, 0.7)
    r = next(r for r in reports if r.key == "node-a/falco")
    restart = next(s for s in r.segs if s["state"] == "LOST")
    a, b = restart["exact"]
    assert g.hms(a) == "09:18:35" and g.hms(b) == "09:19:16"


def test_cross_check_uses_peer_collector():
    """Tetragon이 조용할 때, 같은 호스트 Falco가 활동을 봤으면 LOST, 조용했으면 QUIET."""
    E = g.Event
    events = []
    for t in range(0, 120, 5):  # Falco 하트비트는 내내 살아 있음
        events.append(E(t, "h", "falco-metrics", 0, {"start_ts": 1, "n_evts": t}, "falco"))
    for t in range(0, 120, 3):  # Tetragon 리듬: 30~60초(조용), 80~110초(수집기 꺼짐)에 끊김
        if not (30 <= t < 60 or 80 <= t < 110):
            events.append(E(t + 0.5, "h", "cat", collector="tetragon"))
    for t in range(0, 120, 3):  # Falco 알림: 30~60초만 워크로드가 멈춰 조용함
        if not 30 <= t < 60:
            for _ in range(5):
                events.append(E(t + 0.7, "h", "cat", collector="falco"))
    reports = g.analyze(sorted(events, key=lambda e: e.ts), 10, 0.7)
    tg = next(r for r in reports if r.key == "h/tetragon")
    at = {int(w.start): w for w in tg.wins}
    assert at[40].state == "QUIET" and "falco도 건강하고 조용함" in at[40].reason
    assert at[90].state == "LOST" and "falco는 활동" in at[90].reason


def test_real_falco_drops_under_cpu_limit():
    reports = g.analyze(g.load("real/cross.jsonl"), 10, 0.7)
    falco = next(r for r in reports if r.key == "lab/falco")
    lost = next(s for s in falco.segs if s["state"] == "LOST")
    assert g.hms(lost["wins"][0].start) == "09:58:00" and "드롭" in lost["wins"][0].reason


def test_k8s_pod_restarts_at_5s_windows():
    reports = g.analyze(g.load("real/k8s/k8s.jsonl"), 5, 0.7)

    def gaps(key):
        return [x for x in segs(reports, key) if x[0] in ("SUSP", "LOST", "DELAYED")]
    assert gaps("gap-worker/falco") == [("LOST", "10:07:05")]
    assert gaps("gap-worker2/tetragon") == [("LOST", "10:08:25")]
    # 5초 하트비트가 5.1초로 흔들려도 5초 창에서 SUSP가 생기지 않는다
    assert gaps("gap-worker2/falco") == []


def _tetragon_with_storage_loss(lose_from, lose_to):
    """5초마다 하트비트, 3초마다 워크로드 exec. [lose_from, lose_to) 동안의 줄은 로그에서 지워졌다."""
    E = g.Event
    events, exported = [], 0
    for t in range(0, 120):
        if t % 3 == 0:
            exported += 1
            if not lose_from <= t < lose_to:
                events.append(E(t + 0.5, "h", "cat", collector="tetragon"))
                events.append(E(t + 0.5, "h", "", 0, {"raw": True}, "tetragon"))
        if t % 5 == 0:
            meta = {"start_ts": 1, "n_evts": t, "lost": 0, "exported": exported}
            events.append(E(t + 0.9, "h", "tetragon-metrics", 0, meta, "tetragon"))
    return sorted(events, key=lambda e: e.ts)


def test_storage_reconciliation_flags_deleted_lines():
    reports = g.analyze(_tetragon_with_storage_loss(40, 70), 10, 0.7)
    tg = next(r for r in reports if r.key == "h/tetragon")
    lost = [w for w in tg.wins if w.state == "LOST"]
    assert lost and all("저장 단계 유실" in w.reason for w in lost)
    assert all(35 <= w.start < 75 for w in lost)


def test_storage_reconciliation_quiet_without_loss():
    reports = g.analyze(_tetragon_with_storage_loss(0, 0), 10, 0.7)
    assert not [w for w in reports[0].wins if w.state == "LOST"]


def test_prometheus_text():
    reports = g.analyze(g.load("real/falco_outage.jsonl"), 10, 0.7)
    text = g.prometheus_text(reports, 10)
    assert 'gapfind_gap_seconds_total{host="node-a",collector="falco",state="LOST"} 30' in text
    assert 'gapfind_gap_active{host="node-b",collector="falco"} 0' in text


# ---------- LLM 투표 ----------

def test_votes_split_become_unsure(monkeypatch):
    answers = iter(["QUIET", "UNOBSERVED", "UNOBSERVED"])

    def fake(report, size, provider, model):
        v = next(answers)
        return {(report.key, 0): {"segment_id": 0, "verdict": v, "confidence": "high", "reason": "x"}}

    monkeypatch.setattr(g, "ask_llm", fake)
    report = g.HostReport("h", "tetragon", [], [], [])
    out = g.ask_llm_votes(report, 10, "openai", "m", 3)
    assert out[("h/tetragon", 0)]["verdict"] == "UNSURE"


# ---------- 정확도 회귀 ----------

def test_eval_rules_never_wrong():
    cases = json.load(open("cases.json"))
    _, score = ev.run(cases)
    assert score["규칙만"]["wrong"] == 0
    assert score["규칙만"]["correct"] >= 10
