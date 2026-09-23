#!/usr/bin/env python3
"""eBPF 관측 공백 분석기 (Falco / Tetragon JSON 로그)

로그를 호스트별로 나누고, 시간 창(window)마다 다섯 가지 상태 중 하나로 판정한다.
  OBS      관측됨: 이벤트가 있고 주기 신호도 정상
  QUIET    관측됨, 조용함: 주기 신호는 살아 있고 다른 활동은 거의 없음
  DELAYED  관측됨, 지연: 하트비트는 끊겼지만 커널 카운터가 이어졌고 드롭 0 (나중에 처리됨)
  LOST     관측 안 됨(확정): 드롭 신호가 있거나 수집기가 재시작됨
  SUSP     관측 안 됨(추정): 증거 없이 주기 신호만 끊김 -> --llm으로 판단

사용법:
  python3 gapfind.py sample.jsonl                    # 규칙 기반 판정
  python3 gapfind.py sample.jsonl --llm              # SUSP 구간을 LLM에게 판단 (기본 OpenAI)
  python3 gapfind.py sample.jsonl --html report.html # HTML 타임라인
  python3 gapfind.py falco.jsonl --follow            # 실시간 감시 (tail -f 처럼)
  python3 gapfind.py falco.jsonl --follow --webhook URL --metrics-port 9109   # 알림 + Prometheus
  python3 gapfind.py tetragon.jsonl heartbeat.jsonl  # 여러 파일을 합쳐서 (Tetragon + 하트비트)
  python3 gapfind.py falco.jsonl tetragon.jsonl      # 같은 호스트의 두 수집기를 서로 교차 확인
  python3 gapfind.py sample.jsonl --llm --votes 5    # 5번 물어 답이 갈리면 판단 보류
"""
import argparse
import html
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from bisect import bisect_right
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

SYMBOL = {"OBS": "█", "QUIET": "·", "DELAYED": "~", "LOST": "X", "SUSP": "?"}
LABEL = {"OBS": "관측", "QUIET": "조용", "DELAYED": "지연", "LOST": "유실(확정)", "SUSP": "유실(추정)"}
FALCO_DROP_RULE = "Falco internal: syscall event drop"
FALCO_METRICS_RULE = "Falco internal: metrics snapshot"  # metrics.output_rule=true 일 때
# 수집기가 직접 내는 하트비트. Tetragon 것은 tetragon_heartbeat.py가 만든다
HEARTBEATS = ("falco-metrics", "tetragon-metrics")


# ---------- 1. 파싱: Falco / Tetragon 줄을 같은 모양으로 ----------

@dataclass
class Event:
    ts: float
    host: str
    proc: str           # 빈 문자열이면 활동이 아니라 드롭 알림일 뿐
    drops: int = 0      # 0보다 크면 드롭 신호
    meta: dict = None   # 하트비트의 카운터 (start_ts, n_evts, 있으면 lost)
    collector: str = "" # falco / tetragon. 같은 호스트의 수집기를 서로 교차 확인할 때 쓴다


def parse_ts(s):
    # Falco는 나노초(9자리)를 쓰므로 파이썬이 읽을 수 있게 6자리로 자른다
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)?$", s)
    base, frac, tz = m.group(1), (m.group(2) or ".0")[:7], m.group(3) or "Z"
    tz = "+00:00" if tz == "Z" else tz
    return datetime.fromisoformat(base + frac + tz).timestamp()


def parse_line(d):
    ts = parse_ts(d["time"])
    if "rule" in d:  # Falco
        host = d.get("hostname", "?")
        fields = d.get("output_fields", {})
        if d["rule"].startswith(FALCO_DROP_RULE):
            return Event(ts, host, "", int(fields.get("n_drops", 1)))
        if d["rule"] == FALCO_METRICS_RULE:
            # 주기적으로 나오므로 하트비트가 되고, 직전 스냅숏 이후 드롭 수도 알려준다
            n = int(fields.get("scap.n_drops", 0)) - int(fields.get("scap.n_drops_prev", 0))
            meta = {"start_ts": fields.get("falco.start_ts"), "n_evts": fields.get("scap.n_evts", 0),
                    "exported": fields.get("falco.rules.matches_total")}
            return Event(ts, host, "falco-metrics", max(n, 0), meta)
        return Event(ts, host, fields.get("proc.name", "?"))
    host = d.get("node_name", "?")  # Tetragon
    if "tetragon_heartbeat" in d:
        # 유실 카운터는 누적값이라, 드롭 수는 analyze에서 앞 하트비트와 비교해 구한다
        hb = d["tetragon_heartbeat"]
        meta = {"start_ts": hb["start_ts"], "n_evts": hb["events_received"], "lost": hb["lost_total"],
                "exported": hb.get("events_exported")}
        return Event(ts, host, "tetragon-metrics", 0, meta)
    if "rate_limit_info" in d:  # 내보내기 단계에서 버린 이벤트
        n = int(d["rate_limit_info"].get("number_of_dropped_process_events", 1))
        return Event(ts, host, "", n)
    for key, body in d.items():  # process_exec, process_kprobe, ...
        # exit는 exec 바로 뒤에 붙어 나와 리듬 간격만 흐트러뜨리므로 활동으로 세지 않는다
        if key.startswith("process_") and key != "process_exit" and isinstance(body, dict):
            proc = body.get("process", {})
            # 시작할 때 /proc를 훑어 만든 이벤트는 '프로세스 시작 시각'이 찍혀 있어 새 활동이 아니다
            if "procFS" in proc.get("flags", ""):
                return None
            return Event(ts, host, proc.get("binary", "?").rsplit("/", 1)[-1])
    return None


def load(paths):
    events = []
    for path in [paths] if isinstance(paths, str) else paths:
        events += load_one(path)
    return sorted(events, key=lambda e: e.ts)


def load_one(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.replace("\0", "").strip()  # 로그를 비운 뒤 이어 쓰면 앞이 NUL로 채워질 수 있다
            if not line:
                continue
            try:
                d = json.loads(line)
                ev = parse_line(d)
            except (json.JSONDecodeError, KeyError):
                continue  # --follow 중에 반쯤 쓰인 줄이 올 수 있다
            collector = "falco" if "rule" in d else "tetragon"
            if ev:
                ev.collector = collector
                events.append(ev)
            if is_exported_event(d):
                # 저장 단계 대조용: 수집기가 '내보냈다'고 센 이벤트가 로그에 실제로 몇 줄 있는지
                host = d.get("hostname") or d.get("node_name", "?")
                events.append(Event(parse_ts(d["time"]), host, "", 0, {"raw": True}, collector))
    return events


def is_exported_event(d):
    """수집기의 내보내기 카운터가 세는 줄인가 (Falco: 규칙 알림, Tetragon: 하트비트 외 모든 이벤트)."""
    if "rule" in d:
        return not d["rule"].startswith("Falco internal")
    return "tetragon_heartbeat" not in d


# ---------- 2. 창 나누기 + 판정 ----------

@dataclass
class Window:
    start: float
    procs: Counter = field(default_factory=Counter)
    drops: int = 0
    state: str = ""
    missing: list = field(default_factory=list)
    reason: str = ""
    quiet: bool = False  # 주기 신호를 빼면 활동이 평소의 10% 이하


@dataclass
class HostReport:
    host: str
    collector: str
    wins: list
    rhythm: list
    events: list
    segs: list = field(default_factory=list)

    @property
    def key(self):
        return f"{self.host}/{self.collector}"


def build_windows(events, size, t0, t1):
    wins = [Window(t0 + i * size) for i in range(int((t1 - t0) // size) + 1)]
    for ev in events:
        if not (t0 <= ev.ts < t0 + len(wins) * size):
            continue  # 시간축 밖의 대조용 줄
        w = wins[int((ev.ts - t0) // size)]
        w.drops += ev.drops
        if ev.proc:
            w.procs[ev.proc] += 1
    return wins


def find_rhythm(events, size, ratio):
    """'수집기가 살아 있다'는 신호로 쓸 프로세스를 고른다.

    수집기가 직접 내는 하트비트(Falco metrics)가 있으면 그것만 쓴다. 일정하게 도는
    워크로드(cron 등)는 멈추는 게 정상일 수 있어서 기준으로 삼으면 안 된다.
    없으면 간격이 일정한 프로세스를 쓴다: 간격의 ratio 이상이 중앙값 ±20% 안에 들고,
    주기가 창 크기 이하여야 매 창마다 기대할 수 있다.
    """
    times = {}
    for ev in events:
        if ev.proc:
            times.setdefault(ev.proc, []).append(ev.ts)
    beats = [h for h in HEARTBEATS if h in times]
    if beats:
        return beats
    rhythm = []
    for proc, ts in times.items():
        gaps = sorted(b - a for a, b in zip(ts, ts[1:]))
        if len(gaps) < 5:
            continue
        med = gaps[len(gaps) // 2]
        regular = sum(abs(g - med) <= 0.2 * med for g in gaps) / len(gaps)
        if med <= size and regular >= ratio:
            rhythm.append(proc)
    return sorted(rhythm)


def classify(wins, rhythm):
    def others(w):
        return sum(c for p, c in w.procs.items() if p not in rhythm)

    # 평소 활동량의 10% 이하면 '조용함'으로 본다 (가끔 도는 cron 정도는 허용)
    busy = sorted(others(w) for w in wins)
    quiet_limit = max(1, busy[len(busy) // 2] * 0.1)
    for w in wins:
        w.missing = [p for p in rhythm if p not in w.procs]
        w.quiet = others(w) <= quiet_limit
        if w.drops:
            w.state, w.reason = "LOST", f"드롭 {w.drops}건 보고됨"
        elif w.missing or (not rhythm and not w.procs):
            w.state = "SUSP"
        elif w.quiet:
            w.state = "QUIET"
        else:
            w.state = "OBS"
    # 드롭은 '지난 보고 이후 누적'으로 늦게 보고된다.
    # 그래서 드롭 보고 바로 앞의 SUSP 창들은 같은 유실로 보고 LOST로 올린다.
    for i, w in enumerate(wins):
        if w.state == "LOST":
            j = i - 1
            while j >= 0 and wins[j].state == "SUSP":
                wins[j].state, wins[j].reason = "LOST", w.reason
                j -= 1


def explain_heartbeat_gaps(wins, events, size):
    """수집기 하트비트가 끊긴 구간을 앞뒤 스냅숏의 카운터로 확정한다.

    - start_ts가 바뀌거나 커널 카운터가 줄었다: 수집기가 재시작됨 -> 그 사이는 LOST
    - 카운터가 이어졌고 드롭이 0이다: 커널은 계속 쌓았고 나중에 처리됨 -> DELAYED
    """
    beats = [e for e in events if e.proc in HEARTBEATS and e.meta]
    if len(beats) < 3:
        return
    gaps = sorted(b.ts - a.ts for a, b in zip(beats, beats[1:]))
    normal = gaps[len(gaps) // 2]
    for a, b in zip(beats, beats[1:]):
        if b.ts - a.ts <= 1.5 * normal:
            # 하트비트 간격의 작은 흔들림(5.0초 -> 5.1초)이 창 경계에 걸려 생긴 SUSP는 되돌린다
            for w in wins:
                if w.state == "SUSP" and a.ts < w.start and w.start + size <= b.ts \
                        and set(w.missing) <= set(HEARTBEATS):
                    w.state = "QUIET" if w.quiet else "OBS"
            continue
        if b.ts - a.ts <= 2 * normal:
            continue
        restarted = a.meta["start_ts"] != b.meta["start_ts"] or b.meta["n_evts"] < a.meta["n_evts"]
        if restarted:
            state, reason = "LOST", "수집기 재시작 (프로세스 시작 시각 변경)"
        elif b.drops:
            continue  # classify에서 이미 LOST로 처리됨
        else:
            state = "DELAYED"
            reason = (f"하트비트 {b.ts - a.ts:.0f}초 끊김, 커널 카운터 연속 "
                      f"(+{b.meta['n_evts'] - a.meta['n_evts']}건), 드롭 0")
        for w in wins:
            if a.ts <= w.start < b.ts and w.state == "SUSP":
                w.state, w.reason = state, reason


def reconcile_storage(wins, events):
    """하트비트의 '내보낸 이벤트 수'와 로그에 실제로 있는 줄 수를 대조한다.

    부족분(내보냄 - 로그 줄)은 이벤트 시각과 카운트 시각이 어긋나 잠깐 생겼다 사라지기도 하지만,
    로그에서 지워진 줄 때문에 생긴 부족분은 끝까지 남는다. 그래서 각 하트비트에서 '그 뒤로 가장
    낮은 부족분'(영구 부족분)을 보고, 그것이 늘어난 구간을 저장 단계 유실로 본다 (로그 회전 등).
    """
    beats = [e for e in events if e.meta and e.meta.get("exported") is not None]
    raw = sorted(e.ts for e in events if e.meta and e.meta.get("raw"))
    runs = []
    for b in beats:  # 수집기 재시작마다 카운터가 새로 시작하므로 따로 본다
        if runs and runs[-1][-1].meta["start_ts"] == b.meta["start_ts"]:
            runs[-1].append(b)
        else:
            runs.append([b])
    for run in runs:
        if len(run) < 2:
            continue
        acts = [bisect_right(raw, b.ts) for b in run]
        deficit = [(b.meta["exported"] - run[0].meta["exported"]) - (a - acts[0]) for b, a in zip(run, acts)]
        # 영구 부족분: 그 뒤로 가장 낮은 값. 음수(로그가 카운터보다 앞섬)는 늦게 센 것이라 0으로 본다
        permanent = [max(0, min(deficit[i:])) for i in range(len(run))]
        i = 1
        while i < len(run):
            if permanent[i] <= permanent[i - 1]:
                i += 1
                continue
            j = i  # 영구 부족분이 계속 늘어나는 구간을 하나의 유실로 묶는다
            while j + 1 < len(run) and permanent[j + 1] > permanent[j]:
                j += 1
            missing = permanent[j] - permanent[i - 1]
            sent = run[j].meta["exported"] - run[i - 1].meta["exported"]
            if missing >= max(5, 0.02 * sent):
                reason = (f"저장 단계 유실: 수집기는 {sent}건을 내보냈다는데 로그에는 "
                          f"{acts[j] - acts[i - 1]}건 ({missing}건 없음)")
                for w in wins:
                    if run[i - 1].ts <= w.start < run[j].ts and w.state != "LOST":
                        w.state, w.reason = "LOST", reason
            i = j + 1


def heartbeat_script_down(wins, rhythm):
    """Tetragon 하트비트는 따로 도는 스크립트(tetragon_heartbeat.py)라 그것만 죽을 수 있다.
    앞뒤 하트비트로도 설명되지 않은 SUSP 창에서 Tetragon 이벤트가 계속 나오고 있으면,
    Tetragon 자체는 살아 있는 것으로 본다. (Falco metrics는 Falco가 직접 내므로 해당 없음)"""
    for w in wins:
        if w.state == "SUSP" and w.missing == ["tetragon-metrics"] \
                and any(p not in rhythm for p in w.procs):
            w.state = "QUIET" if w.quiet else "OBS"
            w.reason = "하트비트 수집기만 끊김 (Tetragon 이벤트는 계속 나옴)"


def count_heartbeat_drops(events):
    """누적 유실 카운터만 있는 하트비트(Tetragon)는 앞 하트비트와의 차이를 드롭으로 친다."""
    prev = None
    for e in events:
        if not (e.meta and "lost" in e.meta):
            continue
        if prev and prev.meta["start_ts"] == e.meta["start_ts"]:
            e.drops = max(0, e.meta["lost"] - prev.meta["lost"])
        prev = e


def segments(wins):
    """같은 상태가 이어지는 창을 하나의 구간으로 묶는다."""
    segs = []
    for w in wins:
        if segs and segs[-1]["state"] == w.state:
            segs[-1]["wins"].append(w)
        else:
            segs.append({"state": w.state, "wins": [w]})
    return segs


def cross_check(reports):
    """같은 호스트의 다른 수집기를 증인으로 써서 SUSP 창을 가린다.

    모든 보고서는 같은 시간축이라 창 번호가 같으면 같은 시각이다.
    - 증인이 그 시각 건강하게 활동을 봤다(OBS): 뭔가 일어났는데 이 수집기는 못 봤다 -> LOST
    - 증인이 그 시각 건강하게 조용했다(QUIET): 정말 조용했다 -> QUIET
    - 증인도 SUSP/LOST면 도움이 안 된다
    """
    for r in reports:
        peers = [p for p in reports if p.host == r.host and p is not r]
        for i, w in enumerate(r.wins):
            if w.state != "SUSP":
                continue
            for p in peers:
                pw = p.wins[i]
                n = sum(c for proc, c in pw.procs.items() if proc not in p.rhythm)
                if pw.state == "OBS":
                    w.state, w.reason = "LOST", f"교차 확인: 같은 시각 {p.collector}는 활동 {n}건 관측"
                    break
                if pw.state == "QUIET":
                    w.state, w.reason = "QUIET", f"교차 확인: 같은 시각 {p.collector}도 건강하고 조용함"
                    break


def exact_gaps(report, size):
    """공백 구간의 정확한 경계: 구간 앞 마지막 주기 신호 ~ 구간 뒤 첫 주기 신호."""
    ts = [e.ts for e in report.events if e.proc in report.rhythm]
    for s in report.segs:
        s["exact"] = None
        if s["state"] not in ("SUSP", "LOST", "DELAYED") or not ts:
            continue
        lo, hi = s["wins"][0].start, s["wins"][-1].start + size
        if any(lo <= t < hi for t in ts):
            continue  # 구간 안에도 신호가 있다 (예: 하트비트는 살아 있고 드롭만 보고됨)
        before = [t for t in ts if t < lo]
        after = [t for t in ts if t >= hi]
        if before and after:
            s["exact"] = (before[-1], after[0])


def analyze(events, size, ratio):
    """호스트·수집기별로 나눠 분석한다. 모두 같은 시간축을 쓰게 t0/t1을 맞춘다."""
    # 대조용 줄 표시(raw)는 시간축을 정하지 않는다 (Tetragon procFS 줄은 옛 프로세스 시작 시각을 달고 온다)
    real = [e for e in events if not (e.meta and e.meta.get("raw"))]
    t0 = real[0].ts - real[0].ts % size
    t1 = real[-1].ts
    groups = {}
    for ev in events:
        groups.setdefault((ev.host, ev.collector), []).append(ev)
    reports = []
    for (host, collector) in sorted(groups):
        evs = groups[(host, collector)]
        count_heartbeat_drops(evs)
        rhythm = find_rhythm(evs, size, ratio)
        wins = build_windows(evs, size, t0, t1)
        classify(wins, rhythm)
        explain_heartbeat_gaps(wins, evs, size)
        reconcile_storage(wins, evs)
        heartbeat_script_down(wins, rhythm)
        reports.append(HostReport(host, collector, wins, rhythm, evs))
    cross_check(reports)
    for r in reports:
        r.segs = segments(r.wins)
        exact_gaps(r, size)
    return reports


# ---------- 3. 출력 ----------

def hms(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")


def hms1(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S.%f")[:10]


def legend():
    return "  ".join(f"{SYMBOL[s]} {LABEL[s]}" for s in SYMBOL)


def print_timeline(wins, size, per_line=30):
    for i in range(0, len(wins), per_line):
        row = wins[i:i + per_line]
        print(f"  {hms(row[0].start)}  " + "".join(SYMBOL[w.state] for w in row))


def describe(seg, size):
    ws = seg["wins"]
    span = f"{hms(ws[0].start)}–{hms(ws[-1].start + size)}"
    if seg["state"] == "SUSP":
        missing = sorted({p for w in ws for p in w.missing})
        total = sum(sum(w.procs.values()) for w in ws)
        note = f"끊긴 주기 신호: {', '.join(missing) or '없음'} / 다른 이벤트 {total}건"
    elif seg["state"] == "QUIET":
        note = ws[0].reason or "주기 신호는 정상, 다른 활동 거의 없음"
    else:
        note = ws[0].reason
    if seg.get("exact"):
        a, b = seg["exact"]
        note += f" · 신호 공백 {hms1(a)}–{hms1(b)} ({b - a:.1f}초)"
    return span, note


def print_report(reports, size, verdicts):
    print(f"타임라인 (한 칸 = {size}초)   {legend()}")
    for r in reports:
        n = sum(sum(w.procs.values()) for w in r.wins)
        print(f"\n[{r.key}] 이벤트 {n}개, 주기 신호: "
              f"{', '.join(r.rhythm) if r.rhythm else '없음 (조용함과 유실을 구분하기 어려움)'}")
        print_timeline(r.wins, size)
        for i, s in enumerate(r.segs):
            if s["state"] == "OBS":
                continue
            span, note = describe(s, size)
            print(f"  [{s['state']:7}] {span}  {note}")
            v = verdicts.get((r.key, i))
            if v:
                print(f"            └ LLM: {v['verdict']} ({v['confidence']}) {v['reason']}")


def render_html(reports, size, verdicts, path, title):
    """의존성 없는 HTML 한 장. 칸에 마우스를 올리면 그 창의 근거가 보인다."""
    rows = []
    for r in reports:
        seg_of = {}
        for i, s in enumerate(r.segs):
            for w in s["wins"]:
                seg_of[id(w)] = i
        cells = []
        for w in r.wins:
            v = verdicts.get((r.key, seg_of[id(w)]))
            tip = [f"{hms(w.start)} {LABEL[w.state]}",
                   ", ".join(f"{p}×{c}" for p, c in w.procs.most_common()) or "이벤트 없음"]
            if w.reason:
                tip.append(w.reason)
            if v:
                tip.append(f"LLM: {v['verdict']} ({v['confidence']}) {v['reason']}")
            cells.append(f'<i class="{w.state}" title="{html.escape(chr(10).join(tip))}"></i>')
        segs = []
        for i, s in enumerate(r.segs):
            if s["state"] == "OBS":
                continue
            span, note = describe(s, size)
            v = verdicts.get((r.key, i))
            llm = f"{v['verdict']} ({v['confidence']}) {html.escape(v['reason'])}" if v else ""
            segs.append(f'<tr><td><b class="tag {s["state"]}">{LABEL[s["state"]]}</b></td>'
                        f"<td>{span}</td><td>{html.escape(note)}</td><td>{llm}</td></tr>")
        table = (f'<div class="scroll"><table><tr><th>상태</th><th>구간</th><th>근거</th><th>LLM</th></tr>'
                 f'{"".join(segs)}</table></div>' if segs else '<p class="meta">전 구간 관측됨</p>')
        rows.append(f"""<section><h2>{html.escape(r.key)}</h2>
<p class="meta">주기 신호: {html.escape(', '.join(r.rhythm) or '없음')}</p>
<div class="bar">{''.join(cells)}</div>
<div class="axis"><span>{hms(r.wins[0].start)}</span><span>{hms(r.wins[-1].start + size)}</span></div>
{table}
</section>""")
    keys = "".join(f'<span><i class="{s}"></i>{LABEL[s]}</span>' for s in SYMBOL)
    doc = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>관측 공백 타임라인</title>
<style>
:root {{ --bg:#fbfaf8; --fg:#1f1e1c; --muted:#6b6862; --line:#e4e1db;
  --OBS:#3a7d5c; --QUIET:#c9d8cf; --DELAYED:#d9a441; --LOST:#c2452d; --SUSP:#8a63c7; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#1b1a19; --fg:#ecebe8; --muted:#a09d97; --line:#34322f;
  --OBS:#5fae86; --QUIET:#3d4b43; --DELAYED:#e0b25a; --LOST:#e0654b; --SUSP:#a888de; }} }}
body {{ margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system, "Apple SD Gothic Neo", "Noto Sans KR", sans-serif; }}
main {{ max-width:960px; margin:0 auto; }}
h1 {{ font-size:22px; margin:0 0 4px; }} h2 {{ font-size:17px; margin:28px 0 2px; }}
.meta {{ color:var(--muted); margin:0 0 10px; font-size:13px; }}
.keys {{ display:flex; flex-wrap:wrap; gap:14px; font-size:13px; color:var(--muted); }}
.keys i {{ display:inline-block; width:12px; height:12px; border-radius:2px; margin-right:5px; vertical-align:-1px; }}
.bar {{ display:flex; gap:1px; height:34px; }}
.bar i {{ flex:1; min-width:2px; border-radius:2px; cursor:help; }}
.bar i:hover {{ outline:2px solid var(--fg); }}
.axis {{ display:flex; justify-content:space-between; font-size:12px; color:var(--muted); margin-top:4px; }}
.OBS {{ background:var(--OBS); }} .QUIET {{ background:var(--QUIET); }} .DELAYED {{ background:var(--DELAYED); }}
.LOST {{ background:var(--LOST); }} .SUSP {{ background:var(--SUSP); }}
.scroll {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; margin-top:12px; font-size:13px; }}
th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--muted); font-weight:500; }} td:nth-child(2) {{ white-space:nowrap; font-variant-numeric:tabular-nums; }}
.tag {{ display:inline-block; padding:1px 7px; border-radius:10px; color:#fff; font-weight:600; font-size:12px; white-space:nowrap; }}
.tag.QUIET {{ color:var(--fg); }}
</style></head><body><main>
<h1>관측 공백 타임라인</h1><p class="meta">{html.escape(title)} · 한 칸 = {size}초 · 칸에 마우스를 올리면 근거가 보입니다</p>
<div class="keys">{keys}</div>
{''.join(rows)}
</main></body></html>"""
    with open(path, "w") as f:
        f.write(doc)


# ---------- 4. (선택) LLM 판단 ----------

def window_line(w):
    procs = ", ".join(f"{p}×{c}" for p, c in w.procs.most_common())
    return f"{hms(w.start)} state={w.state} drops={w.drops} events=[{procs}]"


VERDICT_SCHEMA = {
    "type": "object",
    "properties": {"items": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "segment_id": {"type": "integer"},
            "verdict": {"type": "string", "enum": ["QUIET", "UNOBSERVED"]},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "reason": {"type": "string"},
        },
        "required": ["segment_id", "verdict", "confidence", "reason"],
        "additionalProperties": False,
    }}},
    "required": ["items"],
    "additionalProperties": False,
}


def ask_llm(report, size, provider, model):
    """한 호스트·수집기의 SUSP 구간을 한 번에 묻는다. 반환: {(key, segment_id): verdict}"""
    targets = [(i, s) for i, s in enumerate(report.segs) if s["state"] == "SUSP"]
    if not targets:
        return {}
    # 로그 전체가 아니라 '창 요약' 전체를 보낸다. 요약이 작아서 긴 맥락을 통째로 볼 수 있다.
    timeline = "\n".join(window_line(w) for w in report.wins)
    asks = "\n".join(f"- segment_id={i}: {describe(s, size)[0]}" for i, s in targets)
    prompt = f"""eBPF 기반 보안 수집기(Falco/Tetragon) 로그 중 호스트 {report.host}의 {report.collector} 기록을 {size}초 창으로 요약한 타임라인이다.
주기 신호로 쓰는 프로세스: {', '.join(report.rhythm) or '(찾지 못함)'}

<timeline>
{timeline}
</timeline>

아래 구간은 드롭 신호가 없는데도 주기 신호가 끊겼다.
각 구간이 실제로는 관측되었거나 아무 일도 없었던 구간(QUIET)인지, 수집기가 보지 못한 구간(UNOBSERVED)인지 판단하라.
구간 안에서 다른 이벤트가 평소 리듬대로 이어졌는지, 앞뒤 창의 활동량, 끊긴 신호의 종류를 근거로 삼고, 근거는 한국어로 짧게 써라.
{asks}"""
    call = call_openai if provider == "openai" else call_anthropic
    text = call(prompt, VERDICT_SCHEMA, model)
    if text is None:
        print(f"  ({report.key}: LLM이 요청을 거절했습니다)")
        return {}
    return {(report.key, it["segment_id"]): it for it in json.loads(text)["items"]}


def ask_llm_votes(report, size, provider, model, n, agree=0.8):
    """같은 질문을 n번 해서, agree 비율 이상 같은 답일 때만 판정으로 쓴다.

    한 번만 물으면 LLM은 가를 근거가 없는 구간에서도 한쪽을 골라 버린다.
    답이 갈리면 UNSURE(판단 보류)로 남긴다.
    """
    runs = [ask_llm(report, size, provider, model) for _ in range(n)]
    out = {}
    for k in {k for r in runs for k in r}:
        votes = Counter(r[k]["verdict"] for r in runs if k in r)
        top, cnt = votes.most_common(1)[0]
        if n == 1 or cnt / n >= agree:
            first = next(r[k] for r in runs if k in r and r[k]["verdict"] == top)
            conf = first["confidence"] if n == 1 else f"{cnt}/{n} 일치"
            out[k] = {**first, "confidence": conf}
        else:
            tally = ", ".join(f"{v} {c}회" for v, c in votes.most_common())
            out[k] = {"segment_id": k[1], "verdict": "UNSURE", "confidence": f"{cnt}/{n}",
                      "reason": f"실행마다 답이 갈려 판단 보류 ({tally})"}
    return out


def call_openai(prompt, schema, model):
    import openai  # --llm을 쓸 때만 필요. 키는 OPENAI_API_KEY 환경 변수에서 읽는다

    resp = openai.OpenAI().chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_schema", "json_schema": {
            "name": "gap_verdicts", "schema": schema, "strict": True}},
    )
    msg = resp.choices[0].message
    return None if msg.refusal else msg.content


def call_anthropic(prompt, schema, model):
    import anthropic  # 키는 ANTHROPIC_API_KEY 환경 변수에서 읽는다

    resp = anthropic.Anthropic().beta.messages.create(
        model=model,
        max_tokens=16000,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",  # 안전 분류기가 거절하면 서버가 다른 모델로 다시 돌린다
        output_config={"format": {"type": "json_schema", "schema": schema}},
        messages=[{"role": "user", "content": prompt}],
    )
    if resp.stop_reason == "refusal":
        return None
    return next(b.text for b in resp.content if b.type == "text")


DEFAULT_MODEL = {"openai": "gpt-5.5", "anthropic": "claude-opus-5"}


# ---------- 5. 실시간 감시 ----------

def send_webhook(url, alert):
    """새 공백을 JSON으로 POST한다. text 필드가 있어 Slack 수신 웹훅에도 그대로 쓸 수 있다."""
    body = json.dumps(alert, ensure_ascii=False).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except OSError as e:
        print(f"  (웹훅 전송 실패: {e})", flush=True)


def prometheus_text(reports, size):
    """호스트·수집기·상태별 누적 공백 시간과, 지금 공백 중인지를 Prometheus 텍스트 형식으로."""
    lines = ["# HELP gapfind_gap_seconds_total 상태별 누적 시간(초)",
             "# TYPE gapfind_gap_seconds_total counter"]
    for r in reports:
        for state in SYMBOL:
            n = sum(1 for w in r.wins if w.state == state) * size
            lines.append(f'gapfind_gap_seconds_total{{host="{r.host}",collector="{r.collector}",'
                         f'state="{state}"}} {n}')
    lines += ["# HELP gapfind_gap_active 마지막 창이 공백(LOST/SUSP/DELAYED)이면 1",
              "# TYPE gapfind_gap_active gauge"]
    for r in reports:
        active = int(bool(r.wins) and r.wins[-1].state in ("LOST", "SUSP", "DELAYED"))
        lines.append(f'gapfind_gap_active{{host="{r.host}",collector="{r.collector}"}} {active}')
    return "\n".join(lines) + "\n"


def serve_metrics(port, latest):
    """latest["text"]를 /metrics로 내보내는 작은 HTTP 서버를 백그라운드로 띄운다."""
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = latest["text"].encode()
            self.send_response(200 if self.path == "/metrics" else 404)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            if self.path == "/metrics":
                self.wfile.write(body)

        def log_message(self, *a):
            pass
    server = HTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def follow(path, size, ratio, every, webhook=None, metrics_port=None):
    """파일을 주기적으로 다시 읽어, 새로 생긴 공백 구간을 한 번씩만 알린다."""
    seen = set()
    latest = {"text": ""}
    if metrics_port:
        serve_metrics(metrics_port, latest)
    print(f"{' + '.join(path)} 감시 중 ({every}초마다 확인, Ctrl-C로 종료)", flush=True)
    while True:
        events = load(path)
        if events:
            reports = analyze(events, size, ratio)
            latest["text"] = prometheus_text(reports, size)
            for r in reports:
                for i, s in enumerate(r.segs):
                    if s["state"] not in ("LOST", "SUSP", "DELAYED"):
                        continue
                    ongoing = i == len(r.segs) - 1
                    key = (r.key, s["wins"][0].start, s["state"], ongoing)
                    if key in seen:
                        continue
                    seen.add(key)
                    span, note = describe(s, size)
                    tag = "진행 중" if ongoing else "종료"
                    text = f"[{r.key}] {LABEL[s['state']]} {span} ({tag}) {note}"
                    print(f"{hms(time.time())} {text}", flush=True)
                    if webhook:
                        send_webhook(webhook, {"text": text, "host": r.host, "collector": r.collector,
                                               "state": s["state"], "span": span, "ongoing": ongoing,
                                               "reason": note})
        time.sleep(every)


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("log", nargs="+", help="Falco/Tetragon JSON lines 파일 (여러 개면 합쳐서 분석)")
    ap.add_argument("--window", type=int, default=10, help="창 크기(초), 기본 10")
    ap.add_argument("--rhythm-ratio", type=float, default=0.7,
                    help="간격이 이 비율 이상 일정한 프로세스를 주기 신호로 봄, 기본 0.7")
    ap.add_argument("--llm", action="store_true", help="SUSP 구간을 LLM에게 판단시킴")
    ap.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    ap.add_argument("--model", help="기본: openai=gpt-5.5, anthropic=claude-opus-5")
    ap.add_argument("--votes", type=int, default=1, help="같은 질문을 N번 해서 답이 갈리면 보류 (기본 1)")
    ap.add_argument("--html", metavar="PATH", help="HTML 타임라인을 이 경로에 저장")
    ap.add_argument("--follow", nargs="?", const=5, type=int, metavar="SEC",
                    help="파일을 계속 감시하며 새 공백을 알림 (기본 5초마다)")
    ap.add_argument("--webhook", metavar="URL", help="--follow에서 새 공백을 이 URL로 POST (Slack 웹훅 호환)")
    ap.add_argument("--metrics-port", type=int, metavar="PORT", help="--follow에서 /metrics를 이 포트로 노출")
    args = ap.parse_args()

    if args.follow:
        try:
            follow(args.log, args.window, args.rhythm_ratio, args.follow, args.webhook, args.metrics_port)
        except KeyboardInterrupt:
            return

    events = load(args.log)
    if not events:
        raise SystemExit("이벤트가 없습니다")
    reports = analyze(events, args.window, args.rhythm_ratio)

    verdicts = {}
    if args.llm:
        model = args.model or DEFAULT_MODEL[args.provider]
        for r in reports:
            verdicts.update(ask_llm_votes(r, args.window, args.provider, model, args.votes))

    print_report(reports, args.window, verdicts)
    if args.html:
        render_html(reports, args.window, verdicts, args.html, " + ".join(args.log))
        print(f"\nHTML: {args.html}")


if __name__ == "__main__":
    main()
