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
  python3 gapfind.py tetragon.jsonl heartbeat.jsonl  # 여러 파일을 합쳐서 (Tetragon + 하트비트)
"""
import argparse
import html
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
            meta = {"start_ts": fields.get("falco.start_ts"), "n_evts": fields.get("scap.n_evts", 0)}
            return Event(ts, host, "falco-metrics", max(n, 0), meta)
        return Event(ts, host, fields.get("proc.name", "?"))
    host = d.get("node_name", "?")  # Tetragon
    if "tetragon_heartbeat" in d:
        # 유실 카운터는 누적값이라, 드롭 수는 analyze에서 앞 하트비트와 비교해 구한다
        hb = d["tetragon_heartbeat"]
        meta = {"start_ts": hb["start_ts"], "n_evts": hb["events_received"], "lost": hb["lost_total"]}
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
            line = line.strip()
            if not line:
                continue
            try:
                ev = parse_line(json.loads(line))
            except (json.JSONDecodeError, KeyError):
                continue  # --follow 중에 반쯤 쓰인 줄이 올 수 있다
            if ev:
                events.append(ev)
    return events


# ---------- 2. 창 나누기 + 판정 ----------

@dataclass
class Window:
    start: float
    procs: Counter = field(default_factory=Counter)
    drops: int = 0
    state: str = ""
    missing: list = field(default_factory=list)
    reason: str = ""


@dataclass
class HostReport:
    host: str
    wins: list
    rhythm: list
    segs: list = field(default_factory=list)


def build_windows(events, size, t0, t1):
    wins = [Window(t0 + i * size) for i in range(int((t1 - t0) // size) + 1)]
    for ev in events:
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
        if w.drops:
            w.state, w.reason = "LOST", f"드롭 {w.drops}건 보고됨"
        elif w.missing or (not rhythm and not w.procs):
            w.state = "SUSP"
        elif others(w) <= quiet_limit:
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


def explain_heartbeat_gaps(wins, events):
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


def analyze(events, size, ratio):
    """호스트별로 나눠 분석한다. 모든 호스트가 같은 시간축을 쓰게 t0/t1을 맞춘다."""
    t0 = events[0].ts - events[0].ts % size
    t1 = events[-1].ts
    by_host = {}
    for ev in events:
        by_host.setdefault(ev.host, []).append(ev)
    reports = []
    for host in sorted(by_host):
        evs = by_host[host]
        count_heartbeat_drops(evs)
        rhythm = find_rhythm(evs, size, ratio)
        wins = build_windows(evs, size, t0, t1)
        classify(wins, rhythm)
        explain_heartbeat_gaps(wins, evs)
        reports.append(HostReport(host, wins, rhythm, segments(wins)))
    return reports


# ---------- 3. 출력 ----------

def hms(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")


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
        return span, f"끊긴 주기 신호: {', '.join(missing) or '없음'} / 다른 이벤트 {total}건"
    if seg["state"] == "QUIET":
        return span, "주기 신호는 정상, 다른 활동 거의 없음"
    return span, ws[0].reason


def print_report(reports, size, verdicts):
    print(f"타임라인 (한 칸 = {size}초)   {legend()}")
    for r in reports:
        n = sum(sum(w.procs.values()) for w in r.wins)
        print(f"\n[{r.host}] 이벤트 {n}개, 주기 신호: "
              f"{', '.join(r.rhythm) if r.rhythm else '없음 (조용함과 유실을 구분하기 어려움)'}")
        print_timeline(r.wins, size)
        for i, s in enumerate(r.segs):
            if s["state"] == "OBS":
                continue
            span, note = describe(s, size)
            print(f"  [{s['state']:7}] {span}  {note}")
            v = verdicts.get((r.host, i))
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
            v = verdicts.get((r.host, seg_of[id(w)]))
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
            v = verdicts.get((r.host, i))
            llm = f"{v['verdict']} ({v['confidence']}) {html.escape(v['reason'])}" if v else ""
            segs.append(f'<tr><td><b class="tag {s["state"]}">{LABEL[s["state"]]}</b></td>'
                        f"<td>{span}</td><td>{html.escape(note)}</td><td>{llm}</td></tr>")
        table = (f'<div class="scroll"><table><tr><th>상태</th><th>구간</th><th>근거</th><th>LLM</th></tr>'
                 f'{"".join(segs)}</table></div>' if segs else '<p class="meta">전 구간 관측됨</p>')
        rows.append(f"""<section><h2>{html.escape(r.host)}</h2>
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
    """한 호스트의 SUSP 구간을 한 번에 묻는다. 반환: {(host, segment_id): verdict}"""
    targets = [(i, s) for i, s in enumerate(report.segs) if s["state"] == "SUSP"]
    if not targets:
        return {}
    # 로그 전체가 아니라 '창 요약' 전체를 보낸다. 요약이 작아서 긴 맥락을 통째로 볼 수 있다.
    timeline = "\n".join(window_line(w) for w in report.wins)
    asks = "\n".join(f"- segment_id={i}: {describe(s, size)[0]}" for i, s in targets)
    prompt = f"""eBPF 기반 보안 수집기(Falco/Tetragon) 로그 중 호스트 {report.host}의 기록을 {size}초 창으로 요약한 타임라인이다.
주기 신호로 쓰는 프로세스: {', '.join(report.rhythm) or '(찾지 못함)'}
주기 신호가 수집기 자신의 하트비트가 아니라 워크로드라면, 워크로드가 멈춘 것일 수도 있다.

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
        print(f"  ({report.host}: LLM이 요청을 거절했습니다)")
        return {}
    return {(report.host, it["segment_id"]): it for it in json.loads(text)["items"]}


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

def follow(path, size, ratio, every):
    """파일을 주기적으로 다시 읽어, 새로 생긴 공백 구간을 한 번씩만 알린다."""
    seen = set()
    print(f"{' + '.join(path)} 감시 중 ({every}초마다 확인, Ctrl-C로 종료)", flush=True)
    while True:
        events = load(path)
        if events:
            for r in analyze(events, size, ratio):
                for i, s in enumerate(r.segs):
                    if s["state"] not in ("LOST", "SUSP", "DELAYED"):
                        continue
                    ongoing = i == len(r.segs) - 1
                    key = (r.host, s["wins"][0].start, s["state"], ongoing)
                    if key in seen:
                        continue
                    seen.add(key)
                    span, note = describe(s, size)
                    tag = "진행 중" if ongoing else "종료"
                    print(f"{hms(time.time())} [{r.host}] {LABEL[s['state']]} {span} ({tag}) {note}", flush=True)
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
    ap.add_argument("--html", metavar="PATH", help="HTML 타임라인을 이 경로에 저장")
    ap.add_argument("--follow", nargs="?", const=5, type=int, metavar="SEC",
                    help="파일을 계속 감시하며 새 공백을 알림 (기본 5초마다)")
    args = ap.parse_args()

    if args.follow:
        try:
            follow(args.log, args.window, args.rhythm_ratio, args.follow)
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
            verdicts.update(ask_llm(r, args.window, args.provider, model))

    print_report(reports, args.window, verdicts)
    if args.html:
        render_html(reports, args.window, verdicts, args.html, " + ".join(args.log))
        print(f"\nHTML: {args.html}")


if __name__ == "__main__":
    main()
