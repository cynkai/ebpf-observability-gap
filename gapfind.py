#!/usr/bin/env python3
"""eBPF 관측 공백 분석기 (Falco / Tetragon JSON 로그)

로그를 시간 창(window)으로 나누고 창마다 네 가지 상태 중 하나로 판정한다.
  OBS    관측됨: 이벤트가 있고 주기 신호도 정상
  QUIET  관측됨, 조용함: 주기 신호(healthcheck 등)만 있음. 수집기는 살아 있었다
  LOST   관측 안 됨(확정): 드롭 신호가 있음
  SUSP   관측 안 됨(추정): 드롭 신호는 없지만 주기 신호가 끊김

사용법:
  python3 gapfind.py sample.jsonl            # 규칙 기반 판정만
  python3 gapfind.py sample.jsonl --llm      # SUSP 구간을 LLM에게 한 번에 보내 판단 (기본 OpenAI)
  python3 gapfind.py sample.jsonl --llm --provider anthropic
"""
import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

SYMBOL = {"OBS": "█", "QUIET": "·", "LOST": "X", "SUSP": "?"}
FALCO_DROP_RULE = "Falco internal: syscall event drop"
FALCO_METRICS_RULE = "Falco internal: metrics snapshot"  # metrics.output_rule=true 일 때


# ---------- 1. 파싱: Falco / Tetragon 줄을 같은 모양으로 ----------

@dataclass
class Event:
    ts: float
    proc: str           # 빈 문자열이면 활동이 아니라 드롭 알림일 뿐
    drops: int = 0      # 0보다 크면 드롭 신호
    source: str = ""


def parse_ts(s):
    # Falco는 나노초(9자리)를 쓰므로 파이썬이 읽을 수 있게 6자리로 자른다
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)?$", s)
    base, frac, tz = m.group(1), (m.group(2) or ".0")[:7], m.group(3) or "Z"
    tz = "+00:00" if tz == "Z" else tz
    return datetime.fromisoformat(base + frac + tz).timestamp()


def parse_line(d):
    ts = parse_ts(d["time"])
    if "rule" in d:  # Falco
        fields = d.get("output_fields", {})
        if d["rule"].startswith(FALCO_DROP_RULE):
            return Event(ts, "", int(fields.get("n_drops", 1)), "falco")
        if d["rule"] == FALCO_METRICS_RULE:
            # 주기적으로 나오므로 주기 신호가 되고, 직전 스냅숏 이후 드롭 수도 알려준다
            n = int(fields.get("scap.n_drops", 0)) - int(fields.get("scap.n_drops_prev", 0))
            return Event(ts, "falco-metrics", max(n, 0), "falco")
        return Event(ts, fields.get("proc.name", "?"), 0, "falco")
    if "rate_limit_info" in d:  # Tetragon 내보내기 단계에서 버린 이벤트
        n = int(d["rate_limit_info"].get("number_of_dropped_process_events", 1))
        return Event(ts, "", n, "tetragon")
    for key, body in d.items():  # process_exec, process_kprobe, ...
        if key.startswith("process_") and isinstance(body, dict):
            binary = body.get("process", {}).get("binary", "?")
            return Event(ts, binary.rsplit("/", 1)[-1], 0, "tetragon")
    return None


def load(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = parse_line(json.loads(line))
            if ev:
                events.append(ev)
    return sorted(events, key=lambda e: e.ts)


# ---------- 2. 창 나누기 + 판정 ----------

@dataclass
class Window:
    start: float
    procs: Counter = field(default_factory=Counter)
    drops: int = 0
    state: str = ""
    missing: list = field(default_factory=list)


def build_windows(events, size):
    t0 = events[0].ts - events[0].ts % size
    n = int((events[-1].ts - t0) // size) + 1
    wins = [Window(t0 + i * size) for i in range(n)]
    for ev in events:
        w = wins[int((ev.ts - t0) // size)]
        w.drops += ev.drops
        if ev.proc:
            w.procs[ev.proc] += 1
    return wins


def find_rhythm(events, size, ratio):
    """일정한 간격으로 반복되는 프로세스 = '수집기가 살아 있다'는 신호로 쓴다.

    자주 나오기만 하는 프로세스(nginx 등)는 제외한다. 간격의 ratio 이상이
    중앙값 ±20% 안에 들고, 주기가 창 크기 이하여야 매 창마다 기대할 수 있다.
    """
    times = {}
    for ev in events:
        if ev.proc:
            times.setdefault(ev.proc, []).append(ev.ts)
    # 수집기가 직접 내는 하트비트가 있으면 그것만 쓴다.
    # 일정하게 도는 워크로드(cron 등)는 멈추는 게 정상일 수 있어서 기준으로 삼으면 안 된다.
    if "falco-metrics" in times:
        return ["falco-metrics"]
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
            w.state = "LOST"
        elif w.missing or (not rhythm and not w.procs):
            w.state = "SUSP"
        elif others(w) <= quiet_limit:
            w.state = "QUIET"
        else:
            w.state = "OBS"
    # Falco 드롭 알림은 '지난 알림 이후 누적 드롭'을 늦게 보고한다.
    # 그래서 알림 바로 앞의 SUSP 창들은 같은 유실로 보고 LOST로 올린다.
    for i, w in enumerate(wins):
        if w.state == "LOST":
            j = i - 1
            while j >= 0 and wins[j].state == "SUSP":
                wins[j].state = "LOST"
                j -= 1


def segments(wins):
    """같은 상태가 이어지는 창을 하나의 구간으로 묶는다."""
    segs = []
    for w in wins:
        if segs and segs[-1]["state"] == w.state:
            segs[-1]["wins"].append(w)
        else:
            segs.append({"state": w.state, "wins": [w]})
    return segs


# ---------- 3. 출력 ----------

def hms(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")


def print_timeline(wins, size, per_line=30):
    print(f"\n타임라인 (한 칸 = {size}초)   {SYMBOL['OBS']} 관측  {SYMBOL['QUIET']} 조용  "
          f"{SYMBOL['LOST']} 유실(확정)  {SYMBOL['SUSP']} 유실(추정)")
    for i in range(0, len(wins), per_line):
        row = wins[i:i + per_line]
        print(f"  {hms(row[0].start)}  " + "".join(SYMBOL[w.state] for w in row))


def describe(seg, size):
    ws = seg["wins"]
    span = f"{hms(ws[0].start)}–{hms(ws[-1].start + size)}"
    note = ""
    if seg["state"] == "LOST":
        note = f"드롭 {sum(w.drops for w in ws)}건 보고됨"
    elif seg["state"] == "SUSP":
        missing = sorted({p for w in ws for p in w.missing})
        total = sum(sum(w.procs.values()) for w in ws)
        note = f"끊긴 주기 신호: {', '.join(missing) or '없음'} / 다른 이벤트 {total}건"
    elif seg["state"] == "QUIET":
        note = "주기 신호는 정상, 다른 활동 거의 없음"
    return span, note


# ---------- 4. (선택) LLM 판단 ----------

def window_line(w):
    procs = ", ".join(f"{p}×{c}" for p, c in w.procs.most_common())
    return f"{hms(w.start)} state={w.state} drops={w.drops} events=[{procs}]"


def ask_llm(wins, segs, rhythm, size, provider, model):
    targets = [(i, s) for i, s in enumerate(segs) if s["state"] == "SUSP"]
    if not targets:
        return {}
    # 로그 전체가 아니라 '창 요약' 전체를 보낸다. 요약이 작아서 긴 맥락을 통째로 볼 수 있다.
    timeline = "\n".join(window_line(w) for w in wins)
    asks = "\n".join(f"- segment_id={i}: {describe(s, size)[0]}" for i, s in targets)
    prompt = f"""eBPF 기반 보안 수집기(Falco/Tetragon) 로그를 {size}초 창으로 요약한 타임라인이다.
주기 신호로 쓰는 프로세스: {', '.join(rhythm) or '(찾지 못함)'}

<timeline>
{timeline}
</timeline>

아래 구간은 드롭 신호가 없는데도 주기 신호가 끊겼다.
각 구간이 정말 아무 일도 없었던 구간(QUIET)인지, 수집기가 보지 못한 구간(UNOBSERVED)인지 판단하라.
앞뒤 창의 활동량, 끊긴 신호의 종류, 다른 프로세스가 계속 보였는지를 근거로 삼고, 근거는 한국어로 짧게 써라.
{asks}"""

    schema = {
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
    call = call_openai if provider == "openai" else call_anthropic
    text = call(prompt, schema, model)
    if text is None:
        print("  (LLM이 요청을 거절했습니다)")
        return {}
    return {it["segment_id"]: it for it in json.loads(text)["items"]}


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


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("log", help="Falco/Tetragon JSON lines 파일")
    ap.add_argument("--window", type=int, default=10, help="창 크기(초), 기본 10")
    ap.add_argument("--rhythm-ratio", type=float, default=0.7,
                    help="간격이 이 비율 이상 일정한 프로세스를 주기 신호로 봄, 기본 0.7")
    ap.add_argument("--llm", action="store_true", help="SUSP 구간을 LLM에게 판단시킴")
    ap.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    ap.add_argument("--model", help="기본: openai=gpt-5.5, anthropic=claude-opus-5")
    args = ap.parse_args()

    events = load(args.log)
    if not events:
        raise SystemExit("이벤트가 없습니다")
    wins = build_windows(events, args.window)
    rhythm = find_rhythm(events, args.window, args.rhythm_ratio)
    classify(wins, rhythm)
    segs = segments(wins)

    print(f"이벤트 {len(events)}개, 창 {len(wins)}개")
    print(f"주기 신호: {', '.join(rhythm) if rhythm else '없음 (조용함과 유실을 구분하기 어려움)'}")
    print_timeline(wins, args.window)

    model = args.model or {"openai": "gpt-5.5", "anthropic": "claude-opus-5"}[args.provider]
    verdicts = ask_llm(wins, segs, rhythm, args.window, args.provider, model) if args.llm else {}

    print("\n구간 목록 (OBS 제외)")
    for i, s in enumerate(segs):
        if s["state"] == "OBS":
            continue
        span, note = describe(s, args.window)
        print(f"  [{s['state']:5}] {span}  {note}")
        if s["state"] == "SUSP" and i in verdicts:
            v = verdicts[i]
            print(f"          └ LLM: {v['verdict']} ({v['confidence']}) {v['reason']}")


if __name__ == "__main__":
    main()
