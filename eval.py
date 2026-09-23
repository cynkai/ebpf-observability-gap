#!/usr/bin/env python3
"""정답이 있는 구간으로 판정 정확도를 잰다.

cases.json의 각 구간에 대해 세 방식을 비교한다.
  규칙만        : SUSP는 '판단 보류'로 남김
  규칙+단순     : SUSP를 모두 '관측 안 됨'으로 침 (LLM 없이 할 수 있는 가장 쉬운 방법)
  규칙+LLM      : SUSP를 LLM이 판단 (--llm). --votes N이면 N번 물어 답이 갈리면 보류

사용법:
  python3 eval.py                         # 규칙만 / 규칙+단순
  python3 eval.py --llm                   # + OpenAI gpt-5.5
  python3 eval.py --llm --votes 5         # 5번 물어 80% 이상 같은 답일 때만 판정
  python3 eval.py --llm --provider anthropic
"""
import argparse
import json

import gapfind as g


def to_sec(hms):
    h, m, s = (int(x) for x in hms.split(":"))
    return h * 3600 + m * 60 + s


def pick_report(reports, case):
    """케이스의 호스트(와 있으면 수집기)에 맞는 보고서를 고른다."""
    found = [r for r in reports if r.host == case["host"]
             and case.get("collector") in (None, r.collector)]
    if len(found) != 1:
        raise SystemExit(f"{case['file']} {case['host']}: 보고서가 {len(found)}개 (collector를 지정하세요)")
    return found[0]


def judge(case, report, verdicts):
    """구간 안 창들의 상태로 세 방식의 판정을 낸다."""
    day0 = report.wins[0].start - to_sec(g.hms(report.wins[0].start))
    lo, hi = day0 + to_sec(case["start"]), day0 + to_sec(case["end"])
    states, llm = [], []
    for i, s in enumerate(report.segs):
        for w in s["wins"]:
            if lo <= w.start < hi:
                states.append(w.state)
                if w.state == "SUSP" and verdicts is not None:
                    v = verdicts.get((case["file"], report.key, i))
                    llm.append("undecided" if not v or v["verdict"] == "UNSURE" else
                               "unobserved" if v["verdict"] == "UNOBSERVED" else "observed")
    rule = ("unobserved" if "LOST" in states else
            "undecided" if "SUSP" in states else "observed")
    got = {"규칙만": rule, "규칙+단순": "unobserved" if rule == "undecided" else rule}
    if verdicts is not None:
        got["규칙+LLM"] = rule if rule != "undecided" else (
            "unobserved" if "unobserved" in llm else "undecided" if "undecided" in llm else "observed")
    return got


def run(cases, window=10, llm=None):
    """llm = (provider, model, votes) 이면 LLM 판단까지 포함한다. 반환: (행 목록, 점수)"""
    for c in cases:  # "file"은 파일 하나 또는 함께 분석할 파일 목록, "window"는 케이스별 창 크기
        c["files"] = c["file"] if isinstance(c["file"], list) else [c["file"]]
        c["file"] = " + ".join(c["files"])
        c.setdefault("window", window)
    reports, verdicts = {}, ({} if llm else None)
    for (path, win), files in sorted({(c["file"], c["window"]): c["files"] for c in cases}.items()):
        reports[(path, win)] = g.analyze(g.load(files), win, 0.7)
        if llm:  # 파일·수집기마다 한 번씩만 묻는다
            for r in reports[(path, win)]:
                verdicts.update({(path,) + k: v for k, v in
                                 g.ask_llm_votes(r, win, *llm).items()})

    rows = []
    for c in cases:
        got = judge(c, pick_report(reports[(c["file"], c["window"])], c), verdicts)
        rows.append((c, got))
    cols = list(rows[0][1])
    score = {k: {"correct": sum(got[k] == c["truth"] for c, got in rows),
                 "undecided": sum(got[k] == "undecided" for c, got in rows)} for k in cols}
    for k in cols:
        score[k]["wrong"] = len(rows) - score[k]["correct"] - score[k]["undecided"]
    return rows, score


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cases", default="cases.json")
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    ap.add_argument("--model")
    ap.add_argument("--votes", type=int, default=1)
    args = ap.parse_args()
    llm = (args.provider, args.model or g.DEFAULT_MODEL[args.provider], args.votes) if args.llm else None

    rows, score = run(json.load(open(args.cases)), args.window, llm)
    cols = list(score)
    if llm:
        print(f"LLM: {llm[0]} {llm[1]}, 구간마다 {llm[2]}번 질문\n")
    print(f"{'구간':46} {'정답':10} " + " ".join(f"{c:12}" for c in cols))
    for c, got in rows:
        def mark(k):
            return ("- " if got[k] == "undecided" else "O " if got[k] == c["truth"] else "X ") + got[k]
        who = c["host"] + (f"/{c['collector']}" if c.get("collector") else "")
        label = f"{c['files'][0].split('/')[-1]} {who} {c['start']}–{c['end']}"
        print(f"{label:46} {c['truth']:10} " + " ".join(f"{mark(k):12}" for k in cols))
        print(f"{'':46} └ {c['note']}")

    print("\n정답 수 (O 정답 / X 오답 / - 보류)")
    for k in cols:
        s = score[k]
        print(f"  {k:8} {s['correct']}/{len(rows)}  (오답 {s['wrong']}, 보류 {s['undecided']})")


if __name__ == "__main__":
    main()
