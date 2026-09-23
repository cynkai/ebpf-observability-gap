#!/usr/bin/env python3
"""정답이 있는 구간으로 판정 정확도를 잰다.

cases.json의 각 구간에 대해 세 방식을 비교한다.
  규칙만        : SUSP는 '판단 보류'로 남김
  규칙+단순     : SUSP를 모두 '관측 안 됨'으로 침 (LLM 없이 할 수 있는 가장 쉬운 방법)
  규칙+LLM      : SUSP를 LLM이 판단 (--llm)

사용법:
  python3 eval.py                         # 규칙만 / 규칙+단순
  python3 eval.py --llm                   # + OpenAI gpt-5.5
  python3 eval.py --llm --provider anthropic
"""
import argparse
import json

import gapfind as g

OBSERVED = {"OBS", "QUIET", "DELAYED"}


def rule_verdict(states):
    if "LOST" in states:
        return "unobserved"
    if "SUSP" in states:
        return "undecided"
    return "observed"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cases", default="cases.json")
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
    ap.add_argument("--model")
    args = ap.parse_args()
    model = args.model or g.DEFAULT_MODEL[args.provider]

    cases = json.load(open(args.cases))
    reports, verdicts = {}, {}
    for path in sorted({c["file"] for c in cases}):
        reports[path] = {r.host: r for r in g.analyze(g.load(path), args.window, 0.7)}
        if args.llm:  # 파일·호스트마다 한 번씩만 묻는다
            for r in reports[path].values():
                verdicts.update({(path,) + k: v for k, v in
                                 g.ask_llm(r, args.window, args.provider, model).items()})

    cols = ["규칙만", "규칙+단순"] + (["규칙+LLM"] if args.llm else [])
    score = {c: 0 for c in cols}
    wrong = {c: 0 for c in cols}
    print(f"{'구간':44} {'정답':10} " + " ".join(f"{c:10}" for c in cols))
    for c in cases:
        r = reports[c["file"]][c["host"]]
        day = g.hms(r.wins[0].start)  # 케이스 시각은 HH:MM:SS, 같은 날로 본다
        base = r.wins[0].start - sum(int(x) * m for x, m in zip(day.split(":"), (3600, 60, 1)))
        lo = base + sum(int(x) * m for x, m in zip(c["start"].split(":"), (3600, 60, 1)))
        hi = base + sum(int(x) * m for x, m in zip(c["end"].split(":"), (3600, 60, 1)))

        states, llm = [], []
        for i, s in enumerate(r.segs):
            for w in s["wins"]:
                if lo <= w.start < hi:
                    states.append(w.state)
                    v = verdicts.get((c["file"], c["host"], i))
                    if w.state == "SUSP":
                        llm.append("undecided" if not v else
                                   "unobserved" if v["verdict"] == "UNOBSERVED" else "observed")
        rule = rule_verdict(states)
        got = {"규칙만": rule,
               "규칙+단순": "unobserved" if rule == "undecided" else rule}
        if args.llm:
            got["규칙+LLM"] = rule if rule != "undecided" else (
                "unobserved" if "unobserved" in llm else "undecided" if "undecided" in llm else "observed")
        for k in cols:
            score[k] += got[k] == c["truth"]
            wrong[k] += got[k] not in (c["truth"], "undecided")
        mark = lambda k: ("- " if got[k] == "undecided" else  # noqa: E731
                          "O " if got[k] == c["truth"] else "X ") + got[k]
        label = f"{c['file'].split('/')[-1]} {c['host']} {c['start']}–{c['end']}"
        print(f"{label:44} {c['truth']:10} " + " ".join(f"{mark(k):10}" for k in cols))
        print(f"{'':44} └ {c['note']}")

    print("\n정답 수 (O 정답 / X 오답 / - 보류)")
    for k in cols:
        held = len(cases) - score[k] - wrong[k]
        print(f"  {k:8} {score[k]}/{len(cases)}  (오답 {wrong[k]}, 보류 {held})")


if __name__ == "__main__":
    main()
