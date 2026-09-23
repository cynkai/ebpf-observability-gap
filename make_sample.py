#!/usr/bin/env python3
"""테스트용 Tetragon JSON 로그를 만든다 (10분 분량, 호스트 node-1 하나).

심어 둔 구간:
  120~200초  조용함     : 업무 이벤트 없음, healthcheck만 계속 나옴
  300~340초  확정 유실  : 이벤트 없음 + 340초에 Tetragon rate_limit_info (버린 이벤트 수)
  450~490초  은밀한 유실: 이벤트 없음, 드롭 신호도 없음
  540~570초  부분 유실  : 업무 이벤트는 있는데 healthcheck만 사라짐
"""
import json
import random
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 9, 23, 10, 0, 0, tzinfo=timezone.utc)
DURATION = 600
random.seed(7)


def iso(sec):
    return (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def tetragon_exec(sec, binary):
    return {"process_exec": {"process": {"pid": random.randint(1000, 60000),
                                         "binary": binary}},
            "node_name": "node-1", "time": iso(sec)}


def tetragon_drop(sec, n):
    return {"rate_limit_info": {"number_of_dropped_process_events": str(n)},
            "node_name": "node-1", "time": iso(sec)}


def in_range(s, a, b):
    return a <= s < b


events = []
for sec in range(DURATION):
    blackout = in_range(sec, 300, 340) or in_range(sec, 450, 490)
    if blackout:
        continue
    # 5초마다 도는 헬스체크 (주기 신호)
    if sec % 5 == 0 and not in_range(sec, 540, 570):
        events.append(tetragon_exec(sec + 0.1, "/usr/bin/healthcheck"))
    # 30초마다 cron
    if sec % 30 == 0:
        events.append(tetragon_exec(sec + 0.2, "/usr/sbin/cron"))
    # 업무 트래픽 (조용한 구간 제외)
    if not in_range(sec, 120, 200) and random.random() < 0.6:
        for _ in range(random.randint(1, 3)):
            events.append(tetragon_exec(sec + random.random(),
                                        random.choice(["/usr/sbin/nginx", "/usr/bin/curl",
                                                       "/usr/bin/python3"])))

# 확정 유실: 드롭은 끝난 뒤 한 번에 보고된다
events.append(tetragon_drop(340.0, 18342))

events.sort(key=lambda e: e["time"])
with open("sample.jsonl", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")
print(f"sample.jsonl: {len(events)}줄")
