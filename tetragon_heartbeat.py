#!/usr/bin/env python3
"""Tetragon 하트비트 수집기.

Tetragon JSON 내보내기에는 Falco metrics 같은 하트비트가 없다. 그래서 Prometheus
메트릭(--metrics-server)을 주기적으로 읽어 JSON 한 줄씩 남긴다. gapfind.py는 이 줄을
Falco metrics 스냅숏과 같은 방식으로 쓴다.
  - process_start_time_seconds 가 바뀜      -> 수집기 재시작 (그 사이 LOST)
  - 커널 이벤트 카운터가 이어지고 유실 0    -> 늦게 처리됨 (DELAYED)
  - 유실 카운터 증가                          -> LOST

Tetragon이 응답하지 않으면 아무것도 쓰지 않는다. 하트비트가 끊긴 것 자체가 신호다.

사용법:
  python3 tetragon_heartbeat.py --node tg-node --out heartbeat.jsonl
  python3 gapfind.py tetragon.jsonl heartbeat.jsonl
"""
import argparse
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone

# 합쳐서 '유실'로 보는 카운터들 (레이블이 달린 것은 모두 더한다)
LOST_METRICS = (
    "tetragon_observer_ringbuf_events_lost_total",
    "tetragon_observer_ringbuf_queue_events_lost_total",
    "tetragon_missed_prog_probes_total",
    "tetragon_missed_link_probes_total",
    "tetragon_export_ratelimit_events_dropped_total",
)
RECEIVED_METRIC = "tetragon_observer_ringbuf_events_received_total"


def scrape(url):
    """Prometheus 텍스트 형식을 {이름: 레이블 무시하고 더한 값}으로 읽는다."""
    text = urllib.request.urlopen(url, timeout=3).read().decode()
    totals = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name_labels, _, value = line.rpartition(" ")
        name = name_labels.split("{", 1)[0]
        totals[name] = totals.get(name, 0) + float(value)
    return totals


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default="http://localhost:2112/metrics")
    ap.add_argument("--node", required=True, help="Tetragon의 node_name과 같게 맞춘다")
    ap.add_argument("--out", required=True)
    ap.add_argument("--interval", type=float, default=5)
    args = ap.parse_args()

    while True:
        try:
            m = scrape(args.url)
        except OSError as e:
            print(f"{datetime.now():%H:%M:%S} 응답 없음: {e}", file=sys.stderr, flush=True)
        else:
            row = {
                "tetragon_heartbeat": {
                    "start_ts": m.get("process_start_time_seconds"),
                    "events_received": int(m.get(RECEIVED_METRIC, 0)),
                    "lost_total": int(sum(m.get(k, 0) for k in LOST_METRICS)),
                },
                "node_name": args.node,
                "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            }
            with open(args.out, "a") as f:
                f.write(json.dumps(row) + "\n")
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
