# 레퍼런스: 설치, 실행, 동작 방식

[← README](../README.md)

## 설치와 실행

```bash
pip install .                     # gapfind, tetragon-heartbeat 명령이 생긴다 (의존성 없음)
pip install ".[openai]"           # LLM 판단까지 쓰려면 (또는 ".[anthropic]")
```

아래 예시는 저장소에서 바로 `python3 gapfind.py`로 돌리는 형태입니다. 설치했다면 `gapfind`로 바꿔 쓰면 됩니다.

```bash
python3 gapfind.py sample.jsonl                       # 규칙 기반 판정 (호스트·수집기별)
python3 gapfind.py falco.jsonl tetragon.jsonl         # 같은 호스트의 두 수집기를 교차 확인
python3 gapfind.py sample.jsonl --html report.html    # HTML 타임라인 (칸에 마우스를 올리면 근거 표시)
python3 gapfind.py falco.jsonl --follow               # 실시간 감시: 새 공백이 생기면 알림
python3 gapfind.py falco.jsonl --follow --webhook URL --metrics-port 9109   # 웹훅 알림 + Prometheus
python3 gapfind.py k8s.jsonl --window 5               # 짧은 공백(수 초)을 보려면 창을 줄인다
python3 eval.py                                       # 정답이 있는 35개 구간으로 정확도 측정
python3 eval.py --chaos real/chaos                    # 자동 장애 주입 실험을 세 가지 증거 조건으로 채점
pytest -q                                             # 회귀 테스트
```

Tetragon은 하트비트를 따로 모아 함께 넘깁니다 ([실험 3](experiments.md#3-tetragon-하트비트-realtetragon_hbsh) 참고).

```bash
tetragon --export-filename tetragon.jsonl --metrics-server :2112
python3 tetragon_heartbeat.py --node <node_name> --out heartbeat.jsonl
python3 gapfind.py tetragon.jsonl heartbeat.jsonl
```

LLM 판단은 선택입니다.

```bash
pip install openai              # 또는 anthropic
export OPENAI_API_KEY=...       # 또는 ANTHROPIC_API_KEY
python3 gapfind.py sample.jsonl --llm                  # 기본 OpenAI gpt-5.5
python3 gapfind.py sample.jsonl --llm --votes 5        # 5번 물어 80% 이상 같은 답일 때만 판정
python3 gapfind.py sample.jsonl --llm --provider anthropic
python3 eval.py --llm --votes 5                        # LLM 포함 정확도
```

## 동작 방식

1. **파싱**: Falco / Tetragon JSON 줄을 같은 이벤트 형태로 바꾸고 **호스트 × 수집기**별로 나눕니다.
   Tetragon이 시작할 때 `/proc`를 훑어 만든 이벤트(`flags: procFS`)와 `process_exit`는 새 활동이 아니라서 뺍니다.
2. **주기 신호 찾기**: 수집기 하트비트(Falco metrics 스냅숏, [tetragon_heartbeat.py](../tetragon_heartbeat.py)가 남긴 Tetragon 메트릭)가 있으면 그것만 씁니다.
   없으면 간격이 일정한 프로세스를 씁니다. 일정하게 도는 워크로드는 멈추는 게 정상일 수 있어서, 하트비트가 있으면 기준으로 삼지 않습니다.
3. **창별 판정**: 드롭이 보고되면 `LOST`, 주기 신호가 끊기면 `SUSP`. 드롭은 늦게 보고되므로 보고 바로 앞의 `SUSP` 창들도 `LOST`로 올립니다.
4. **하트비트 공백 확정**: 끊긴 하트비트 앞뒤를 비교합니다.
   - 프로세스 시작 시각(Falco `falco.start_ts`, Tetragon `process_start_time_seconds`)이 바뀌었거나 커널 카운터가 줄었다 → 수집기 재시작 → `LOST`
   - 카운터가 이어졌고 드롭 0 → 커널은 계속 쌓았고 나중에 처리됨 → `DELAYED`
   - 간격이 평소의 1.5배 이내(5.0초 → 5.1초)면 창 경계에 걸린 흔들림일 뿐이라 `SUSP`로 보지 않음
5. **저장 단계 대조**: 하트비트의 "내보낸 이벤트 수"(Falco `falco.rules.matches_total`, Tetragon `tetragon_events_total`)와 로그에 실제로 있는 줄 수를 비교합니다.
   부족분 중 끝까지 회복되지 않는 부분(영구 부족분)이 늘어난 구간은 로그에서 지워진 것이라 `LOST`로 봅니다. 이벤트 시각과 카운트 시각이 어긋나 잠깐 생기는 부족분은 무시합니다.
6. **하트비트 스크립트만 죽은 경우**: Tetragon 하트비트는 따로 도는 스크립트라 그것만 죽을 수 있습니다. 앞뒤 하트비트로도 설명되지 않는 `SUSP` 창에서 Tetragon 이벤트가 계속 나오면 Tetragon은 살아 있는 것으로 봅니다.
7. **교차 확인**: 남은 `SUSP` 창에서, 같은 호스트의 다른 수집기가 그 시각 건강하게 활동을 봤으면 `LOST`, 건강하게 조용했으면 `QUIET`.
8. **정확한 경계**: 공백 앞 마지막 주기 신호와 뒤 첫 주기 신호로 공백을 초 단위로 적습니다 (예: `신호 공백 10:07:03.0–10:07:28.7 (25.7초)`).
9. **(`--llm`)** 그래도 남은 `SUSP` 구간만, 창 요약 전체와 함께 LLM에게 보내 `QUIET` / `UNOBSERVED`와 근거를 받습니다.
   `--votes N`이면 N번 물어 80% 이상 같은 답일 때만 쓰고, 갈리면 `UNSURE`(보류)로 남깁니다.

## 실시간 감시

`--follow`는 파일을 주기적으로 다시 읽어 새 공백을 한 번씩 알립니다. 하트비트가 끊긴 순간에는 "진행 중"인 추정 유실로 알리고, 이후 로그가 들어오면 확정된 판정을 다시 알립니다.

```
live.jsonl 감시 중 (1초마다 확인, Ctrl-C로 종료)
09:32:50 [node-a/falco] 유실(추정) 09:17:20–09:17:40 (진행 중) 끊긴 주기 신호: falco-metrics / 다른 이벤트 4건
09:32:53 [node-a/falco] 지연 09:17:20–09:17:50 (종료) 하트비트 44초 끊김, 커널 카운터 연속 (+897건), 드롭 0
09:32:53 [node-a/falco] 유실(확정) 09:18:40–09:19:10 (종료) 수집기 재시작 (프로세스 시작 시각 변경)
```

### 알림과 Prometheus

`--webhook URL`은 새 공백마다 JSON을 POST합니다. `text` 필드가 있어 Slack 수신 웹훅에 그대로 쓸 수 있습니다.

```json
{"text": "[node-a/falco] 유실(확정) 09:18:40–09:19:10 (종료) 수집기 재시작 ...", "host": "node-a", "collector": "falco",
 "state": "LOST", "span": "09:18:40–09:19:10", "ongoing": false, "reason": "수집기 재시작 ..."}
```

`--metrics-port 9109`는 `/metrics`로 호스트·수집기·상태별 누적 시간과 지금 공백 중인지를 내보냅니다.

```
gapfind_gap_seconds_total{host="node-a",collector="falco",state="LOST"} 30
gapfind_gap_seconds_total{host="node-a",collector="falco",state="DELAYED"} 30
gapfind_gap_active{host="node-a",collector="falco"} 0
```

## 테스트

`pytest -q`로 파싱, 판정(합성·실제 로그), 교차 확인, 하트비트 흔들림, 저장 단계 대조, Prometheus 출력, LLM 투표, 정확도 회귀("규칙만은 틀리지 않는다")를 확인합니다 (15개). GitHub Actions에서 Python 3.11–3.13으로 테스트와 `eval.py`를 돌립니다. LLM은 키가 필요해서 CI에서는 부르지 않습니다.
