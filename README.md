# ebpf-observability-gap

Falco / Tetragon 로그에서 **"아무 일도 없었던 구간"과 "관측되지 않은 구간"을 구분**하는 작은 분석기입니다.

보안 로그가 비어 있을 때, 그게 정말 조용했던 건지 수집기가 못 본 건지는 로그만 봐서는 알 수 없습니다.
이 도구는 기계적으로 확정할 수 있는 증거(드롭 카운터, 수집기 재시작, 커널 카운터 연속성)로 먼저 판정하고,
증거가 없는 구간만 LLM에게 넘깁니다.

| 상태 | 뜻 | 근거 |
|---|---|---|
| `OBS` █ | 관측됨 | 이벤트가 있고 주기 신호도 정상 |
| `QUIET` · | 관측됨, 조용함 | 주기 신호는 살아 있고 다른 활동은 거의 없음 |
| `DELAYED` ~ | 관측됨, 지연 | 하트비트는 끊겼지만 커널 카운터가 이어졌고 드롭 0 (나중에 처리됨) |
| `LOST` X | 관측 안 됨 (확정) | 드롭 신호(Falco drop 알림, 하트비트의 유실 카운터 증가, Tetragon `rate_limit_info`), 또는 수집기 재시작(프로세스 시작 시각 변경) |
| `SUSP` ? | 관측 안 됨 (추정) | 증거 없이 주기 신호만 끊김 → `--llm`으로 판단 |

## 실행

```bash
python3 gapfind.py sample.jsonl                     # 규칙 기반 판정 (호스트별)
python3 gapfind.py sample.jsonl --html report.html  # HTML 타임라인 (칸에 마우스를 올리면 근거 표시)
python3 gapfind.py falco.jsonl --follow             # 실시간 감시: 새 공백이 생기면 알림
python3 eval.py                                     # 정답이 있는 15개 구간으로 정확도 측정
```

Tetragon은 하트비트를 따로 모아 함께 넘깁니다 (아래 [Tetragon 하트비트](#tetragon-하트비트-realtetragon_hbsh) 참고).

```bash
tetragon --export-filename tetragon.jsonl --metrics-server :2112
python3 tetragon_heartbeat.py --node <node_name> --out heartbeat.jsonl
python3 gapfind.py tetragon.jsonl heartbeat.jsonl   # 파일 여러 개를 합쳐서 분석
```

LLM 판단은 선택입니다.

```bash
pip install openai              # 또는 anthropic
export OPENAI_API_KEY=...       # 또는 ANTHROPIC_API_KEY
python3 gapfind.py sample.jsonl --llm                        # 기본 OpenAI gpt-5.5
python3 gapfind.py sample.jsonl --llm --provider anthropic   # Claude
python3 eval.py --llm                                        # LLM 포함 정확도
```

## 동작 방식

1. **파싱**: Falco / Tetragon JSON 줄을 같은 이벤트 형태로 바꾸고 호스트(Falco `hostname`, Tetragon `node_name`)별로 나눕니다.
   Tetragon이 시작할 때 `/proc`를 훑어 만든 이벤트(`flags: procFS`)와 `process_exit`는 새 활동이 아니라서 뺍니다.
2. **주기 신호 찾기**: 수집기 하트비트(Falco metrics 스냅숏, [tetragon_heartbeat.py](tetragon_heartbeat.py)가 남긴 Tetragon 메트릭)가 있으면 그것만 씁니다.
   없으면 간격이 일정한 프로세스를 씁니다. 일정하게 도는 워크로드는 멈추는 게 정상일 수 있어서, 수집기 자신의 하트비트가 있으면 기준으로 삼지 않습니다.
3. **창별 판정**: 드롭이 보고되면 `LOST`, 주기 신호가 끊기면 `SUSP`. 드롭은 늦게 보고되므로 보고 바로 앞의 `SUSP` 창들도 `LOST`로 올립니다.
4. **하트비트 공백 확정**: 끊긴 하트비트 앞뒤 스냅숏을 비교합니다.
   - 프로세스 시작 시각(Falco `falco.start_ts`, Tetragon `process_start_time_seconds`)이 바뀌었거나 커널 카운터가 줄었다 → 수집기 재시작 → `LOST`
   - 카운터가 이어졌고 드롭 0 → 커널은 계속 쌓았고 나중에 처리됨 → `DELAYED`
5. **(`--llm`)** 남은 `SUSP` 구간만, 호스트의 창 요약 전체와 함께 LLM에게 보내 `QUIET` / `UNOBSERVED`와 근거를 받습니다.

## 실제 로그 실험

Docker Desktop(macOS, linuxkit 커널 7.0, arm64)에서 돌렸습니다. 스크립트와 로그는 [real/](real/)에 있습니다.

### Falco: 수집기 장애 ([real/outage.sh](real/outage.sh))

Falco 0.45.0(modern_ebpf) 두 대를 띄우고, 3초마다 `/etc/shadow`를 읽는 워크로드(`Read sensitive file untrusted` 규칙에 걸림)를 돌리면서 node-a만 두 번 멈췄습니다. node-b는 대조군입니다.
Falco는 기본적으로 규칙에 걸릴 때만 로그를 남기므로 `metrics`를 켜서 하트비트를 얻었습니다.

```bash
falco -o engine.kind=modern_ebpf -o json_output=true \
      -o metrics.enabled=true -o metrics.interval=5s -o metrics.output_rule=true
```

```
[node-a] 이벤트 80개, 주기 신호: falco-metrics
  09:16:30  █████~~~█████XXX·████
  [DELAYED] 09:17:20–09:17:50  하트비트 44초 끊김, 커널 카운터 연속 (+897건), 드롭 0
  [LOST   ] 09:18:40–09:19:10  수집기 재시작 (프로세스 시작 시각 변경)
  [QUIET  ] 09:19:10–09:19:20  주기 신호는 정상, 다른 활동 거의 없음

[node-b] 이벤트 108개, 주기 신호: falco-metrics
  09:16:30  █████████████████████
```

| 구간 | 한 일 | 실제로 일어난 일 | 판정 |
|---|---|---|---|
| 09:17:20–09:17:50 | `docker pause` 40초 | 커널은 계속 링버퍼에 쌓았고 재개 후 늦게 처리됨. 3초 간격 알림이 빠짐없이 있음 | `DELAYED` ✓ |
| 09:18:40–09:19:10 | 컨테이너 삭제 후 재시작 | 수집기가 없어서 아무것도 기록되지 않음. 드롭을 셀 주체도 없어 드롭 신호도 없음 | `LOST` ✓ |

두 구간 모두 "하트비트가 끊겼고 드롭 신호는 없음"이라, 처음 버전에서는 둘 다 `SUSP`였습니다.
metrics 스냅숏의 `falco.start_ts`와 `scap.n_evts` 연속성을 보면서 LLM 없이 확정할 수 있게 됐습니다.

HTML 타임라인: [real/falco_outage.html](real/falco_outage.html) (내려받아 브라우저로 열기)

### Tetragon: 하트비트 없는 경우 ([real/tetragon.sh](real/tetragon.sh))

Tetragon v1.6.0 내보내기에는 하트비트가 없어서, 3초마다 도는 워크로드(`cat`, `sleep`)가 주기 신호가 됩니다.

```
[tg-node] 이벤트 111개, 주기 신호: cat, sleep
  09:20:10  ?█···█???█····???█···█
  [SUSP   ] 09:20:10–09:20:20  끊긴 주기 신호: cat, sleep / 다른 이벤트 2건
  [SUSP   ] 09:21:10–09:21:40  끊긴 주기 신호: cat, sleep / 다른 이벤트 1건
  [SUSP   ] 09:22:30–09:23:00  끊긴 주기 신호: cat, sleep / 다른 이벤트 0건
```

| 구간 | 실제로 일어난 일 | 정답 |
|---|---|---|
| 09:20:10–09:20:20 | Tetragon은 막 켜졌고 워크로드 시작 전 | 관측됨 |
| 09:21:10–09:21:40 | 워크로드를 멈춤 (정말 조용함) | 관측됨 |
| 09:22:30–09:23:00 | Tetragon 컨테이너 삭제 (수집기 꺼짐) | 관측 안 됨 |

셋 다 "워크로드 리듬이 끊김"으로 똑같이 보여서 규칙으로는 가를 수 없습니다. 아래 정확도에서 보듯 LLM도 가르지 못했습니다.

### Tetragon 하트비트 ([real/tetragon_hb.sh](real/tetragon_hb.sh))

Tetragon의 유실 카운터는 JSON 내보내기에는 없고 Prometheus 메트릭(`--metrics-server`)에만 있습니다.
[tetragon_heartbeat.py](tetragon_heartbeat.py)가 5초마다 메트릭을 읽어 JSON 한 줄씩 남기고, 분석기는 이것을 Falco metrics와 같은 하트비트로 씁니다.

| 필드 | 메트릭 | 쓰임 |
|---|---|---|
| `start_ts` | `process_start_time_seconds` | 바뀌면 수집기 재시작 |
| `events_received` | `tetragon_observer_ringbuf_events_received_total` | 끊김 앞뒤로 이어지면 늦게 처리된 것 |
| `lost_total` | `…ringbuf_events_lost_total` + `…ringbuf_queue_events_lost_total` + `tetragon_missed_*_probes_total` + `tetragon_export_ratelimit_events_dropped_total` | 늘어나면 드롭 |

Tetragon이 응답하지 않으면 아무것도 쓰지 않아서, 하트비트가 끊긴 것 자체가 신호가 됩니다.
같은 워크로드에 pause 단계를 더해 다시 돌렸습니다.

```bash
python3 gapfind.py real/tetragon_hb.jsonl real/tetragon_hb_heartbeat.jsonl
```

```
[tg-node] 이벤트 202개, 주기 신호: tetragon-metrics
  09:45:10  █████···█████~~~~████XXXX████
  [QUIET  ] 09:46:00–09:46:30  주기 신호는 정상, 다른 활동 거의 없음
  [DELAYED] 09:47:20–09:48:00  하트비트 45초 끊김, 커널 카운터 연속 (+96건), 드롭 0
  [LOST   ] 09:48:40–09:49:20  수집기 재시작 (프로세스 시작 시각 변경)
```

| 구간 | 한 일 | 판정 |
|---|---|---|
| 09:46:00–09:46:30 | 워크로드 중지 (정말 조용함) | `QUIET` ✓ |
| 09:47:20–09:48:00 | `docker pause tetragon` 40초 | `DELAYED` ✓ |
| 09:48:40–09:49:20 | Tetragon 컨테이너 삭제 후 재시작 | `LOST` ✓ |

하트비트가 없을 때 규칙도 LLM도 가르지 못한 "워크로드 중지"와 "수집기 중지"를, 하트비트가 있으면 규칙만으로 모두 맞힙니다.

HTML 타임라인: [real/tetragon_hb.html](real/tetragon_hb.html)

### 부하로 드롭 유도는 실패 ([real/scenario.sh](real/scenario.sh))

링버퍼를 가장 작게(`engine.modern_ebpf.buf_size_preset=1`) 두고 syscall 폭주(`dd`), exec/open 폭주를 1분씩 걸었지만 드롭은 0건이었습니다.
Falco는 read/write를 기본으로 수집하지 않고, 10코어 환경에서는 exec/open 폭주도 따라잡았습니다. 이 로그들은 "조용함"과 "부하 중 정상 관측" 정답 케이스로 씁니다.

## 정확도 ([eval.py](eval.py), [cases.json](cases.json))

합성 4개 + 실제 Falco 5개 + 실제 Tetragon(하트비트 없음) 3개 + 실제 Tetragon(하트비트) 3개, 정답이 있는 15개 구간입니다.

| 방식 | 정답 | 오답 | 보류 |
|---|---|---|---|
| 규칙만 (`SUSP`는 판단 보류) | 10 | 0 | 5 |
| 규칙 + 단순 (`SUSP`를 모두 "관측 안 됨"으로) | 13 | 2 | 0 |
| 규칙 + LLM (OpenAI, `eval.py` 기본 모델 `gpt-5.5`) | 13 | 2 | 0 |

- **규칙만**은 틀리지 않고, 보류한 5개는 모두 하트비트가 없는 로그(합성 2개, Tetragon 3개)입니다. 하트비트가 있는 로그 8개는 규칙만으로 모두 맞혔습니다.
- **규칙+단순**은 하트비트 없는 Tetragon의 두 "정말 조용한" 구간을 유실로 잘못 봅니다(오탐).
- **규칙+LLM**도 13개로 점수는 같지만, 틀린 곳이 다르고 실행마다 바뀝니다.

### LLM 판단 (3회 실행)

LLM에게 넘어간 5개 `SUSP` 구간의 결과입니다. 마지막 실행의 전체 출력은 [eval_llm.txt](eval_llm.txt)에 있습니다.

| 구간 | 정답 | 규칙+단순 | LLM 1, 2회차 | LLM 3회차 |
|---|---|---|---|---|
| 합성: 드롭 신호 없는 전체 블랙아웃 | 관측 안 됨 | ✓ | ✓ | ✓ |
| 합성: healthcheck만 사라진 부분 유실 | 관측 안 됨 | ✓ | ✗ | ✗ |
| Tetragon: 막 켜졌고 워크로드 시작 전 | 관측됨 | ✗ | ✓ | ✓ |
| Tetragon: 워크로드를 멈춘 조용한 40초 | 관측됨 | ✗ | ✗ 관측 안 됨 | ✓ 관측됨 |
| Tetragon: 수집기 삭제 | 관측 안 됨 | ✓ | ✓ 관측 안 됨 | ✗ 관측됨 |

해석:

- **Tetragon "워크로드 중지" vs "수집기 중지"**: LLM은 매번 두 구간에 **같은 답**을 냈고, 회차에 따라 둘 다 "관측 안 됨"이거나 둘 다 "관측됨"이었습니다. 점수가 같아 보여도 실제로는 둘을 가르지 못하고 한쪽으로 찍고 있습니다. 로그 안에 둘을 가를 정보가 없기 때문이고, 하트비트를 더하자 규칙만으로 풀렸습니다.
- **Tetragon이 막 켜진 구간**은 3회 모두 맞혔습니다. 앞뒤 흐름에서 워크로드가 아직 시작 전이라는 걸 읽은 것으로 보입니다.
- **합성 부분 유실**은 3회 모두 "관측됨"으로 틀렸습니다. 이전 프롬프트로 돌렸을 때는 `UNOBSERVED (medium)`이었습니다. 프롬프트에 넣은 "주기 신호가 워크로드라면 워크로드가 멈춘 것일 수도 있다"는 문장이 healthcheck가 멈춘 경우에도 적용된 것으로 보입니다.
- 결론: 이 실험에서 LLM이 확실히 더한 가치는 1개 구간입니다. 판단을 바꾼 건 LLM보다 **수집기 하트비트**였습니다. 정답이 있는 LLM 판단 구간이 5개뿐이라 일반화하기는 어렵습니다.

### LLM 출력 예시

`sample.jsonl`, OpenAI `gpt-5.5`. `SUSP` 구간 아래에 판정, 확신도, 근거가 붙습니다.

```
  [SUSP   ] 10:07:30–10:08:10  끊긴 주기 신호: healthcheck / 다른 이벤트 0건
            └ LLM: UNOBSERVED (high) 직전/직후에는 nginx·curl·python3와 healthcheck가 정상적으로 보이는데, 해당 4개 창은 drops=0이어도 모든 이벤트가 비어 있고 healthcheck도 끊겼다. 실제 quiet라기보다 수집 공백에 가깝다.
  [SUSP   ] 10:09:00–10:09:30  끊긴 주기 신호: healthcheck / 다른 이벤트 45건
            └ LLM: UNOBSERVED (medium) 구간 동안 nginx·curl·python3 등 다른 이벤트는 계속 보이지만 주기 신호인 healthcheck만 사라졌다. 아무 일도 없는 quiet는 아니며, healthcheck 관측이 빠진 부분 관측 실패로 판단된다.
```

근거 문장은 실행할 때마다 조금씩 달라집니다.

## 실시간 감시

`--follow`는 파일을 주기적으로 다시 읽어 새 공백을 한 번씩 알립니다. 하트비트가 끊긴 순간에는 "진행 중"인 추정 유실로 알리고, 이후 로그가 들어오면 확정된 판정을 다시 알립니다.

```
live.jsonl 감시 중 (1초마다 확인, Ctrl-C로 종료)
09:32:50 [node-a] 유실(추정) 09:17:20–09:17:40 (진행 중) 끊긴 주기 신호: falco-metrics / 다른 이벤트 4건
09:32:53 [node-a] 지연 09:17:20–09:17:50 (종료) 하트비트 44초 끊김, 커널 카운터 연속 (+897건), 드롭 0
09:32:53 [node-a] 유실(확정) 09:18:40–09:19:10 (종료) 수집기 재시작 (프로세스 시작 시각 변경)
```

## 한계

- 창 크기, 주기 판정 비율, 조용함 기준은 이 실험들에 맞춘 값입니다.
- 실제 로그는 한 대의 Mac 위 Docker VM에서 나온 짧은 로그입니다. 여러 노드가 실제로 다른 커널을 보는 클러스터에서는 확인하지 않았습니다.
- 부하로 인한 드롭은 재현하지 못했습니다. 드롭 판정은 합성 데이터로만 확인됐습니다.
