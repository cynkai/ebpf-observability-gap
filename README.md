# ebpf-observability-gap

Falco / Tetragon 로그에서 **"아무 일도 없었던 구간"과 "관측되지 않은 구간"을 구분**하는 작은 분석기입니다.

보안 로그가 비어 있을 때, 그게 정말 조용했던 건지 수집기가 못 본 건지는 로그만 봐서는 알 수 없습니다.
이 도구는 기계적으로 확정할 수 있는 증거로 먼저 판정하고, 증거가 없는 구간만 LLM에게 넘깁니다.

- **드롭 카운터**: Falco drop 알림·metrics, Tetragon `rate_limit_info`·Prometheus 유실 카운터
- **수집기 하트비트**: 끊긴 앞뒤로 프로세스 시작 시각과 커널 이벤트 카운터를 비교
- **교차 확인**: 같은 호스트의 다른 수집기가 그 시각 무엇을 봤는지

| 상태 | 뜻 | 근거 |
|---|---|---|
| `OBS` █ | 관측됨 | 이벤트가 있고 주기 신호도 정상 |
| `QUIET` · | 관측됨, 조용함 | 주기 신호는 살아 있고 다른 활동은 거의 없음, 또는 같은 호스트의 다른 수집기도 건강하게 조용함 |
| `DELAYED` ~ | 관측됨, 지연 | 하트비트는 끊겼지만 커널 카운터가 이어졌고 드롭 0 (나중에 처리됨) |
| `LOST` X | 관측 안 됨 (확정) | 드롭 보고, 수집기 재시작(프로세스 시작 시각 변경), 또는 같은 호스트의 다른 수집기는 그 시각 활동을 봄 |
| `SUSP` ? | 관측 안 됨 (추정) | 증거 없이 주기 신호만 끊김 → `--llm`으로 판단 |

## 결과 요약

정답이 있는 26개 구간(합성 4 + 실제 로그 22)에서, **규칙만으로 21개를 맞히고 틀린 것은 0개**입니다.
나머지 5개는 하트비트도 다른 수집기도 없는 로그라 판단을 보류합니다.

| 방식 | 정답 | 오답 | 보류 |
|---|---|---|---|
| 규칙만 (`SUSP`는 판단 보류) | 21 | 0 | 5 |
| 규칙 + 단순 (`SUSP`를 모두 "관측 안 됨"으로) | 24 | 2 | 0 |

LLM은 보류한 5개에서만 쓰이는데, 3번 돌린 결과 **가를 근거가 없는 두 구간에 매번 같은 답을 내고 방향만 바뀌었습니다** ([아래](#llm-판단)).
판단을 바꾼 건 LLM보다 **수집기 쪽 증거(하트비트, 교차 확인)** 였습니다.

## 실행

```bash
python3 gapfind.py sample.jsonl                       # 규칙 기반 판정 (호스트·수집기별)
python3 gapfind.py falco.jsonl tetragon.jsonl         # 같은 호스트의 두 수집기를 교차 확인
python3 gapfind.py sample.jsonl --html report.html    # HTML 타임라인 (칸에 마우스를 올리면 근거 표시)
python3 gapfind.py falco.jsonl --follow               # 실시간 감시: 새 공백이 생기면 알림
python3 gapfind.py k8s.jsonl --window 5               # 짧은 공백(수 초)을 보려면 창을 줄인다
python3 eval.py                                       # 정답이 있는 26개 구간으로 정확도 측정
pytest -q                                             # 회귀 테스트
```

Tetragon은 하트비트를 따로 모아 함께 넘깁니다 ([Tetragon 하트비트](#3-tetragon-하트비트-realtetragon_hbsh) 참고).

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
2. **주기 신호 찾기**: 수집기 하트비트(Falco metrics 스냅숏, [tetragon_heartbeat.py](tetragon_heartbeat.py)가 남긴 Tetragon 메트릭)가 있으면 그것만 씁니다.
   없으면 간격이 일정한 프로세스를 씁니다. 일정하게 도는 워크로드는 멈추는 게 정상일 수 있어서, 하트비트가 있으면 기준으로 삼지 않습니다.
3. **창별 판정**: 드롭이 보고되면 `LOST`, 주기 신호가 끊기면 `SUSP`. 드롭은 늦게 보고되므로 보고 바로 앞의 `SUSP` 창들도 `LOST`로 올립니다.
4. **하트비트 공백 확정**: 끊긴 하트비트 앞뒤를 비교합니다.
   - 프로세스 시작 시각(Falco `falco.start_ts`, Tetragon `process_start_time_seconds`)이 바뀌었거나 커널 카운터가 줄었다 → 수집기 재시작 → `LOST`
   - 카운터가 이어졌고 드롭 0 → 커널은 계속 쌓았고 나중에 처리됨 → `DELAYED`
   - 간격이 평소의 1.5배 이내(5.0초 → 5.1초)면 창 경계에 걸린 흔들림일 뿐이라 `SUSP`로 보지 않음
5. **교차 확인**: 남은 `SUSP` 창에서, 같은 호스트의 다른 수집기가 그 시각 건강하게 활동을 봤으면 `LOST`, 건강하게 조용했으면 `QUIET`.
6. **정확한 경계**: 공백 앞 마지막 주기 신호와 뒤 첫 주기 신호로 공백을 초 단위로 적습니다 (예: `신호 공백 10:07:03.0–10:07:28.7 (25.7초)`).
7. **(`--llm`)** 그래도 남은 `SUSP` 구간만, 창 요약 전체와 함께 LLM에게 보내 `QUIET` / `UNOBSERVED`와 근거를 받습니다.
   `--votes N`이면 N번 물어 80% 이상 같은 답일 때만 쓰고, 갈리면 `UNSURE`(보류)로 남깁니다.

## 실제 로그 실험

Docker Desktop(macOS, linuxkit 커널 7.0, arm64, 10코어)에서 돌렸습니다. 스크립트와 로그는 [real/](real/)에 있고, 각 실험의 HTML 타임라인(`real/*.html`)은 내려받아 브라우저로 열면 됩니다.

### 1. Falco 수집기 장애 ([real/outage.sh](real/outage.sh))

Falco 0.45.0(modern_ebpf) 두 대를 띄우고, 3초마다 `/etc/shadow`를 읽는 워크로드(`Read sensitive file untrusted` 규칙에 걸림)를 돌리면서 node-a만 두 번 멈췄습니다. node-b는 대조군입니다.
Falco는 기본적으로 규칙에 걸릴 때만 로그를 남기므로 `metrics`를 켜서 하트비트를 얻었습니다.

```bash
falco -o engine.kind=modern_ebpf -o json_output=true \
      -o metrics.enabled=true -o metrics.interval=5s -o metrics.output_rule=true
```

```
[node-a/falco] 이벤트 80개, 주기 신호: falco-metrics
  09:16:30  █████~~~█████XXX·████
  [DELAYED] 09:17:20–09:17:50  하트비트 44초 끊김, 커널 카운터 연속 (+897건), 드롭 0 · 신호 공백 09:17:11.3–09:17:55.4 (44.1초)
  [LOST   ] 09:18:40–09:19:10  수집기 재시작 (프로세스 시작 시각 변경) · 신호 공백 09:18:35.5–09:19:16.6 (41.2초)

[node-b/falco] 이벤트 108개, 주기 신호: falco-metrics
  09:16:30  █████████████████████
```

| 구간 | 한 일 | 실제로 일어난 일 | 판정 |
|---|---|---|---|
| 09:17:20–09:17:50 | `docker pause` 40초 | 커널은 계속 링버퍼에 쌓았고 재개 후 늦게 처리됨. 3초 간격 알림이 빠짐없이 있음 | `DELAYED` ✓ |
| 09:18:40–09:19:10 | 컨테이너 삭제 후 재시작 | 수집기가 없어서 아무것도 기록되지 않음. 드롭을 셀 주체도 없어 드롭 신호도 없음 | `LOST` ✓ |

### 2. Tetragon, 하트비트 없음 ([real/tetragon.sh](real/tetragon.sh))

Tetragon v1.6.0 내보내기에는 하트비트가 없어서, 3초마다 도는 워크로드(`cat`, `sleep`)가 주기 신호가 됩니다.

```
[tg-node/tetragon] 이벤트 111개, 주기 신호: cat, sleep
  09:20:10  ?█···█???█····???█···█
  [SUSP   ] 09:20:10–09:20:20  (정답: 관측됨, 워크로드 시작 전)
  [SUSP   ] 09:21:10–09:21:40  (정답: 관측됨, 워크로드 중지)
  [SUSP   ] 09:22:30–09:23:00  (정답: 관측 안 됨, Tetragon 삭제)
```

셋 다 "워크로드 리듬이 끊김"으로 똑같이 보여서 규칙으로는 가를 수 없습니다. 이 셋이 정확도 표의 보류 5개 중 3개입니다.

### 3. Tetragon 하트비트 ([real/tetragon_hb.sh](real/tetragon_hb.sh))

Tetragon의 유실 카운터는 JSON 내보내기에는 없고 Prometheus 메트릭(`--metrics-server`)에만 있습니다.
[tetragon_heartbeat.py](tetragon_heartbeat.py)가 5초마다 메트릭을 읽어 JSON 한 줄씩 남기고, 분석기는 이것을 Falco metrics와 같은 하트비트로 씁니다.
Tetragon이 응답하지 않으면 아무것도 쓰지 않아서, 하트비트가 끊긴 것 자체가 신호가 됩니다.

| 필드 | 메트릭 | 쓰임 |
|---|---|---|
| `start_ts` | `process_start_time_seconds` | 바뀌면 수집기 재시작 |
| `events_received` | `tetragon_observer_ringbuf_events_received_total` | 끊김 앞뒤로 이어지면 늦게 처리된 것 |
| `lost_total` | `…ringbuf_events_lost_total` + `…ringbuf_queue_events_lost_total` + `tetragon_missed_*_probes_total` + `tetragon_export_ratelimit_events_dropped_total` | 늘어나면 드롭 |

```
[tg-node/tetragon] 이벤트 202개, 주기 신호: tetragon-metrics
  09:45:10  █████···█████~~~~████XXXX████
  [QUIET  ] 09:46:00–09:46:30  워크로드 중지 ✓
  [DELAYED] 09:47:20–09:48:00  docker pause: 하트비트 45초 끊김, 커널 카운터 연속 (+96건), 드롭 0 ✓
  [LOST   ] 09:48:40–09:49:20  컨테이너 삭제: 수집기 재시작 (프로세스 시작 시각 변경) ✓
```

2번에서 가르지 못한 "워크로드 중지"와 "수집기 중지"를 하트비트가 있으면 규칙만으로 모두 맞힙니다.

### 4. 실제 드롭 재현 + Falco·Tetragon 교차 확인 ([real/cross.sh](real/cross.sh))

같은 호스트(`lab`)에서 Falco와 Tetragon(하트비트 없이)을 함께 돌렸습니다.

- **드롭 재현**: CPU 여유가 있을 때는 링버퍼를 가장 작게 해도 폭주를 따라잡아 드롭이 0이었습니다 ([real/scenario.sh](real/scenario.sh)). 폭주 동안 `docker update --cpus 0.05`로 Falco를 CPU 5%로 묶자 **5초마다 수십만 건씩 실제 드롭**이 났습니다.
- **교차 확인**: Tetragon의 리듬이 끊긴 시각에 Falco가 무엇을 봤는지로 가립니다.

```
[lab/falco] 주기 신호: falco-metrics
  09:57:10  ·████XXXXX███····████████████·
  [LOST   ] 09:58:00–09:58:50  드롭 908595건 보고됨                          ← CPU 5% + 폭주
  [QUIET  ] 09:59:20–10:00:00  주기 신호는 정상, 다른 활동 거의 없음          ← 워크로드 중지

[lab/tetragon] 주기 신호: sleep
  09:57:10  ·XXXX?████████···████·XXX█████
  [LOST   ] 09:57:20–09:58:00  교차 확인: 같은 시각 falco는 활동 3건 관측     ← Tetragon 아직 준비 중
  [SUSP   ] 09:58:00–09:58:10  끊긴 주기 신호: sleep                         ← Falco도 드롭 중이라 증인 없음
  [QUIET  ] 09:59:30–10:00:00  교차 확인: 같은 시각 falco도 건강하고 조용함   ← 워크로드 중지 ✓
  [LOST   ] 10:00:50–10:01:20  교차 확인: 같은 시각 falco는 활동 3건 관측     ← Tetragon 삭제 ✓
```

- 하트비트가 없는 Tetragon에서도 "워크로드 중지"(`QUIET`)와 "수집기 중지"(`LOST`)가 교차 확인으로 갈렸습니다.
- 첫 `LOST`는 의도한 장애가 아니었습니다. Tetragon의 첫 이벤트가 09:58:14로, 켜지는 데 1분 가까이 걸렸고 그동안 Falco는 워크로드를 보고 있었습니다.
- **잡지 못한 것**: 폭주 구간(09:57:59–09:58:40) 동안 Tetragon은 폭주 프로세스의 exec를 마지막 1초치만 남겼습니다. 앞의 약 26초는 **JSON에 아무 드롭 신호 없이** 빠졌습니다. 워크로드 리듬은 이어져서 규칙도 교차 확인도 잡지 못합니다. 3번의 Tetragon 하트비트(유실 카운터)가 필요한 경우입니다.

### 5. Kubernetes (kind) ([real/k8s/](real/k8s/))

kind 클러스터(워커 2대)에 Falco(차트 9.2.0)와 Tetragon(차트 1.7.1)을 DaemonSet으로 올리고, 워커마다 같은 워크로드를 돌렸습니다.
파드가 재시작돼도 로그가 이어지도록, 각 노드의 `/gaplogs`를 kind `extraMounts`로 Mac 폴더에 붙였습니다 ([kind.yaml](real/k8s/kind.yaml), [falco-values.yaml](real/k8s/falco-values.yaml), [run.sh](real/k8s/run.sh)).

```bash
kind create cluster --name gap --config real/k8s/kind.yaml
helm install falco falcosecurity/falco --version 9.2.0 -n falco --create-namespace -f real/k8s/falco-values.yaml
helm install tetragon cilium/tetragon --version 1.7.1 -n kube-system
# Tetragon 차트 1.7.1은 exportDirectory 값을 쓰지 않아서, export-logs 볼륨의 hostPath를 /gaplogs/tetragon으로 직접 바꿨습니다
kubectl apply -f real/k8s/workload.yaml
sh real/k8s/run.sh
python3 gapfind.py real/k8s/k8s.jsonl --window 5
```

```
[gap-worker/falco]
  [LOST   ] 10:07:05–10:07:25  수집기 재시작 (프로세스 시작 시각 변경) · 신호 공백 10:07:03.0–10:07:28.7 (25.7초)
[gap-worker/tetragon]          (같은 시각 정상)
[gap-worker2/falco]            (같은 시각 정상)
[gap-worker2/tetragon]
  [LOST   ] 10:08:25–10:08:30  교차 확인: 같은 시각 falco는 활동 2건 관측 · 신호 공백 10:08:24.7–10:08:30.7 (6.0초)
```

| 구간 | 한 일 | 판정 |
|---|---|---|
| gap-worker Falco 10:07:05–10:07:25 | Falco 파드 삭제 → DaemonSet이 약 25초 만에 다시 띄움 | `LOST` (재시작) ✓ |
| gap-worker2 Tetragon 10:08:25–10:08:30 | Tetragon 파드 삭제 → 약 6초 만에 다시 뜸 | `LOST` (교차 확인) ✓ |
| 두 노드 Tetragon 10:10:20–10:10:25 | 워크로드 DaemonSet 삭제 → 새로 뜨기 전 약 13초 조용함 | `QUIET` (교차 확인) ✓ |

실제 클러스터에서 배운 것:

- **공백이 짧습니다.** DaemonSet이 파드를 바로 다시 띄워서 Tetragon 공백은 6초였습니다. 기본 10초 창에서는 보이지 않아 `--window 5`로 봐야 합니다.
  5초 창은 5초 하트비트의 작은 흔들림(5.1초)을 공백으로 오인했는데, 하트비트 간격이 평소의 1.5배 이내면 공백으로 보지 않게 고쳤습니다.
- **조용한 구간도 짧습니다.** 워크로드를 지워도 셸이 SIGTERM을 무시해 30초 유예 뒤에야 멈췄고, 실제로 조용했던 건 13초였습니다.
- **로그를 비울 때 조심해야 합니다.** Tetragon은 파일을 연 채 원래 위치에 이어 써서, 앞에서 비운 부분이 NUL 바이트(약 125KB)로 채워졌습니다. 분석기는 NUL을 걸러 읽습니다.
- kind 노드는 같은 Docker VM 커널을 공유하는 컨테이너라, 노드마다 커널이 다른 실제 클러스터와는 다릅니다.

## 정확도 ([eval.py](eval.py), [cases.json](cases.json))

| 묶음 | 구간 | 규칙만 |
|---|---|---|
| 합성 샘플 | 4 | 2 맞힘, 2 보류 |
| Falco 단독 (조용함, 폭주, 장애 2대) | 5 | 5 맞힘 |
| Tetragon 하트비트 없음 | 3 | 3 보류 |
| Tetragon 하트비트 | 3 | 3 맞힘 |
| Falco + Tetragon 교차 | 5 | 5 맞힘 |
| Kubernetes (5초 창) | 6 | 6 맞힘 |
| **합계** | **26** | **21 맞힘, 0 틀림, 5 보류** |

"규칙+단순"(보류를 모두 유실로)은 24개를 맞히지만, 2번 실험의 "정말 조용한" Tetragon 두 구간을 유실로 잘못 봅니다.

### LLM 판단

보류된 5개 구간(합성 2 + 하트비트 없는 Tetragon 3)만 LLM에게 갑니다. 아래는 이 5개를 OpenAI `gpt-5.5`로 3번 돌린 결과입니다(`--votes` 도입 전, 한 번씩 질문).

| 구간 | 정답 | 규칙+단순 | LLM 1, 2회차 | LLM 3회차 |
|---|---|---|---|---|
| 합성: 드롭 신호 없는 전체 블랙아웃 | 관측 안 됨 | ✓ | ✓ | ✓ |
| 합성: healthcheck만 사라진 부분 유실 | 관측 안 됨 | ✓ | ✗ | ✗ |
| Tetragon: 막 켜졌고 워크로드 시작 전 | 관측됨 | ✗ | ✓ | ✓ |
| Tetragon: 워크로드를 멈춘 조용한 40초 | 관측됨 | ✗ | ✗ 관측 안 됨 | ✓ 관측됨 |
| Tetragon: 수집기 삭제 | 관측 안 됨 | ✓ | ✓ 관측 안 됨 | ✗ 관측됨 |

- **Tetragon "워크로드 중지" vs "수집기 중지"**: LLM은 매번 두 구간에 같은 답을 냈고, 회차에 따라 방향만 바뀌었습니다. 로그 안에 둘을 가를 정보가 없기 때문이고, 하트비트(3번)나 교차 확인(4번)을 더하자 규칙만으로 풀렸습니다.
- **Tetragon이 막 켜진 구간**은 3회 모두 맞혔습니다. 앞뒤 흐름에서 워크로드가 아직 시작 전이라는 걸 읽은 것으로 보입니다.
- **합성 부분 유실**은 3회 모두 틀렸습니다. 프롬프트의 "주기 신호가 워크로드라면 워크로드가 멈춘 것일 수도 있다"는 문장이 healthcheck가 멈춘 경우에도 적용된 것으로 보입니다.
- 이런 "한쪽으로 찍기"를 막으려고 `--votes`를 넣었습니다. 같은 질문을 N번 해서 80% 이상 같은 답일 때만 판정하고, 갈리면 `UNSURE`로 보류합니다. `python3 eval.py --llm --votes 5`로 잴 수 있으며, 아직 실제 LLM으로 측정하지 않았습니다.
- 샘플은 이후 순수 Tetragon 로그로 다시 만들어서(아래 참고) 합성 2개 구간의 LLM 결과는 이전 샘플 기준입니다.

마지막 실행의 전체 출력은 [eval_llm.txt](eval_llm.txt)에 있습니다 (15개 구간 시절).

### LLM 출력 예시

이전 샘플, OpenAI `gpt-5.5`. `SUSP` 구간 아래에 판정, 확신도, 근거가 붙습니다.

```
  [SUSP   ] 10:07:30–10:08:10  끊긴 주기 신호: healthcheck / 다른 이벤트 0건
            └ LLM: UNOBSERVED (high) 직전/직후에는 nginx·curl·python3와 healthcheck가 정상적으로 보이는데, 해당 4개 창은 drops=0이어도 모든 이벤트가 비어 있고 healthcheck도 끊겼다. 실제 quiet라기보다 수집 공백에 가깝다.
```

## 합성 샘플 ([make_sample.py](make_sample.py))

호스트 하나(node-1)의 Tetragon 로그 10분 분량입니다. 처음에는 Falco 알림을 섞었는데, 수집기별로 나눠 분석하면서 Falco의 드롭이 Tetragon의 드롭이 아니게 되어 순수 Tetragon 로그로 바꿨습니다.

```
[node-1/tetragon] 이벤트 651개, 주기 신호: healthcheck
  10:00:00  ████████████········██████████
  10:05:00  XXXXX██████████????█████???███
  [QUIET  ] 10:02:00–10:03:20  주기 신호는 정상, 다른 활동 거의 없음
  [LOST   ] 10:05:00–10:05:50  드롭 18342건 보고됨
  [SUSP   ] 10:07:30–10:08:10  끊긴 주기 신호: healthcheck / 다른 이벤트 0건 · 신호 공백 10:07:25.1–10:08:10.1 (45.0초)
  [SUSP   ] 10:09:00–10:09:30  끊긴 주기 신호: healthcheck / 다른 이벤트 36건 · 신호 공백 10:08:55.1–10:09:30.1 (35.0초)
```

## 실시간 감시

`--follow`는 파일을 주기적으로 다시 읽어 새 공백을 한 번씩 알립니다. 하트비트가 끊긴 순간에는 "진행 중"인 추정 유실로 알리고, 이후 로그가 들어오면 확정된 판정을 다시 알립니다.

```
live.jsonl 감시 중 (1초마다 확인, Ctrl-C로 종료)
09:32:50 [node-a/falco] 유실(추정) 09:17:20–09:17:40 (진행 중) 끊긴 주기 신호: falco-metrics / 다른 이벤트 4건
09:32:53 [node-a/falco] 지연 09:17:20–09:17:50 (종료) 하트비트 44초 끊김, 커널 카운터 연속 (+897건), 드롭 0
09:32:53 [node-a/falco] 유실(확정) 09:18:40–09:19:10 (종료) 수집기 재시작 (프로세스 시작 시각 변경)
```

## 테스트

`pytest -q`로 파싱, 판정(합성·실제 로그), 교차 확인, 하트비트 흔들림, LLM 투표, 정확도 회귀("규칙만은 틀리지 않는다")를 확인합니다. GitHub Actions에서 Python 3.11–3.13으로 테스트와 `eval.py`를 돌립니다. LLM은 키가 필요해서 CI에서는 부르지 않습니다.

## 한계

- 실제 로그는 모두 한 대의 Mac 위 Docker VM에서 나왔습니다. kind 클러스터도 노드들이 같은 커널을 공유합니다.
- 창 크기, 주기 판정 비율, 조용함 기준, 교차 확인 규칙은 이 실험들에 맞춘 값입니다. 특히 교차 확인은 두 수집기가 같은 종류의 활동을 본다고 가정합니다. 한쪽만 보는 활동(예: Tetragon만 보는 백그라운드 exec)이 많으면 오판할 수 있습니다.
- 하트비트도 교차 확인도 없는 로그에서는 여전히 판단을 보류하거나 LLM에 기대야 하고, LLM은 이 경우 믿을 만하지 않았습니다.
