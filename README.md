# ebpf-observability-gap

Falco / Tetragon 로그에서 **"아무 일도 없었던 구간"과 "관측되지 않은 구간"을 구분**하는 작은 분석기입니다.

보안 로그가 비어 있을 때, 그게 정말 조용했던 건지 수집기가 못 본 건지는 로그만 봐서는 알 수 없습니다.
이 도구는 기계적으로 확정할 수 있는 증거로 먼저 판정하고, 증거가 없는 구간만 LLM에게 넘깁니다.

- **드롭 카운터**: Falco drop 알림·metrics, Tetragon `rate_limit_info`·Prometheus 유실 카운터
- **수집기 하트비트**: 끊긴 앞뒤로 프로세스 시작 시각과 커널 이벤트 카운터를 비교
- **교차 확인**: 같은 호스트의 다른 수집기가 그 시각 무엇을 봤는지
- **저장 단계 대조**: 수집기가 "내보냈다"고 센 이벤트 수와 로그에 실제로 남은 줄 수 (로그 회전 등으로 지워진 것)

| 상태 | 뜻 | 근거 |
|---|---|---|
| `OBS` █ | 관측됨 | 이벤트가 있고 주기 신호도 정상 |
| `QUIET` · | 관측됨, 조용함 | 주기 신호는 살아 있고 다른 활동은 거의 없음, 또는 같은 호스트의 다른 수집기도 건강하게 조용함 |
| `DELAYED` ~ | 관측됨, 지연 | 하트비트는 끊겼지만 커널 카운터가 이어졌고 드롭 0 (나중에 처리됨) |
| `LOST` X | 관측 안 됨 (확정) | 드롭 보고, 수집기 재시작(프로세스 시작 시각 변경), 같은 호스트의 다른 수집기는 그 시각 활동을 봄, 또는 내보낸 이벤트가 로그에서 지워짐 |
| `SUSP` ? | 관측 안 됨 (추정) | 증거 없이 주기 신호만 끊김 → `--llm`으로 판단 |

## 결과 요약

**손으로 정답을 매긴 35개 구간** (합성 4 + 실제 로그 31)

| 방식 | 정답 | 오답 | 보류 |
|---|---|---|---|
| 규칙만 (`SUSP`는 판단 보류) | 30 | 0 | 5 |
| 규칙 + 단순 (`SUSP`를 모두 "관측 안 됨"으로) | 33 | 2 | 0 |

보류 5개는 하트비트도 다른 수집기도 없는 로그(합성 2, 하트비트 없는 Tetragon 3)입니다.

**자동 장애 주입 30분, 장애 27개** ([8번](#8-자동-장애-주입-realchaos)). 장애 7종을 무작위로 넣고 정답을 자동으로 기록했습니다.

| 증거 조건 | 구간 | 규칙만 |
|---|---|---|
| 하트비트 + 교차 확인 | 48 | **48 맞힘** |
| 교차 확인만 (Tetragon 하트비트 없음) | 48 | **48 맞힘** |
| Tetragon 단독 | 21 | 18 맞힘, 3 보류, 0 틀림 |

LLM은 보류된 구간에서만 쓰이는데, 여러 번 돌려 보니 **가를 근거가 없는 구간에서는 답이 실행마다 바뀌었습니다** ([아래](#llm-판단)).
판단을 바꾼 건 LLM보다 **수집기 쪽 증거(하트비트, 교차 확인, 저장 단계 대조)** 였습니다.

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
5. **저장 단계 대조**: 하트비트의 "내보낸 이벤트 수"(Falco `falco.rules.matches_total`, Tetragon `tetragon_events_total`)와 로그에 실제로 있는 줄 수를 비교합니다.
   부족분 중 끝까지 회복되지 않는 부분(영구 부족분)이 늘어난 구간은 로그에서 지워진 것이라 `LOST`로 봅니다. 이벤트 시각과 카운트 시각이 어긋나 잠깐 생기는 부족분은 무시합니다.
6. **하트비트 스크립트만 죽은 경우**: Tetragon 하트비트는 따로 도는 스크립트라 그것만 죽을 수 있습니다. 앞뒤 하트비트로도 설명되지 않는 `SUSP` 창에서 Tetragon 이벤트가 계속 나오면 Tetragon은 살아 있는 것으로 봅니다.
7. **교차 확인**: 남은 `SUSP` 창에서, 같은 호스트의 다른 수집기가 그 시각 건강하게 활동을 봤으면 `LOST`, 건강하게 조용했으면 `QUIET`.
8. **정확한 경계**: 공백 앞 마지막 주기 신호와 뒤 첫 주기 신호로 공백을 초 단위로 적습니다 (예: `신호 공백 10:07:03.0–10:07:28.7 (25.7초)`).
9. **(`--llm`)** 그래도 남은 `SUSP` 구간만, 창 요약 전체와 함께 LLM에게 보내 `QUIET` / `UNOBSERVED`와 근거를 받습니다.
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
  [LOST   ] 09:57:20–09:58:00  교차 확인: 같은 시각 falco는 활동 3건 관측     ← 저장된 로그에 Tetragon 이벤트 없음
  [SUSP   ] 09:58:00–09:58:10  끊긴 주기 신호: sleep                         ← Falco도 드롭 중이라 증인 없음
  [QUIET  ] 09:59:30–10:00:00  교차 확인: 같은 시각 falco도 건강하고 조용함   ← 워크로드 중지 ✓
  [LOST   ] 10:00:50–10:01:20  교차 확인: 같은 시각 falco는 활동 3건 관측     ← Tetragon 삭제 ✓
```

- 하트비트가 없는 Tetragon에서도 "워크로드 중지"(`QUIET`)와 "수집기 중지"(`LOST`)가 교차 확인으로 갈렸습니다.
- 첫 `LOST`는 의도한 장애가 아니었습니다. 저장된 로그에서 Tetragon의 첫 이벤트는 09:58:14이고, 그전에 Falco는 워크로드를 보고 있었습니다.
  처음에는 Tetragon이 늦게 켜진 것으로 봤지만, 아래의 로그 회전을 확인한 뒤로는 이 구간의 이벤트가 담긴 첫 파일이 가장 먼저 지워졌을 가능성이 더 높다고 봅니다. 어느 쪽이든 저장된 로그에는 없어서 "관측 안 됨" 판정은 맞지만, 원인은 확정하지 못했습니다.
- **잡지 못한 것: 로그 회전으로 사라진 이벤트.** 폭주 동안 Tetragon은 초당 약 1만 2천 건을 내보냈고, 내보내기 파일이 10MB를 넘을 때마다(약 0.85초마다) 파일을 돌렸습니다. 기본 설정(`export-file-max-size-mb: 10`, `export-file-max-backups: 5`)이라 돌린 파일은 5개만 남고 나머지는 지워져서, 폭주 구간 중 **마지막 약 5초치만 남았습니다**.
  커널에서 드롭된 게 아니라 **저장된 로그에서 지워진 것**이라 Tetragon 유실 카운터로도 잡히지 않고, 워크로드 리듬은 이어져서 규칙도 교차 확인도 잡지 못합니다.
  처음에는 이것을 "드롭 신호 없는 커널 유실"로 잘못 해석했고, 돌린 파일을 확인하고서야 원인을 알았습니다. (이 실험의 `cross.jsonl`에는 돌린 파일이 합쳐져 있지 않습니다. [cross.sh](real/cross.sh)는 이후 돌린 파일까지 합치도록 고쳤습니다.)
  이 실험에는 Tetragon 하트비트가 없었습니다. 하트비트의 내보낸 이벤트 수와 대조하면 잡을 수 있고, [7번](#7-로그-회전-유실-realvmrotationsh)에서 확인했습니다.

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

### 6. 별도 커널 VM ([real/vm/vm.sh](real/vm/vm.sh))

kind 노드는 커널을 공유해서, lima로 Ubuntu 24.04 VM 2대(각 2코어, 2GB)를 띄웠습니다. 두 VM은 커널(6.8)과 boot ID가 서로 다르고 Docker Desktop(7.0)과도 다릅니다.
각 VM 안에서 Falco + Tetragon + 하트비트 + 워크로드를 돌리고 장애는 한 VM에만 넣었습니다. 하트비트 스크립트도 VM 안에서 돌려 이벤트와 같은 시계를 쓰게 했습니다.

```
[gap-vm1/falco]
  [LOST   ] 21:42:15–21:42:50  수집기 재시작 (프로세스 시작 시각 변경) · 신호 공백 21:42:13.0–21:42:54.5 (41.5초)
[gap-vm1/tetragon]   (같은 시각 정상)
[gap-vm2/falco]      (같은 시각 정상)
[gap-vm2/tetragon]
  [LOST   ] 21:43:25–21:44:05  수집기 재시작 (프로세스 시작 시각 변경) · 신호 공백 21:43:23.8–21:44:08.8 (45.0초)
```

**우연히 생긴 장애: 감시자의 감시자가 죽음.** 실험을 정리하는 명령이 gap-vm1의 하트비트 스크립트만 먼저 죽였고(Tetragon은 그 뒤 3분 동안 계속 기록), 처음 버전은 이 구간을 Tetragon 장애로 오판했습니다.
Falco metrics는 Falco가 직접 내지만 Tetragon 하트비트는 따로 도는 스크립트라 그것만 죽을 수 있습니다. 하트비트가 끊겨도 Tetragon 이벤트가 계속 나오면 Tetragon은 살아 있는 것으로 보게 고쳤고, 이 구간도 정답 케이스로 넣었습니다.

### 7. 로그 회전 유실 ([real/vm/rotation.sh](real/vm/rotation.sh))

4번에서 잡지 못한 로그 회전 유실을 재현했습니다. gap-vm2에서 Tetragon 내보내기를 1MB·백업 1개로 잡고, 평소 1분 → exec 폭주 5초 → 평소 1분을 돌렸습니다.
폭주로 파일이 여러 번 돌면서 폭주 전 평소 구간까지 지워졌습니다.

```
[rot/tetragon] 주기 신호: tetragon-metrics
  21:49:50  ···XXXXXXXXXXXXXXX████████████
  [LOST   ] 21:50:05–21:51:20  저장 단계 유실: 수집기는 63701건을 내보냈다는데 로그에는 1862건 (61839건 없음)
```

Tetragon은 모든 이벤트를 봤고 드롭도 없었습니다. 로그에서 지워진 것이라 드롭 카운터로는 잡히지 않고, 하트비트의 `events_exported`(= `tetragon_events_total`)와 로그 줄 수를 대조해야 보입니다.
미리 확인해 보니 이 메트릭은 로그 줄 수와 정확히 같았습니다(127/127, 594/594, 673/673).

### 8. 자동 장애 주입 ([real/chaos/](real/chaos/))

손으로 정한 구간만으로는 규칙을 실험에 맞춰 튜닝했을 위험이 있어서, 무작위 장애를 넣고 정답을 자동으로 남기는 실험을 만들었습니다 ([chaos.py](real/chaos/chaos.py)).
같은 호스트에서 Falco + Tetragon + 하트비트 + 워크로드를 돌리며 30분 동안 장애 7종을 무작위로 15–40초씩 넣었습니다 (장애 27개, 시드 2).

| 장애 | 정답 (Falco / Tetragon) | 횟수 |
|---|---|---|
| `falco_pause` | 관측됨(지연) / 관측됨 | 1 |
| `falco_kill` (삭제 후 다시 띄움) | 관측 안 됨 / 관측됨 | 2 |
| `falco_starve` (CPU 5% + open 폭주) | 관측 안 됨 / (채점 안 함) | 6 |
| `tetragon_pause` | 관측됨 / 관측됨(지연) | 5 |
| `tetragon_kill` | 관측됨 / 관측 안 됨 | 3 |
| `wl_stop` (워크로드 중지) | 관측됨 / 관측됨 | 6 |
| `none` (대조군) | 관측됨 / 관측됨 | 4 |

같은 데이터를 세 가지 증거 조건으로 채점했습니다 (`python3 eval.py --chaos real/chaos`, 5초 창).

| 증거 조건 | 구간 | 규칙만 | 규칙+단순 |
|---|---|---|---|
| 하트비트 + 교차 확인 | 48 | 48 맞힘 | 48 맞힘 |
| 교차 확인만 (Tetragon 하트비트 파일 제외) | 48 | 48 맞힘 | 48 맞힘 |
| Tetragon 단독 (Falco도 하트비트도 없음) | 21 | 18 맞힘, 3 보류 | 21 맞힘 |

- **Tetragon 단독**에서는 워크로드가 자주 멈춰 `cat`/`sleep` 리듬이 규칙적이지 않아 주기 신호를 찾지 못했습니다. 이때는 이벤트가 하나라도 있으면 수집기가 살아 있다는 증거로 봅니다. 워크로드를 멈춘 구간에도 `iptables`, `runc` 같은 배경 exec가 이어져 "관측됨"을 맞혔고, Tetragon을 지운 3개 구간은 이벤트가 아예 없어 보류했습니다.
- `falco_starve`는 open만 반복하는 폭주라 Falco에만 부담이 가고 Tetragon 로그는 커지지 않습니다 (Tetragon은 기본으로 exec/exit만 내보냄). Falco는 매번 수백만 건씩 드롭했습니다.

**첫 번째 실행은 Mac이 잠들어 망가졌습니다** ([run1-sleep/](real/chaos/run1-sleep/)). 30분짜리가 2시간에 걸쳐 장애 9개만 넣었고, 잠든 동안 두 수집기 모두 하트비트가 수백–수천 초씩 끊겼습니다.
깨어난 뒤에는 Docker VM의 시계(이벤트 시각)와 Mac의 시계(하트비트 스크립트가 찍은 시각)가 어긋나, 저장 단계 대조가 "내보낸 67건 중 로그 0건"으로 오판했습니다.
두 번째는 `caffeinate`로 잠들지 않게 하고 다시 돌렸습니다. 하트비트 스크립트는 수집기와 같은 시계를 쓰는 곳에서 돌려야 합니다 (6·7번은 VM 안에서 돌렸습니다).

## 정확도 ([eval.py](eval.py), [cases.json](cases.json))

| 묶음 | 구간 | 규칙만 |
|---|---|---|
| 합성 샘플 | 4 | 2 맞힘, 2 보류 |
| Falco 단독 (조용함, 폭주, 장애 2대) | 5 | 5 맞힘 |
| Tetragon 하트비트 없음 | 3 | 3 보류 |
| Tetragon 하트비트 | 3 | 3 맞힘 |
| Falco + Tetragon 교차 | 5 | 5 맞힘 |
| Kubernetes (5초 창) | 6 | 6 맞힘 |
| 별도 커널 VM (5초 창) | 7 | 7 맞힘 |
| 로그 회전 (5초 창) | 2 | 2 맞힘 |
| **합계** | **35** | **30 맞힘, 0 틀림, 5 보류** |

"규칙+단순"(보류를 모두 유실로)은 33개를 맞히지만, 2번 실험의 "정말 조용한" Tetragon 두 구간을 유실로 잘못 봅니다.
자동 장애 주입의 채점은 [8번](#8-자동-장애-주입-realchaos)에 있습니다.

### LLM 판단

보류된 5개 구간(합성 2 + 하트비트 없는 Tetragon 3)만 LLM에게 갑니다. 아래는 이 5개를 OpenAI `gpt-5.5`로 4번 돌린 결과입니다(모두 구간마다 한 번씩 질문).

| 구간 | 정답 | 규칙+단순 | 1, 2회차 | 3회차 | 4회차 |
|---|---|---|---|---|---|
| 합성: 드롭 신호 없는 전체 블랙아웃 | 관측 안 됨 | ✓ | ✓ | ✓ | ✓ |
| 합성: healthcheck만 사라진 부분 유실 | 관측 안 됨 | ✓ | ✗ | ✗ | ✗ |
| Tetragon: 막 켜졌고 워크로드 시작 전 | 관측됨 | ✗ | ✓ | ✓ | ✓ |
| Tetragon: 워크로드를 멈춘 조용한 40초 | 관측됨 | ✗ | ✗ | ✓ | ✓ |
| Tetragon: 수집기 삭제 | 관측 안 됨 | ✓ | ✓ | ✗ | ✓ |
| **5개 중 정답** | | 3 | 3 | 3 | **4** |

같은 5개를 `--votes 5`(구간마다 5번 질문, 80% 이상 같은 답일 때만 판정)로 돌린 결과입니다.
마지막 열은 프롬프트에서 "주기 신호가 워크로드라면 워크로드가 멈춘 것일 수도 있다"는 문장을 뺀 뒤의 결과입니다.

| 구간 | 정답 | 한 번 질문 1–4회차 | 5번 질문 투표 | 투표, 문장 뺌 |
|---|---|---|---|---|
| 합성: 드롭 신호 없는 전체 블랙아웃 | 관측 안 됨 | ✓✓✓✓ | ✓ | ✓ |
| 합성: healthcheck만 사라진 부분 유실 | 관측 안 됨 | ✗✗✗✗ | ✗ | ✗ |
| Tetragon: 막 켜졌고 워크로드 시작 전 | 관측됨 | ✓✓✓✓ | ✓ | ✓ |
| Tetragon: 워크로드를 멈춘 조용한 40초 | 관측됨 | ✗✗✓✓ | – 보류 (답이 갈림) | ✗ (80% 이상 일치) |
| Tetragon: 수집기 삭제 | 관측 안 됨 | ✓✓✗✓ | ✓ | ✓ |
| **35개 전체 (규칙+LLM)** | | | 24 맞힘, 1 틀림, 1 보류 ¹ | 33 맞힘, 2 틀림 |

¹ 이때는 26개 구간 시절이라 "24/26"입니다. 이후 추가된 9개 구간은 규칙만으로 모두 맞혀 LLM에게 가지 않습니다.

- **Tetragon "워크로드 중지" vs "수집기 중지"**: 1–3회차에는 두 구간에 매번 같은 답을 내고 방향만 바뀌었고, 4회차에 처음으로 둘 다 맞혔습니다. 네 번의 답이 (✗✓), (✗✓), (✓✗), (✓✓)로 모두 달라서 믿고 쓰기 어렵습니다. 하트비트(3번)나 교차 확인(4번)을 더하면 규칙만으로 매번 같은 답이 나옵니다.
- **Tetragon이 막 켜진 구간**은 4회 모두 맞혔습니다. 앞뒤 흐름에서 워크로드가 아직 시작 전이라는 걸 읽은 것으로 보입니다. LLM이 규칙보다 확실히 나은 곳은 여기 한 곳입니다.
- **합성 부분 유실**은 모든 실행에서 틀렸습니다. 처음에는 프롬프트의 "주기 신호가 워크로드라면 워크로드가 멈춘 것일 수도 있다"는 문장 탓으로 봤지만, 이 문장을 빼도 그대로 틀려서 **이 가설은 틀렸습니다**.
  이 구간에서는 healthcheck만 사라지고 nginx·curl·python3가 계속 보여서, LLM은 "수집기는 계속 보고 있었다"고 판단합니다. 샘플에 심은 "부분 유실" 자체가 로그만으로는 가르기 어려운 경우입니다.
- 1–3회차는 샘플을 순수 Tetragon 로그로 다시 만들기 전이고, 4회차는 다시 만든 샘플과 26개 구간 기준입니다. 5개 구간의 판정 내용은 같습니다.
- **투표의 효과와 한계**: 실행마다 답이 바뀌던 "워크로드 중지" 구간은 투표에서 답이 갈려 보류가 됐습니다. 틀린 답을 자신 있게 내는 대신 모른다고 말하게 된 것입니다.
  하지만 합성 부분 유실처럼 **매번 같은 방향으로 틀리는 구간은 투표해도 그대로 틀립니다.** 투표는 흔들림을 걸러낼 뿐, 일관된 편향은 고치지 못합니다.
- 투표는 요청 수가 N배라 비용도 N배입니다. 이 실험에서는 5개 구간만 LLM에게 가서 부담이 크지 않았습니다.
- **문장을 뺀 결과**: 부분 유실은 고쳐지지 않았고, 오히려 "워크로드 중지" 구간을 80% 이상 일치로 "관측 안 됨"이라고 틀렸습니다(이전에는 답이 갈려 보류). 이 문장은 워크로드가 멈춘 경우를 제대로 보게 돕고 있었던 것이라 **다시 넣었습니다**.

투표 실행의 전체 출력은 [eval_llm.txt](eval_llm.txt)에 있습니다.

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

## 한계

- 실제 로그는 모두 한 대의 Mac에서 나왔습니다. 별도 커널 VM(6번)으로 커널 공유 문제는 줄였지만, 실제 서버·클라우드 노드에서는 확인하지 않았습니다.
- 창 크기, 주기 판정 비율, 조용함 기준, 교차 확인 규칙은 이 실험들에서 정했습니다. 자동 장애 주입(8번)은 같은 환경에서 새로 만든 장애라, 다른 워크로드·환경에서는 다시 확인해야 합니다.
- 교차 확인은 두 수집기가 같은 종류의 활동을 본다고 가정합니다. 한쪽만 보는 활동(예: Tetragon만 보는 백그라운드 exec)이 많으면 오판할 수 있습니다.
- 저장 단계 대조는 하트비트와 이벤트가 같은 시계를 쓴다고 가정합니다. 호스트가 잠들었다 깨는 등으로 시계가 어긋나면 오판합니다 (8번 첫 실행).
- 하트비트도 교차 확인도 없는 로그에서는 여전히 판단을 보류하거나 LLM에 기대야 하고, LLM은 이 경우 믿을 만하지 않았습니다.
