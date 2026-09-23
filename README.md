# ebpf-observability-gap

Falco / Tetragon 로그에서 **"아무 일도 없었던 구간"과 "관측되지 않은 구간"을 구분**하는 작은 분석기입니다.

| 상태 | 뜻 | 근거 |
|---|---|---|
| `OBS` █ | 관측됨 | 이벤트가 있고 주기 신호도 정상 |
| `QUIET` · | 관측됨, 조용함 | 주기 신호(healthcheck 등)는 살아 있고 다른 활동은 거의 없음 |
| `LOST` X | 관측 안 됨 (확정) | Falco `syscall event drop`, Falco metrics의 `scap.n_drops` 증가, Tetragon `rate_limit_info` |
| `SUSP` ? | 관측 안 됨 (추정) | 드롭 신호는 없는데 주기 신호가 끊김 |

`SUSP` 구간은 선택적으로 LLM(OpenAI 또는 Claude)에게 창 요약 전체를 한 번에 보내 판단시킬 수 있습니다.

## 실행

```bash
python3 make_sample.py          # 테스트용 sample.jsonl 생성
python3 gapfind.py sample.jsonl
```

```
타임라인 (한 칸 = 10초)   █ 관측  · 조용  X 유실(확정)  ? 유실(추정)
  10:00:00  ████████████···█····██████████
  10:05:00  XXXXX██████████????█████???███
```

### LLM 판단 (선택)

```bash
pip install openai              # 또는 anthropic
export OPENAI_API_KEY=...       # 또는 ANTHROPIC_API_KEY
python3 gapfind.py sample.jsonl --llm                          # 기본 OpenAI gpt-5.5
python3 gapfind.py sample.jsonl --llm --provider anthropic     # Claude
```

출력 예시 (`sample.jsonl`, OpenAI `gpt-5.5`). `SUSP` 구간 아래에 LLM의 판정, 확신도, 근거가 붙습니다.

```
구간 목록 (OBS 제외)
  [QUIET] 10:02:00–10:02:30  주기 신호는 정상, 다른 활동 거의 없음
  [QUIET] 10:02:40–10:03:20  주기 신호는 정상, 다른 활동 거의 없음
  [LOST ] 10:05:00–10:05:50  드롭 18342건 보고됨
  [SUSP ] 10:07:30–10:08:10  끊긴 주기 신호: healthcheck / 다른 이벤트 0건
          └ LLM: UNOBSERVED (high) 직전/직후에는 nginx·curl·python3와 healthcheck가 정상적으로 보이는데, 해당 4개 창은 drops=0이어도 모든 이벤트가 비어 있고 healthcheck도 끊겼다. 실제 quiet라기보다 수집 공백에 가깝다.
  [SUSP ] 10:09:00–10:09:30  끊긴 주기 신호: healthcheck / 다른 이벤트 45건
          └ LLM: UNOBSERVED (medium) 구간 동안 nginx·curl·python3 등 다른 이벤트는 계속 보이지만 주기 신호인 healthcheck만 사라졌다. 아무 일도 없는 quiet는 아니며, healthcheck 관측이 빠진 부분 관측 실패로 판단된다.
```

두 `SUSP` 구간은 샘플에 일부러 심은 유실(전체 블랙아웃, healthcheck만 사라진 부분 유실)이라 정답은 둘 다 `UNOBSERVED`입니다. 근거 문장은 실행할 때마다 조금씩 달라집니다.

## 실제 Falco 로그로 돌려보기

Falco는 기본적으로 **규칙에 걸릴 때만** 로그를 남기므로, 그대로는 "조용함"과 "못 봄"을 구분할 신호가 없습니다.
`metrics`를 켜면 Falco가 정해진 간격으로 `Falco internal: metrics snapshot`을 남기고, 여기에 드롭 카운터(`scap.n_drops`)가 들어 있습니다.
분석기는 이 이벤트를 **주기 신호이자 드롭 신호**로 씁니다.

```bash
falco -o engine.kind=modern_ebpf -o json_output=true \
      -o metrics.enabled=true -o metrics.interval=5s -o metrics.output_rule=true
```

### 수집기 장애 실험 ([real/outage.sh](real/outage.sh))

Docker Desktop(macOS, linuxkit 커널 7.0, arm64)에서 Falco 0.45.0(modern_ebpf)을 띄우고, 3초마다 `/etc/shadow`를 읽는 워크로드(`Read sensitive file untrusted` 규칙에 걸림)를 계속 돌리면서 수집기를 두 번 멈췄습니다. 로그는 [real/falco_outage.jsonl](real/falco_outage.jsonl)입니다.

```bash
python3 gapfind.py real/falco_outage.jsonl
```

```
주기 신호: falco-metrics

타임라인 (한 칸 = 10초)   █ 관측  · 조용  X 유실(확정)  ? 유실(추정)
  08:46:20  ·████???█████????████

구간 목록 (OBS 제외)
  [QUIET] 08:46:20–08:46:30  주기 신호는 정상, 다른 활동 거의 없음
  [SUSP ] 08:47:10–08:47:40  끊긴 주기 신호: falco-metrics / 다른 이벤트 10건
  [SUSP ] 08:48:30–08:49:10  끊긴 주기 신호: falco-metrics / 다른 이벤트 0건
```

| 구간 | 한 일 | 실제로 일어난 일 | 정답 |
|---|---|---|---|
| 08:47:10–08:47:40 | `docker pause falco` 40초 | 커널은 계속 이벤트를 링버퍼에 쌓았고, 재개 후 늦게 처리됨. 3초 간격 알림 10건이 빠짐없이 있음. 멈춘 건 Falco의 metrics 하트비트뿐 | 관측됨 (지연) |
| 08:48:30–08:49:10 | `docker rm -f falco` 후 재시작 | 수집기가 없어서 아무것도 기록되지 않음. 드롭을 셀 주체도 없어서 드롭 신호도 없음 | 관측 안 됨 |

두 구간 모두 "하트비트가 끊겼고 드롭 신호는 없음"이라 규칙만으로는 같은 `SUSP`가 됩니다. 구간 안의 워크로드 알림이 평소 리듬대로 이어졌는지를 봐야 둘을 가를 수 있고, 이것이 `--llm` 단계가 판단할 몫입니다.

### 부하로 드롭 유도는 실패

같은 환경에서 링버퍼를 가장 작게(`engine.modern_ebpf.buf_size_preset=1`) 두고 syscall 폭주(`dd`), exec/open 폭주를 1분씩 걸었지만 드롭은 0건이었습니다 ([real/scenario.sh](real/scenario.sh)). Falco는 read/write를 기본으로 수집하지 않고, 10코어 환경에서는 exec/open 폭주도 따라잡았습니다. 부하 드롭을 재현하려면 코어가 적은 VM이나 더 무거운 부하가 필요합니다.

## 동작 방식

1. Falco / Tetragon JSON 줄을 같은 이벤트 형태로 바꿉니다.
2. "수집기가 살아 있다"는 **주기 신호**를 찾습니다. Falco metrics 스냅숏이 있으면 그것만 쓰고, 없으면 간격이 일정한 프로세스를 씁니다. 일정하게 도는 워크로드는 멈추는 게 정상일 수 있어서, 수집기 자신의 하트비트가 있으면 기준으로 삼지 않습니다.
3. 시간 창마다 상태를 판정합니다. Falco 드롭 알림은 늦게 보고되므로, 알림 바로 앞의 `SUSP` 창들은 `LOST`로 올립니다.
4. (`--llm`) `SUSP` 구간만 LLM에게 물어 `QUIET` / `UNOBSERVED`와 근거를 받습니다.

## 한계

- Tetragon의 커널 링버퍼 유실은 JSON 내보내기에 나오지 않고 Prometheus 메트릭에만 있습니다. 그래서 주기 신호가 있어야 조용한 유실을 잡을 수 있습니다.
- 창 크기, 주기 판정 비율, 조용함 기준은 샘플에 맞춘 값이라 실제 로그에서 조정이 필요합니다.
