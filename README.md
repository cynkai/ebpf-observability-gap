# ebpf-observability-gap

Falco / Tetragon 로그에서 **"아무 일도 없었던 구간"과 "관측되지 않은 구간"을 구분**하는 작은 분석기입니다.

| 상태 | 뜻 | 근거 |
|---|---|---|
| `OBS` █ | 관측됨 | 이벤트가 있고 주기 신호도 정상 |
| `QUIET` · | 관측됨, 조용함 | 주기 신호(healthcheck 등)는 살아 있고 다른 활동은 거의 없음 |
| `LOST` X | 관측 안 됨 (확정) | Falco `syscall event drop`, Tetragon `rate_limit_info` |
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

## 동작 방식

1. Falco / Tetragon JSON 줄을 같은 이벤트 형태로 바꿉니다.
2. 간격이 일정한 프로세스를 "수집기가 살아 있다"는 **주기 신호**로 찾습니다.
3. 시간 창마다 상태를 판정합니다. Falco 드롭 알림은 늦게 보고되므로, 알림 바로 앞의 `SUSP` 창들은 `LOST`로 올립니다.
4. (`--llm`) `SUSP` 구간만 LLM에게 물어 `QUIET` / `UNOBSERVED`와 근거를 받습니다.

## 한계

- Tetragon의 커널 링버퍼 유실은 JSON 내보내기에 나오지 않고 Prometheus 메트릭에만 있습니다. 그래서 주기 신호가 있어야 조용한 유실을 잡을 수 있습니다.
- 창 크기, 주기 판정 비율, 조용함 기준은 샘플에 맞춘 값이라 실제 로그에서 조정이 필요합니다.
