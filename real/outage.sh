#!/bin/sh
# 수집기 장애 시나리오 (약 3.5분). 워크로드(3초마다 /etc/shadow 읽기)는 계속 돈다.
#   0~40s     평소
#   40~80s    docker pause falco  : 프로세스만 멈춤. 커널은 계속 이벤트를 쌓다 버퍼가 차면 드롭을 센다
#   80~120s   평소
#   120~160s  docker stop falco   : 수집기가 아예 꺼짐. 드롭을 셀 주체도 없다
#   160~200s  평소 (새로 뜬 falco)
set -e
cd "$(dirname "$0")"
log() { echo "$(date -u +%H:%M:%S) $*"; }

start_falco() {
  docker run -d --name falco --privileged \
    -v /sys/kernel/tracing:/sys/kernel/tracing:ro -v /proc:/host/proc:ro -v /etc:/host/etc:ro \
    -v /var/run/docker.sock:/host/var/run/docker.sock -v "$PWD":/out falcosecurity/falco:latest falco \
    -o engine.kind=modern_ebpf -o json_output=true -o json_include_output_property=false \
    -o file_output.enabled=true -o file_output.filename=/out/falco_outage.jsonl -o stdout_output.enabled=false \
    -o metrics.enabled=true -o metrics.interval=5s -o metrics.output_rule=true \
    -o engine.modern_ebpf.buf_size_preset=1 >/dev/null
}

docker rm -f falco wl >/dev/null 2>&1 || true
rm -f falco_outage.jsonl
start_falco; sleep 5
docker run -d --rm --name wl alpine sh -c 'while true; do cat /etc/shadow >/dev/null; sleep 3; done' >/dev/null

log "phase normal";   sleep 40
log "phase pause";    docker pause falco >/dev/null;   sleep 40
log "phase normal";   docker unpause falco >/dev/null; sleep 40
log "phase stopped";  docker rm -f falco >/dev/null;   sleep 40
log "phase normal";   start_falco;                      sleep 40
docker rm -f falco wl >/dev/null
log "done"
