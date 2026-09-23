#!/bin/sh
# 수집기 장애 시나리오 (약 3.5분). 워크로드(3초마다 /etc/shadow 읽기)는 계속 돈다.
# Falco 두 대를 띄운다: node-a는 장애를 겪고, node-b는 끝까지 정상(대조군).
#   0~40s     평소
#   40~80s    docker pause node-a : 프로세스만 멈춤. 커널은 계속 이벤트를 쌓는다
#   80~120s   평소
#   120~160s  node-a 삭제         : 수집기가 아예 꺼짐. 드롭을 셀 주체도 없다
#   160~200s  평소 (node-a 재시작)
set -e
cd "$(dirname "$0")"
log() { echo "$(date -u +%H:%M:%S) $*"; }

start_falco() {  # $1 = 노드 이름 (hostname으로도 쓴다)
  docker run -d --name "$1" --hostname "$1" --privileged \
    -v /sys/kernel/tracing:/sys/kernel/tracing:ro -v /proc:/host/proc:ro -v /etc:/host/etc:ro \
    -v /var/run/docker.sock:/host/var/run/docker.sock -v "$PWD":/out falcosecurity/falco:latest falco \
    -o engine.kind=modern_ebpf -o json_output=true -o json_include_output_property=false \
    -o file_output.enabled=true -o file_output.filename="/out/.falco_$1.jsonl" -o stdout_output.enabled=false \
    -o metrics.enabled=true -o metrics.interval=5s -o metrics.output_rule=true >/dev/null
}

docker rm -f node-a node-b wl falco >/dev/null 2>&1 || true
rm -f .falco_node-a.jsonl .falco_node-b.jsonl
start_falco node-a; start_falco node-b; sleep 5
docker run -d --rm --name wl alpine sh -c 'while true; do cat /etc/shadow >/dev/null; sleep 3; done' >/dev/null

log "phase normal";   sleep 40
log "phase pause";    docker pause node-a >/dev/null;   sleep 40
log "phase normal";   docker unpause node-a >/dev/null; sleep 40
log "phase stopped";  docker rm -f node-a >/dev/null;   sleep 40
log "phase normal";   start_falco node-a;                sleep 40
docker rm -f node-a node-b wl >/dev/null

# 두 노드 로그를 시간순으로 합친다 (ISO 시각이라 문자열 정렬로 충분)
python3 -c "
import json
rows = [l for f in ('.falco_node-a.jsonl', '.falco_node-b.jsonl') for l in open(f) if l.strip()]
rows.sort(key=lambda l: json.loads(l)['time'])
open('falco_outage.jsonl', 'w').writelines(rows)
"
rm -f .falco_node-a.jsonl .falco_node-b.jsonl
log "done"
