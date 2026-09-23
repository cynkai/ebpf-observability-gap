#!/bin/sh
# Falco + Tetragon 교차 확인 실험 (약 5분). 같은 호스트(lab)에서 두 수집기를 함께 돌린다.
# 워크로드: 3초마다 /etc/shadow 읽기 -> Falco 알림 + Tetragon exec 이벤트 둘 다 남는다.
# Tetragon에는 일부러 하트비트를 붙이지 않았다 (교차 확인만으로 가를 수 있는지 보려고).
#   0~40s     평소
#   40~80s    폭주 + Falco CPU 5%로 제한 : Falco가 따라가지 못해 실제 드롭 -> Falco LOST
#   80~120s   평소 (CPU 제한 해제)
#   120~160s  워크로드 중지             : 정말 조용함 -> Tetragon SUSP, Falco는 건강하고 조용함
#   160~200s  평소
#   200~240s  Tetragon 삭제             : Tetragon SUSP, Falco는 같은 시각 활동을 봄
#   240~280s  평소 (Tetragon 재시작)
set -e
cd "$(dirname "$0")"
log() { echo "$(date -u +%H:%M:%S) $*"; }

start_falco() {
  docker run -d --name falco --hostname lab --cpus 2 --privileged \
    -v /sys/kernel/tracing:/sys/kernel/tracing:ro -v /proc:/host/proc:ro -v /etc:/host/etc:ro \
    -v /var/run/docker.sock:/host/var/run/docker.sock -v "$PWD":/out falcosecurity/falco:latest falco \
    -o engine.kind=modern_ebpf -o json_output=true -o json_include_output_property=false \
    -o file_output.enabled=true -o file_output.filename=/out/.cross_falco.jsonl -o stdout_output.enabled=false \
    -o metrics.enabled=true -o metrics.interval=5s -o metrics.output_rule=true \
    -o engine.modern_ebpf.buf_size_preset=1 >/dev/null
}
start_tetragon() {
  docker run -d --name tetragon --pid=host --cgroupns=host --privileged \
    -e NODE_NAME=lab -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf -v "$PWD":/out \
    quay.io/cilium/tetragon:v1.6.0 /usr/bin/tetragon --export-filename /out/.cross_tetragon.jsonl >/dev/null
}
start_wl() { docker run -d --rm --name wl alpine sh -c 'while true; do cat /etc/shadow >/dev/null; sleep 3; done' >/dev/null; }
storm() {
  for i in 1 2 3 4; do
    docker run -d --rm --name st$i alpine sh -c 'while true; do /bin/true; cat /etc/hostname >/dev/null; done' >/dev/null
  done
}

docker rm -f falco tetragon wl st1 st2 st3 st4 >/dev/null 2>&1 || true
rm -f .cross_falco.jsonl .cross_tetragon*.jsonl
start_falco; start_tetragon; sleep 10

log "phase normal";   start_wl;                                sleep 40
log "phase storm";    docker update --cpus 0.05 falco >/dev/null; storm; sleep 40
log "phase normal";   docker rm -f st1 st2 st3 st4 >/dev/null; docker update --cpus 2 falco >/dev/null; sleep 40
log "phase quiet";    docker rm -f wl >/dev/null;              sleep 40
log "phase normal";   start_wl;                                sleep 40
log "phase stopped";  docker rm -f tetragon >/dev/null;        sleep 40
log "phase normal";   start_tetragon;                          sleep 40
docker rm -f falco tetragon wl >/dev/null

python3 -c "
import json
import glob
# Tetragon은 내보내기 파일이 10MB를 넘으면 .cross_tetragon-<시각>.jsonl로 돌리고 5개만 남긴다(나머지는 지움).
# 돌린 파일까지 함께 읽어야 남은 이벤트를 모두 얻는다.
files = ['.cross_falco.jsonl'] + sorted(glob.glob('.cross_tetragon*.jsonl'))
rows = [l for f in files for l in open(f) if l.strip()]
rows.sort(key=lambda l: json.loads(l)['time'])
open('cross.jsonl', 'w').writelines(rows)
"
rm -f .cross_falco.jsonl .cross_tetragon*.jsonl
log "done"
