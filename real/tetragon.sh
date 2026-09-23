#!/bin/sh
# Tetragon 실험 (약 3.5분). Tetragon 내보내기에는 하트비트가 없어서 규칙만으로는 구분이 어렵다.
#   0~40s     평소: 3초마다 cat + sleep 실행 (process_exec 이벤트)
#   40~80s    워크로드 중지     : 실제로 아무 일도 없음 -> 정답 QUIET
#   80~120s   평소
#   120~160s  tetragon 중지     : 수집기가 꺼짐 -> 정답 UNOBSERVED
#   160~200s  평소 (tetragon 재시작)
set -e
cd "$(dirname "$0")"
log() { echo "$(date -u +%H:%M:%S) $*"; }
IMAGE=quay.io/cilium/tetragon:v1.6.0

start_tetragon() {
  docker run -d --name tetragon --pid=host --cgroupns=host --privileged \
    -e NODE_NAME=tg-node -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf -v "$PWD":/out \
    "$IMAGE" /usr/bin/tetragon --export-filename /out/tetragon.jsonl >/dev/null
}
start_wl() { docker run -d --rm --name wl alpine sh -c 'while true; do cat /etc/hostname >/dev/null; sleep 3; done' >/dev/null; }

docker rm -f tetragon wl >/dev/null 2>&1 || true
rm -f tetragon.jsonl
start_tetragon; sleep 10

log "phase normal";   start_wl;                        sleep 40
log "phase quiet";    docker rm -f wl >/dev/null;      sleep 40
log "phase normal";   start_wl;                        sleep 40
log "phase stopped";  docker rm -f tetragon >/dev/null; sleep 40
log "phase normal";   start_tetragon;                  sleep 40
docker rm -f tetragon wl >/dev/null
log "done"
