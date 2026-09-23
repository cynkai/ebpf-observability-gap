#!/bin/sh
# Tetragon + 하트비트 실험 (약 5분). tetragon.sh와 같은 워크로드에 하트비트 수집기를 붙였다.
#   0~40s     평소: 3초마다 cat + sleep 실행
#   40~80s    워크로드 중지     : 실제로 아무 일도 없음 -> 정답 관측됨(QUIET)
#   80~120s   평소
#   120~160s  docker pause      : Tetragon 프로세스만 멈춤 -> 커널 버퍼에 쌓이면 DELAYED
#   160~200s  평소
#   200~240s  tetragon 삭제     : 수집기가 꺼짐 -> 정답 관측 안 됨
#   240~280s  평소 (tetragon 재시작)
set -e
cd "$(dirname "$0")"
log() { echo "$(date -u +%H:%M:%S) $*"; }
IMAGE=quay.io/cilium/tetragon:v1.6.0

start_tetragon() {
  docker run -d --name tetragon --pid=host --cgroupns=host --privileged -p 2112:2112 \
    -e NODE_NAME=tg-node -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf -v "$PWD":/out \
    "$IMAGE" /usr/bin/tetragon --export-filename /out/tetragon_hb.jsonl --metrics-server :2112 >/dev/null
}
start_wl() { docker run -d --rm --name wl alpine sh -c 'while true; do cat /etc/hostname >/dev/null; sleep 3; done' >/dev/null; }

docker rm -f tetragon wl >/dev/null 2>&1 || true
rm -f tetragon_hb.jsonl tetragon_hb_heartbeat.jsonl
start_tetragon; sleep 10
python3 ../tetragon_heartbeat.py --node tg-node --out tetragon_hb_heartbeat.jsonl 2>/dev/null &
HB=$!

log "phase normal";   start_wl;                          sleep 40
log "phase quiet";    docker rm -f wl >/dev/null;        sleep 40
log "phase normal";   start_wl;                          sleep 40
log "phase pause";    docker pause tetragon >/dev/null;  sleep 40
log "phase normal";   docker unpause tetragon >/dev/null; sleep 40
log "phase stopped";  docker rm -f tetragon >/dev/null;  sleep 40
log "phase normal";   start_tetragon;                    sleep 40
kill $HB; docker rm -f tetragon wl >/dev/null
log "done"
