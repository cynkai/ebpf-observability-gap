#!/bin/sh
# 실제 Falco 로그 수집용 워크로드 시나리오 (약 5분)
#   0~60s    평소: 3초마다 /etc/shadow 읽기 (Falco 규칙에 걸림)
#   60~120s  조용: 워크로드 중지
#   120~180s 폭주: 평소 워크로드 + exec/open 폭주로 드롭 유도
#   180~300s 평소
set -e
log() { echo "$(date -u +%H:%M:%S) $*"; }

docker rm -f wl storm1 storm2 storm3 storm4 >/dev/null 2>&1 || true
start_wl() { docker run -d --rm --name wl alpine sh -c 'while true; do cat /etc/shadow >/dev/null; sleep 3; done' >/dev/null; }

log "phase normal";  start_wl; sleep 60
log "phase quiet";   docker rm -f wl >/dev/null; sleep 60
log "phase storm";   start_wl
# Falco는 read/write는 기본으로 안 잡으므로 exec/open 위주로 폭주시킨다
for i in 1 2 3 4; do
  docker run -d --rm --name storm$i alpine sh -c 'while true; do /bin/true; cat /etc/hostname >/dev/null; done' >/dev/null
done
sleep 60
docker rm -f storm1 storm2 storm3 storm4 >/dev/null
log "phase normal";  sleep 120
docker rm -f wl >/dev/null
log "done"
