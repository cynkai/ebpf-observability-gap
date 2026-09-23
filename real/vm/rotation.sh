#!/bin/sh
# 로그 회전 유실 실험 (약 3분, gap-vm2). Tetragon 내보내기 파일을 1MB, 백업 1개로 잡고
# 짧은 exec 폭주를 넣는다. 폭주로 파일이 여러 번 돌면서 앞의 로그가 지워진다.
#   0~60s   평소 (3초마다 cat + sleep)        -> 나중에 회전으로 지워짐: 저장된 로그에서는 관측 안 됨
#   60~65s  exec 폭주 5초
#   65~125s 평소                              -> 남아 있음: 관측됨
# 수집기(Tetragon)는 모든 이벤트를 봤고 하트비트의 events_exported도 그만큼 늘었다.
# 로그에서 지워진 만큼 '내보냄 - 로그 줄' 부족분이 남으므로 저장 단계 유실로 잡혀야 한다.
set -e
cd "$(dirname "$0")"
log() { echo "$(date -u +%H:%M:%S) $*"; }
V=gap-vm2
D=$PWD/logs/rotation
vm() { limactl shell --workdir / $V -- sudo sh -c "$*"; }

mkdir -p logs/rotation
vm "docker rm -f tetragon wl storm >/dev/null 2>&1; pkill -f 'tetragon_heartbea[t]'; rm -f $PWD/logs/$V/*rotation* " || true
rm -f logs/rotation/*.jsonl
# lima에는 logs/gap-vm2만 마운트돼 있어서, VM 안에서는 그 아래에 쓰고 끝나면 옮긴다
W=$PWD/logs/$V/rotation
vm "mkdir -p $W && rm -f $W/*.jsonl"
cp ../../tetragon_heartbeat.py logs/$V/
vm "docker run -d --name tetragon --pid=host --cgroupns=host --privileged --network host \
  -e NODE_NAME=rot -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf -v $W:/out \
  quay.io/cilium/tetragon:v1.6.0 /usr/bin/tetragon --export-filename /out/tetragon.jsonl \
  --export-file-max-size-mb 1 --export-file-max-backups 1 --metrics-server 127.0.0.1:2112 >/dev/null"
vm "nohup python3 $PWD/logs/$V/tetragon_heartbeat.py --node rot --out $W/heartbeat.jsonl >/dev/null 2>&1 &"
sleep 20
vm "docker run -d --rm --name wl alpine sh -c 'while true; do cat /etc/hostname >/dev/null; sleep 3; done' >/dev/null"

log "phase normal";  sleep 60
log "phase burst";   vm "docker run -d --rm --name storm alpine sh -c 'while true; do /bin/true; done' >/dev/null"; sleep 5
vm "docker rm -f storm >/dev/null"
log "phase normal";  sleep 60
vm "pkill -f 'tetragon_heartbea[t]'; docker rm -f tetragon wl >/dev/null"

python3 -c "
import json, glob
files = sorted(glob.glob('$W/*.jsonl'))
print('남은 파일:', [f.split('/')[-1] for f in files])
rows = [l for f in files for l in open(f) if l.strip()]
rows.sort(key=lambda l: json.loads(l)['time'])
open('rotation.jsonl', 'w').writelines(rows)
"
log "done"
