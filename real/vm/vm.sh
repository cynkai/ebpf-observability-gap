#!/bin/sh
# 별도 커널 VM 실험 (약 5분). lima VM 2대(gap-vm1, gap-vm2)는 각자 자기 커널을 쓴다.
# 각 VM 안에서 Falco + Tetragon + 하트비트 + 워크로드를 돌리고, 장애는 한 VM에만 넣는다.
# 하트비트 스크립트도 VM 안에서 돌려 이벤트와 같은 시계를 쓰게 했다.
#   0~40s     평소
#   40~80s    gap-vm1의 Falco 삭제 후 다시 띄움   : vm1 falco=관측 안 됨, 나머지=관측됨
#   80~110s   평소
#   110~150s  gap-vm2의 Tetragon 삭제 후 다시 띄움: vm2 tetragon=관측 안 됨, 나머지=관측됨
#   150~180s  평소
#   180~220s  gap-vm1의 워크로드 중지             : vm1 두 수집기 모두 관측됨(조용함)
#   220~250s  평소
# 준비: limactl create --name=gap-vmN --mount-only "$PWD/logs/gap-vmN:w" template:ubuntu-24.04 (+ docker.io)
set -e
cd "$(dirname "$0")"
log() { echo "$(date -u +%H:%M:%S) $*"; }
vm() { v=$1; shift; limactl shell --workdir / "$v" -- sudo sh -c "$*"; }

falco() {  # $1 = VM
  vm "$1" "docker run -d --name falco --hostname $1 --privileged \
    -v /sys/kernel/tracing:/sys/kernel/tracing:ro -v /proc:/host/proc:ro -v /etc:/host/etc:ro \
    -v /var/run/docker.sock:/host/var/run/docker.sock -v $PWD/logs/$1:/out falcosecurity/falco:latest falco \
    -o engine.kind=modern_ebpf -o json_output=true -o json_include_output_property=false \
    -o file_output.enabled=true -o file_output.filename=/out/falco.jsonl -o stdout_output.enabled=false \
    -o metrics.enabled=true -o metrics.interval=5s -o metrics.output_rule=true >/dev/null"
}
tetragon() {
  vm "$1" "docker run -d --name tetragon --pid=host --cgroupns=host --privileged --network host \
    -e NODE_NAME=$1 -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf -v $PWD/logs/$1:/out \
    quay.io/cilium/tetragon:v1.6.0 /usr/bin/tetragon --export-filename /out/tetragon.jsonl \
    --metrics-server 127.0.0.1:2112 >/dev/null"
}
wl() { vm "$1" "docker run -d --rm --name wl alpine sh -c 'while true; do cat /etc/shadow >/dev/null; sleep 3; done' >/dev/null"; }

for v in gap-vm1 gap-vm2; do
  vm $v "docker rm -f falco tetragon wl >/dev/null 2>&1; pkill -f 'tetragon_heartbea[t]'; rm -f $PWD/logs/$v/*.jsonl" || true
  cp ../../tetragon_heartbeat.py logs/$v/
  falco $v; tetragon $v; wl $v
  vm $v "nohup python3 $PWD/logs/$v/tetragon_heartbeat.py --node $v --out $PWD/logs/$v/heartbeat.jsonl >/dev/null 2>&1 &"
done
sleep 60

log "phase normal";             sleep 40
log "phase vm1-falco-deleted";  vm gap-vm1 "docker rm -f falco >/dev/null"; sleep 40; falco gap-vm1
log "phase normal";             sleep 30
log "phase vm2-tetragon-deleted"; vm gap-vm2 "docker rm -f tetragon >/dev/null"; sleep 40; tetragon gap-vm2
log "phase normal";             sleep 30
log "phase vm1-quiet";          vm gap-vm1 "docker rm -f wl >/dev/null"; sleep 40; wl gap-vm1
log "phase normal";             sleep 30

for v in gap-vm1 gap-vm2; do vm $v "pkill -f 'tetragon_heartbea[t]'; docker rm -f falco tetragon wl >/dev/null"; done
python3 -c "
import json, glob
rows = [l for f in sorted(glob.glob('logs/*/*.jsonl')) for l in open(f) if l.strip()]
rows.sort(key=lambda l: json.loads(l)['time'])
open('vm.jsonl', 'w').writelines(rows)
"
log "done"
