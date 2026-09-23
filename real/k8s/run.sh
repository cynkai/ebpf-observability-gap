#!/bin/sh
# kind 클러스터 실험 (약 5분). Falco·Tetragon DaemonSet + 워커마다 워크로드(wl).
# 준비: kind create cluster --name gap --config kind.yaml, helm 설치 (README 참고)
#   0~40s     평소
#   40~100s   gap-worker의 Falco 파드 삭제  : DaemonSet이 새로 띄울 때까지 Falco 공백 -> 재시작 LOST
#   100~120s  평소
#   120~180s  gap-worker2의 Tetragon 파드 삭제: Tetragon 공백, 같은 노드 Falco는 워크로드를 봄 -> 교차 LOST
#   180~200s  평소
#   200~240s  워크로드 삭제                  : 두 노드 모두 정말 조용함 -> QUIET
#   240~280s  평소
set -e
cd "$(dirname "$0")"
log() { echo "$(date -u +%H:%M:%S) $*"; }
pod_on() { kubectl get pods -A -l "$1" --field-selector "spec.nodeName=$2" -o jsonpath='{.items[0].metadata.namespace} {.items[0].metadata.name}'; }

for n in gap-worker gap-worker2; do : > "logs/$n/falco.jsonl"; : > "logs/$n/tetragon/tetragon.jsonl"; done

log "phase normal";           sleep 40
log "phase falco-deleted";    kubectl delete pod -n $(pod_on app.kubernetes.io/name=falco gap-worker) --wait=false >/dev/null; sleep 60
log "phase normal";           sleep 20
log "phase tetragon-deleted"; kubectl delete pod -n $(pod_on app.kubernetes.io/name=tetragon gap-worker2) --wait=false >/dev/null; sleep 60
log "phase normal";           sleep 20
log "phase quiet";            kubectl delete ds wl --wait=true >/dev/null; sleep 40
log "phase normal";           kubectl apply -f workload.yaml >/dev/null; sleep 40

python3 -c "
import json
files = [f'logs/{n}/{f}' for n in ('gap-worker', 'gap-worker2') for f in ('falco.jsonl', 'tetragon/tetragon.jsonl')]
# Tetragon은 파일을 연 채로 원래 위치에 이어 써서, 앞에서 비운 부분이 NUL 바이트로 채워진다
rows = [l.replace(chr(0), '') for f in files for l in open(f) if l.strip(chr(0) + ' \\n')]
rows.sort(key=lambda l: json.loads(l)['time'])
open('k8s.jsonl', 'w').writelines(rows)
"
log "done"
