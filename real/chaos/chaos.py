#!/usr/bin/env python3
"""자동 장애 주입 실험. 같은 호스트(chaos)에서 Falco + Tetragon(+하트비트)를 돌리며
무작위 장애를 넣고, 정답을 faults.jsonl에 남긴다. eval.py --chaos 가 이 정답으로 채점한다.

장애 종류와 정답 (장애가 걸린 동안):
  falco_pause     docker pause falco            falco=관측됨(지연)   tetragon=관측됨
  falco_kill      falco 삭제 후 끝에 다시 띄움  falco=관측 안 됨     tetragon=관측됨
  tetragon_pause  docker pause tetragon         falco=관측됨         tetragon=관측됨(지연)
  tetragon_kill   tetragon 삭제 후 다시 띄움    falco=관측됨         tetragon=관측 안 됨
  falco_starve    Falco CPU 5% + open 폭주      falco=관측 안 됨     tetragon=(채점 안 함)
  wl_stop         워크로드 중지                  falco=관측됨         tetragon=관측됨
  none            아무것도 안 함 (대조군)        falco=관측됨         tetragon=관측됨

open 폭주는 exec를 하지 않아 Tetragon(기본: exec/exit만 내보냄) 로그는 커지지 않는다.
Tetragon 내보내기 파일은 크게 잡아 로그 회전이 일어나지 않게 했다 (회전은 rotation.sh에서 따로 본다).

사용법: python3 chaos.py --minutes 30 --seed 1
"""
import argparse
import json
import os
import random
import subprocess
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
FALCO = ["docker", "run", "-d", "--name", "falco", "--hostname", "chaos", "--cpus", "2", "--privileged",
         "-v", "/sys/kernel/tracing:/sys/kernel/tracing:ro", "-v", "/proc:/host/proc:ro",
         "-v", "/etc:/host/etc:ro", "-v", "/var/run/docker.sock:/host/var/run/docker.sock",
         "-v", f"{HERE}:/out", "falcosecurity/falco:latest", "falco",
         "-o", "engine.kind=modern_ebpf", "-o", "json_output=true", "-o", "json_include_output_property=false",
         "-o", "file_output.enabled=true", "-o", "file_output.filename=/out/falco.jsonl",
         "-o", "stdout_output.enabled=false", "-o", "metrics.enabled=true", "-o", "metrics.interval=5s",
         "-o", "metrics.output_rule=true"]
TETRAGON = ["docker", "run", "-d", "--name", "tetragon", "--pid=host", "--cgroupns=host", "--privileged",
            "-p", "2112:2112", "-e", "NODE_NAME=chaos", "-v", "/sys/kernel/btf/vmlinux:/var/lib/tetragon/btf",
            "-v", f"{HERE}:/out", "quay.io/cilium/tetragon:v1.6.0", "/usr/bin/tetragon",
            "--export-filename", "/out/tetragon.jsonl", "--export-file-max-size-mb", "2000",
            "--metrics-server", ":2112"]
WL = ["docker", "run", "-d", "--rm", "--name", "wl", "alpine", "sh", "-c",
      "while true; do cat /etc/shadow >/dev/null; sleep 3; done"]
STORM = "while true; do : < /etc/hostname; done"

TRUTH = {
    "falco_pause": {"falco": "observed", "tetragon": "observed"},
    "falco_kill": {"falco": "unobserved", "tetragon": "observed"},
    "tetragon_pause": {"falco": "observed", "tetragon": "observed"},
    "tetragon_kill": {"falco": "observed", "tetragon": "unobserved"},
    "falco_starve": {"falco": "unobserved"},
    "wl_stop": {"falco": "observed", "tetragon": "observed"},
    "none": {"falco": "observed", "tetragon": "observed"},
}


def sh(*args):
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def start(fault):
    if fault == "falco_pause":
        sh("docker", "pause", "falco")
    elif fault == "falco_kill":
        sh("docker", "rm", "-f", "falco")
    elif fault == "tetragon_pause":
        sh("docker", "pause", "tetragon")
    elif fault == "tetragon_kill":
        sh("docker", "rm", "-f", "tetragon")
    elif fault == "falco_starve":
        sh("docker", "update", "--cpus", "0.05", "falco")
        for i in range(4):
            sh("docker", "run", "-d", "--rm", "--name", f"st{i}", "alpine", "sh", "-c", STORM)
    elif fault == "wl_stop":
        sh("docker", "rm", "-f", "wl")


def stop(fault):
    if fault == "falco_pause":
        sh("docker", "unpause", "falco")
    elif fault == "falco_kill":
        sh(*FALCO)
    elif fault == "tetragon_pause":
        sh("docker", "unpause", "tetragon")
    elif fault == "tetragon_kill":
        sh(*TETRAGON)
    elif fault == "falco_starve":
        sh("docker", "rm", "-f", "st0", "st1", "st2", "st3")
        sh("docker", "update", "--cpus", "2", "falco")
    elif fault == "wl_stop":
        sh(*WL)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    os.chdir(HERE)

    sh("docker", "rm", "-f", "falco", "tetragon", "wl", "st0", "st1", "st2", "st3")
    for f in ("falco.jsonl", "tetragon.jsonl", "heartbeat.jsonl", "faults.jsonl"):
        if os.path.exists(f):
            os.remove(f)
    sh(*FALCO)
    sh(*TETRAGON)
    hb = subprocess.Popen(["python3", "../../tetragon_heartbeat.py", "--node", "chaos", "--out", "heartbeat.jsonl"],
                          stderr=subprocess.DEVNULL)
    sh(*WL)
    print(f"{now()} 준비 (60초)", flush=True)
    time.sleep(60)

    end_at = time.time() + args.minutes * 60
    kinds = list(TRUTH)
    try:
        while time.time() < end_at:
            fault = rng.choice(kinds)
            length = rng.randint(15, 40)
            t0 = time.time()
            start(fault)
            time.sleep(length)
            t1 = time.time()
            stop(fault)
            with open("faults.jsonl", "a") as f:
                f.write(json.dumps({"fault": fault, "start": t0, "end": t1, "truth": TRUTH[fault]}) + "\n")
            print(f"{now()} {fault} {length}초", flush=True)
            time.sleep(rng.randint(30, 50))  # 회복·재시작을 기다린다
    finally:
        hb.terminate()
        sh("docker", "rm", "-f", "falco", "tetragon", "wl", "st0", "st1", "st2", "st3")
    print(f"{now()} done", flush=True)


if __name__ == "__main__":
    main()
