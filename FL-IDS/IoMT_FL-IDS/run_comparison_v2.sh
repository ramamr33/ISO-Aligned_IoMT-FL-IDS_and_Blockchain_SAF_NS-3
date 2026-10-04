#!/bin/bash
# FL-IDS (Rajab et al., wASI + FedAvg classifier + multi-standard mapping) vs
# BFLIDS (Begum et al., CNN + KL-adaptive FedAvg + SMOTE), as two SEPARATE programs on the
# same IoMT network, MITM attacker, attack schedule and seeds.
# Run from the ns-3.42 root (no sudo):
#     bash run_comparison_v2.sh                 (seeds 1 2 3 4)
#     SEEDS="1" bash run_comparison_v2.sh       (quick check)
# Override program names if yours differ:
#     PROG_FLIDS=<name> PROG_BFLIDS=<name> bash run_comparison_v2.sh
set -e
SEEDS=${SEEDS:-"1 2 3 4"}
PROG_FLIDS=${PROG_FLIDS:-IoMT-wifi_wip_blocksec_mitm2_flids_only}
PROG_BFLIDS=${PROG_BFLIDS:-IoMT-wifi_wip_blocksec_mitm2_bflids_only}
OUT="$PWD/comparison_logs"
mkdir -p "$OUT"

TARGETS=$(./ns3 show targets 2>/dev/null)
for p in "$PROG_FLIDS" "$PROG_BFLIDS"; do
    if ! echo "$TARGETS" | grep -qw "$p"; then
        echo "ERROR: ns-3 has no program called '$p'. Build it first:  ./ns3 build $p"; exit 1
    fi
done

run () {   # $1 = program, $2 = log name stem, rest = flags
    local prog=$1 name=$2; shift 2
    echo ">>> $name  ($prog $*)"
    ./ns3 run "$prog $* --outputFile=$OUT/${name}.xml \
        --detLog=$OUT/${name}.csv --roundLog=$OUT/${name}_rounds.csv" > "$OUT/${name}.log" 2>&1
    echo "    done: $(wc -l < "$OUT/${name}.csv") window rows"
}

ATTACK="--attackStart=15 --labelMode=targeted"
for s in $SEEDS; do
    # 1. Detection quality: attacker stays active from 15 s, no mitigation
    run $PROG_FLIDS  attack_flids_s$s  --seed=$s --mitigate=0 $ATTACK
    run $PROG_BFLIDS attack_bflids_s$s --seed=$s --mitigate=0 $ATTACK
    # 2. False positives: no attacker at all
    run $PROG_FLIDS  benign_flids_s$s  --seed=$s --mitigate=0 --attackType=none --labelMode=targeted
    run $PROG_BFLIDS benign_bflids_s$s --seed=$s --mitigate=0 --attackType=none --labelMode=targeted
    # 3. Mitigation: each framework detects AND mitigates; attacker re-arms 10 s later
    run $PROG_FLIDS  mitig_flids_s$s   --seed=$s --mitigate=1 --gatedMitigation=1 $ATTACK --rearmDelay=10
    run $PROG_BFLIDS mitig_bflids_s$s  --seed=$s --mitigate=1 $ATTACK --rearmDelay=10
done

cd "$OUT"
python3 ../evaluate_bflids_vs_flids.py --runs "attack_*_s*.csv" --benign "benign_*_s*.csv" \
        --baseline "benign_flids_s*.csv" --label targeted --out results
echo "Detection results in $OUT/results (summary.csv, per_seed_metrics.csv, latex_rows.tex)"
echo "Mitigation outputs: mitig_*_s*.xml (FlowMonitor) and mitig_*_s*_rounds.csv"
