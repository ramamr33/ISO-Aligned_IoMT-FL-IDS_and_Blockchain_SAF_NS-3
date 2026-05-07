#!/bin/bash

# Configuration
SIM_NAME="IoMT-wifi_wip_blocksec_mitm2_sec23"
ATTACK_TYPE="mitm"
SEED_START=1
SEED_END=10  # Adjust this as needed

# Loop over seed values
for ((seed=$SEED_START; seed<=$SEED_END; seed++))
do
  OUTPUT_FILE="flowmonitor-${SIM_NAME}-${ATTACK_TYPE}-seed${seed}.xml"
  echo "Running simulation with seed $seed..."
  
  ./ns3 run $SIM_NAME -- --attackType=$ATTACK_TYPE --seed=$seed --outputFile=$OUTPUT_FILE

  if [ $? -eq 0 ]; then
    echo "✔ Simulation seed $seed completed successfully: $OUTPUT_FILE"
  else
    echo "✖ Simulation seed $seed failed"
  fi
done

