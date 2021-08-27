#!/bin/sh

NUM_PROCS=$(grep -c ^processor /proc/cpuinfo)
echo "Using ${NUM_PROCS} processes"

ls /opt/sgCheckup/groups | (
  while read filepath; do
    echo $filepath
    /opt/sgCheckup/groups/$filepath &
    if [[ $(jobs -p | wc -l) -ge $NUM_PROCS ]]; then wait -n; fi
  done;
  wait
)
