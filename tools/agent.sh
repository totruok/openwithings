#!/bin/bash
cd ~/withings_ble
rm -f agent.fifo; mkfifo agent.fifo
exec 5<> agent.fifo
: > agent.out
bluetoothctl -a NoInputNoOutput <&5 > agent.out 2>&1 &
sleep 1; echo "default-agent" >&5
seen=0
while kill -0 %1 2>/dev/null; do
  n=$(grep -c "Accept pairing\|Confirm passkey\|Authorize service\|Request confirmation" agent.out)
  if [ "$n" -gt "$seen" ]; then echo "yes" >&5; echo "$(date +%T) auto-answered yes (#$n)" >> agent.answers; seen=$n; fi
  sleep 0.2
done
