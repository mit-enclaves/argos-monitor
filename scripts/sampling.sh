#!/bin/bash

# set -uxoe pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 [log]"
fi

# log=$(cat "$1" | grep "VCPU0: ")

cat "$1" | while read line 
do
    if echo "$line" | grep -q "^VCPU0"; then
      addr=$(echo "$line" | sed 's/^.\{7\}//')
      echo "$addr"
      addr2line -e /home/qian/vmxvmm/linux-image/images/vmlinux  "$addr" -f
    fi
done
