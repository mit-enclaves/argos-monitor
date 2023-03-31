#!/bin/bash

insmod tyche-capabilities.ko
mod_number=`cat /proc/devices | grep tyche-capabilities | awk '{print $1}'`
check=`echo $mod_number | wc -l`
if [ "$check" != "1" ]; then
  echo "Error: multiple lines from the device driver"
  echo $check
  exit 1
fi
mknod /dev/tyche-capabilities c $mod_number 0
