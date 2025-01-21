#!/bin/bash
set -Eeuo pipefail  
kernel_version=$(uname -r)
if [[ "$kernel_version" == 6.* ]]; then
  if [[ $(cat /sys/devices/system/cpu/vulnerabilities/itlb_multihit) == "Not affected" ]]; then
    KVM_VENDOR_MOD=$(lsmod |grep -P "^kvm_(amd|intel)" | awk '{print $1}')
    sudo modprobe -r $KVM_VENDOR_MOD kvm
    sudo modprobe kvm nx_huge_pages=never
    sudo modprobe $KVM_VENDOR_MOD
  fi
  if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    sudo mount -o remount,favordynmods /sys/fs/cgroup
  fi
fi
