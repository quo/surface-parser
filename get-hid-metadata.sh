#!/bin/sh

cat /dev/ithc > ithc-hid-meta.dat &

# read report descriptor
echo d 7 8 0 0 > /sys/kernel/debug/ithc/cmd
# read metadata
echo d 4 1 6 > /sys/kernel/debug/ithc/cmd

sleep 1
kill $!

