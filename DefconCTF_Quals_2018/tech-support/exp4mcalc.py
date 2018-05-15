#!/usr/bin/env python
# coding: utf-8
from pwn import *

#init
context.log_level = "debug"
local=False
name = "mcalc"

if local:
    p = process(name)
else:
    p = remote("02528625.quals2018.oooverflow.io", 9009)

def pow_hash(challenge, solution):
	return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
	h = pow_hash(challenge, solution)
	return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
	candidate = 0
	while True:
		if check_pow(challenge, n, candidate):
			return candidate
		candidate += 1

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

def power():

	if not local:
		cv("Challenge: ")
		challenge = p.recvuntil("\n",drop = True)
		cv("n: ")
		n = int(p.recvuntil("\n",drop = True))
		cv("Solution:")
		sol = solve_pow(challenge, n)
		sd(str(sol))
		print("solution: ",sol)

power()
cv("how can I help you?")
sd("yes")

anslib = ["a tiring afternoon","experience","electromagnetic",'presence of floppy drives',"be... you?","long enough","happen in the morning?","Nintendo Wii","change the date","of the angle"]


for i in range(0,5):
	da = cv("?")
	answed = False
	for i in anslib:
		if i in da:
			sd("no")
			answed = True
			break
	if not answed:
		sd("yes")

p.interactive()
