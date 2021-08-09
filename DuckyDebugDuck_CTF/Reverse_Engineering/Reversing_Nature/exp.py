#!/usr/bin/env python3

from pwn import *

#Diagnosing file not found issue
#Solved by: Specifying file path within c2c_CTF directory
#import os
#print(os.getcwd())

def fib_gen():
    cur_val, next_val = 1, 1
    while True:
        yield cur_val
        cur_val, next_val = next_val, cur_val + next_val

def wrap_int(val):
    out = val
    if out > 2**31-1:
        out = val % 2**32
        if out > 2**31-1:
            out = out - 2**32
    return out

def main():
    context.os = 'linux'
    fail = b"Enter the key: You're not good enough at reversing nature, try again\n"

    elf = ELF("./DuckyDebugDuck_CTF/Reverse_Engineering/Reversing_Nature/target")
    p = None
    for i in range(10,100):
        print("Trying value:",i)
        p = elf.process()
        p.sendline(str(i).encode('utf-8'))
        gen = fib_gen()
        for _ in range(i):
            msg = wrap_int(next(gen))
            #This also works too:
            #msg = next(gen)
            print(msg)
            p.sendline(str(msg).encode('utf-8'))
        res = p.recvall()
        print(res)
        if res != fail:
            log.info("Found it!")
            print(res)
            break
        #res = p.recvline()
        #print(res)
        p.close()

main()