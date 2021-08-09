from pwn import *
from base64 import b64decode

r = remote('ctf.cs.technion.ac.il',4042)
start = "> ".encode('utf-8')


## Result: Accounting for padding, we can say that the block size is 16.
def guess_block_size():
    last_length = None
    log.info("[+] Detecting the block size")
    for i in range(64):
        r.recvuntil(start)
        msg = 'A'*i
        r.sendline(msg.encode('utf-8'))
        res = r.recvline().decode('utf-8')
        if last_length is None or len(res) > last_length:
            last_length = len(res)
            print("i:",i,"Length:",len(res))

def pad(target_length,end_str):
    '''
    Given the target_length (int) and the
    end_str to append at the end of the string,
    return a padded string of length target_length
    '''
    pad_length = target_length - len(end_str)
    #print("Pad length:",pad_length)
    out = b'A'*pad_length + end_str
    #print(out)
    return out

block_size = 16

start_i = 32

#First byte
known = b""

for target_len in range(1,50):
    original = None
    msg = None
    for i in range(start_i,128):
        #Establish target encryption
        r.recvuntil(start)
        num_blocks = target_len // block_size + 1
        if i == start_i:
            msg = "A"*(num_blocks*16-len(known)-1) #Want to be one less than the full block
        else:
            msg = pad(num_blocks*16-1,known) + bytes([i]) #Same as before except now with character guess
        r.sendline(msg)
        res = r.recvline()
        res = bytes.fromhex(res[:-1].decode('utf-8'))
        res = res[(num_blocks-1)*block_size:num_blocks*block_size]
        #print("Guessing:",chr(i),"Result:",res)
        if i == start_i:
            original = res
            print("Original: ",original)
        else:
            if res == original:
                known += bytes([i])
                print("Inspected:",(num_blocks-1)*block_size,"to",num_blocks*block_size)
                print("Got match at i:",i)
                print("Current known: ",known)
                break

r.close()