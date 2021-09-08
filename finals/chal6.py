# -*- coding: utf-8 -*-
"""
Created on Fri Jul 10 22:58:20 2020

@author: Envy3
"""
import base64, string, os, binascii, string

os.chdir("./finals/")

def Hamm_Dist(str1,str2): #returns Hamming distance of two strings
    total = 0
    XOR_array = [ a ^ b for (a,b) in zip(str1,str2)]
    for num in XOR_array:
        total += bin(num).count("1")
    return total

#print(Hamm_Dist("this is a test","wokka wokka!!!"))
#Sucess! - Step 1
#print(Hamm_Dist('jake','fire')) = 6 , additional verification it is correct

#import single-byte XOR cipher functions from Challenge 3
def hex_XOR(str1,str2):
    XOR_array = [ a ^ b for (a,b) in zip(str1,str2)]
    return bytes(XOR_array)

def count_alphanum(byte_array):
    count = 0
    for num in byte_array:
        if chr(num).isalpha():
            count+=1
    return count

def freq_analysis(byte_array): #improved metric for frequency analysis
    lookup_table = {
        'a':0.0855, 'b':0.0160, 'c':0.0316,
        'd':0.0387, 'e':0.1210, 'f':0.0218,
        'g':0.0209, 'h':0.0496, 'i':0.0733,
        'j':0.0022, 'k':0.0081, 'l':0.0421,
        'm':0.0253, 'n':0.0717, 'o':0.0747,
        'p':0.0207, 'q':0.0010, 'r':0.0633,
        's':0.0673, 't':0.0894, 'u':0.0268,
        'v':0.0106, 'w':0.0183, 'x':0.0019,
        'y':0.0172, 'z':0.0011
        } #not used
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies[chr(num).lower()] for num in byte_array if chr(num) in character_frequencies])

def solve_single_XOR(input1): #input: ciphertext in bytes, output: most likely key character
    
    char_set = string.ascii_lowercase
    highest_score = 0
    best_guess = ''    
    
    for char in char_set:
        key = (char * len(input1))
        key = key.encode("utf-8")
        output = hex_XOR(input1,key)
        
        if freq_analysis(output) > highest_score:
            highest_score = freq_analysis(output)
            best_guess = char
            #print('likely guess:',best_guess,'value:',highest_score)
    #('best guess:',best_guess,'value:',highest_score)     
    return best_guess

#import XOR_solver from problem 5 to check output with slight modifications
def repeating_XOR(plain,key): #input: two strings, output: bytes object
    byte_array = []
    for i in range(len(plain)):
        byte_array.append(ord(plain[i]) ^ ord(key[i%len(key)]))
    return bytes(byte_array)
#print(repeating_XOR('abc','a'))

def encrypt_file(infile, key, outfile):
    with open(infile,'r') as f:
        with open(outfile,'a') as out:
            out.write(repeating_XOR(f.read(),key).hex())

def decrypt_file(infile, key,outfile):
     with open(infile,'r') as f:
         with open(outfile,'a') as out:
             out.write(repeating_XOR(base64.b64decode(f.read()).decode('utf-8'),key).decode('utf-8'))

ciphertext = ''
with open('xor_encrypted_messages.txt','r') as f:
    ciphertext = f.readline()[:-1]
    print(repr(ciphertext))
    ciphertext = binascii.unhexlify(ciphertext)
    print(ciphertext)
    #ciphertext = base64.b64decode(ciphertext)

array_dist = []

for keysize in range(2,41):
    #copied code from further down below
    dists = []
    
    end_index = keysize * 2
    while end_index <= len(ciphertext):
        first_block = ciphertext[end_index-(keysize*2):end_index-keysize]
        second_block = ciphertext[end_index-keysize:end_index]
        dists.append(Hamm_Dist(first_block,second_block)/keysize)
        end_index += keysize*2
        
    array_dist.append((sum(dists)/len(dists),keysize))

array_dist.sort(key=lambda tup: tup[0])
print(array_dist)

'''
for case in range(3):
    target_key = array_dist[case][1]
    
    start_index = 0
    init_blocks = []
    
    while start_index < len(ciphertext):
        init_blocks.append(ciphertext[start_index:start_index+target_key])
        start_index += target_key
        
    #print('length of init-blocks[0]:',len(init_blocks[0]))
    #print('init-blocks[0]:',init_blocks[0])
    
    commit_blocks = []
    
    for index in range(1,target_key+1):
        ith_bytes = []
        for block in init_blocks:
            if(len(block)>=index):
                ith_bytes.append(block[index-1:index])  
        commit_blocks.append(ith_bytes)    
    print(len(commit_blocks))   
    #print(commit_blocks)
    
    likely_key = ''
    for block in commit_blocks:
        #print(b''.join(block))
        likely_key += solve_single_XOR(b''.join(block))
        
    print(likely_key)
    #decrypt_file('6.txt',likely_key,'output.txt')
'''

target_key = 16

start_index = 0
init_blocks = []

while start_index < len(ciphertext):
    init_blocks.append(ciphertext[start_index:start_index+target_key])
    start_index += target_key
    
#print('length of init-blocks[0]:',len(init_blocks[0]))
#print('init-blocks[0]:',init_blocks[0])

commit_blocks = []

for index in range(1,target_key+1):
    ith_bytes = []
    for block in init_blocks:
        if(len(block)>=index):
            ith_bytes.append(block[index-1:index])  
    commit_blocks.append(ith_bytes)    
print(len(commit_blocks))   
print(commit_blocks)

likely_key = ''
for block in commit_blocks:
    #print(b''.join(block))
    likely_key += solve_single_XOR(b''.join(block))
    
print(likely_key)

    
    
    
    
    
    
    
