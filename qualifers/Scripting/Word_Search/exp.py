from pwn import *
from pprint import pprint
import numpy as np
from pwnlib.util.sh_string import test_all

def trans_diag(diag_num,b_i,e_i,forward=True):

    d_start = None
    start = None
    end = None
    if forward:
        if diag_num <= 0:
            d_start = (abs(diag_num),0)
        else:
            d_start = (0,diag_num)
        start = (d_start[0]+b_i, d_start[1]+b_i)
        end = (d_start[0]+e_i, d_start[1]+e_i)
    else:
        if diag_num <= 0:
            d_start = (0, abs(diag_num))
        else:
            d_start = (diag_num, 14)
        start = (d_start[0]+b_i,d_start[1]-b_i)
        end = (d_start[0]+e_i,d_start[1]-e_i)
    return start, end

r = remote('word-search.ctf.fifthdoma.in',4243)
res = r.recv().decode('utf-8').split('\n')
print(res)

#Retrieve word list and grid data
words = []
grid = []

split_str = '   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14'
split_pos = res.index(split_str)
for i in range(1,split_pos):
    words.append(res[i])
for i in range(split_pos+1,len(res)-2):
    grid.append(res[i][3:].split("  "))
print(words)
#print(grid)

#Perform search
test_lst = words[:1]

grid = np.array(grid) #Convert to numpy matrix
print(grid)

for word in words:
    start_pos = None #row, column
    end_pos = None

    found = False
    word_rev = word[::-1]
    #Check columns
    for i in range(15):
        col = ''.join(grid[:,i])
        if word in col or word_rev in col:
            print("I found in column!")
            if word in col:
                start_pos = (col.index(word),i)
                end_pos = (col.index(word)+len(word)-1,i)
            else:
                end_pos = (col.index(word_rev),i)
                start_pos = (col.index(word_rev)+len(word_rev)-1,i)
            print(start_pos,end_pos)
            found = True
            break
    #Check rows
    if not found:
        for i in range(15):
            row = ''.join(grid[i,:])
            if word in row or word_rev in row:
                print("I found in row!")
                if word in row:
                    start_pos = (i, row.index(word))
                    end_pos = (i,row.index(word)+len(word)-1)
                else:
                    end_pos = (i, row.index(word_rev))
                    start_pos = (i,row.index(word_rev)+len(word_rev)-1)
                print(start_pos,end_pos)
                found = True
                break
    if not found:
        #Forward diagonal
        for i in range(-15,15):
            diag = ''.join(grid.diagonal(i))
            if word in diag or word_rev in diag:
                if word in diag:
                    start_pos, end_pos = trans_diag(i, diag.index(word), diag.index(word)+len(word)-1)
                else:
                    start_pos, end_pos = trans_diag(i, diag.index(word_rev)+len(word_rev)-1, diag.index(word_rev))
                print("I found in diagonal!")
                found = True
                break
        #Backward diagonal
        for i in range(-15,15):
            diag = ''.join(np.rot90(grid).diagonal(i))
            if word in diag or word_rev in diag:
                if word in diag:
                    start_pos, end_pos = trans_diag(i, diag.index(word), diag.index(word)+len(word)-1, False)
                else:
                    start_pos, end_pos = trans_diag(i, diag.index(word_rev)+len(word_rev)-1, diag.index(word_rev), False)
                print("I found in other diagonal!")
                found = True
                break
    if not found:
        print("Houston we got a problem")
    if start_pos:
        start = str(start_pos[0]) + ", " + str(start_pos[1])
        end = str(end_pos[0]) + ", " + str(end_pos[1])
        r.sendline(start.encode('utf-8'))
        res = r.recv().decode('utf-8')
        print(res)
        r.sendline(end.encode('utf-8'))
        res = r.recv().decode('utf-8')
        print(res)
print(r.recv())
#r.interactive()




r.close()