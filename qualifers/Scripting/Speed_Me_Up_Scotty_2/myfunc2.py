"""
Example:
> my_func2('ABAAABBCCACBBBBCBCBCBBBBACBCBCCBBBBCBBBBCAACCABCAACABACACCAB', 'CCCBAABAACCCAABABBCCABBCBCABAABAABCABACACACABABBBCACBACBABCC')
CCCBBCCCBABBCCBBCBBBBCAACCACAACABACACC
"""
def my_func2_inner(x, y, a, b):
    if a == 0 or b == 0:
        return 0, ""
    if x[a - 1] == y[b - 1]:
        m, n = my_func2_inner(x, y, a - 1, b - 1)
        return m + 1, n + x[a - 1]
    return max(my_func2_inner(x, y, a, b - 1), my_func2_inner(x, y, a - 1, b))


def my_func2(x, y):
    return my_func2_inner(x, y, len(x), len(y))[1]

def LCSLength_DP (seq1, seq2):

    sz1 = len(seq1)
    sz2 = len(seq2)
    length_lcs = 0

    # Create a DP table of size [sz1 + 1][sz2 + 1]
    LCSTable = [0] * ( sz1 + 1 )
    for i in range ( sz1 + 1 ) :
        LCSTable[i] = [0] * ( sz2 + 1 )

    # Finding the length of LCS
    for a in range (sz1 + 1) :
        for b in range (sz2 + 1) :
            if (a == 0 or b == 0) :
                LCSTable[a][b] = 0
            elif ( seq1[a-1] == seq2[b-1] ) :
                LCSTable[a][b] = 1 + LCSTable[a-1][b-1]
            else :
                LCSTable[a][b] = max ( LCSTable[a-1][b], LCSTable[a][b-1] )

    length_lcs = LCSTable[sz1][sz2]

    # Constructing the LCS
    i = sz1
    j = sz2
    lcs = ""
    while ( i > 0 and j > 0 ) :
       if ( seq1[i-1] == seq2[j-1] ) :
          lcs += seq1[i-1]  # Move diagonally towards top left 
          i -= 1
          j -= 1
       elif ( LCSTable[i-1][j] > LCSTable[i][j-1] ) :
          i -= 1 # Move upwards
       else :
          j -= 1 # Move towards left

    # Reverse lcs to find the actual sequence  
    lcs = lcs[::-1]

    return length_lcs, lcs

def test():
    return 'CCCBBCCCBABBCCBBCBBBBCAACCACAACABACACC'

#print(f"flag{{{test()}}}")

print(test())

print(f"flag{{{LCSLength_DP('CCABBCBACABBABACACBBBCBCABABBAABACBCAAACBBCCCBBABBBACCBBBBAB', 'ACCCCBCBCBBCBABBCACCCBBAABCCCCAAABBAABACAAABCBABBCCBCAACCCAA')}}}")

str1 = 'CCABBCBACABBABACACBBBCBCABABBAABACBCAAACBBCCCBBABBBACCBBBBAB'
str2 = 'ACCCCBCBCBBCBABBCACCCBBAABCCCCAAABBAABACAAABCBABBCCBCAACCCAA'

import pylcs
print(pylcs.lcs(str1,str2))
print(LCSLength_DP(str1,str2)[1])
