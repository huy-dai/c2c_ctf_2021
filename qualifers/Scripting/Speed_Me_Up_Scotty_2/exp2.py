# Dynamic Programming implementation of LCS problem
 
# Maximum string length
N = 100
L = [[0 for i in range(N)]
        for j in range(N)]
 
# Returns set containing all LCS
# for X[0..m-1], Y[0..n-1]
def findLCS(x, y, m, n):
 
    # construct a set to store possible LCS
    s = set()
 
    # If we reaches end of either string, return
    # a empty set
    if m == 0 or n == 0:
        s.add("")
        return s
 
    # If the last characters of X and Y are same
    if x[m - 1] == y[n - 1]:
 
        # recurse for X[0..m-2] and Y[0..n-2] in
        # the matrix
        tmp = findLCS(x, y, m - 1, n - 1)
 
        # append current character to all possible LCS
        # of substring X[0..m-2] and Y[0..n-2].
        for string in tmp:
            s.add(string + x[m - 1])
 
    # If the last characters of X and Y are not same
    else:
 
        # If LCS can be constructed from top side of
        # the matrix, recurse for X[0..m-2] and Y[0..n-1]
        if L[m - 1][n] >= L[m][n - 1]:
            s = findLCS(x, y, m - 1, n)
 
        # If LCS can be constructed from left side of
        # the matrix, recurse for X[0..m-1] and Y[0..n-2]
        if L[m][n - 1] >= L[m - 1][n]:
            tmp = findLCS(x, y, m, n - 1)
 
            # merge two sets if L[m-1][n] == L[m][n-1]
            # Note s will be empty if L[m-1][n] != L[m][n-1]
            for i in tmp:
                s.add(i)
    return s
 
# Returns length of LCS for X[0..m-1], Y[0..n-1]
def LCS(x, y, m, n):
 
    # Build L[m+1][n+1] in bottom up fashion
    for i in range(m + 1):
        for j in range(n + 1):
            if i == 0 or j == 0:
                L[i][j] = 0
            elif x[i - 1] == y[j - 1]:
                L[i][j] = L[i - 1][j - 1] + 1
            else:
                L[i][j] = max(L[i - 1][j],
                              L[i][j - 1])
    return L[m][n]
 
# Driver Code
if __name__ == "__main__":
    x = 'CCABBCBACABBABACACBBBCBCABABBAABACBCAAACBBCCCBBABBBACCBBBBAB'
    y = 'ACCCCBCBCBBCBABBCACCCBBAABCCCCAAABBAABACAAABCBABBCCBCAACCCAA'
    m = len(x)
    n = len(y)
 
    print("LCS length is", LCS(x, y, m, n))
 
    s = findLCS(x, y, m, n)
     
    for i in s:
        print("flag{"+i+"}")

    print(len(s))
 
# This code is contributed by
# sanjeev2552