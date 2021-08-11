def my_func(x):
    # Note: Don't fall for the off by one
    if x == 0 or x == 1:
        return 1
    return my_func(x - 1) + my_func(x - 2)

print(f"flag{{{my_func(100)}}}")

def fib(n):
    cur, next = 1, 1
    for i in range(n): # n >= 2
        cur, next = next, cur + next
    return cur

print(f"flag{{{fib(100)}}}")