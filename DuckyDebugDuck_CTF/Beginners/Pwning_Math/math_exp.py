from pwn import *

r = remote('ctf.cs.technion.ac.il',4091)

target_str = "What is "

log.info("[+] Starting the search")
while True:
    prompt = r.recvline().decode('utf-8')
    print(prompt)
    try:
        start_index = prompt.index(target_str) + len(target_str)
    except:
        log.info("[+] Found the flag")
        break
    eval_exp = prompt[start_index:-2]
    print("Eval exp:",eval_exp)
    result = int(eval(eval_exp))
    print("Result:",result)
    r.sendline(str(result))

r.close()

