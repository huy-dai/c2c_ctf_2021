# Team 17 Solutions for C2C CTF Finals

Link to the original CTF can be found here: <http://ctf.cs.technion.ac.il/>

These are writeups to problems that my team members and I were able to solve in the C2C CTF finals. We ended up placing 3rd in the entire competition, narrowly trailing 1st and 2nd place who got the same number of solves as us but did so in a faster time period. This competition has definitely taught me a lot about working in a team and also learning to perservere through hard problems. I'm excited with how well we did this year and I'm very much looking forward to being a part of C2C CTF again next year, where MIT will be the hosting university!

# What a Mess

Category: Crypto
Points: 500

Prompt: Unravel this sweet mess

~~~text
<--------------GE2Q====----00110001 00110100-----<--------------GE2Q====----00110001 00110100-----<0a<-----GE2Q====--------------------<-----GE2Q====--------------------<0a<--------00110001 00110100-31 32----00110001 00110100----00110001 00110100--<--------00110001 00110100-31 32----00110001 00110100----00110001 00110100--<0a<--31 32-----------------------<--31 32-----------------------<0a<---------------------------<---------------------------<0a<---------------------------<---------------------------<0a<--------------GE2Q====----00110001 00110100-----<--------------GE2Q====----00110001 00110100-----<0a<-----GE2Q====--------------------<-----GE2Q====--------------------<0a<--------00110001 00110100-31 32----00110001 00110100----00110001 00110100--<--------00110001 00110100-31 32----00110001 00110100----00110001 00110100--<0a<--00110001 00110100-----------------------<--00110001 00110100-----------------------<0a<---------------------------<---------------------------<0a<---------------------------<---------------------------<0a<--------------GE2Q====----00110001 00110100-----<--------------GE2Q====----00110001 00110100-----<0a<-----GE2Q====--------------------<-----GE2Q====--------------------<0a<--31 32----00110001 00110100-31 32----00110001 00110100----00110001 00110100--<--31 32----00110001 00110100-31 32----00110001 00110100----00110001 00110100--<0a<---------------------------<---------------------------<0a<---------------------------<---------------------------<0a<---------------------------<---------------------------<0a<--------------GE2Q====----00110001 00110100-----<--------------GE2Q====----00110001 00110100-----<0a<-----GE2Q====--------------------<-----GE2Q====--------------------<0a<--------00110001 00110100-31 32----00110001 00110100----00110001 00110100--<--------00110001 00110100-31 32----00110001 00110100----00110001 00110100--<0a<--31 32-----------------------<--31 32-----------------------<0a<---------------------------<---------------------------<0a<---------------------------<---------------------------<
~~~

The flag will be in the format flag{What a nice clean flag}

Solution: At first glance, it seems the ciphertext is made of multiple parts that are encrypted differently.

`<---------------------------<---------------------------<0a`

`GE2Q====`

`00110001 00110100`

`31 32`

The binary decodes to '14', while GE2Q==== is base32 and decodes to 15. 31 32 decodes to 12 in hex. Putting it all together, we get something like this:

~~~text
<--------------15----14-----<--------------15----14-----<
<-----15--------------------<-----15--------------------<
<--------14-12----14----14--<--------14-12----14----14--<
<--12-----------------------<--12-----------------------<
<---------------------------<---------------------------<
<---------------------------<---------------------------<


<--------------15----14-----<--------------15----14-----<
<-----15--------------------<-----15--------------------<
<--------14-12----14----14--<--------14-12----14----14--<
<--14-----------------------<--14-----------------------<
<---------------------------<---------------------------<
<---------------------------<---------------------------<


<--------------15----14-----<--------------15----14-----<
<-----15--------------------<-----15--------------------<
<--12----14-12----14----14--<--12----14-12----14----14--<
<---------------------------<---------------------------<
<---------------------------<---------------------------<
<---------------------------<---------------------------<


<--------------15----14-----<--------------15----14-----<
<-----15--------------------<-----15--------------------<
<--------14-12----14----14--<--------14-12----14----14--<
<--12-----------------------<--12-----------------------<
<---------------------------<---------------------------<
<---------------------------<---------------------------<
~~~

Once we got to this point, our team were stuck for a long time trying to figure out how the ciphertext could further be decoded. We considered ideas like esoteric languages like BF or breaking the quadrants apart and looking for symmetry. At the end one of our team member with a background in music recognized this as a song tablature for guitar which plays the tune of the song "Sweet Child of Mine".

Flag: flag{sweet child o mine}

## Message from the past 

Category: Crypto
Points: 350

Prompt: There is an important message here

~~~text
4qCo4qCo4qCo4qCo4qCo4qCA4qCo4qCo4qCo4qCo4qCkCuKgpOKgqOKgqOKgqOKgqOKggOKgpOKgpOKgpOKgqOKgqArioKTioKjioKjioKjioKjioIDioKTioKTioKTioKTioKgK4qCk4qCk4qCo4qCo4qCo4qCA4qCo4qCo4qCo4qCk4qCkCuKgqOKgqOKgpOKgpOKgpOKggOKgpOKgpOKgpOKgpOKgpArioKTioKjioKjioKjioKjioIDioKTioKTioKTioKTioKgK4qCk4qCk4qCo4qCo4qCo4qCA4qCo4qCo4qCo4qCk4qCkCuKgqOKgqOKgpOKgpOKgpOKggOKgpOKgpOKgpOKgpOKgpArioKTioKTioKjioKjioKjioIDioKjioKjioKjioKjioKQK4qCk4qCo4qCo4qCo4qCo4qCA4qCk4qCk4qCk4qCo4qCoCuKgpOKgqOKgqOKgqOKgqOKggOKgqOKgqOKgqOKgqOKgqArioKjioKjioKTioKTioKTioIDioKTioKTioKTioKTioKQK4qCo4qCo4qCo4qCo4qCo4qCA4qCk4qCk4qCo4qCo4qCoCuKgpOKgqOKgqOKgqOKgqOKggOKgqOKgpOKgpOKgpOKgpArioKTioKTioKjioKjioKjioIDioKTioKTioKTioKTioKg=
~~~

Flag will be in the format FLAG{You found a Flag}

Solution: This prompt is similar to the last problem. The equals sign at the end of the string indicates to us this is some kind of base32 or base64 encoding. Using CyberChef we were able to figure the message can be decoded using the following translation steps:

Ciphertext -> Base64 -> Braille -> More Code -> Hex

Flag: flag{This is the Way}


## 9 Lives

Category: Crypto
Points: 350 

~~~text
Can you crack this hash?

88ad4a0b84b7af2234d1c3169562b0d0

Flag will be in the format FLAG{password}
~~~

Solution: The hint provided tell us that the password was resetted this year. Thus we can assume that the number "21" or "2021" or "twenty" and "one" will be in there somewhere in the password.With the problem titled "9 Lives", we can infer that it wants us to use hashcat.

I was able to crack the using the following command with the `rockyou.txt` password list:

`hashcat -a 1 -m 0 ex.hash rockyou.txt hint.txt`

Note: The hint.txt contains the hints I mentioned earlier.

The password came out to be "rachmaninoff2021"

Flag: flag{rachmaninoff2021}

## Very Secure Protocol

Category: Crypto
Points: 600

Prompt: We have detected a C2 payload on one of our servers! The Networks team have extracted its communications from their traffic logs, and Operations have dumped the payload code from the running process before killing it. Find out what the actors have exfiltrated!

Solution: We are given a Python file with code used by one side to encrypt their message, and the output is provided in the logs.json file. After a bit of deciphering and research on the Python variable names we were able to tell that they are performing a Diffie-Hellman key exchange and then using the key generated as their AES encryption key. They then encrypt their message/flag using AES.

Taking a look at the JSON file we can see some of the variable values encoded in Base64. Specifically we are given `p`, `q` , `A` , and `B`

The shared AES key is generated by doing `A^b mod p` and then SHA256 hashing the result. In  Here `b` is a number which we do not know (except for the fact that it is less than `p`).

We are also given `B`, which is calculated by doing `g^b mod p`.

In that case, the target for this problem is that we want to find `b` so we can recover the shared key. From looking around online I see that there is a discrete logarithm calculator that can help us do this quickly, e.g., finding the exponent in `x^y mod n` when x and n is known (and when they aren't too large). By putting that in we see that `b` is equal to 620620105.

After that I plugged in the value for b and used the provided function in the file to decrypt both `ret` messages. All this code was inserted in the original encryption file at [payload.py](Very_Secure_Protocol/payload.py)

~~~py
p = base64_to_long(j['inc'][0]['p'])
g = base64_to_long(j['inc'][0]['g'])
A = base64_to_long(j['inc'][0]['A'])
print(p,g,A)
B = base64_to_long("Ph6IeA==")
print("B",B)
b = 620620105
print(pow(g,b,p))

shared = pow(A, b, p)
shared = sha256(long_to_bytes(shared)).digest()
cipher = AES.new(shared, AES.MODE_ECB)
print(decrypt(cipher, j['out'][1]['return']))
print(decrypt(cipher, j['out'][2]['return']))
~~~~

Output: 
~~~py
2272978429 2 1116819144
B 1042188408
1042188408
b'sensitive.txt\n'
b'FLAG{wh4dy4_m3an_32_b1t5_1s_1n53cur3}\n
~~~