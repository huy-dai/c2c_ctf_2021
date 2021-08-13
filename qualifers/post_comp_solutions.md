## My solutions for problems solved after the C2C CTF Qualfiers

After the qualfiers had concluded, I saw that people were sharing their solutions for different problems. I decided to take advantage of this opportunity to go over challenges that I didn't get during the 24-hour period and see what I could learn. 

In my writeups, I will also try to highlight what I had gotten to on my own and how I was able to complete the challenge with others help.

## Broky

Category: Crypto

Points: 950

We were given an encrypted data file named `killswitch` and an RSA public key `public-key.pub`. With a bit of research, we find that we can directly encrypt files using an RSA public key and decrypt with the private, given that the data is smaller than or equal to the key length.

When we dump the key parameters `public-key.pub` file with `RsaCtfTool` we get the following:

~~~console
$ python3 RsaCtfTool.py --publickey public-key.pub --dumpkey
private argument is not set, the private key will not be displayed, even if recovered.
Details for public-key.pub:
n: 174776634499365185044152993509362624036904353007427805459068176329835550069164957428014245129075350521665501113613732156274308708416158135093542590677545505977327257686941870374910044600757349485405575480034556717469583373661251050825191173966631184463407966953014469657004165922729869240061652972104818333329
e: 65537
~~~

After running `RsaCtfTool` on the public key for a few minutes I saw that it wasn't very successful, so I tried looking up `n` on `factordb`. Result [here](http://factordb.com/index.php?query=174776634499365185044152993509362624036904353007427805459068176329835550069164957428014245129075350521665501113613732156274308708416158135093542590677545505977327257686941870374910044600757349485405575480034556717469583373661251050825191173966631184463407966953014469657004165922729869240061652972104818333329).


Turns out `n` is a perfect square, which is not something that I've seen in an RSA problem before. Generally perfect squares are never used for `n` because they can be factored easily. Adding to that, even though we now know the factors `p`,`q`, most standard RSA tools are not equipped to handle this special case since it almost never happens (`RsaCtfTool` and `Crypto.PublicKey.RSA.construct()` both explodes on you when you provide `p`==`q`).

Turns out that for a perfect square `n` the calculation process is a bit different. Instead of the totient(n) being `(p-1)*(q_1)`, you would do `(p-1)*p`. From this, you can just calculate `d` by finding the modular inverse of `e mod phi` or `e mod (p-1)*p`.

In my script, I had got to this point but I got stuck on being able to construct the private key using `Crypto.PublicKey.RSA.construct()`. By taking a look at a script given by `Social_Anthrax,` I found that the process of decrypting a file using an RSA key is the same as:

1. Interpreting the bytes of the file as a `long` int
2. Performing the calculation `Plaintext = Ciphertext^d mod n`
3. Converting the `plaintext` long int back to bytes and saving it as a file

For step 1. and 3., Crypto.Util.number provides the nifty `bytes_to_long` and `long_to_bytes` function which does exactly what we need it to do. Also, I didn't realize that in version Python 3.8+ the `mod` function now has the ability to calculate modular inverses like `pow(e,-1,n)` to calculate `d`. Very nifty!


You can find the full script at `exp.py`. The main logic looks like the following:

~~~py

phi = (p)*(p-1) #Different from normal RSA
d_old = modinv(e,phi)
#Alternatively...
d = pow(e,-1,phi)
print("d:",d)

print("[+] Performing checks")
assert(d_old==d)
assert(p*q==n)
assert(e*d%phi==1)

cipher = None

with open("./killswitch","rb") as f:
    cipher = bytes_to_long(f.read())
print("Ciphertext:",cipher)

#Decrypt
plain = long_to_bytes(pow(cipher,d,n))
print("Plain:",plain)

out = open('output.enc', 'wb')
out.write(plain)
out.close()
~~~

## Identify and decrypt

Cateogry: RevEng

Points: 700

**Note:** I wasn't able to get the flag from this problem but I believe that the process should work based on what I've heard from the other participants.

We were given a data file named `salvaged` and also a relevant hex string:

`dd7d71e9af727c4be5c58fd87df8e682f9b4830118d6c1b5796021dd9ed82fe565572867db629ca90d70c53071c677433a94b89b1e6ffbb8e81cb47cb7da674a`

Using `xxd`, we can view the first 8 bytes of the file to help us identify the file signature. It should be noted that file signatures can be of various lengths, from 4 to 8 bytes or even more. 

~~~console
$ xxd salvaged 
00000000: 0100 0000 d08c 9ddf 0115 d111 8c7a 00c0  .............z..
00000010: 4fc2 97eb 0100 0000 4bc9 3e4c f13c 5f46  O.......K.>L.<_F
00000020: b1dd 6bd3 fe9b d49a 0000 0000 0200 0000  ..k.............
[...]
~~~

Searching up "01 00 00 00 d0 8c 9d df" on Google we find that it is the file signature of files encrypted by DPAPI. ([ref](https://www.nirsoft.net/utils/dpapi_data_decryptor.html)) DPAPI stands for Data Protection Application Programming Interface and is a cryptographic API built in Windows that allows symmetric encryption of any type of data. According to [Wikipedia](https://en.wikipedia.org/wiki/Data_Protection_API), "thhe DPAPI keys used for encrypting the user's RSA keys are stored under %APPDATA%\Microsoft\Protect\{SID} directory, where {SID} is the Security Identifier of that user. The DPAPI key is stored in the same file as the master key that protects the users private keys. It usually is 64 bytes of random data."

Regardless, there are a number of tools out there which can decrypt DPAPI data, including the DataProtectionDecryptor tool in the first link (it didn't work for me however). We can assume that the hex string the challenge provided us with was the Master Key that can encrypted. However, I ended up spending about an hour and a half trying different solutions to decrypt the `salaved` file but no avail. The Github tools which can perform the decryption operation are all written for Python 2.7 and depends on the outdated M2Crypto library, which I wasn't able to successfully install. Apparently `Mimikatz` can also decrypt this type of file ([ref](https://miloserdov.org/?p=4205)), but after disabling my antivirus program and running it the tool had just crashed on me.

But, I digress. The important thing is that we understand how the problem *could* be solved.

Flag: ???

## Lost and Found

Category: Stego

Points: 150

We were given an image of a maze-like structure, though it's not clear from the picture whether we should solve it or even if doing that will give us more information.

However, since the picture is in black and white I should have thought about how information could be hidden in very small pixels in either the white space or black outlines. If we drop the picture in `Windows Paint` and fill in the white lines with black, we'll see the outline of the flag in the top left corner

Flag: flag{paint_is_the_old_school_cool}

## SunTzu

Category: Misc

Points: 100

We were given a website (<http://suntzu.ctf.fifthdoma.in>) that represented some ticket support system asking us for our name, explanation of technical issue, and a Captcha code for verification. Since the Captcha system stops working after the competion ended, I couldn't verify the solve but apparently you were suppose to infer that they are running some kind of bash script [see the next solve] to interpret the inputs. Additionally, since all the hints point to the `username` being the insecure field you could have done `; cat *` to escape from the bash operation and cat all the files in the current directory. There should be some files which has SunTzu quotes and another file which contains the flag.

Flag: ???

## Guess the flag

Category: Exp

Points: 100

We were given a `nc` web server which simply asks us to guess the flag. When we provide an unexpected input like `*` or two entries separated by a space we can see that it gives us back the response:

~~~console
$ nc guess-the-flag.ctf.fifthdoma.in 4242
What do you think the flag is?
*
Checking...
./run.sh: line 15: [: too many arguments
Good attempt, but no.

What do you think the flag is?
flag flag2
Checking...
./run.sh: line 15: [: too many arguments
Good attempt, but no.
~~~

If we look up the [error](https://stackoverflow.com/questions/13781216/meaning-of-too-many-arguments-error-from-if-square-brackets), we see that this is happening because bash is interpreting our input as a literal bash variable. Thus, `*` will get interpreted as all files in the current directory, which is why we get back the error of `two many arguments`. 

Assuming that the program is performing some equality check like `[ $input -eq FLAG ]`, we can use the OR (-o) and EQ (-eq) conditionals to get it to always return True. Note that if the structure had been reversed like `[ FLAG -eq $input]` we would have needed to flip our conditionals around as well.

In our case,

~~~console
$ nc guess-the-flag.ctf.fifthdoma.in 4242
What do you think the flag is?
1 -eq 1 -o abc
Checking...
You're right, the flag is FLAG{why_is_[_a_regular_command}.
~~~

gets us the flag.

Flag: FLAG{why_is_\[_a_regular_command}.
