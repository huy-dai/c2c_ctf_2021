# My Solutions for DuckyDebugDuck's Fun with Flags Practice CTF

Link to the original CTF can be found here: <http://ctf.cs.technion.ac.il/>

## Biblical

Category: Crypto

Points: 50

We are given the follow ciphertext:

`uozt{yryorxzo_xrksvih_ziv_gsv_yvhg}`

Given the curly braces are preserved after the encryption and that the ciphertext contains only normal letters, we can assume it is some subsitution cipher like ROT13. However, running a Caesar Cipher decoder yields us no result.

Taking a look at the prompt, the problem's name being  "Biblical" and the text being found in a synagogue points us to an encoding algorithm with a religious connection. 

After exploring CyberChef encoding choices, we find that `Atbash`, which is a monoalphabetic substitution cipher originally used to encrypt the Hebrew alphabet (explaing the synagogue connection) works to decode our text.

Flag: flag{biblical_ciphers_are_the_best}

## Relatively Secure Algorithm

Category: Crypto

Points: 100

We were given a text file which contains values for `n`, `e`, and `c`. Along with the problem's name, we can assume the ciphertext has been encoded using RSA. The problem recommends using a Python library called `pycryptodome`, which provides functions for constructing an RSA public key and private key with provided known parameters. However, this library is not necessary to solve the problem. 

The hints remark that this problem uses a less well-known implementation of RSA, and also that there should be a way to find factors [of n] without having to perform computations.

We can find the prime factorization (which is always unique for a given number) of `n` using the `factordb` website. In our case, `n` suprisingly has five prime factors, each being 309 digits. From this reference [post](https://crypto.stackexchange.com/questions/74891/decrypting-multi-prime-rsa-with-e-n-and-factors-of-n-given), we can see that we are dealing with a Multi-Prime RSA. The main benefit of this implementation is that it has more efficient key generation and better encrypting/decrypting performance, though one of its potential drawbacks is that in some cases it is easier to factor `n` with multiple smaller prime factors.

The first reference tells us that that the private key parameter `d` can be determined by the equation: 

$$d\gets e^{-1}\bmod\bigl((p-1)\,(q-1)\,(r-1)\,(s-1)\bigr)$$

given that `p`,`q`,`r`,`s` are factors of `n`. We can have more or less prime factors depending on the `n`.

Expanding further, the following [post](https://crypto.stackexchange.com/questions/31109/rsa-enc-decryption-with-multiple-prime-modulus-using-crt) provides for an efficient algorithm which can quickly solve the decryption problem for RSA for # of prime factors >= 2 using Chinese Remainder Theorem. Nicely for us, a Python implementation has already been created for this algorithm [here](https://gist.github.com/jackz314/09cf253d3451f169c2dbb6bbfed73782).

I've copied this file over and replaced the corresponding parameter variables at `rsa_solver.py`.  I've also added comments to the steps that are being covered in that Python script. One of the important things to cover is that we used the Extended Euclidean Algorithm as part of finding fast multiplicative inverses, which you can find more information about [here](https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/)


From the script, we find the decrypted text to be:

~~~text
CTF or Capture the Flag are a type of computer security competition where each participant or team competes to collect points by solving challenges in a number of areas in computer security. In order to solve a challenge a team must retrieve a flag. Flags are strings with certain fixed formats that are placed on servers, encrypted, hidden, returned after showing a specific ability and more. Submitting this flag to the website will yield points which will move the participants up the leaderboard. Anyways, here's the flag: flag{Rs4_1s_s1mpl3_t0_us3_4nd_4t7ack}
~~~

Flag: flag{Rs4_1s_s1mpl3_t0_us3_4nd_4t7ack}

## Secret Bits

https://www.hackerfactor.com/blog/index.php?/archives/894-PNG-and-Hidden-Pixels.html
https://fotoforensics.com/analysis.php?id=5725e300b5d6d30a7266abd477eb20cf6422a30d.189136
https://github.com/Hedroed/png-parser
https://www.google.com/search?channel=fs&client=ubuntu&q=Extract+PNG+chunks


## Ducking

Category: Stego

Points: 50

When we run `exiftool` on the image, we get the following:

~~~console
grayhimakar@grayhimakar-VirtualBox:~/Documents/c2c_ctf_2021/DuckyDebugDuck_CTF/Steganography/Ducking$ exiftool ducking.jpg 
ExifTool Version Number         : 11.88
File Name                       : ducking.jpg
Directory                       : .
File Size                       : 36 kB
File Modification Date/Time     : 2021:08:04 00:40:27-04:00
File Access Date/Time           : 2021:08:04 00:40:35-04:00
File Inode Change Date/Time     : 2021:08:04 18:45:33-04:00
File Permissions                : rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Comment                         : passphrase:duck
Image Width                     : 460
Image Height                    : 460
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 460x460
Megapixels                      : 0.212
~~~

Seeing the presence of a passphrase made me thought of the `steghide` tool, since it often requires a passphrase to extract the hidden message.

~~~console
$ steghide extract -sf ducking.jpg 
Enter passphrase: 
the file "flag.txt" does already exist. overwrite ? (y/n) y
wrote extracted data to "flag.txt".
~~~

Inside `flag.txt`, we find the flag.

Flag: flag{qu4ck_qu4ck}

## My Favorite Color

Category: Stego
Points: 50

When we open up the image, we see what appears to be a one-color image. Or is it? When inspecting the image using `xxd`, I noticed that the RGB data wasn't consistent across the file, meaning that some pixels must have a slightly different color/hue.

Splitting the image by its RGB channels didn't seem to yield anything, but if we invert the image using a image color inverter ([link](https://pinetools.com/invert-image-colors)), we can see the flag text faintly in the background. The reason why this works was because the flag was being represented by a transparent color (as noted in the hints).

Flag: flag{transparent_is_the_new_black}

## A Needle in a Haystack

Category: Beginners
Points: 10

The problem notes that the server returns a lot of fake flags and sometimes the real one. Our challenge is to use the `grep` command with regular expression to filter out the real flag.

When we connect to the appropriate server using nc, we see that it quickly spews out lines of fake flags:

~~~console
$ nc ctf.cs.technion.ac.il 4082
n0p3_n0pe_n0p3
the_fl4g_th1s_1s_n0t
flag(bu7_n0t_th3_fl4g)
flag_th1s_1s_n0t_th3_fl4g
flag(bu7_n0t_th3_fl4g)
n0p3_n0pe_n0p3
flag(bu7_n0t_th3_fl4g)
flag{Gr3p_T0_W1n}
n0p3_n0pe_n0p3
flag(bu7_n0t_th3_fl4g)
n0p3_n0pe_n0p3
flag_th1s_1s_n0t_th3_fl4g
flag{0r_n0t}
flag(bu7_n0t_th3_fl4g)
n0p3_n0pe_n0p3
 flag(bu7_n0t_th3_fl4g)
flag_th1s_1s_n0t_th3_fl4g
n0p3_n0pe_n0p3
flag_th1s_1s_n0t_th3_fl4g
n0t_th3_fl4g
flag(bu7_n0t_th3_fl4g)
flag(bu7_n0t_th3_fl4g)
~~~

I struggled with this problem for a bit, mainly because I'm not used to working with regular expressions. I ended up having to use `egrep` to be able to filter out a specific starting pattern (e.g. "flag{"), and then I pipe that result to `grep -v` (which returns results which do NOT contain the pattern) to filter out the lines with "n0t" in its body.


~~~console
$ nc ctf.cs.technion.ac.il 4082 | egrep "flag\{.*\}" | grep -v "n0t"
flag{Gr3p_T0_W1n}
flag{Gr3p_T0_W1n}
flag{Gr3p_T0_W1n}
flag{Gr3p_T0_W1n}
~~~

Flag: flag{Gr3p_T0_W1n}

## Pwning Math

Category: Beginners

Points: 10

This problem was designed to teach us `pwntools`, which is a framework designed for exploit development. It contains two libraries, one called `pwn` designed for CTFs and `pwnlib` which is a cleaner version of `pwn` designed as a normal library.

According to DuckyDebugDuck, he personally prefers `pwnlib.tubes` because it allows generic high-level interaction with binaries or with a server than most libraries allow.

Even though I ended up using the normal `pwn` module, I've included his links to the pwnlibs.tubs documentation and tutorial here.

Documentation: <https://docs.pwntools.com/en/stable/tubes.html>

Tutorial: <https://github.com/Gallopsled/pwntools-tutorial>

The problem was straightforward, with us receiving questions in the form of "What is \[math_expression\]?", which we can extract and evaluate using Python's `eval` function. The script for it can be found in the Beginners folder called `math_exp.py`

## Flag Server

Category: BinExp

Points: 50

`fflush(out)` - When you do write operations (to the console, in the case of stdout), what actually happens is that the data gets written into a buffer, and then that buffer is displayed on the terminal once it is close to full or other conditions are met. However, if you would like for the data to be released right away to the system, you would call `fflush(stdout)` to display all the buffered at that point and discard them.

