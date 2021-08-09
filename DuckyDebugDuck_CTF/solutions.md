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

At the end, we get back the message: 

`Nice! here's your flag: flag{E4t_Sl33p_Pwn_m47H_R3pe47}`

Flag: flag{E4t_Sl33p_Pwn_m47H_R3pe47}

## Flag Server

Category: BinExp

Points: 50

We took the "easy" way and inspected the source code before taking a look at the cleaned binary.

The source code snippet can be found below:

~~~c
extern char flag[100];

#define USERNAME_LENGTH 32
#define PASSWORD_LENGTH 64

int main() {
    int authenticated = 0;
    char username[USERNAME_LENGTH] = {0};
    char password[PASSWORD_LENGTH] = {0};

    printf("Hello and thank you for using Flag Distibuter v1.0 🚩🚩🚩\n");

    printf("To receive the flag, please enter your username and password\n");
    printf("Username: ");
    fflush(stdout);
    	read(STDIN_FILENO, username, PASSWORD_LENGTH);
    printf("Password: ");
    fflush(stdout);
    read(STDIN_FILENO, password, PASSWORD_LENGTH);
    printf("Autenticating...\n");

    authenticate_with_server(&authenticated);

    if(authenticated)
        print_flag();
    else
        printf("Could not authenticate using these username and password\n");
        
    return 0;
}
~~~

Explanation of`fflush(out)` - When you do write operations (to the console, in the case of stdout), what actually happens is that the data gets written into a buffer, and then that buffer is displayed on the terminal once it is close to full or other conditions are met. However, if you would like for the data to be released right away to the system, you would call `fflush(stdout)` to display all the buffered at that point and discard them.

The primary vulnerability seems to be that we seem to be reading in up to the PASSWORD_LENGTH (64) number of bytes for the `username` char array, which is only 32 bytes in length. Thus, this read operation is vulnerable to a buffer overflow. Our target is to change the `authenticated` integer to be something other than 0 for us to trigger the `print_flag()` function.

Aside: After a month since completing the Protostar excercises, I forgot that you had to do `break *main` and `run` (gdb commands) before viewing the disassembly, and so I was so confused when my breakpoints for the `read` operations weren't working.

The following is the summary of what I found from inspecting the binary behavior in gdb:

~~~text
Start of main(): 0x5555555551c9 

break *0x0000555555555285 - At first read()
break *0x000055555555528a - The instruction right after read()

Region of stack:
0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]

Location of username array:
x/100wx $rbp-0x30

Location of `authenticated` variable:
gef➤  x/wx $rbp-0x4
0x7fffffffde0c:	0x00000000
~~~

When viewing the disassembly, I could tell that the `authenticated` variable was located at $rbp-0x4 because it was used in the `test` instruction to decide whether or not to jump to `print_flag()`. Additionally, I was able to deduct that the `username` char array was at $rbp-0x30. Taking their difference, I find that I need to provide a string 44 characters in length to override the `authenticated` integer:

~~~console
$ nc ctf.cs.technion.ac.il 4068
Hello and thank you for using Flag Distibuter v1.0 🚩🚩🚩
To receive the flag, please enter your username and password
Username: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Password: doesn't matter
Autenticating...
Authenticated, here's the flag: flag{protect_your_boundaries}
~~~

Flag: flag{protect_your_boundaries}

## Buffering 1

Category: Binary Exploitation

Points: 100

Compared to the `flag_server` challenge, this problem placed the `read()` actions in a separate function called `get_credentials`. In this case, there's no way for us to override the `authenticated` integer, but we can change the execution flow by overriding the return address of `get_credentials()` to get us into `print_flag()`. 

This could be achieved simply by padding the data in `username` until the return address, at which we replace the current value with the address of `print_flag` (which is found with `p print_flag`).

The following are my notes from the problem:

~~~text
Start of main(): 0x4011d6

Vulnerability: read() gets up to 64 characters for a 32-bytes char array `username` in function `get_credentials`

Instruction to `print_flag()`:
	call   0x401381 <print_flag>
	
Location of `username`: rbp-0x20

First breakpoint - First `read` instruction:
break *0x0000000000401343

Second breakpoint - Instruction after first `read`:
break *0x0000000000401348

Third breakpoint - `leave` instruction for `get_credentials()`:
break *0x000000000040137f

Stack at first breakpoint:
gef➤  x/100wx $rbp-0x20 
0x7fffffffdd80:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdd90:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdda0:	0xffffddc0	0x00007fff	0x00401207	0x00000000
0x7fffffffddb0:	0xffffdeb0	0x00000000	0x00000000	0x00000000
0x7fffffffddc0:	0x00000000	0x00000000	0xf7de20b3	0x00007fff
0x7fffffffddd0:	0x00000071	0x00000000	0xffffdeb8	0x00007fff
0x7fffffffdde0:	0xf7fa3618	0x00000001	0x004011d6	0x00000000
0x7fffffffddf0:	0x004013d0	0x00000000	0xb97f9d8e	0xc9c7ad95

Stack at second breakpoint after entering some characters:
gef➤  x/100wx $rbp-0x20 
0x7fffffffdd80:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffdd90:	0x41414141	0x41414141	0x0000000a	0x00000000
0x7fffffffdda0:	0xffffddc0	0x00007fff	0x00401207	0x00000000
0x7fffffffddb0:	0xffffdeb0	0x00000000	0x00000000	0x00000000


Location on stack which is used for return address: 0x7fffffffdda8

Location of libc library:
 0x7ffff7dbb000     0x7ffff7de0000    0x25000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.31.so

Offset of string relative to libc:
$ strings -a -t x /usr/lib/x86_64-linux-gnu/libc-2.31.so | grep "/bin/sh"
 1b75aa /bin/sh
~~~

You may notice that at the end there are notes about the libc library. This was because I also tried spawning a shell by returning into the Libc library and calling `system(/bin/sh")`. The `exp_2.py` file highlights my attempt to do so, though I was not sucessful in this task. In GDB, I saw that the execution led into `system` and that the address to the string `/bin/sh` was indeed on the stack, though it still resulted in a Segmentation Fault. It's possible that I had missed something in trying to implement what I learned from Protostar with 32-bit ELFs and applying it towards 64-bit ELFs. (More information about this issue can be found at `Buffering 2` problem writeup right below)

## Buffering 2

Category: BinExp

Points: 250

`Buffering_2` seems very familar to the `Buffering_1` in that they have the same user interface asking us to provide a username and password. Upon normal submission, the program will simply read "Authenticating..." forever.

Taking a look at the source code, we can see that the vulnerability of buffer overflowing the `username` char array is still there. However, this time, the `print_flag()` function no longer prints a flag for us, but rather a static message.

I got some help on the problem from `Oshawk` on Discord, and they explained that if we look at the binary we can see that some of the `printfs` have been converted to `puts` by the compiler. As a result of this, we can return into the `puts` libc function from `get_credentials()` (since we control the return address from the buffer overflow) and print out the `flag` variable.

Now the last time I attempted to perform a ret2libc attack was on the `Buffering_1`, and I was unable to spawn a shell using `system('/bin/sh')`. As it turns out, since the programs we are working with are `x86_64` (64-bits) rather than `x86_32` (32-bits), the calling conventions are a bit different. According to the reference [here](https://en.wikipedia.org/wiki/X86_calling_conventions#List_of_x86_calling_conventions), and [here](https://nuc13us.wordpress.com/2015/12/26/return-to-libc-in-64-bit/comment-page-1/), instead of placing function arguments on the stack, in 64-bit binaries you would actually pop them off into pre-defined registers. For example, your first argument would also be in the `rdi` register, followed by `rsi` for your 2nd-argument, then `rdx`, then `rcx`, and so on. In our case, `puts` only requires one argument, which is the address of the string we want to print out.

Since the executables do not use ASLR, we can count on addresses being the same across executions. Using the provided ELF file, I opened it in GDB, noted the spacing between the `username` char array and the return address, and discovered the address of `puts@plt` and address of `flag` (found by doing `p &flag` command in gdb). I also used the tool `ROPgadget` to identify ROP-gadgets that I could use from the binary:

`ROPgadget --binary buffering`

I noted the entry which had `pop rdi; ret` since it was all I needed to perform the print-out:

~~~console
0x00000000004013ef : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040119d : pop rbp ; ret
0x00000000004013f3 : pop rdi ; ret
~~~

To construct the exploit using `pwntools`, I consulted a similar tutorial from John Hammond (found [here](https://www.youtube.com/watch?v=E8Ykh-UC2f0&list=RDCMUCVeW9qkBjo3zosnqUbG7CFw&start_radio=1&rv=E8Ykh-UC2f0&t=910)). The script he created was very helpful because it included instructions for how to interact with a local binary versus a live server (which is the instance that has the flag stored in it). He also pointed out how we could construct a ROP-chain in Python by placing the elements in a list and then using `p64()` to pack the hex values into 64-bit entries.

The solution to the problem can be found at `sec_exp.py`

I have also included some of my gdb notes from the problem below:

~~~text
Location of `username`: rbp-0x20

`leave` instruction for `get_credentials()`: 0x000000000040135f
`ret` instruction for `get_credentials()`: 0x0000000000401360

Return instruction after `get_credentials()`: 0x00000000004011e7

Stack at `leave`: 
gef➤  x/64wx $rbp-0x20
0x7fffffffddd0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffdde0:	0x41414141	0x41414141	0x000a4141	0x00000000
0x7fffffffddf0:	0xffffde10	0x00007fff	0x004011e7	0x00000000
0x7fffffffde00:	0xffffde10	0x00000000	0x00000000	0x00000000
0x7fffffffde10:	0x00000000	0x00000000	0xf7de20b3	0x00007fff
0x7fffffffde20:	0x00000071	0x00000000	0xffffdf08	0x00007fff
0x7fffffffde30:	0xf7fa3618	0x00000001	0x004011b6	0x00000000
0x7fffffffde40:	0x00401390	0x00000000	0xed4353ff	0x9d50202e
0x7fffffffde50:	0x004010d0	0x00000000	0xffffdf00	0x00007fff
0x7fffffffde60:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffde70:	0x510353ff	0x62afdfd1	0xad8d53ff	0x62afcf92
0x7fffffffde80:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffde90:	0x00000000	0x00000000	0x00000001	0x00000000
0x7fffffffdea0:	0xffffdf08	0x00007fff	0xffffdf18	0x00007fff
0x7fffffffdeb0:	0xf7ffe190	0x00007fff	0x00000000	0x00000000
0x7fffffffdec0:	0x00000000	0x00000000	0x004010d0	0x00000000

Location of `print_flag()`: 0x401361

Location of `flag` buffer:
gef➤  p &flag
$1 = (<data variable, no debug info> *) 0x404060 <flag>

Location of `puts@plt`: 
0x0000000000401370 <+15>:	call   0x401080 <puts@plt>

Gadget: 
0x00000000004013f3 : pop rdi ; ret
~~~

Flag: flag{w3'll_r3turn_sh0rt1y}


## Extremely Covert Bytes

Category: Crypto

Points: 250

The problem provides a link to [Crypton](https://github.com/ashutosh1206/Crypton), which is a collection of commonly used attacks and their implementations against encryption systems, digital signatures, message authentication codes, etc. Based on the initials ECB in the problem's name, I decided to take a look at the `ECB Byte at a Time` attack, found [here](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher/Attack-ECB-Byte-at-a-Time)

When we connect to the encryption service, we see that it prompts us to enter a message we want to encrypt and returns a base64 encoding like output:

~~~console
Enter the message you want to encrypt: 
>                
ecd419874f70a34f0d8f195f0bf6da551b4cf9277c6438279be18ed413ee2b11
Enter the message you want to encrypt: 
> 
ecd419874f70a34f0d8f195f0bf6da551b4cf9277c6438279be18ed413ee2b11
Enter the message you want to encrypt: 
> asdf
4b9f44f059362db838dfa25c64e3b0999d06f5fff3c4cf43a3592319d1f5a01c
Enter the message you want to encrypt: 
> aaaa
a38a638a14cc36853ab2c5a73995af889d06f5fff3c4cf43a3592319d1f5a01c
Enter the message you want to encrypt: 
> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
dafc06cfeda926069a35d51ab056b9dadafc06cfeda926069a35d51ab056b9da84aeca318a89377f9182d60b63b537c572dd6f30989ac7ae30e9c18ce669c283
~~~

Taking a closer look at the source code (again, I was taking the "easy" way out), I discovered that the server is:

1. Concatenating our providing text with the flag
2. Padding the overall message until it fits a specific block size, in this case 16
3. Encrypting the message using AES-ECB mode
4. Returning the hexilify result (our guess earlier is wrong, we should have realized earlier that this format is too simple-looking for base64)

Going back to take a look at the guide for ECB Byte at a time Attack, we can see that having this crypto Oracle that we can consult with in addition to be able to feed it cleartext that we control allows us to retrieve the byte-by-byte content of the flag through primarily brute force. More information can be found at this adjacent page for CryptoPals challenge 12 (which implements the same ideas) here: <https://braincoke.fr/write-up/cryptopals/cryptopals-byte-a-time-ecb-decryption-simple/>

When it comes time to implementing the exploit script, one of the mistakes I made that took the longest to debug was realizing that the original 'text', i.e., the cleartext we send that we want for the oracle to "fill in" with actual flag data, should only contain only 0-16 characters of our padding characters and NOT any of the known plaintext. Otherwise, if we add back in the known plaintext in addition to our padding (which grows as we discover more characters), we will only ever see the first character of the actual flag at the last byte of the target block, which is why I was so confused when I kept getting "TTTTT..." (the first character of my text flag) as the resulting flag.

Also, due to the way that the Python server interprets and receives input, if we send it a trailing space or a non-printable character it will simply ignore it and cut off the string early. Thus, we had to limit our character space to between value 33 and 127 in the ASCII table. In my code, I started my range at 32 because I will always use the first for-iteration to establish the target encrypted result that we want to replicate.

As an aside, I also created a function that allows us figure out the size of the encryption block when it is unknown. It does this by simply sending incrementally larger cleartext and checking for when the length of the output suddenly jumps. We have to take out the offset of the first jump because that represents the padding necessary to get the flag text by itself to fill up a full block. In Cryptopals challenge 11, they also define a way to figure out the block-encryption mode of the encryption method, though I didn't implement this in my code. Knowing that it was ECB from the challenge's name was enough for me.

The full exploit script can be found at `exp.py`. I primarily tested the script first on my local server instance by defining a `flag.py` file and then running it. The local server instance was also hugely helpful in that I could print debugging info from the server's side that helped me figure out what I was doing wrong at times.

Flag: flag{1_byt3_4t_a_t1me}

## Reversing Nature

Category: Rev

Points: 100

In this problem, we are only given the ELF and its EXE version, which I've renamed the ELF file to "target". When we run the executable on terminal, we can see that it prompts us to "Enter the key:".

If we open `target` in Ghidra and view the decompiled result, we see the following under `FUN_001011c9`:

~~~c
  printf("Enter the key: ");
  __isoc99_scanf(&DAT_00102030,&local_1b0);
  if (100 < local_1b0) {
    local_1b0 = 100;
  }
  local_1ac = 0;
  while (local_1ac < local_1b0) {
    lVar2 = (long)local_1ac;
    local_1ac = local_1ac + 1;
    __isoc99_scanf(&DAT_00102030,(undefined8 *)((long)local_1a8 + lVar2 * 4));
  }
  uVar1 = FUN_001012f9(local_1b0 + -1,(int *)local_1a8,0);
  if ((char)uVar1 == '\0') {
    puts("You\'re not good enough at reversing nature, try again");
  }
  else {
    FUN_0010140f((long)local_1a8,local_1b0);
  }
~~~

The program interprets our first line as input as an integer to signal the number of entries, call it `n`, we are going to enter (capping out at 100). Following that, it `scanf` in `n` number of integers and stores them in an `int *` pointer. (Aside: If we provide anything other than integers the program will exit immediately following it). From there, it jumps to a verification function. If that function returns `\0`, it will exit the program, otherwise it will print out the flag. I've included the implementation of that verification function below:

~~~c
undefined4 FUN_001012f9(int param_1,int *param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_1 < 2) {
    if ((((param_1 == 1) && (param_2[1] == *param_2)) && (param_2[1] == 1)) &&
       (param_3 == -0x53f35e20)) {
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  else {
    if ((param_2[(long)param_1 + -2] + param_2[(long)param_1 + -1] == param_2[param_1]) &&
       (uVar1 = FUN_001012f9(param_1 + -1,param_2,param_2[param_1] + param_3), (char)uVar1 != '\0'))
    {
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  return uVar1;
}
~~~

With a little bit of pen-and-paper, we can see that the function is checking for:

- That the entries in the array follow a Fibonacci sequence, where `x_1 + x_2 = x_3`
- That the first two entries are both 1, and
- That the sum of all the entries (besides the first two) equals out to `-0x53f35e20` or `-1408458272` in decimal.

At first, I was a bit dumbfounded on this specific sum value, since it was negative and the Fibonacci sequence is a sequence of positive numbers. When I later talked to `dd__` on Discord (they helped me out with the problem since I was having trouble), they explained that this summation value is possible given that the sum is being stored in a fixed-width signed 32-bit int (which is what the `x86_64` binary was using), integer overflow will occur and so we can arrive to a weird negative value because of the int wrapping and signed int.

If you are curious, the process to "wrap" a value into a signed 32-bit integer, which has range from [-2^31,2^31-1] is:

1. Take the number modulo 2^32
2. If that number is greater than 2^31-1, subtract 2^31 from it
3. Otherwise, return the number 

`dd__` also pointed out that it was important for me to pre-wrap my own integer inputs because at a certain point the values I will be sending is be greater than `2**31-1`, which is the maximum positive value represented by signed 32-bit ints, and we might run into unexpected behavior with `scanf` through that way. I would say that I later found out that it was not necessary to wrap my integer, at least for this problem, but nevertheless it's a very important mechanic to recognize when working with sending program inputs.

Ultimately I was able to put together an exploit script, which you can find at `sec_exp.py`, that iterates through sending a Fibonacci sequence of length 1 through length 100. 

An issue I ran into: When I was first testing the script, I noticed that I kept running into an EOF file error at Fibonacci sequence of length 50. As I later found out from `dd__`, when the program decides to send back the flag (after having received a correct sequence), it doesn't end the output with a newline `\n` character, and so the command `p.recvline()` will run into an EOF error. However, for me I originally misnterpreted it as me crashing the program due to too large of an integer input, and didn't realized that I had actually got to the flag. `dd__` explains that it was better to do `p.recv()` or `p.recvall()` to make sure that I don't over-read in the future.

The problem was also very helpful introducing me to pwntools utilies when working with binary, which I have never used before.

At length 50, we get the following output from the binary:

`b'Enter the key: Yeah maybe I exaggerated about reversing nature, the flag is flag{th3_g0ld3n_r3v3r53}\x00'`

Flag: flag{th3_g0ld3n_r3v3r53}

