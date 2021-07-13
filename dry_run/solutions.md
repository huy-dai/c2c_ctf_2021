# My Solutions for C2C CTF 2021 Pre-Competition Warm Ups


## Getting Roasted
### Category: DFIR
Points: 50

**Prompt:** You notice a zip file containing a lot of information about your Active Directory environment on a computer. Perhaps the attacker is planning their lateral movements. See if you can find the Object ID (sometimes known as "objectSID" or "SID") of a user susceptible to a technique known as "AS-REP Roasting". Flag format is FLAG{ObjectID}, for example if the ObjectID is "S-1-2-33-444", the flag would be FLAG{S-1-2-33-444}

**Solution:** 

Once we unzip the prompt folder, we can see a number of json files, including computers.json, domains.json, gpos.json, groups.json, etc. If we search up these file names, we can see they correspond to the BloodHound JSON Formats.

BloodHound is a security/pen-testing tool used to analyze Active Directory and Azure environments. It also supports searches for vulnerabilities and attack paths. I was able to follow the installation guide to get both neo4j and BloodHound GUI installed on my system (link: https://bloodhound.readthedocs.io/en/latest/installation/linux.html). Note that most of the commands on there required sudo permissions.

I then loaded in the provided data and then went to the Analysis > Find AS-REP Roastable Users (DontReqPreAuth) option. My GUI was bugging out and didn't show the resulting node, but in Node Info tab I was able to find the Object-ID of S-1-5-21-514270060-138634441-3981690375-1108 for user Phyllis@CTFAD.CTF.FIFTHDOMA.IN


* Note: AS-REP Roasting is an attack against Kerberos for user accounts which do not require preauthentication. Normally in preauthentication a user will enter their password that will be used to encrypt a timestamp and then the domain controller will attempt to decrypt it and validate that the right password was used and it was not replaying a previous request. After that the DC will issue a TGT to the user for future authentication. However, if preauthentication is disabled, an attack could request authentication data for any user and the DC would return an encrypted TGT which we can try to brute-force offline. By default, preauthentication is enabled for all users in Active Directory.


Flag: flag{S-1-5-21-514270060-138634441-3981690375-1108}

---

## Cheater
### Category: Exploitation
Points: 50 

**Prompt:** I get the feeling that the writer of http://cheater.ctf.fifthdoma.in/ was a big fan of retro games.

**Solution:**

Viewing the source of the page didn't yield anything particularly interesting. 

One of the blog post had the following description: 

`I've found this new exploit that runs using the aHR0cHM6Ly9lbi53aWtpcGVkaWEub3JnL3dpa2kvS29uYW1pX0NvZGU=. This seems like a good method to run persistence with a malicious script.`

If we decode the middle text as base64 we find that it is a link to the Konami Code: https://en.wikipedia.org/wiki/Konami_Code. Performing the keyboard Konami Code we get a raptor that appears on the page and quickly strafe left out of sight. For a few brief moments we could see a subtext above it, which turns out to be our flag.

Flag: flag{Inline_Checks_Get_Recked}

---

## Secret Ciphers
### Category: Cryptography
Points: 100

**Prompt:** We discovered this ciphertext on a target's server. Our analysis has determined it has been encrypted using 3 letter key. Can you decipher the contents and recover the flag?

Opening the ciphertext.txt file we get the following text: 

`RTAS{aeozef_kibpeda_tmzgqb_ie_UIM}`

Keeping things simple, I assume that this was some form of the Caesar Cipher / Vignere Cipher with key. Using an online Vignere Cipher tool we can brute force the 3-letter key. Link: https://www.boxentriq.com/code-breaking/vigenere-cipher

The key turned out to be "MIA". 

Flag: flag{secret_ciphers_target_is_MIA}

---

## Total Virus
### Cateogry: OSINT
Points: 100

**Prompt:** A USB was recently recovered after a successful operation by defence force personnel. The file is gone but we do have the hash though - `1f1d6aa5f683d7ebd346e591320cea275cca00c3ec0fdc7e2858ddfb1ed837e5` Can you find out if it was actually malicious?

**Solution:** 

Based on the problem title we can assume that we can use VirusTotal website to reverse-search the file which the has corresponds to (Link: https://www.virustotal.com/gui/home/search). Turns out the name of such a file is `FLAG{totally_not_a_virus}.exe` 

Flag: flag{totally_not_a_virus}

---

## Looks the Same
### Category: Steganography
Points: 100

**Prompt:** One of our internal contacts has sent us a photo of the back of one of their servers. Can you perform a meta-meta-meta-analysis to if they passed us any further information?

**Solution:** 

We can check out the metadata of the file using `exiftool`:

~~~~~~
grayhimakar@grayhimakar-VirtualBox:~/Documents/c2c_ctf/looks_the_same/a905d08a-1d69-4d5b-91a4-759800bcbc49 (1)$ exiftool looks-the-same.jpg 
ExifTool Version Number         : 11.88
File Name                       : looks-the-same.jpg
Directory                       : .
File Size                       : 410 kB
File Modification Date/Time     : 2021:06:17 02:35:23-04:00
File Access Date/Time           : 2021:07:11 17:06:44-04:00
File Inode Change Date/Time     : 2021:07:11 17:06:41-04:00
File Permissions                : rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
XMP Toolkit                     : Image::ExifTool 11.16
Flag                            : flag{i_was_here_all_along}
Profile CMM Type                : Little CMS
Profile Version                 : 2.1.0
Profile Class                   : Display Device Profile
[...]
~~~~~~~

Flag: flag{i_was_here_all_along}

---


Overall, the problems didn't seem to be too bad. Hopefully I will be able to pass the qualifiers round.