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


