# Solution for Sample Problem 

This problem was published on the C2C CTF Discord on June 29th, 2021. It simply read:

**Prompt:**
<pre>
Don't judge a book by its cover...

1612130291
0140283331
0553588486
0307588378
031606792X
0762447699 
0439023483
0439708184
0143038419
0316042676
0142000671
0440242940
1400079276
</pre>

**Solution:**
We are given 13 rows of 10-digit numbers. If we try Googling the number we can see that they consistently match with a book. Thus, these must be ISBN-10 codes.

We can see the list of books these numbers correspond to are as follows:

<pre >
Fifty Shades of Grey
Lord of the Flies
A Game of Thrones
Gone Girl
Breaking Dawn
You Are a Badass
The Hunger Games
Harry Potter and the Sorcerer's Stone
Eat, Pray, Love
Beautiful Creatures
Of Mice and Men
Outlander
Kafka on the Shore
</pre >

If we take the first letter of each word we can see they spell out: "FLAG BY THE BOOK"

