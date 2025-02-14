# not-a-cipher

## m0leCon CTF 2023 Finals challenge

[m0leCon CTF 2023 Finals](https://ctftime.org/event/2033) was an on-site jeopardy-style CTF organized by [pwnthem0le](https://pwnthem0le.polito.it/). The competition was held at Politecnico di Torino, where the top 10 teams qualified during the Teaser round were invited.

### Description

_Author: Andrea Angelo Raineri <@Rising>_

_Category: rev_

The challenge implements a stream cipher very much inspired by the Hitag-2 cipher typically used in car key RF authentication systems. The keystream generated by the cipher is then encoded to a sequence of `+/-` triplets, representing voltage values of an MMS43 encoding scheme, and then xored with the plaintext.

Two different outputs are generated by the executable, one is the encryption of the string `ptm{m4yb3_d1z?__https://www.youtube.com/watch?v=S8z9mgIkqBA}`, the other being the encryption of the flag itself. From the output of the first encryption we can recover the keystream, decode it (from MMS43) and the recover the initial state of the cipher. The initial state of the cipher is simply the concatenation of the secret key and a (public) nonce.

After recovering the secret key we can emulate the cipher in Python and initialize it with the key and the flag nonce, allowing us to recover the keystream and correctly decrypt the flag

## Solution

[solve.py](/solve.py)
