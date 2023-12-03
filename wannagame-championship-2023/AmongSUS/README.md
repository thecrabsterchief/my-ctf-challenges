# AmongSUS

- Category: Crypto
- Score: 484/500
- Solves: 7
- Flag: `W1{k3y_mult1c0ll1siOns_vS_V4r14nt_43s-p0ly1305_2f537541cedc262c8cc215fc9dcf8700}`

## Overview
You have to pass 20 rounds to get the final flag. Here is the information of each round:

- `Info players` and `Report Imposter`: you have all `crewmates`'s name and the missions is figuring out the exact one impostor among $512$ `crewmates`.
- `Generate task`: give you a random valid task token (you can have as much as you want).
- `Do task`: check whether your input token is valid or not (you can use this functionality at most $14$ times per each round).
- Cryptographic behind the scene: to generate and verify token, we use our customed [Authenticated Encryption with Additional Data (AEAD) algorithm](https://en.wikipedia.org/wiki/Authenticated_encryption)

## Solution

The `master_key` use for generate and verify token is derived from imposter's name. We already have all crewmate's name, so there are two ways to abuse the functionality `Generate task` and `Do task`.

### Unintended

You have infinite times to `Generate task` per each round, that seem pretty bad 🥲. Just generate all possible `master_key` and use this functionality to bruteforce the right valid `master_key`

P/s: Damn, I should not release this functionality, bad author 🤕

### Intended

The intended solution is targeting to `Do task` functionality. You are give a decryption oracle that checks if your ciphertext can correctly be decrypted. But you are allowed to use at most $14$ times to find out the real `master_key` among $512$ possibles.

It's clearly that you some how be able to generate one single ciphertext that can be decrypted by multiple `master_key` instead of trying verify one single key per one ciphertext.

So the strategy now is very clear, partition the set of all possible keys, generate the ciphertext that is valid for all keys of each partition, then use the oracle to verify which partition contain the reaal `master_key`.

P/s: This kind of attack is **"Key partitioning oracle attack"**

Our AEAD scheme looks pretty messy, but the only thing you should consider here is **MAC**

```python
class MAC:
    MASK_R = 0x1337fffc0ffffffc0ffffffc0fff1337
    MASK_S = 0xffffffffffffffffffffffffffffffff
    P      = 0x7ffffffffffffffffffffffffffffffbb
    Q      = 0x100000000000000000000000000000000

    def __init__(self, key: bytes) -> None:
        if len(key) != 0x20:
            raise ValueError("[MAC Error]: The key's length must be (in byte)")

        self.r = int.from_bytes(key[0x00:0x10], byteorder='little') & self.MASK_R
        self.s = int.from_bytes(key[0x10:0x20], byteorder='little') ^ self.MASK_S

    def commit(self, message):
        res = 0
        
        for i in range(0, math.ceil(len(message)/0x10)):
            res += int.from_bytes(message[i*0x10:(i+1)*0x10], byteorder='little') + self.Q
            res  = (self.r * res) % self.P
            
        res = (res + self.s) % self.Q
        return int.to_bytes(res, length=0x10, byteorder='little')
```

which is the verifier. Don't be afraid 😂 it's just my customed [poly1305](https://en.wikipedia.org/wiki/Poly1305)

Before going straight ahead, I strongly recommend you read this very detailed article:
- **https://www.kryptoslogic.com/blog/2021/01/faster-poly1305-key-multicollisions/**

P/s: I was inspired to create this challenge after reading the above article 😁

You can try writing your own exploit by following the instructions of the above article, but there are some differences in my challenge that you should be considered:

- The `mac_key` generation was different to the original.
- I adding some `associated_data` (instead of null in the article) at the beginning of `mac_data`, so you must discard this part too when creating polynomial (the step before the interpolation step)
- There is a small problem in my challenge, the space of possible keys is pretty large that lead to the dimension of matrix basis is large too, so the lattice reduction step will be slow and you will not have enough time to pass total 20 rounds.
- So you cannot just do binary search right away (very slow at the first step to build the ciphertext that valid for $256$ keys). But build the ciphertext that valid for $64$ keys is pretty fast (about $\sim20$ seconds)
- The interesting here is that you have maximum $14$ `TRIES`, and the fun fact that: 

$$
14 = log_{2}(64) + \dfrac{512}{64}
$$

so the strategy is:
- First partition $512$ keys to $8$ sets, each set has $64$ keys.
- Next build the ciphertext that valid for each key sets at the same time using multiprocces
- Then use oracle to verify which 64-keys-set contained the real `master_key` (use $8$ tries)
- Finnaly just do binary search to figure out the exact `master_key` (use $6$ tries)


Here is my messy [exploit script](./solve.py) 🥲