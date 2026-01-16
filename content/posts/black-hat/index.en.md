---
title: "TDS"
date: 2025-01-16T00:00:00+00:00
draft: false
tags: ["blackhat-finals", "crypto", "aes-gcm", "polynomial", "oracle"]
categories: ["Cryptography"]

---

<!--more-->
{{< admonition type="info" title="Challenge Info" open="true" >}}
- **CTF**: blackhat-finals
- **Challenge**: TDS
- **Category**: Crypto
- **Description**: AES-GCM implementation with oracle access
{{< /admonition >}}

## TL;DR

This challenge exploits weaknesses in AES-GCM authentication when given:
1. A flag ciphertext and its authentication tag
2. Two encryption oracle calls with the same key/nonce
3. Unlimited verification oracle with controllable AAD and ciphertext length

The solution:
1. Recovers the GCM mask by encrypting an empty string
2. Recovers the authentication key H by solving a polynomial equation
3. Brute-forces the keystream byte-by-byte using the verification oracle
4. XORs the recovered keystream with the flag ciphertext

---

## Challenge Overview

The server implements AES-GCM encryption and provides several operations:
```python
flag_ciphertext, flag_tag = encrypt(FLAG, key, nonce, b"")

user_plaintext = input("your_text1:")
ciphertext, tag = encrypt(user_plaintext.encode(), key, nonce, b"")

user_plaintext = input("your_text2:")
ciphertext, tag = encrypt(user_plaintext.encode(), key, nonce, b"")

while True:
    length = int(input("length:"))
    aad = base64.b64decode(input("aad: "))
    print(query(ciphertext[:length], aad, key, tag, nonce))
```

{{< admonition type="warning" title="The Vulnerability" open="true" >}}
The critical flaws:
1. **Nonce reuse**: Same nonce used for all encryptions
2. **Verification oracle**: We can verify arbitrary (AAD, ciphertext_prefix, tag) tuples
3. **Controllable AAD**: The oracle lets us control additional authenticated data

This breaks the security model of AES-GCM completely!
{{< /admonition >}}

---

## Understanding GCM Authentication

{{< admonition type="note" title="GCM Authentication Mechanism" open="true" >}}
AES-GCM authentication is based on **GHASH**, a polynomial hash over GF(2^128). Understanding this is crucial to solving the challenge.

For a comprehensive explanation, see: [**AES-GCM Deep Dive**](https://frereit.de/aes_gcm/)

This resource provides all the mathematical details needed to understand the attack.
{{< /admonition >}}

### GHASH Polynomial

The authentication tag in GCM is computed as:

$$\text{tag} = \text{GHASH}(H, A, C) \oplus E_K(N \mathbin\Vert 0^{31} \mathbin\Vert 1)$$

Where:
- $H = E_K(0^{128})$ is the authentication key
- $A$ is the additional authenticated data (AAD)
- $C$ is the ciphertext
- $E_K(N \mathbin\Vert 0^{31} \mathbin\Vert 1)$ is the mask (keystream at counter 0)

The GHASH function computes:

$$\text{GHASH}(H, A, C) = \sum_{i=1}^{m} A_i \cdot H^{m+n+1-i+1} + \sum_{j=1}^{n} C_j \cdot H^{n+1-j+1} + L \cdot H$$

Where:
- $A_i$ are 128-bit blocks of AAD
- $C_j$ are 128-bit blocks of ciphertext  
- $L = (\text{len}(A) \mathbin\Vert \text{len}(C))$ is the length block
- All operations are in $\text{GF}(2^{128})$

**Key insight**: If we know the tag and all blocks except H, we can solve for H as a polynomial root!

---

## Exploitation Strategy

### Phase 1: Recover the Mask

The mask is $E_K(N \mathbin\Vert 0^{31} \mathbin\Vert 1)$. When we encrypt an empty string with no AAD:

$$\text{tag}_\emptyset = \text{GHASH}(H, \emptyset, \emptyset) \oplus \text{mask} = (0 \oplus 0 \oplus L \cdot H) \oplus \text{mask}$$

But since both AAD and ciphertext are empty, $L = 0$, so:

$$\text{tag}_\emptyset = 0 \oplus \text{mask} = \text{mask}$$
```python
io.sendlineafter(b"your_text1:", b"")
io.recvuntil(b"tag1: ")
mask = bytes_to_long(base64.b64decode(io.recvline().strip()))
```

### Phase 2: Recover Authentication Key H

Now we have:
- Flag ciphertext blocks: $C_1, C_2, \ldots, C_n$
- Flag tag: $\text{tag}_{\text{flag}}$
- Mask value

We can compute:

$$\text{GHASH}_{\text{flag}} = \text{tag}_{\text{flag}} \oplus \text{mask}$$

The GHASH equation becomes:

$$\text{GHASH}_{\text{flag}} = C_1 \cdot H^{n+1} + C_2 \cdot H^n + \cdots + C_n \cdot H^2 + L \cdot H$$

This is a **polynomial equation in H** over $\text{GF}(2^{128})$:

$$C_1 \cdot H^{n+1} + C_2 \cdot H^n + \cdots + C_n \cdot H^2 + L \cdot H - \text{GHASH}_{\text{flag}} = 0$$

We solve this using SageMath's polynomial root finding:
```python
def recover_h(coeffs, target_val):

    F = GF(2)
    P.<x> = PolynomialRing(F)
    irr_poly = x^128 + x^7 + x^2 + x + 1
    GFghash.<y> = GF(2^128, modulus=irr_poly)

    poly_terms = []
    for i, c in enumerate(coeffs):
        power = len(coeffs) - i
        poly_terms.append(to_field(c) * y^power)

    poly = sum(poly_terms) - to_field(target_val)
    roots = poly.roots()

    return from_field(roots[0][0])

target_val = bytes_to_long(flag_tag) ^ mask
pad_len = (16 - len(flag_ct) % 16) % 16
ct_padded = flag_ct + b'\0' * pad_len

coeffs = [bytes_to_long(ct_padded[i:i+16]) for i in range(0, len(ct_padded), 16)]
coeffs.append((0 << 64) | (len(flag_ct) * 8))

H = recover_h(coeffs, target_val)
print(f"[+] Recovered H: {hex(H)}")
```

{{< admonition type="tip" title="Why This Works" open="true" >}}
The polynomial has degree at most $n+1$ (number of ciphertext blocks + 1). Since we know all coefficients and the target value, there's typically only one valid root in $\text{GF}(2^{128})$ that corresponds to the actual H value.
{{< /admonition >}}

### Phase 3: Keystream Recovery via Oracle

With H recovered, we can now abuse the verification oracle. The key observation:

**For any partial ciphertext and AAD, we can compute the required AAD value that makes verification succeed!**

Strategy: Encrypt $\texttt{0x00} \times \text{len(flag)}$ to get a reference tag, then brute-force the keystream byte-by-byte.

First, get a reference tag:
```python
io.sendlineafter(b"your_text2:", b"\x00" * len(flag_ct))
io.recvuntil(b"tag2: ")
tag2 = bytes_to_long(base64.b64decode(io.recvline().strip()))

keystream = b""
target_tag = tag2 ^ mask
```

For each byte position $i$:

1. **Guess the keystream byte** (0-255)
2. **Calculate partial GHASH** of guessed ciphertext + length block
3. **Solve for required AAD** that makes the tag verify
4. **Query oracle** with this AAD

The math for step 3:

$$\text{GHASH}(H, A, C) = A \cdot H^{n+2} + C_1 \cdot H^{n+1} + \cdots + C_n \cdot H^2 + L \cdot H$$

Rearranging to solve for $A$:

$$A = \frac{\text{target} \oplus (C_1 \cdot H^{n+1} + \cdots + L \cdot H)}{H^{n+2}}$$
```python
for i in range(len(flag_ct)):
    curr_len = i + 1
    n_blocks = (curr_len + 15) // 16
    len_bits_val = (128 << 64) | (curr_len * 8)

    h_inv = gcm.inv(gcm.pow(H, n_blocks + 2))

    for b in range(256):
        guess_ks = keystream + bytes([b])

        c_padded = guess_ks + b'\0' * ((16 - len(guess_ks) % 16) % 16)

        y = 0
        for k in range(0, len(c_padded), 16):
            blk = bytes_to_long(c_padded[k:k+16])
            y = gcm.mul(y ^ blk, H)

        y = gcm.mul(y ^ len_bits_val, H)

        aad_val = gcm.mul(target_tag ^ y, h_inv)
        aad_bytes = long_to_bytes(aad_val, 16).rjust(16, b'\0')

        io.sendline(str(curr_len).encode())
        io.sendline(base64.b64encode(aad_bytes))

        if b"True" in io.recvline():
            keystream += bytes([b])
            print(f"\r[+] Progress: {keystream.hex()}", end="")
            break
```

Finally, decrypt the flag:
```python
flag = strxor(flag_ct, keystream)
print(f"\n[+] FLAG: {flag.decode()}")
```

---

## Full Solution Script
```python
from pwn import *
from Crypto.Util.number import *
from Crypto.Util.strxor import strxor
import base64
import sys
from sage.all import *

class GCMHelper:

    def __init__(self):
        F = GF(2)
        P.<x> = PolynomialRing(F)
        self.irr = x^128 + x^7 + x^2 + x + 1
        self.GFghash.<y> = GF(2^128, modulus=self.irr)

    def to_field(self, val):
        bits = bin(val)[2:].zfill(128)
        coeffs = [int(b) for b in bits[::-1]]
        return self.GFghash(coeffs)

    def from_field(self, elem):
        coeffs = elem.polynomial().list()
        return int(''.join(str(c) for c in coeffs[::-1]), 2)

    def mul(self, a, b):
        return self.from_field(self.to_field(a) * self.to_field(b))

    def pow(self, base, exp):
        return self.from_field(self.to_field(base) ^ exp)

    def inv(self, a):
        return self.from_field(self.to_field(a)^(-1))

def to_field(val):
    F = GF(2)
    P.<x> = PolynomialRing(F)
    irr_poly = x^128 + x^7 + x^2 + x + 1
    GFghash.<y> = GF(2^128, modulus=irr_poly)
    bits = bin(val)[2:].zfill(128)
    coeffs = [int(b) for b in bits[::-1]]
    return GFghash(coeffs)

def from_field(elem):
    coeffs = elem.polynomial().list()
    return int(''.join(str(c) for c in coeffs[::-1]), 2)

def recover_h(coeffs, target_val):

    F = GF(2)
    P.<x> = PolynomialRing(F)
    irr_poly = x^128 + x^7 + x^2 + x + 1
    GFghash.<y> = GF(2^128, modulus=irr_poly)

    poly_terms = []
    for i, c in enumerate(coeffs):
        power = len(coeffs) - i
        poly_terms.append(to_field(c) * y^power)

    poly = sum(poly_terms) - to_field(target_val)
    roots = poly.roots()

    if not roots:
        raise ValueError("No roots found!")

    return from_field(roots[0][0])

def solve():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <HOST> <PORT>")
        sys.exit(1)

    io = remote(sys.argv[1], int(sys.argv[2]))
    gcm = GCMHelper()

    io.recvuntil(b"flag ciphertext: ")
    flag_ct = base64.b64decode(io.recvline().strip())
    io.recvuntil(b"flag tag: ")
    flag_tag = base64.b64decode(io.recvline().strip())

    print(f"[*] Flag ciphertext length: {len(flag_ct)} bytes")

    io.sendlineafter(b"your_text1:", b"")
    io.recvuntil(b"tag1: ")
    mask = bytes_to_long(base64.b64decode(io.recvline().strip()))
    print(f"[+] Recovered mask: {hex(mask)}")

    target_val = bytes_to_long(flag_tag) ^ mask

    pad_len = (16 - len(flag_ct) % 16) % 16
    ct_padded = flag_ct + b'\0' * pad_len

    coeffs = [bytes_to_long(ct_padded[i:i+16]) for i in range(0, len(ct_padded), 16)]
    coeffs.append((0 << 64) | (len(flag_ct) * 8))

    H = recover_h(coeffs, target_val)
    print(f"[+] Recovered H: {hex(H)}")

    io.sendlineafter(b"your_text2:", b"\x00" * len(flag_ct))
    io.recvuntil(b"tag2: ")
    tag2 = bytes_to_long(base64.b64decode(io.recvline().strip()))

    keystream = b""
    target_tag = tag2 ^ mask

    print("[*] Brute-forcing keystream byte-by-byte...")

    for i in range(len(flag_ct)):
        curr_len = i + 1
        n_blocks = (curr_len + 15) // 16
        len_bits_val = (128 << 64) | (curr_len * 8)

        h_inv = gcm.inv(gcm.pow(H, n_blocks + 2))

        found = False
        for b in range(256):
            guess_ks = keystream + bytes([b])

            c_padded = guess_ks + b'\0' * ((16 - len(guess_ks) % 16) % 16)

            y = 0
            for k in range(0, len(c_padded), 16):
                blk = bytes_to_long(c_padded[k:k+16])
                y = gcm.mul(y ^ blk, H)

            y = gcm.mul(y ^ len_bits_val, H)

            aad_val = gcm.mul(target_tag ^ y, h_inv)
            aad_bytes = long_to_bytes(aad_val, 16).rjust(16, b'\0')

            io.sendline(str(curr_len).encode())
            io.sendline(base64.b64encode(aad_bytes))

            if b"True" in io.recvline():
                keystream += bytes([b])
                sys.stdout.write(f"\r[+] Progress: {i+1}/{len(flag_ct)} - {keystream.hex()}")
                sys.stdout.flush()
                found = True
                break

        if not found:
            print(f"\n[!] Failed to recover byte at position {i}")
            return

    print("\n")

    flag = strxor(flag_ct, keystream)
    print(f"[+] FLAG: {flag.decode(errors='ignore')}")

    io.close()

if __name__ == "__main__":
    solve()
```

---

## Attack Timeline
```
┌─────────────────────────┐
│   Phase 1: Mask         │
├─────────────────────────┤
│ Encrypt("")             │
│ → tag_empty = mask      │
└────────┬────────────────┘
         │
┌────────▼────────────────┐
│   Phase 2: Recover H    │
├─────────────────────────┤
│ GHASH = tag_flag ⊕ mask │
│ Solve polynomial in H   │
│ → H recovered           │
└────────┬────────────────┘
         │
┌────────▼────────────────┐
│ Phase 3: Keystream      │
├─────────────────────────┤
│ Encrypt("\x00" * n)     │
│ For each byte:          │
│  ├─ Guess byte (0-255)  │
│  ├─ Compute GHASH       │
│  ├─ Solve for AAD       │
│  └─ Query oracle        │
└────────┬────────────────┘
         │
┌────────▼────────────────┐
│  Phase 4: Decrypt       │
├─────────────────────────┤
│ flag = ct ⊕ keystream   │
└─────────────────────────┘
```

**Runtime**: ~2-5 minutes (256 queries per byte worst case)

---

## Behind the Math

### Why GCM Authentication is Vulnerable

GCM's authentication relies on the **secrecy of H**. Once H is known:

1. **Forgery**: Craft arbitrary (ciphertext, AAD, tag) tuples that verify
2. **Plaintext recovery**: Use oracle to leak information bit by bit

The polynomial structure means:

$$\text{tag} = \text{poly}(H) \oplus \text{mask}$$

If we can:
- Remove the mask (by encrypting empty string)
- Know all coefficients of poly(H) except H itself
- Know the result poly(H)

Then we can **solve for H algebraically**!

### Oracle Abuse Technique

The verification oracle checks:

$$\text{GHASH}(H, \text{AAD}, C) \stackrel{?}{=} \text{tag} \oplus \text{mask}$$

By controlling AAD and partial ciphertext, we can:

1. Fix all terms except the AAD term
2. Solve for the AAD value that makes the equation true
3. Query the oracle with this AAD

This is a **chosen-AAD attack** that leaks one keystream byte per 256 queries (worst case).

### GF(2^128) Arithmetic

All operations in GHASH are performed in $\text{GF}(2^{128})$ with irreducible polynomial:

$$f(x) = x^{128} + x^7 + x^2 + x + 1$$

This means:
- Addition is XOR: $a + b = a \oplus b$
- Multiplication is polynomial multiplication modulo $f(x)$
- Every non-zero element has a multiplicative inverse

---

## Mitigations

{{< admonition type="success" title="How to Prevent This Attack" open="true" >}}

1. **Never reuse nonces**: Each (key, nonce) pair must be used for at most one encryption
2. **No verification oracle**: Don't expose tag verification as an oracle to attackers
3. **Limit encryption queries**: Bound the number of encryptions with the same key
4. **Use AES-GCM-SIV**: Nonce-misuse resistant variant that derives nonce from plaintext
5. **Proper key rotation**: Regularly rotate encryption keys

In this challenge, all these rules were violated simultaneously!
{{< /admonition >}}

---

## Key Takeaways

1. **GCM is fragile**: Nonce reuse + oracle access = complete break
2. **Polynomial algebra is powerful**: Knowing coefficients lets us solve for unknowns
3. **Oracle abuse is subtle**: Even a simple True/False oracle can leak full plaintexts
4. **Understanding crypto internals matters**: Knowing how GHASH works made this challenge straightforward

---

## References

- [**AES-GCM Deep Dive by Frederik Reitemeyer**](https://frereit.de/aes_gcm/) - Comprehensive explanation of GCM internals
- [Forbidden Attack: Nonce reuse in AES-GCM](https://eprint.iacr.org/2016/475.pdf)
- [NIST SP 800-38D: GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- McGrew, D. A., & Viega, J. (2004). "The Galois/Counter Mode of Operation (GCM)"

---

{{< admonition type="quote" title="Challenge Reflection" open="true" >}}
This challenge demonstrates that **implementation flaws can completely bypass cryptographic security**. AES-GCM is provably secure under proper usage, but violating its assumptions (unique nonces, no oracle access) turns a secure primitive into a trivial break.

The lesson: **Security proofs have assumptions. Violate them at your peril.**
{{< /admonition >}}

