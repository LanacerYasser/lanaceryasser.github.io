---
title: "XORSA"
date: 2025-04-21T00:00:00+00:00
draft: false
author: "Koyphshi"
description: "Exploiting RSA with leaked XOR bits"
categories: ["Cryptography"]
tags: ["rsa", "xor-leak", "coppersmith", "prime-factorization", "lattice-reduction"]
math: true
code:
  maxShownLines: 50
toc:
  enable: true
  auto: true

---

<!--more-->

{{< admonition type="info" title="Challenge Info" open="true" >}}
- **CTF**: UMASSCTF
- **Challenge**: XORSA
- **Category**: Crypto
- **Points**: 488 (19 solves)
- **Description**: I leaked a bit more than half of the XOR of the primes.
{{< /admonition >}}

## TL;DR

This challenge involved exploiting a vulnerability in an RSA implementation where the creator leaked **more than half of the XOR of the prime factors**. The solution reconstructs the prime factors bit-by-bit using a recursive approach that:

1. Starts with the most significant bits
2. Uses the leaked XOR bits to constrain possibilities
3. Prunes invalid paths via product bounds
4. Switches to Coppersmith's method for remaining bits
5. Decrypts the flag with the recovered private key

---

## Challenge Overview

The challenge provides this RSA implementation:

```python
from Crypto.Util import number
flag = b"REDACTED"
bits = 1024
p = number.getPrime(bits)
q = number.getPrime(bits)
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = number.inverse(e, phi)
extra = 75
c = pow(int.from_bytes(flag, 'big'), e, n)
print(f"n: {hex(n)}")
print(f"e: {hex(e)}")
print(f"c: {hex(c)}")
print(f"partial p^q: {hex((p^q) >> (bits // 2 - extra))}")
```

This looks like standard RSA encryption, but there's a **critical information leak**:

$${\tt partial\ p\oplus q} = (p \oplus q) \gg (\text{bits} // 2 - \text{extra})$$

{{< admonition type="warning" title="The Vulnerability" open="true" >}}

The script leaks the most significant \\( \text{bits}/2 + \text{extra} \\) bits of \\( p \oplus q \\).

With \\( \text{bits} = 1024 \\) and \\( \text{extra} = 75 \\), we get:
- 1024/2 + 75 = **575 bits** of the XOR leaked
- Out of 1024 total bits
- That's **56% of the information** about the relationship between \\( p \\) and \\( q \\)

This is a catastrophic information leak!

{{< /admonition >}}

---

## Task Analysis

What do we know?

| Known | Unknown |
|-------|---------|
| MSBs of \\( p \oplus q \\) (575 bits) | LSBs of \\( p \oplus q \\) (449 bits) |
| \\( n = p \cdot q \\) | \\( p \\) and \\( q \\) individually |
| Public key \\( (n, e) \\) | Private key \\( d \\) |
| Ciphertext \\( c \\) | Plaintext \\( m \\) |

**Key Insight**: The XOR constraint dramatically reduces the search space. For each bit position, if we know \\( p_i \oplus q_i \\), we only have **2 possibilities** instead of 4:

| \\( p_i \oplus q_i \\) | Valid \\( (p_i, q_i) \\) pairs |
|------------|---------------------------|
| 0 | (0, 0) or (1, 1) |
| 1 | (0, 1) or (1, 0) |

This is much better than trying all 4 combinations!

{{< admonition type="note" title="Mathematical Background" open="true" >}}

This approach is based on the discussion: [Integer factorization with additional knowledge of \\( p \oplus q \\)](https://math.stackexchange.com/questions/2087588/integer-factorization-with-additional-knowledge-of-p-oplus-q/2087589)

The key observation: tracking sets of k-bit values that satisfy \\( p_k \cdot q_k \equiv n \pmod{2^k} \\), then extending by one bit at a time. With the XOR constraint, most paths get pruned, leaving few valid continuations.

{{< /admonition >}}

---

## Exploitation

### Algorithm Overview

Our recursive algorithm works **from MSB to LSB**:

1. Start at the most significant bit
2. For each bit position, try both possibilities allowed by \\( p \oplus q \\)
3. Prune invalid candidates using product bounds
4. Once XOR bits are exhausted, use Coppersmith's method for remaining bits
5. Recover the private key and decrypt

### Product Bounds Pruning

For partially reconstructed \\( p_{\text{high}} \\) and \\( q_{\text{high}} \\), if we've decided \\( k \\) bits, the remaining \\( m \\) bits form unknown parts.

The minimum product (all remaining bits 0):
$$p_{\min} \cdot q_{\min} = (p_{\text{high}} \ll m) \cdot (q_{\text{high}} \ll m)$$

The maximum product (all remaining bits 1):
$$p_{\max} \cdot q_{\max} = ((p_{\text{high}} << m) + 2^m - 1) \cdot ((q_{\text{high}} << m) + 2^m - 1)$$

**Pruning rule**: If \\( n \\) is outside \\( [p_{\min}, p_{\max}] \\), this branch cannot produce the target modulus and can be skipped!

```
┌─────────────────────────┐
│ Bit-by-bit recursion    │
├─────────────────────────┤
│ k = 1023 (MSB)          │
│ Try 2 possibilities     │
│ ├─ Check bounds         │
│ ├─ If valid: recurse    │
│ └─ If invalid: skip     │
│                         │
│ ...repeat down to LSB   │
│                         │
│ k < 512 - 75            │
│ └─ Call Coppersmith     │
└─────────────────────────┘
```

### Complete Solution

```python
from Crypto.Util.number import *
from sage.all import *
import sys
load('coppersmith.sage')

b = 1024
xor = 0x64...        # Leaked XOR of p and q (MSBs)
n = 0x46...          # RSA modulus
e = 0x10001          # Public exponent
c = 0x38...          # Ciphertext

def find(k, p_high, q_high):
    """
    Recursively recover p and q bit by bit from MSB to LSB
    
    Args:
        k: Current bit position (starts at NBITS-1, decreases)
        p_high: Recovered bits of p so far
        q_high: Recovered bits of q so far
    """
    l = p_high.bit_length()
    
    # Switch to Coppersmith once we've used all leaked XOR bits
    if k < b//2 - 75:
        l = 512 - 75
        R = 2**l
        x, y = var('x y')
        p_ = p_high * R + x
        q_ = q_high * R + y
        f = (p_ * q_ - n).expand()
        PR = PolynomialRing(Zmod(n), names=('x', 'y'))
        f = PR(f)
        try:
            x, y = small_roots(f, [R, R], m=3, d=4)[0]
            P = int(p_high * R + x)
            Q = int(q_high * R + y)
            if n % P == 0:
                phi = (P - 1) * (Q - 1)
                d = inverse(e, phi)
                m = pow(c, d, n)
                print(long_to_bytes(m))
                sys.exit(0)
        except:
            pass
        return

    # Extract the XOR bit at position k
    xor_k = (xor >> (k - b//2 + 75)) & 1
    
    # Determine valid bit pairs
    possibilities = [(0, 0), (1, 1)] if xor_k == 0 else [(0, 1), (1, 0)]
    
    for p_k, q_k in possibilities:
        # Extend with new bits
        p_high_new = (p_high << 1) | p_k
        q_high_new = (q_high << 1) | q_k
        
        # Calculate bounds for remaining bits
        m = NBITS - k
        shift = NBITS - m
        min_prod = (p_high_new << shift) * (q_high_new << shift)
        max_prod = (((p_high_new << shift) + (1 << shift) - 1) * 
                    ((q_high_new << shift) + (1 << shift) - 1))
        
        # Prune if n cannot be achieved
        if min_prod <= n <= max_prod:
            find(k - 1, p_high_new, q_high_new)

NBITS = b
find(NBITS - 1, 0, 0)
```

{{< admonition type="tip" title="Why This Works" open="true" >}}

**Complexity Analysis**: 

Without any constraints, we'd need to try all \\( 2^{1024} \\) combinations (infeasible). 

With the XOR constraint, we branch with factor 2 at each step, giving \\( 2^{1024} \\) possibilities still...

But the **bounds checking** prunes ~99% of branches! Most bit combinations make \\( n \\) unachievable. Combined with Coppersmith's method for the final stretch, this becomes tractable.

{{< /admonition >}}

---

## Behind the Math

### Why XOR Information is Powerful

For each bit position \\( i \\):

$$p_i \oplus q_i = \begin{cases} 0 & \text{if } p_i = q_i \\ 1 & \text{if } p_i \neq q_i \end{cases}$$

This transforms a **combinatorial search** problem (try all \\( 2^{1024} \\) candidates) into a **constraint satisfaction** problem (only 2 valid choices per bit).

### Product Bounds as a Pruning Heuristic

The modulus \\( n = p \cdot q \\) is a strict constraint. For fixed MSBs:

$$p = p_{\text{high}} \cdot 2^m + p_{\text{low}}$$
$$q = q_{\text{high}} \cdot 2^m + q_{\text{low}}$$

where \\( 0 \leq p_{\text{low}}, q_{\text{low}} < 2^m \\).

Therefore:
$$n = (p_{\text{high}} \cdot 2^m + p_{\text{low}}) \cdot (q_{\text{high}} \cdot 2^m + q_{\text{low}})$$

The product ranges from:
$$(p_{\text{high}} \cdot 2^m) \cdot (q_{\text{high}} \cdot 2^m)$$

to:
$$((p_{\text{high}} + 1) \cdot 2^m - 1) \cdot ((q_{\text{high}} + 1) \cdot 2^m - 1)$$

If \\( n \\) is outside this range, no valid \\( p_{\text{low}}, q_{\text{low}} \\) exist. Pruning is safe!

### Coppersmith's Method for the Tail

Once we've fixed ~575 MSBs via the XOR constraint, we need to find the remaining ~449 bits. These form a "small" root:

$$f(x, y) = (p_{\text{high}} \cdot R + x) \cdot (q_{\text{high}} \cdot R + y) - n$$

where \\( R = 2^{449} \\) and \\( x, y < R \\).

Coppersmith's theorem guarantees we can find this small root using lattice reduction (LLL algorithm), provided:

$$X \cdot Y < n^{1/(d+1)}$$

where \\( d \\) is the polynomial degree and \\( X, Y \\) are the bounds on roots.

---

## Exploitation Timeline

```
┌────────────┐
│   Start    │
└─────┬──────┘
      │
      ├─ Parse leaked XOR (575 MSBs)
      ├─ Parse modulus n
      └─ Start recursive search from MSB
      │
      ├─ [~5 mins] Try bit combinations with bounds checking
      ├─ Most branches pruned early
      ├─ Explore ~10,000 valid paths to LSB
      │
      └─ [~5 mins] Hit base case, call Coppersmith
         │
         ├─ Solve \\( f(x,y) = p_{\text{high}} \cdot R + x \\)
         ├─ Recover p and q
         └─ Compute \\( d = e^{-1} \pmod{\phi(n)} \\)
         │
         └─ [~1 sec] Decrypt: \\( m = c^d \pmod{n} \\)
            │
            └─ Flag: UMASS{i_will_make_a_solve_script}
```

**Total runtime**: ~10 minutes

---

## Conclusions

{{< admonition type="success" title="Key Takeaways" open="true" >}}

1. **Information Leakage Breaks RSA**: Any partial information about \\( p \\) and \\( q \\) or their relationships can compromise security. The XOR of primes should be as secret as the primes themselves.

2. **Constraint Satisfaction > Brute Force**: Rather than trying all \\( 2^{1024} \\) candidates, the XOR constraint and bounds checking reduced the search space by ~99+%, making factorization tractable.

3. **Hybrid Approaches**: Combining classical bit-by-bit search with modern lattice techniques (Coppersmith) gives a powerful cryptanalytic tool.

4. **Implementation Flaws Matter**: This vulnerability came from a seemingly minor leak—just shifting right instead of discarding all bits. One line of code broke 1024-bit RSA.

5. **Formal Security Proofs**: RSA's security depends on factorization hardness. Proving no information leaks about \\( p \oplus q \\) is crucial.

{{< /admonition >}}

---

## References

- [Integer factorization with additional knowledge of \\( p \oplus q \\)](https://math.stackexchange.com/questions/2087588/integer-factorization-with-additional-knowledge-of-p-oplus-q/2087589)
- [XOR Factor Implementation](https://github.com/sliedes/xor_factor)
- [Coppersmith's Attack on RSA](https://github.com/defund/coppersmith)
- Coppersmith, D. "Small solutions to polynomial equations, and low exponent RSA vulnerabilities." Journal of Cryptology 10.4 (1997): 233-260.
