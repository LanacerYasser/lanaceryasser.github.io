---
title: "Vrai Sahl"
date: 2025-05-26T00:00:00+00:00
draft: false
author: "Koyphshi"
summary: "Breaking a hybrid RSA-ECC cryptosystem through weak prime generation. This challenge exploited predictable patterns in RSA prime generation and combined it with elliptic curve mathematics to recover the flag."
categories: ["Cryptography"]
tags: ["ecc", "rsa", "coppersmith", "weak-primes", "hybrid-crypto"]





math: true
toc:
  enable: true
  auto: true
code:
  copy: true
  maxShownLines: 50
---

Breaking a hybrid RSA-ECC cryptosystem through weak prime generation.

<!--more-->

{{< admonition type="info" title="Challenge Info" open="true" >}}
- **CTF**: Ingeneer
- **Challenge**: Vrai Sahl
- **Category**: Crypto
- **Points**: Hard
- **Description**: I didn't have much time, so I made an easy challenge but labeled it hard—kind of like calling a first-year spell a N.E.W.T.-level exam. Sorry for the mix-up!
{{< /admonition >}}

## TL;DR

This challenge presented a hybrid encryption scheme combining **RSA** and **Elliptic Curve Cryptography (ECC)**. The primary vulnerability lay in the RSA prime generation, where a significant portion of the least significant bits (LSBs) of both prime factors was generated using a predictable pattern. 

The exploitation involved three stages:
1. **Exploit weak RSA primes**: Recover LSBs using the fixed 0x3 nibble vulnerability
2. **Factor the modulus**: Apply Coppersmith's method to find remaining MSBs
3. **Extract the flag**: Use polynomial GCD to find the common root of two equations

## Initial Analysis

The challenge source code `main.py` reveals a multi-layered encryption process:

```python
from Crypto.Util.number import *
from random import *
from sage.all import *

def generate_custom_prime():
    while True:
        suffix = str(getRandomNBitInteger(140)).encode().hex()[2:]
        prefix = hex(getRandomNBitInteger(100))[2:]
        candidate = int(prefix + suffix, 16)
        if isPrime(candidate):
            return candidate

def get_flag_value():
    with open("flag.txt", "rb") as f:
        return bytes_to_long(f.read().strip())

def elliptic_curve_encrypt(flag_val):
    p = getPrime(512)
    q = getPrime(512)
    modulus = p * q # ecc_modulus
    y = randint(0, modulus - 1)
    a = randint(1, modulus)
    b = (y**2 - (flag_val**3 + a * flag_val)) % modulus
    curve = EllipticCurve(Zmod(modulus), [a, b])
    base = curve(flag_val, y)
    result_point = 2 * base
    encrypted = pow(bytes_to_long(b'ANA M9WD'), 0x10001, modulus)
    return {
        "a": a,
        "b": b,
        "point": result_point.xy(),
        "modulus": modulus,
        "ciphertext": encrypted
    }

def hybrid_encrypt(flag_val, ecc_modulus):
    P = generate_custom_prime()
    Q = generate_custom_prime()
    rsa_modulus = P * Q
    pub = pow(flag_val + P, 0x10001, ecc_modulus)
    rsa_ciphertext = pow(bytes_to_long(b'ANA CHIKOUR'), 0x10001, rsa_modulus)
    return {
        "rsa_modulus": rsa_modulus,
        "pub": pub,
        "ciphertext": rsa_ciphertext
    }

def main():
    flag_val = get_flag_value()
    ecc_data = elliptic_curve_encrypt(flag_val)
    hybrid_data = hybrid_encrypt(flag_val, ecc_data["modulus"])
    save_all(ecc_data, hybrid_data)
main()
```

### RSA Weakness: `generate_custom_prime()`

{{< admonition type="warning" title="Critical Vulnerability" open="true" >}}

The function constructs candidate primes by concatenating:
- A random **100-bit prefix**
- A random **140-bit suffix** (converted via `str → bytes → hex`)

**The vulnerability**: When converting a number to string, then to hex bytes, the ASCII representation of digits '0'-'9' always produces bytes starting with `0x3`:

| Character | Hex Byte |
|-----------|----------|
| '0'       | 0x30     |
| '1'       | 0x31     |
| ...       | ...      |
| '9'       | 0x39     |

This means **the first nibble of every byte in the suffix is fixed to 0x3**.

{{< /admonition >}}

### Elliptic Curve Encryption

An elliptic curve is defined over the ECC modulus:

$$E: y^2 \equiv x^3 + ax + b \pmod{n}$$

The flag value is used as the x-coordinate of the base point:
- \\(\text{base} = ({\tt flag\_val}, y)\\)
- \\(\text{result\_point} = 2 \cdot \text{base}\\)

The x-coordinate of `result_point` is leaked as `point[0]`.

### Hybrid Encryption Layer

The crucial equation linking everything:

$${\tt pub} = ({\tt flag\_val} + P)^{0x10001} \pmod{n}$$

where \\(P\\) is one of the weak RSA primes and \\(n\\) is the ECC modulus.

---

## Task Analysis

The challenge requires three sequential stages:

| Stage | Task | Method |
|-------|------|--------|
| **1** | Recover LSBs of \\(P\\) and \\(Q\\) | Brute-force second nibble (10 candidates per byte) |
| **2** | Factor `rsa_modulus` completely | Coppersmith's theorem on small roots |
| **3** | Extract flag value | Polynomial GCD of two equations |

---

## Exploitation

### Part 1: Recovering RSA Prime LSBs

Since each byte has the first nibble fixed to 0x3, we only need to brute-force the second nibble (0-9, not 0-F). This reduces the search space from \\(16 \times 16\\) to \\(10 \times 10\\) per byte pair.

**Algorithm**: Iterate from LSB upward, recovering bytes incrementally by checking if the product matches modulo powers of 16.

```python
def bf_2nd_nibbles(N, A, B, n):
    for x in range(16): # Possible values for the 2nd nibble of P
        for y in range(16): # Possible values for the 2nd nibble of Q
            # Construct candidate for P's current byte: 0x3X...
            bfA = 0x3 * pow(16, n - 1) + pow(16, n - 2) * x + A
            # Construct candidate for Q's current byte: 0x3X...
            bfB = 0x3 * pow(16, n - 1) + pow(16, n - 2) * y + B
            # Check if product matches modulo 16^n
            if bfA * bfB % pow(16, n) == N % pow(16, n):
                return bfA, bfB
    return None, None

p = q = 0
for i in range(2, 86, 2): # Recover up to 86 nibbles (43 bytes)
    p, q = bf_2nd_nibbles(rsa_n, p, q, i)
```

{{< admonition type="tip" title="Why This Works" open="true" >}}

If \\(P \approx P_{\text{high}} \cdot 2^k + p_{\text{known}}\\) and \\(Q \approx Q_{\text{high}} \cdot 2^k + q_{\text{known}}\\), then:

$$N \equiv P \cdot Q \pmod{2^{8k}}$$

By checking this congruence for increasing \\(k\\), we progressively recover more bits of both primes.

{{< /admonition >}}

### Part 2: Factoring RSA with Coppersmith's Method

After recovering \\(p_{\text{known}}\\) and \\(q_{\text{known}}\\) (sufficient LSBs), we have:

$$P = x \cdot R + p_{\text{known}}$$
$$Q = y \cdot R + q_{\text{known}}$$

where \\(R = 2^{\text{known\_bits}}\\) and \\(x, y\\) are the unknown high parts (small relative to \\(N\\)).

Substituting into \\(N = P \cdot Q\\):

$$N = (x \cdot R + p_{\text{known}})(y \cdot R + q_{\text{known}})$$

This is a bivariate polynomial with **small roots** \\(x\\) and \\(y\\). Coppersmith's theorem finds them efficiently:

```python
R = 2 ** (p.bit_length())
x, y = var('x y')
p_ = x * R + p
q_ = y * R + q
f = (p_ * q_ - rsa_n).expand()

PR = PolynomialRing(Zmod(rsa_n), names=('x', 'y'))
f = PR(f)
x, y = f.parent().gens()

# Find small roots using lattice reduction
roots = small_roots(f, [R, R], m=3, d=4)
x_root, y_root = roots[0]

P = int(x_root * R + p)
Q = rsa_n // P  # Verify: rsa_n % P == 0
```

{{< admonition type="note" title="Coppersmith's Theorem" open="true" >}}

If a polynomial \\(f(x, y)\\) of degree \\(d\\) has a root \\((x_0, y_0)\\) where \\(|x_0| < X\\) and \\(|y_0| < Y\\), and if \\(XY < N^{d/(d+1)}\\), then the root can be found in polynomial time using lattice reduction (LLL algorithm).

{{< /admonition >}}

### Part 3: Recovering the Flag via Polynomial GCD

The flag is the **common root** of two polynomials over \\(\mathbb{Z}_n\\) (ECC modulus).

#### **Polynomial from hybrid encryption**

From \\({\tt pub} = (z + P)^{0x10001} \pmod{n}\\), we get:

$$f(z) = (z + P)^{0x10001} - {\tt pub}$$

#### **Polynomial from elliptic curve point doubling**

For a point \\((x_1, y_1)\\) on \\(y^2 = x^3 + ax + b\\), the x-coordinate of \\(2(x_1, y_1)\\) is:

$$x_2 = \left(\frac{3x_1^2 + a}{2y_1}\right)^2 - 2x_1$$

With \\(x_1 = z\\) (the flag) and \\(x_2 = {\tt point}[0]\\) (known), we can eliminate \\(y_1\\) using \\(y_1^2 = z^3 + az + b\\):

$$4(z^3 + az + b)({\tt point}[0] + 2z) = (3z^2 + a)^2$$

Therefore:

$$g(z) = (3z^2 + a)^2 - 4(z^3 + az + b)(2z + {\tt point}[0])$$

#### **Finding the common root**

Both polynomials share \\(z = {\tt flag\_val}\\) as a root. Computing their GCD gives \\((z - m)\\) where \\(m = {\tt flag\_val}\\):

```python
F = Zmod(n)
PR = PolynomialRing(F, names=('z',))
z = PR.gen()

f = (z + Q) ** 0x10001 - pub
g = (3 * z**2 + a)**2 - 4 * (z**3 + a * z + b) * (2 * z + point[0])

# Compute polynomial GCD using Euclidean algorithm
def pgcd(g1, g2):
    return g1.monic() if not g2 else pgcd(g2, g1 % g2)

result = pgcd(f, g)  # Result is of form (z - m)
m = -result.coefficients()[0]  # Extract the root

print(long_to_bytes(int(m)))  # Reveal the flag!
```

{{< admonition type="success" title="Why GCD Works" open="true" >}}

If \\(\alpha\\) is a root of both \\(f(z)\\) and \\(g(z)\\), then \\((z - \alpha)\\) divides \\(\gcd(f(z), g(z))\\). If there's exactly one common root, the GCD is linear: \\(c(z - \alpha)\\) for some constant \\(c\\). Normalizing to monic form gives \\((z - \alpha)\\) directly.

{{< /admonition >}}

---

## Behind the Math

### Weak Prime Suffix

The ASCII hex encoding of digits constrains the LSBs of primes to a highly predictable pattern. This reduces brute-force complexity from exponential to tractable.

### Coppersmith's Method

A cornerstone of RSA cryptanalysis:

> **Coppersmith's Theorem** (1997): If you know a significant portion (MSBs or LSBs) of a prime factor of \\(N\\), you can recover the remaining bits in polynomial time.

This applies to our scenario where we've recovered \\(\approx 140\\) bits of \\(P\\) (the suffix) out of \\(\approx 240\\) bits total.

### Elliptic Curve Point Doubling Formula

On the curve \\(y^2 = x^3 + ax + b\\), point doubling uses the tangent line's slope:

$$\lambda = \frac{3x^2 + a}{2y}$$

The resulting x-coordinate is:

$$x(2P) = \lambda^2 - 2x(P)$$

By substituting known values and using the curve equation, we derive a polynomial constraint on \\(x(P)\\).

### Polynomial GCD for Common Roots

The Euclidean algorithm for polynomials finds \\(\gcd(f, g)\\) by successive remainder operations. If both polynomials share a root, that root appears in the GCD. For a linear GCD \\((z - m)\\), the constant term is \\(-m\\).

---

## Conclusions

**"Vrai Sahl"** exemplified sophisticated cryptographic vulnerabilities:

{{< admonition type="success" title="Key Lessons" open="true" >}}

1. **Random number generation is critical**: Even subtle patterns in prime construction (like ASCII hex encoding) can be exploited for complete factorization.

2. **Coppersmith's method is powerful**: It transforms partial knowledge into complete recovery of cryptographic secrets.

3. **Hybrid systems require careful integration**: Vulnerabilities in one component (RSA primes) can compromise the entire system (ECC + RSA).

4. **Polynomial algebra is a cryptanalytic tool**: GCD computation over finite fields reveals hidden relationships between encrypted values.

5. **Defense requires rigor**: Use cryptographic libraries' standard random prime generators, never implement your own.

{{< /admonition >}}

This challenge demonstrates how cryptographic implementations with subtle flaws can be completely compromised through sophisticated mathematical attacks.
