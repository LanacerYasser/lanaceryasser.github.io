---
title: "Geni"
date: 2025-12-22T00:00:00+00:00
draft: false
author: "Koyphshi"
description: "Exploiting a CSI-FiSh variant by tracking torsion points through a sequence of leaked generator images."
categories: ["Cryptography"]
tags: [isogeny, crypto, csidh, weil-pairing]
math: true
code:
  maxShownLines: 50
toc:
  enable: true
  auto: true


---
<!--more-->

Last weekend, I participated in **BSides Algiers CTF**, hosted by **Shellmates**, and I was able to win **1st place**! I managed to solve all the cryptography challenges. This writeup focuses on the one I found to be the most interesting and hardest: **Geni**.

At first, I didn't have a deep understanding of isogenies, but by reading the [CryptoHack Isogeny Challenges](https://cryptohack.org/challenges/isogenies/), I gained a basic understanding that allowed me to start reading the challenge files and understand the underlying mechanics.


{{< admonition type="info" title="Challenge Info" open="true" >}}
- **CTF**: BSides Algiers 2025
- **Challenge**: Geni
- **Category**: Crypto
- **Description**: what about an isogeny challenge?
- **Author**: scalio
{{< /admonition >}}

## File Analysis

The challenge provided several SageMath files that implemented the cryptosystem:

1.  **`CSIDH.sage`**: Contains the core logic for the Commutative Supersingular Isogeny Diffie-Hellman (CSIDH) group action over 74 small primes.
2.  **`scheme.sage`**: The main logic for the signature scheme. It defines key generation, Fiat-Shamir signing, and verification. It defines the structure of the public key.
3.  **`HKZbasis.sage`**: Provides lattice reduction functions (LLL/BKZ) to find short vectors in the relation basis of the class group, ensuring secret keys are manageable.
4.  **`out.txt`**: The challenge output containing the `Points_list` (public keys), parameters, message signature, and the encrypted flag.

---

## Detailed Vulnerability Analysis

The vulnerability is a combination of **Torsion Point Leakage** and a **Linear Secret Sequence**.

### 1. Torsion Point Leakage
In standard CSIDH, a public key is just the target curve $E$. However, `scheme.sage` discloses the images of the generators $Q_1$ and $Q_2$ of the base curve $E_0$ under the secret isogeny $\Phi$:

```python
"Points_list": [(P.xy() , PP.xy()) for _ , P , PP in self.PK]
```

This disclosure is fatal. In isogeny-based cryptography, knowing where a torsion basis $(Q_1, Q_2)$ maps allows an attacker to compute the image of **any** point $T$ in the torsion group $E_0[p+1]$. If $T = uQ_1 + vQ_2$, then $\Phi(T) = u\Phi(Q_1) + v\Phi(Q_2)$.

### 2. The Linear Sequence Leak
The secret key is a list of 16 vectors (`SK`) where each vector is derived linearly:
$$ SK[j] = SK[j-1] + \text{quick} \quad \text{where} \quad \text{quick} = -\text{sign}(SK[1]) $$
This means that for every prime lane $\ell_i$, the exponent $v_i$ is slowly counting down toward zero across the 16 curves provided in the public key. This allows us to "read" the secret exponents by watching when the image of a torsion point stops being zero.

---

## Behind the Math

### Frobenius Eigenspaces and Kernels
In CSIDH, the group action by a prime ideal $\mathfrak{l}_i$ corresponds to an isogeny whose kernel is a subgroup of the $\ell_i$-torsion $E_0[\ell_i]$. On a supersingular curve over $\mathbb{F}_p$, the $\ell_i$-torsion splits into two eigenspaces under the Frobenius endomorphism $\pi$:
1.  **Positive Eigenspace ($T^+$):** Points where $\pi(T) = T$.
2.  **Negative Eigenspace ($T^-$):** Points where $\pi(T) = -T$.

If the secret exponent $v_i$ is positive, the isogeny $\Phi$ "swallows" the positive eigenspace. This means $\Phi(T^+) = 0$ (the point at infinity) on the target curve. If $v_i$ is negative, it swallows $T^-$.

### The Weil Pairing
To track these points, we must express $T^+$ and $T^-$ as linear combinations of the generators $Q_1, Q_2$. Since we are working with the full $(p+1)$-torsion, we use the **Weil Pairing** $e(\cdot, \cdot)$ to solve the discrete logarithm problem on the torsion group:
$$ u \equiv \log_{e(Q_1, Q_2)}(e(T, Q_2)) \pmod{\ell_i} $$
$$ v \equiv \log_{e(Q_1, Q_2)}(e(Q_1, T)) \pmod{\ell_i} $$

---

## Exploitation Process

### Step 1: Reconstructing the Curves
We reconstruct the coefficients of the 16 target curves from the coordinates in `Points_list` by solving the curve equation $y^2 = x^3 + Ax + B$ for $A$ and $B$.

### Step 2: Tracking Torsion Images
We compute the coefficients $(u, v)$ for the $+1$ and $-1$ torsion points for each prime. We then evaluate their images across the 16 curves to check if they map to the point at infinity:

```python
def get_uv(T):
    u = T.weil_pairing(Q2, p+1).log(pairing_base)
    v = Q1.weil_pairing(T, p+1).log(pairing_base)
    return u, v

img1_p = up * P_imgs[1] + vp * PP_imgs[1]
img1_m = um * P_imgs[1] + vm * PP_imgs[1]
```

### Step 3: Recovering the Exponents
Because the 16 curves count down the exponent to zero, we check how many curves in the sequence map the torsion point to Zero. If it stops being zero at curve $j+1$, the exponent was exactly $j$.

```python
if img1_p.is_zero():
    count = 1
    for j in range(2, 16):
        if (up * P_imgs[j] + vp * PP_imgs[j]).is_zero():
            count += 1
        else:
            break
    v_found = count
```

By repeating this for all 74 primes, we perfectly reconstruct the secret vector $SK[1]$, derive the full $SK$ list, and hash it to obtain the AES key.

---

## Full Solver Script

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 
          73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 
          157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 
          239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 
          331, 337, 347, 349, 353, 359, 367, 373, 587]

p = 4 * prod(primes) - 1
Fp = GF(p)
F.<i> = GF(p^2, modulus=x^2 + 1)
E0 = EllipticCurve(F, [1, 0])

def parse_out():
    with open("out.txt", "r") as f:
        data = f.read()
    
    sections = {}
    current = None
    for line in data.split('\n'):
        if ':' in line and not line.startswith(' '):
            current = line.split(':')[0]
            sections[current] = ""
        elif current:
            sections[current] += line
            
    pts_list = sage_eval(sections['Points_list'], locals={'i': i})
    hex_res = sections['Hex result'].strip()
    return pts_list, hex_res

pts_list, hex_res = parse_out()
Q1_coords, Q2_coords = pts_list[0]
Q1 = E0(Q1_coords)
Q2 = E0(Q2_coords)
pairing_base = Q1.weil_pairing(Q2, p + 1)

E_list = []
P_imgs = []
PP_imgs = []
for j in range(16):
    (x1, y1), (x2, y2) = pts_list[j]
    x1, y1, x2, y2 = F(x1), F(y1), F(x2), F(y2)
    A = ((y1^2 - x1^3) - (y2^2 - x2^3)) / (x1 - x2)
    B = y1^2 - x1^3 - A*x1
    Ej = EllipticCurve(F, [A, B])
    E_list.append(Ej)
    P_imgs.append(Ej(x1, y1))
    PP_imgs.append(Ej(x2, y2))

sk1 = []
print("[*] Recovering exponents via Zero-Image analysis...")

for idx, l in enumerate(primes):
    while True:
        xr = Fp.random_element()
        rhs = xr^3 + xr
        if is_square(rhs):
            Tp = ((p+1)//l) * E0(xr, sqrt(rhs))
            if not Tp.is_zero(): break
    while True:
        xr = Fp.random_element()
        rhs = xr^3 + xr
        if not is_square(rhs):
            Tm = ((p+1)//l) * E0(xr, i * sqrt(-rhs))
            if not Tm.is_zero(): break
            
    def get_uv(T):
        u = T.weil_pairing(Q2, p+1).log(pairing_base)
        v = Q1.weil_pairing(T, p+1).log(pairing_base)
        return u, v

    up, vp = get_uv(Tp)
    um, vm = get_uv(Tm)

    v_found = 0
    img1_p = up * P_imgs[1] + vp * PP_imgs[1]
    img1_m = um * P_imgs[1] + vm * PP_imgs[1]
    
    if img1_p.is_zero():
        count = 1
        for j in range(2, 16):
            if (up * P_imgs[j] + vp * PP_imgs[j]).is_zero(): count += 1
            else: break
        v_found = count
    elif img1_m.is_zero():
        count = 1
        for j in range(2, 16):
            if (um * P_imgs[j] + vm * PP_imgs[j]).is_zero(): count += 1
            else: break
        v_found = -count
    
    sk1.append(int(v_found))

SK = [[0]*74]
SK.append(sk1)
quick = [int(-sign(x)) for x in sk1]
curr = list(sk1)
for _ in range(14):
    curr = [int(curr[k] + quick[k]) for k in range(74)]
    SK.append(curr)

key_str = str(SK)
aes_key = hashlib.sha256(key_str.encode()).digest()

res = bytes.fromhex(hex_res)
iv, ct = res[:16], res[16:]
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16)

print(f"\n[+] Success! Flag: {flag.decode()}")
```

**Flag:** `shellmates{Weil_Pairing_and_Frobenius_u_get_torsion_group_Kernel_Sign}`
