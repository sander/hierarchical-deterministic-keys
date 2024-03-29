**Workgroup:** N/A \
**Internet-Draft:** TODO \
**Published:** TODO \
**Intended Status:** TODO \
**Expires:** TODO \
**Authors:** Peter Altmann (Digg), Sander Q. Dijkhuis (Cleverbase)

# Hierarchical Deterministic Key Derivation (HDKD)

## Abstract

TODO

## Discussion Venues

_This note is to be removed before publishing as an RFC._

Source for this draft and an issue tracker can be found at [GitHub: AltmannPeter/privacy-key-management](https://github.com/AltmannPeter/privacy-key-management).

## Status of This Memo

This is a working document.

## Copyright Notice

TODO

## 1. Introduction

See for context: [Privacy-preserving key management in the EU Digital Identity Wallet](context.md).

This document represents the consensus of the authors. It is not an IETF product and is not a standard.

## 2. Conventions and Definitions

The key words “MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”, “SHOULD”, “SHOULD NOT”, “RECOMMENDED”, “NOT RECOMMENDED”, “MAY”, and “OPTIONAL” in this document are to be interpreted as described in BCP 14 [[RFC2119]] [[RFC8174]] when, and only when, they appear in all capitals, as shown here.

The following notation is used throughout the document.

- byte: A sequence of eight bits.
- I2OS(x): Conversion of a nonnegative integer `x` to a byte array using a big-endian representation of the integer without padding.

## 3. Cryptographic Dependencies

HDKD depends on the following cryptographic constructs:

- Prime-Order Group;
- Cryptographic Hash Function.

These are described in the following sections.

### 3.1. Prime-Order Group

Let $B$ be the group generator of order $q$ of an elliptic curve $E$ defined over $GF(p)$. Denote scalar multiplication between a scalar $x$ and a point $A$ as $[x]A$.

This document uses types `Element` and `Scalar` to denote elements of $E$ and its set of scalars, respectively.

This document represents $E$ as the object `G`. The following member functions can be invoked on `G`.

- Order(): Outputs the order of $E$ (i.e. $p$).
- Identity(): Outputs the identity `Element` of $E$.
- Add(A, B): Outputs the sum of Elements `A` and `B`.
- SerializeScalar(s): Maps a Scalar `s` to a canonical byte array of fixed length `Ns`.
- ScalarMult(A, k): Outputs the scalar multiplication between Element `A` and Scalar `k`.
- ScalarBaseMult(k): Outputs the scalar multiplication between Scalar `k` and the group generator $B$.
- ECDH(k, A): Outputs the result of an Elliptic Curve Diffie-Hellman key exchange between Scalar `k` and Element `A`. The details vary based on the ciphersuite.

### 3.2. Cryptographic Hash Function

This document represents a cryptographically secure hash function as `H`. This function maps arbitrary byte strings to Scalar elements associated with `G`. The details vary based on the ciphersuite.

## 4. Helper Functions

## 4.1. Additive Key Derivation

```
Inputs:
- sk, the user-issuer shared key, a byte array.
- vkU, the user PoP verification key, an Element.
- j, the index of the key to be derived, a non-negative integer.

Outputs:
- vkU_j, an Element.

def derive_additive_verification_key(sk, vkU, j):
  sku_j = H(sk || "add" || I2OS(j))
  vkU_j = G.Add(U, G.ScalarBaseMult(u_j))
  return vkU_j
```

## 4.2. Multiplicative Key Derivation

```
Inputs:
- sk, the user-issuer shared key, a byte array.
- vkU, the user PoP verification key, an Element.
- j, the index of the key to be derived, a non-negative integer.

Outputs:
- vkU_j, an Element.

def derive_multiplicative_verification_key(sk, vkU, j):
  sku_j = H(sk || "mult" || I2OS(j))
  vkU_j = G.ScalarMult(U, u_j)
  return vkU_j
```

## 5. Hierarchical Deterministic Keys

Steps (can be performed by either party in a issuer-user pair):

1. Assume the existence of a user key pair $(u, U)$, where $u$ is a derived PoP private key, and $U$ is a derived PoP public key (i.e., a level 1 or below), and issuer key pair $(i, I)$.
    * Either key can be either static or one-time use.
    * The user may needs to be able to retrieve $I$ at the time of presentation.
2. The issuer authenticates the user using $U$.
3. Compute shared key `sk = G.ECDH(i, U)`.
4. Compute `u_j = H(sk || I2OS(j) || operation)` where `operation = "add"` in the case of additive derivation and `operation = "mult"` in the case of multiplicative derivation.
5. Compute derived public key $U_j$ in either of the two following ways:
    * Additive: $U_j^+ = U + [u_j]G$ computed using `U_j = G.Add(U, G.ScalarBaseMult(u_j))`.
    * Multiplicative: $U_j^{\times} = [u_j]U$ computed using `U_j = G.ScalarMult(U, u_j)`.
6. If $I$ is ephemeral, then include it in the issued attestation or otherwise ensure the user can retrieve it.

Steps 3–5 for the issuer are described in the subroutine below.

```
Inputs:
- skp, the ephemeral provider private key, a Scalar.
- vkU, the proven user PoP verification key, an Element.
- method, either ADDITIVE or MULTIPLICATIVE, an enum value.
- n, the amount of keys to be derived, a positive integer.

Outputs:
- result, a list of Elements.

def derive_keys_to_attest(skp, vkU, method, n):
  sk = G.ECDH(skp, vkU)

  result = []
  if method == ADDITIVE:
    for j in range(0, n):
      vkU_j = derive_additive_verification_key(sk, vkU, j)
      result.append(vkU_j)
  elif method == MULTIPLICATIVE:
    for j in range(0, n):
      vkU_j = derive_multiplicative_verification_key(sk, vkU, j)
      result.append(vkU_j)
  return result
```

Note that the performance of this algorithm scales linearly relative to the number of keys to derive. For short-lived one-time-use keys, the amount `n` is likely to be relatively small. For improved performance in case of large `n`, the result can be computed by caching intermediate values while computing `H` or otherwise breaking down the implementation of `H`.

## 6. Ciphersuites

The RECOMMENDED ciphersuite is (P-256, SHA-256).

### 6.1. HDKD(P-256, SHA-256)

This ciphersuite uses P-256 for `G`, SHA-256 for `H`. The `contextString` value is “`HDKD-P256-SHA256-v1`”.

- Group `G`: P-256 (secp256r1), where `Ns = 32`.
    - ECDH(k, A): Implemented using `G.SerializeScalar(x)` where `x` is the $x$-coordinate of `G.ScalarMult(A, k)`.
    - SerializeScalar(s): Implemented using the Field-Element-to-Octet-String conversion.
- Hash `H(m)`: Implemented as `hash_to_field(msg=m, count=1)` from [[RFC9380]] using `expand_message_xmd` with SHA-256 with parameters `DST = contextString`, `F` set to the scalar field, `p` set to `G.Order()`, `m = 1`, and `L = 48`.

## 7. Security Considerations

TODO

## 8. IANA Considerations

This document makes no IANA requests.

## 9. References

## 9.1. Normative References

<dl>

  <dt id=RFC2119>[RFC2119]<dd>

[RFC2119]: #RFC2119
Bradner, S., “Key words for use in RFCs to Indicate Requirement Levels”, BCP 14, [RFC 2119](https://www.rfc-editor.org/info/rfc2119), DOI 10.17487/RFC2119, March 1997.

  <dt id=RFC8174>[RFC8174]<dd>

[RFC8174]: #RFC8174
Leiba, B., “Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words”, BCP 14, [RFC 8174](https://www.rfc-editor.org/info/rfc8174), DOI 10.17487/RFC8174, May 2017.

  <dt id=RFC9380>[RFC9380]<dd>

[RFC9380]: #RFC9380
Faz-Hernandez, A., Scott, S., Sullivan, N., Wahby, R. S., and C. A. Wood, “Hashing to Elliptic Curves”, [RFC 9380](https://www.rfc-editor.org/info/rfc9380), DOI 10.17487/RFC9380, August 2023.

</dl>
