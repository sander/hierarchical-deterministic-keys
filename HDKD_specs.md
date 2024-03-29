# HDKD

Requirements:

* HKDF-SHA512
* HMAC
* ECDH

Let $G$ be the group generator of order $q$ of an elliptic curve $E$ defined over $GF(p)$. Denote scalar multiplication between a scalar $x$ and a point $A$ as $[x]A$.

Steps (can be performed by either party in a issuer-user pair):

1. Assume the existance of a user key pair $(u, U)$, where $u$ is a derived PoP private key, and $U$ is a derived PoP public key (i.e., a level 1 or below), and issuer key pair $(i, I)$.
  * Either key can be either static or one time use
  * The user may needs to be able to retrieve $I$ at the time of presentation
2. The issuer authenticates the user using $U$.
3. Compute shared key `sk = ECDH(i, U)` where sk is x-coordinate only. ADD SERIALIZATION. FE2OS in BSI?
4. Construct the DST using a [DST parameter](https://www.rfc-editor.org/rfc/rfc9380.html#name-domain-separation-requireme)
  * `msg = suite_identifier || sk || i2os(j)`
  * Should include mul or add, and crypto primitive identifiers
6. Let `u_j = Hash-to-field(msg, count=1)` with [_xmd](https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message).
9. Compute derived public key $U_j$ in either of the two following ways:
  * Additive: $U_j^+ = U + [u_j]G$
  * Multiplicative: $U_j^{\times} = [u_j]U$

If $I$ is ephemeral, then include it in issued attestation?
