---
title: Hierarchical Deterministic Keys for OpenID4VCI
abbrev: HDK for OpenID4VCI
category: info
docname: draft-dijkhuis-hdk-latest
submissiontype: independent
v: 3
area: Internet
keyword:
  - OpenID4VCI
  - credential binding
  - key derivation
venue:
  github: sander/hierarchical-deterministic-keys
author:
  - fullname: Sander Dijkhuis
    role: editor
    initials: S. Q.
    surname: Dijkhuis
    organization: Cleverbase
    email: mail@sanderdijkhuis.nl
contributor:
  - fullname: Micha Kraus
ipr: trust200902
normative:
  FIPS180-4:
    title: Secure Hash Standard (SHS)
    target: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
    seriesinfo:
      FIPS: 180-4
    author:
      - organization: National Institute of Standards and Technology (NIST)
    date: 2015-08
  OpenID4VCI:
    title: OpenID for Verifiable Credential Issuance 1.0
    target: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html
    author:
      - name: T. Lodderstedt
      - name: K. Yasuda
      - name: T. Looker
  RFC4648:
  RFC7748:
  RFC8017:
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography, Version 2.0"
    target: https://www.secg.org/sec1-v2.pdf
    author:
      - organization: Standards for Efficient Cryptography Group
    date: 2009-05
informative:
  ARKG:
    title: The Asynchronous Remote Key Generation (ARKG) algorithm
    target: https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-09.html
    author:
      - name: E. Lundberg
      - name: J. Bradley
  CryptoSpec:
    title: Guidelines for Writing Cryptography Specifications
    target: https://www.ietf.org/archive/id/draft-irtf-cfrg-cryptography-specification-01.html
    author:
      - name: N. Sullivan
      - name: C. A. Wood
  ETSI-TR-119-476-1:
    title: "ETSI TR 119 476-1 V1.3.1: Selective disclosure and zero-knowledge proofs applied to Electronic Attestation of Attributes; Part 1: Feasibility study"
    target: https://www.etsi.org/deliver/etsi_tr/119400_119499/11947601/01.03.01_60/tr_11947601v010301p.pdf
    author:
      - organization: ETSI
    date: 2025-08
  KeyBlinding:
    title: Key Blinding for Signature Schemes
    target: https://www.ietf.org/archive/id/draft-irtf-cfrg-signature-key-blinding-11.html
  OpenID4VP:
    title: OpenID for Verifiable Presentations 1.0
    target: https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html
  RFC7517:
--- abstract

This document defines an OpenID for Verifiable Credential Issuance (OpenID4VCI) extension for deriving unlinkable P-256 Credential keys from a parent key protected by a Wallet secure area. The Issuer derives each child public key, while only the Wallet can use the corresponding child private key.

--- middle

# Introduction

Credentials can use distinct holder-binding keys to avoid giving Relying Parties a common correlation handle. An Issuer can nevertheless need assurance that these keys remain associated with a holder-binding key whose security properties it has already accepted.

For example, an Issuer can accept a hardware-protected key when a Wallet presents a PID, then issue mDL Credentials bound to distinct child keys. The mDL keys appear unrelated to Relying Parties, while retaining their association with the accepted parent key. HDK preserves this association; it does not establish the holder's identity.

Generating and storing a separate secure-area key pair for every Credential can also be expensive or impossible. HDK instead derives many P-256 child keys from one protected parent. Child-key operations can retain the parent's protections, including user authentication.

During issuance, the Wallet and Issuer establish a shared secret using ephemeral X25519 keys. Together with the parent public key and Credential index, this determines each child key. The Issuer can derive the child public keys but not the corresponding private keys. Verifiers see ordinary P-256 keys and need no HDK support.

[ETSI-TR-119-476-1] identifies key management and Proof of Association (PoA) as challenges when issuing multiple single-use holder-binding keys in the EUDI Wallet setting. It discusses ARKG [ARKG], including HDK, for deriving such keys and related-key PoA for associating them. This document defines a concrete OpenID4VCI mechanism for that design space. See also key blinding [KeyBlinding].

A child key can itself be a parent, allowing hierarchical derivation.

This document is an early, not yet reviewed proposal. Its cryptographic notation follows [CryptoSpec].

# Conventions and Encoding

{::boilerplate bcp14-tagged}

`a || b` denotes byte-string concatenation.

OS2IP and I2OSP are the octet-string/integer conversions defined in [RFC8017].

`base64(x)` is unpadded base64url as defined in Section 5 of [RFC4648].

When a P-256 public key `pk` is used as a byte string in the algorithms below, it is encoded as the 65-byte uncompressed SEC 1 representation `0x04 || x || y` [SEC1].

# Cryptographic Dependencies

This specification uses P-256 [SEC1], SHA-256 [FIPS180-4], and X25519 [RFC7748].

The P-256 group order is:

~~~
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
~~~

`ScalarMult(pk, k)` is P-256 scalar multiplication of public key `pk` by scalar `k`.

`ECDH(sk, pk)` returns the 32-byte big-endian x-coordinate of `ScalarMult(pk, sk)`. Received P-256 public keys MUST be validated as required by [SEC1].

`GenerateX25519KeyPair()` generates a fresh X25519 private key and corresponding 32-byte public key.

`X25519(sk, pk)` is the X25519 function defined in [RFC7748]. Its 32-byte output is the shared secret. An all-zero output MUST be rejected.

# Credential Request

The Wallet has a P-256 parent key pair `(sk_parent, pk_parent)` protected by its secure area. Before the request, the Issuer MUST already have established that `pk_parent` represents the intended Credential Holder and meets its requirements for key protection and user authentication. How this is established is out of scope. For example, it can be established by a PID presentation using OpenID4VP [OpenID4VP], or by proof of possession associated with a refresh token bound to `pk_parent`.

For each request, the Wallet generates:

~~~
(sk_eph, pk_eph) = GenerateX25519KeyPair()
~~~

and sends an `hdk` proof containing:

* `parent`: the P-256 parent public key as a JWK [RFC7517]; and
* `pk_eph`: `base64(pk_eph)`.

For example:

~~~http
POST /credential HTTP/1.1
Host: issuer.example.com
Content-Type: application/json
Authorization: Bearer czZCaGRSa3F0MzpnWDFmQmF0M2JW

{
  "credential_configuration_id": "org.iso.18013.5.1.mDL",
  "proofs": {
    "hdk": [{
      "parent": {
        "kty": "EC",
        "crv": "P-256",
        "x": "<base64url x-coordinate>",
        "y": "<base64url y-coordinate>"
      },
      "pk_eph": "<base64url 32-byte X25519 public key>"
    }]
  }
}
~~~

The Wallet MUST generate a fresh `(sk_eph, pk_eph)` for each request and retain `sk_eph` until it processes the response.

# Credential Response

The Issuer generates:

~~~
(sk_eph_issuer, pk_eph_issuer) = GenerateX25519KeyPair()
shared_secret = X25519(sk_eph_issuer, pk_eph)
~~~

If `shared_secret` is all zero, the Issuer MUST reject the request.

The Issuer returns `base64(pk_eph_issuer)` once in the `hdk` response parameter:

~~~http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "hdk": {
    "pk_eph": "<base64url 32-byte X25519 public key>"
  },
  "credentials": [
    { "credential": "<base64url encoded Credential 0>" },
    { "credential": "<base64url encoded Credential 1>" },
    { "credential": "<base64url encoded Credential 2>" }
  ]
}
~~~

Credential position is its zero-based HDK index. The Issuer MUST bind Credential `i` to the child public key for index `i`. A response MUST NOT contain more than `2^32` Credentials.

The Wallet computes:

~~~
shared_secret = X25519(sk_eph, pk_eph_issuer)
~~~

If `shared_secret` is all zero, the Wallet MUST reject the response.

# Child-Key Derivation

Define:

~~~
H(msg) = (OS2IP(SHA-256(msg)) mod (n - 1)) + 1

BlindPK(pk, bk, ctx) = ScalarMult(pk, H(bk || ctx))
BlindSK(sk, bk, ctx) = sk * H(bk || ctx) mod n
~~~

This is multiplicative key blinding, as used for ECDSA in [KeyBlinding]. Its use here for remote child-key derivation serves a role related to ARKG [ARKG], whose `ARKG-P256` instance instead uses additive blinding.

`H` returns an integer in `1..n-1`. The small statistical bias from reduction modulo `n - 1` is accepted for simplicity.

For Credential `i`, where `0 <= i <= 0xffffffff`:

~~~
index = I2OSP(i, 4)
ctx = pk_parent || index

sk_child = BlindSK(sk_parent, shared_secret, ctx)
pk_child = BlindPK(pk_parent, shared_secret, ctx)
~~~

Because the blinding factor and `sk_parent` are non-zero modulo the prime `n`, `sk_child` is non-zero.

## Hierarchical Derivation

A child key pair MAY itself be used as a parent. For successive blinding factors `b1` and `b2`:

~~~
pk_child2 = ScalarMult(pk_parent, b1 * b2 mod n)
sk_child2 = sk_parent * b1 * b2 mod n
~~~

# Using a Child Key

Child-key operations SHOULD receive protections equivalent to parent-key operations, including the same user-authentication policy. A secure area can derive `sk_child` internally, or use the equivalences below while continuing to operate with `sk_parent`.

## ECDH

For the blinding factor `b` of a child:

~~~
ECDH(sk_child, pk) = ECDH(sk_parent, ScalarMult(pk, b))
~~~

This allows `b` to be applied outside the secure area while the protected ECDH operation still uses `sk_parent`. `pk` MUST be validated before scalar multiplication; the result MUST also be validated if required by the ECDH interface.

## ECDSA

A secure area can derive the child and sign directly:

~~~
sk_child = BlindSK(sk_parent, shared_secret, ctx)
signature = SHA256withECDSA(sk_child, msg)
~~~

Alternatively, for the blinding factor `b` of the child, let:

~~~
z = OS2IP(SHA-256(msg))
~~~

Then `SHA256withECDSA(sk_child, msg)` is equivalent to `(r, s * b mod n)`, where:

~~~
(r, s) = NONEwithECDSA(
    sk_parent,
    I2OSP(z * b^-1 mod n, 32))
~~~

`b^-1` is the inverse of `b` modulo `n`. `NONEwithECDSA` means ECDSA over the supplied 32-byte representative without hashing it again. Implementations MUST verify that their API has exactly this behavior.

The resulting `(r, s * b mod n)` is an ordinary ECDSA signature under `pk_child` for `msg`.

This ECDSA construction may be covered by patent claims in some jurisdictions or implementations. This document makes no determination about their validity or applicability. Deriving `sk_child` inside the secure area and signing with it is an alternative architecture and can have a different intellectual-property analysis.

# OpenID4VCI Metadata

Support is advertised with the `hdk` proof type in `proof_types_supported` [OpenID4VCI]:

~~~json
{
  "credential_configurations_supported": {
    "org.iso.18013.5.1.mDL": {
      "format": "mso_mdoc",
      "doctype": "org.iso.18013.5.1.mDL",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "hdk": {}
      }
    }
  }
}
~~~

Implementations MUST NOT infer HDK support merely from P-256 support.

# Design Considerations

The derivation in this document is not interoperable with either `ARKG-P256` [ARKG] or the ECDSA construction in [KeyBlinding].

`ARKG-P256` uses additive blinding, P-256 ECDH, and ARKG-specific seed and key-handle structures. This document uses multiplicative blinding and an ephemeral X25519 exchange directly in OpenID4VCI. The simpler construction avoids introducing ARKG key representations and key handles, and the multiplicative relation also permits the ECDH and ECDSA child-key equivalences above while the secure area continues to operate with the parent key.

The ECDSA construction in [KeyBlinding] uses the same multiplicative relation between parent and blinded keys, but derives the blinding scalar differently. It uses a separately generated private blinding key, domain separation, and `hash_to_field`; this document uses the X25519 `shared_secret` as `bk`, the parent public key and Credential index as `ctx`, and the compact `H` function above. Consequently, implementations of the two constructions will not derive the same keys from nominally corresponding inputs.

These deviations are intentional: HDK needs one high-entropy per-request secret from which both parties can deterministically derive a batch of child keys, and it applies the same child-key relation to ECDH as well as ECDSA. They should not be interpreted as inheriting interoperability or security analysis from either referenced construction.

# Security Considerations

HDK relies on the Issuer having already accepted `pk_parent`, including its holder binding, key protection, and user-authentication properties. It preserves that association for child keys; it does not establish it.

The security guarantee remains rooted in `sk_parent`. Disclosure of `shared_secret` does not reveal `sk_parent` or by itself enable child-key operations, but it reveals the relationship between `pk_parent` and its child public keys. Implementations SHOULD therefore protect and erase it when no longer needed.

Both parties MUST use fresh ephemeral X25519 key pairs for each request.

Compromise of both `sk_parent` and an issuance `shared_secret` permits reconstruction of every child private key from that response.

The biased `H` construction is intentional. Replacing it with an unbiased construction would not be wire-compatible and requires a new algorithm identifier or protocol version.

See the ECDSA section for intellectual-property considerations.

# Privacy Considerations

Distinct child public keys prevent correlation merely through reuse of the holder-binding public key. Other Credential contents, protocol metadata, network identifiers, or application behavior can still enable correlation.

The Issuer knows `pk_parent` and derives all child public keys, so HDK does not provide unlinkability from the Issuer. `shared_secret` is privacy-sensitive because it reveals these relationships.

--- back

# Acknowledgements
{:numbered="false"}

Helpful ideas and feedback came from Peter Lee Altmann, Micha Kraus, Emil Lundberg, John Bradley, and Remco Schaar.

ChatGPT was used to sketch the not yet reviewed rewrite in this version of the draft.
