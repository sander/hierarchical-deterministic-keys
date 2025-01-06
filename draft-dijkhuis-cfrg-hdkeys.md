---
title: Hierarchical Deterministic Keys
abbrev: HDK
category: info
docname: draft-dijkhuis-cfrg-hdkeys-latest
submissiontype: independent
v: 3
area: IRTF
workgroup: Crypto Forum
keyword:
    - KDF
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
            DOI: 10.6028/NIST.FIPS.180-4
        author:
            - organization: National Institute of Standards and Technology (NIST)
        date: 2012-06
    ISO18013-5:
        title: "Personal identification - ISO-compliant driving licence - Part 5: Mobile driving licence (mDL) application"
        target: https://www.iso.org/standard/69084.html
        seriesinfo:
            ISO/IEC: 18013-5:2021
        author:
            - organization: ISO/IEC
        date: 2019-09
    RFC8017:
    RFC9180:
    RFC9380:
    RFC9497:
    SEC2:
        title: "SEC 2: Recommended Elliptic Curve Domain Parameters, Version 2.0"
        target: https://www.secg.org/sec2-v2.pdf
        seriesinfo:
            SEC: 2 Version 2.0
        author:
            - organization: Certicom Research
        date: 2010-01
    TR03111:
        title: Elliptic Curve Cryptography
        target: https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03111/tr-03111.html
        seriesinfo:
            BSI: TR-03111 Version 2.10
        author:
            - organization: Federal Office for Information Security (BSI)
        date: 2018-06
informative:
    BIP32:
        title: Hierarchical Deterministic Wallets
        target: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        seriesinfo:
            BIP: 32
        author:
            - name: Pieter Wuille
        date: 2021-02
    draft-OpenID4VCI:
        title: OpenID for Verifiable Credential Issuance, draft 13
        target: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
        author:
            - name: T. Lodderstedt
            - name: K. Yasuda
            - name: T. Looker
        date: 2024-02-08
    EU2015-1502:
        title: Commission Implementing Regulation (EU) 2015/1502 of 8 September 2015 on setting out minimum technical specifications and procedures for assurance levels for electronic identification means
        target: https://eur-lex.europa.eu/legal-content/TXT/?uri=CELEX%3A32015R1502
        author:
            - organization: European Commission
        seriesinfo:
            (EU): 2015/1502
        date: 2025-09
    EU2024-1183:
        title: Amending Regulation (EU) No 910/2014 as regards establishing the European Digital Identity Framework
        target: https://data.europa.eu/eli/reg/2024/1183/oj
        author:
            - organization: The European Parliament and the Council of the European Union
        seriesinfo:
            (EU): 2024/1183
        date: 2024-04
    I-D.draft-bradleylundberg-cfrg-arkg-02:
    I-D.draft-irtf-cfrg-signature-key-blinding-07:
    RFC7800:
    RFC8235:
    Verheul2024:
        title: Attestation Proof of Association – provability that attestation keys are bound to the same hardware and person
        target: https://eprint.iacr.org/2024/1444
        author:
            - name: E. Verheul
        date: 2024-09-18
    Wilson2023:
        title: Post-Quantum Account Recovery for Passwordless Authentication. Master’s thesis
        target: https://hdl.handle.net/10012/19316
        author:
            - name: Spencer MacLaren Wilson
        date: 2023-04-24

--- abstract

Hierarchical Deterministic Keys enables managing large sets of keys bound to a secure cryptographic device that protects a single key. This enables the development of secure digital identity wallets providing many one-time-use public keys. Some instantiations can be implemented in such a way that the secure cryptographic device does not need to support key blinding, enabling the use of devices that already are widely deployed.

--- middle

# Introduction

This document specifies the algorithms to apply Hierarchical Deterministic Keys (HDKeys). The purpose of an HDK architecture is to manage large sets of keys bound to a secure cryptographic device that protects a single key. This enables the development of secure digital identity wallets providing many one-time-use public keys.

The core idea has been introduced in [BIP32] to create multiple cryptocurrency addresses in a manageable way. The present document extends the idea towards devices commonly used for digital wallets, and towards common interaction patterns for document issuance and authentication.

To store many HDKeys, only a seed string needs to be stored confidentially, associated with a device private key. Each HDK is then deterministically defined by a path of indices, optionally alternated by key handles provided by another party. Such a path can efficiently be stored and requires less confidentiality than the seed.

To prove possession of many HDKeys, the secure cryptographic device only needs to perform common cryptographic operations on a single private key. The HDK acts as a blinding factor that enables blinding the device public key. In several instantiations, such as those [using ECDH shared secrets](#using-ecdh-shared-secrets) and those [using EC-SDSA signatures](#using-ec-sdsa-signatures), the secure cryptographic device does not need to support key blinding natively, and the application can pre-process the input or post-process the output from the device to compute the blinded device authentication data. This enables the application of HDK on devices that are already deployed without native support for HDK.

This document provides a specification of the generic HDK function, generic HDK instantiations, and fully specified concrete HDK instantiations.

An HDK instantiation is expected to be applied in a solution deployed as (wallet) units. One unit can have multiple HDK instantiations, for example to manage multiple identities or multiple cryptographic algorithms or key protection mechanisms.

This document represents the consensus of the authors, based on working group input and feedback. It is not a standard. It does not include security or privacy proofs.

## Conventions and definitions

{::boilerplate bcp14-tagged}

The following notation is used throughout the document.

- byte: A sequence of eight bits.
- `I2OSP(n, w)`: Convert non-negative integer `n` to a `w`-length, big-endian byte string, as described in [RFC8017].

# The Hierarchical Deterministic Key function

An HDK instantiation enables local key derivation to create many key pairs from a single seed value. It enables remote parties to generate key handles from which both parties can derive more key pairs asynchronously. Additionally, an HDK instantiation enables securely proving possession of the private keys, such as required in [RFC7800], either in a centralised or in a distributed manner.

Solutions MAY omit application of the remote functionality. In this case, a unit can only derive keys locally.

## Introductory examples

### Local deterministic key derivation

The following example illustrates the use of local key derivation. An HDK tree is associated with a device key pair and initiated using confidential static data: a `seed` value, which is a byte array containing sufficient entropy. Now tree nodes are constructed as follows.

~~~
                          +----+ +--+
Confidential static data: |seed| |pk|
                          +-+--+ +--+
                            v
                          +----+ +----+
Level 0 HDKeys:           |hdk0| |hdk1|
                          +-+--+ +----+
                            v
                          +-----+ +-----+ +-----+
Level 1 HDKeys:           |hdk00| |hdk01| |hdk02|
                          +-----+ ++---++ +-----+
                                   v   v
                             +------+ +------+
Level 2 HDKeys at hdk01:     |hdk000| |hdk001| ...
                             +------+ +------+
~~~

The unit computes a Level 0 HDK at the root node using a deterministic function, taking the device public key `pk` and the `seed` as input: `(pk0, salt0, bf0) = hdk0 = HDK(0, pk, seed)`. The HDK consists of a first blinded public key `pk0`, a first byte string `salt0` to derive next-level keys, and a first blinding factor `bf0`. Using `bf0` and the device key pair, the unit can compute blinded private keys and proofs of possession.

The unit computes any Level `n > 0` HDK from any other HDK `(pk, salt, bf)` using the same deterministic function: `(pk', salt', bf') = hdk' = HDK(index, pk, salt, bf)`. The function takes as input the `index` starting at 0, an the previous-level HDK. The function returns a new HDK as output, which can be used in the same way as the root HDK.

### Remote deterministic key derivation

Instead of local derivation, an HDK salt can also be derived using a key handle that is generated remotely. Using the derived salt, the local and remote parties can derive the same new HDKeys. The remote party can use these to derive public keys. The local party can use these to derive associated private keys for proof of possession.

This approach is similar to Asynchronous Remote Key Generation (ARKG) [I-D.draft-bradleylundberg-cfrg-arkg-02] when considered at a single level. However, ARKG does not enable distributed proof of possession with deterministic hierarchies. Such hierarchies can be used for example to enable remote parties to derive keys from previously derived keys. Secure cryptographic devices that support ARKG may therefore not support all features of HDK.

To enable remote derivation of child HDKeys, the unit uses the parent HDK to derive the parent public key and a second public key for key encapsulation. The issuer returns a key handle, using which both parties can derive a sequence of child HDKeys. Key encapsulation prevents other parties from discovering a link between the public keys of the parent and the children, even if the other party knows the parent HDK or can eavesdrop communications.

Locally derived parents can have remotely derived children. Remotely derived parents can have locally derived children.

### Blinded proof of possession

The next concept to illustrate is blinded proof of possession. This enables a unit to prove possession of a (device) private key without disclosing the directly associated public key. This way, solutions can avoid linkability across readers of a digital document that is released with proof of possession.

In this example, a document is issued with binding to a public key `pk'`, which is a blinding public key `pk` blinded with the blinding factor `bf` in some HDK `hdk = (pk', salt, bf)`. The unit can present the document with a proof of possession of the corresponding blinded private key, which is the blinding private key `sk` blinded with `bf`. The unit applies some authentication function `device_data = authenticate(sk, reader_data, bf)` to the blinding private key, reader-provided data and the blinding factor. The unit can subsequently use the output `device_data` to prove possession to the reader using common algorithms.

~~~
+------------------+ +--------+
|       +--+ +---+ | |        |
| Unit  |sk| |hdk| | | Reader |
|       +--+ +---+ | |        |
+---+--------------+ +----+---+
    |                     |
    |                     |
    |  1. Request and     |
    |     reader_data     |
    | <------------------ |
    |                     |
+---+-------------+       |
| 2. authenticate |       |
+---+-------------+       |
    |                     |
    |  3. Proof with      |
    |     device_data     |
    | ------------------> |
    |                     |
    |    +-----------+    |
    |    | Document  |    |
    |    |           |    |
    |    | +---+     |    |
    |    | |pk'|     |    |
    |    | +---+     |    |
    |    |           |    |
         +-----------+
~~~

The reader does not need to be aware that an HDK function or key blinding was used, since for common algorithms, the blinded public key and the proof are indistinguishable from non-blinded keys and proofs.

When applied on HDK level `n`, the blinding private key `sk` is the device private key blinded with a combination of `n` blinding factors. These can either be combined within the secure cryptographic device, by subsequent computation of the blinded private key starting with the device private key, or outside of the secure cryptographic device, by combining the blinding factors outside of the secure cryptographic device.

Blinding methods can be constructed such that the secure cryptographic device does not need to be designed for key blinding. In such cases, the computation of `device_data` is distributed between two parties: the secure cryptographic device using common cryptographic operations, and the unit component invoking these operations. Some blinded proof of possession algorithms can only be centralised.

## Instantiation parameters

The parameters of an HDK instantiation are:

- `Ns`: The amount of bytes of a salt value with sufficient entropy.
- `H`: A cryptographic hash function.
  - H(msg): Outputs `Ns` bytes.
- `BL`: A key blinding scheme [Wilson2023] with opaque blinding factors and algebraic properties, consisting of the functions:
  - DeriveBlindKey(ikm): Outputs a blind key `bk` based on input keying material `ikm`.
  - DeriveBlindingFactor(bk, ctx): Outputs a blinding factor `bf` based on a blind key `bk` and an application context byte string `ctx`.
  - BlindPublicKey(pk, bk, ctx): Outputs the result public key `pk'` of blinding public key `pk` with blind key `bk` and application context byte string `ctx`.
  - BlindPrivateKey(sk, bf): Outputs the result private key `sk'` of blinding private key `sk` with blinding factor `bf`. This result `sk'` is such that if `bf = DeriveBlindingFactor(bk, ctx)` for some `bk` and `ctx`, `(sk', pk')` forms a key pair for `pk' = BlindPublicKey(pk, bk, ctx)`.
  - Combine(bf1, bf2): Outputs a blinding factor `bf` such that for all key pairs `(sk, pk)`:

    ~~~
    BlindPrivateKey(sk, bf) ==
        BlindPrivateKey(BlindPrivateKey(sk, bf1), bf2)
    ~~~

- `KEM`: A key encapsulation mechanism [RFC9180], consisting of the functions:
    - DeriveKeyPair(ikm): Outputs a key encapsulation key pair `(sk, pk)`.
    - Encap(pk): Outputs `(k, c)` consisting of a shared secret `k` and a ciphertext `c`, taking key encapsulation public key `pk`.
    - Decap(c, sk): Outputs shared secret `k`, taking ciphertext `c` and key encapsulation private key `sk`.

An HDK instantiation MUST specify the instantiation of each of the above functions and values.

Note that by design of BL, when a document is issued using HDK, the reader does not need to know that HDK was applied: the public key will look like any other public key used for proofs of possession.

An HDK implementation MAY leave BlindPrivateKey implicit in cases where the blinding method is constructed in a distributed way. In those cases, the secure cryptographic device holding the private key does not need to support key blinding, and the value of the blinded private key is never available during computation.

## The HDK context

A local unit or remote party creates an HDK context from an index.

~~~
Inputs:
- index, an integer between 0 and 2^32-1 (inclusive).

Outputs:
- ctx, an application context byte string.

def CreateContext(index):
    ctx = ID || I2OSP(index, 4)
    return ctx
~~~

This context byte string is used as input for DeriveBlindingFactor, BlindPublicKey, and [DeriveSalt](#the-hdk-salt).

## The HDK salt

A local unit or remote party derives a next-level HDK salt from within an HDK context.

~~~
Inputs:
- salt, a string of Ns bytes.
- ctx, an HDK context byte string.

Outputs:
- salt', the next salt for HDK derivation.

def DeriveSalt(salt, ctx):
    salt' = H(salt || ctx)
    return salt'
~~~

Salt values are used as input for DeriveBlindKey, DeriveKeyPair, and DeriveSalt.

Salt values, including the original seed value, MUST NOT be reused outside of HDK.

## The HDK function

A local unit or a remote party deterministically computes an HDK from an index, a parent public key, a salt, and an optional parent blinding factor. The salt can be an initial seed value of `Ns` bytes or it can be taken from another parent HDK. The secure generation of the seed is out of scope for this specification.

~~~
Inputs:
- index, an integer between 0 and 2^32-1 (inclusive).
- pk, a public key to be blinded.
- salt, a string of Ns bytes.
- bf, a blinding factor to combine with, Nil otherwise.

Outputs:
- pk', the blinded public key at the provided index.
- salt', the salt for HDK derivation at the provided index.
- bf', the blinding factor at the provided index.

def HDK(index, pk, salt, bf = Nil):
    ctx   = CreateContext(index)
    salt' = DeriveSalt(salt, ctx)

    bk  = DeriveBlindKey(salt)
    pk' = BlindPublicKey(bk, ctx)
    bf' = if bf == Nil:
        DeriveBlindingFactor(bk, ctx)
    else:
        Combine(bf, DeriveBlindingFactor(bk, ctx))

    return (pk', salt', bf')
~~~

A unit MUST NOT persist a blinded private key. Instead, if persistence is needed, a unit can persist either the blinding factor of each HDK, or a path consisting of the seed salt, indices and key handles. In both cases, the application of Combine in the HDK function enables reconstruction of the blinding factor with respect to the original private key, enabling application of for example BlindPrivateKey.

If the unit uses the blinded private key directly, the unit MUST use it within the secure cryptographic device protecting the device private key.

If the unit uses the blinded private key directly, the unit MUST ensure the secure cryptographic device deletes it securely from memory after usage.

When presenting multiple documents, a reader can require a proof that multiple keys are associated to a single device. Several protocols for a cryptographic proof of association are possible, such as [Verheul2024]. For example, a unit could prove in a zero-knowledge protocol knowledge of the association between two elliptic curve keys `B1 = [bf1]D` and `B2 = [bf2]D`, where `bf1` and `bf2` are multiplicative blinding factors for a common blinding public key `D`. In this protocol, the association is known by the discrete logarithm of `B2 = [bf2/bf1]B1` with respect to generator `B1`. The unit can apply Combine to obtain values to compute this association.

## The local HDK procedure

This is a procedure executed locally by a unit.

To begin, the unit securely generates a `seed` salt of `Ns` bytes and a device key pair:

~~~
seed = random(Ns) # specification of random out of scope
(skD, pkD) = GenerateKeyPair()
~~~

The unit MUST generate `skD` within a secure cryptographic device.

Whenever the unit requires the HDK with some `index` at level 0, the unit computes:

~~~
(pk, salt, bf) = HDK(index, pkD, seed)

sk = BlindPrivateKey(skD, bf) # optional
~~~

Now the unit can use the blinded key pair `(sk, pk)` or derive child HDKeys.

Whenever the unit requires the HDK with some `index` at level `n > 0` based on a parent HDK `hdk = (pk, salt, bf)` with blinded key pair `(sk, pk)` at level `n`, the unit computes:

~~~
(pk', salt', bf') = HDK(index, pk, salt)

sk' = BlindPrivateKey(sk, bf') # optional
~~~

Now the unit can use the blinded key pair `(sk', pk')` or derive child HDKeys.

## The remote HDK protocol

This is a protocol between a local unit and a remote issuer.

As a prerequisite, the unit possesses a `salt` of `Ns` bytes associated with a parent key pair `(sk, pk)` generated using the local HDK procedure.

~~~
# 1. Unit computes:
(skR, pkR) = DeriveKeyPair(salt)

# 2. Unit shares with issuer: (pk, pkR)

# 3. Issuer computes:
(salt_kem, kh) = Encap(pkR)

# 4. Issuer shares with unit: kh

# Subsequently, for any index known to both parties:

# 5. Issuer computes:
(pk', salt', bf') = HDK(index, pk, salt_kem)

# 6. Issuer shares with unit: pk'

# 7. Unit verifies integrity:
salt_kem = Decap(kh, skR)
(pk_expected', salt', bf') = HDK(index, pk, salt_kem)
pk' == pk_expected'

# 8. Unit computes:
sk' = BlindPrivateKey(sk, bf) # optional
~~~

After step 7, the unit can use the value of `salt'` to derive next-level HDKeys.

Step 4 MAY be postponed to be combined with step 6. Steps 5 to 8 MAY be combined in concurrent execution for multiple indices.

# Generic HDK instantiations

## Using digital signatures

Instantiations of HDK using digital signatures require the following cryptographic constructs:

- `DSA`: A digital signature algorithm, consisting of the functions:
  - GenerateKeyPair(): Outputs a new key pair `(sk, pk)` consisting of private key `sk` and public key `pk`.
  - Sign(sk, msg): Outputs the signature created using private signing key `sk` over byte string `msg`.
  - Verify(signature, pk, msg): Outputs whether `signature` is a signature over `msg` using public verification key `pk`.

Using these constructs, an example proof of possession protocol is:

~~~
# 1. Unit shares with reader: pk

# 2. Reader computes:
nonce = generate_random_nonce() # out of scope for this spec

# 3. Reader shares with unit: nonce

# 4. Unit computes:
msg = create_message(pk, nonce) # out of scope for this spec
signature = Sign(sk, msg)

# 5. Reader computes:
msg = create_message(pk, nonce) # out of scope for this spec
Verify(signature, pk, msg)
~~~

Instantiations of HDK using digital signatures instantiat the following:

- `BL`: A cryptographic construct that extends `DSA` as specified in [I-D.draft-irtf-cfrg-signature-key-blinding-07], implementing the interface from [Instantiation parameters](#instantiation-parameters).

While [I-D.draft-irtf-cfrg-signature-key-blinding-07] does not expose blinding factors, it provides public algorithms to compute these. In HDK, the computed blinding factors are applied in `BL` as follows:

~~~
def BlindSign(sk, bf, msg):
    sk' = BlindPrivateKey(sk, bf)
    signature = Sign(sk', msg)
    return signature
~~~

By design of `BL`, the same proof of possession protocol can be used with blinded key pairs and BlindSign, in such a way that the reader does not recognise that key blinding was used.

In the default implementation, BlindSign requires support from the secure cryptographic device protecting `sk`. In some cases, BlindSign can be implemented in an alternative, distributed way. An example will be provided below.

Applications MUST bind the message to be signed to the blinded public key. This mitigates attacks based on signature malleability. Several proof of possession protocols require including document data in the message, which includes the blinded public key indeed.

## Using prime-order groups

Instantiations of HDK using prime-order groups require the following cryptographic constructs:

- `G`: A prime-order group as defined in [RFC9497] with elements of type Element and scalars of type Scalar, consisting of the functions:
  - RandomScalar(): Outputs a random Scalar `k`.
  - Add(A, B): Outputs the sum between Elements `A` and `B`.
  - ScalarMult(A, k): Outputs the scalar multiplication between Element `A` and Scalar `k`.
  - ScalarBaseMult(k): Outputs the scalar multiplication between the base Element and Scalar `k`.
  - Order(): Outputs the order of the base Element.
  - SerializeElement(A): Outputs a byte string representing Element `A`.
  - SerializeScalar(k): Outputs a byte string representing Scalar `k`.`
  - HashToScalar(msg): Outputs the result of deterministically mapping a byte string `msg` to an element in the scalar field of the prime order subgroup of `G`, using the `hash_to_field` function from a hash-to-curve suite [RFC9380].

~~~
def GenerateKeyPair():
    sk = GenerateRandomScalar()
    pk = ScalarBaseMult(sk)
    return (sk, pk)

def DeriveBlindKey(ikm):
    bk_scalar = HashToScalar(ikm)
    bk = SerializeScalar(bk_scalar)
    return bk

def DeriveBlindingFactor(bk, ctx):
    msg = bk || 0x00 || ctx
    bf = HashToScalar(msg)
    return bf
~~~

Note that DeriveBlindingFactor is compatible with the definitions in [I-D.draft-irtf-cfrg-signature-key-blinding-07].

## Using multiplicative blinding

Such instantations of HDK [use prime-order groups](#using-prime-order-groups) and instantiate the following:

~~~
def BlindPublicKey(pk, bk, ctx):
    bf = DeriveBlindingFactor(bk, ctx)
    pk' = ScalarMult(pk, bf)
    return pk

def BlindPrivateKey(sk, bf):
    sk' = sk * bf mod Order()
    return sk

def Combine(bf1, bf2):
    bf = bf1 * bf2 mod Order()
    return bf
~~~

## Using additive blinding

Such instantations of HDK use [use prime-order groups](#using-prime-order-groups) and instantiate the following:

~~~
def BlindPublicKey(pk, bk, ctx):
    bf = DeriveBlindingFactor(bk, ctx)
    pk' = Add(pk, ScalarBaseMult(bf))
    return pk

def BlindPrivateKey(sk, bf):
    sk' = sk + bf mod Order()
    return sk

def Combine(bf1, bf2):
    bf = bf1 + bf2 mod Order()
    return bf
~~~

## Using ECDH shared secrets

Such instantiations of HDK [use multiplicative blinding](#using-multiplicative-blinding) and require the following cryptographic construct:

- `DH`: An Elliptic Curve Key Agreement Algorithm - Diffie-Hellman (ECKA-DH) [TR03111] with elliptic curve `EC`, consisting of the functions:
  - CreateSharedSecret(skX, pkY): Outputs a shared secret byte string `Z_AB` representing the x-coordinate of the Element `ScalarMult(pkY, skX)`.

Note that DH enables an alternative way of authenticating a key pair `(sk, pk)` without creation or verification of a signature:

~~~
# 1. Unit shares with reader: pk

# 2. Reader computes:
(skR, pkR) = GenerateKeyPair()

# 3. Reader shares with unit: pkR

# 4. Unit computes:
Z_AB = CreateSharedSecret(sk, pkR)

# 5. Reader computes:
Z_AB = CreateSharedSecret(skR, pk)
~~~

Now with the shared secret `Z_AB`, the unit and the reader can compute a secret shared key. The unit can convince the reader that it possesses `sk` for example by sharing a message authentication code created using this key. The reader can verify this by recomputing the code using its value of `Z_AB`. This is for example used in ECDH-MAC authentication defined in [ISO18013-5].

In this example, step 1 can be postponed in the interactions between the unit and the reader if a trustworthy earlier commitment to `pk` is available, for example in a sealed document.

Similarly, ECDH enables authentication of key pair `(sk', pk')` blinded from an original key pair `(sk, pk)` using a blinding factor `bf` such that:

~~~
sk' = BlindPrivateKey(sk, bf)
    = sk * bf mod Order()
pk' = ScalarMult(pk, bf)
~~~

In this case, the computation in step 4 can be performed as such:

~~~
# 4. Unit computes:
Z_AB = CreateSharedSecret(sk', pkR)
     = CreateSharedSecret(sk * bf mod Order(), pkR)
     = CreateSharedSecret(sk, ScalarMult(pkR, bf))
~~~

Note that the value of `ScalarMult(pkR, bf)` does not need to be computed within the secure cryptographic device that protects `sk`.

## Using EC-SDSA signatures

Such instantiations of HDK [use digital signatures](#using-digital-signatures) and [use additive blinding](#using-additive-blinding) and instantiate the following:

- `DSA`: An EC-SDSA (Schnorr) digital signature algorithm [TR03111], representing signatures as pairs `(c, s)`.

Note that in this case, the following definition is equivalent to the original definition of BlindSign:

~~~
def BlindSign(sk, bf, msg):
    # Compute signature within the secure cryptographic device.
    (c, s) = Sign(sk, msg)

    # Post-process the signature outside of this device.
    s' = s + c * bf mod Order()

    signature = (c, s')
    return signature
~~~

## Using P-256

Such instantiations of HDK [use prime-order groups](#using-prime-order-groups) and require the following parameter:

- `DST`: A domain separation tag for use with HashToScalar.

Such instantiations instantiate the following:

- `Ns`: 32
- `H`: SHA-256 [FIPS180-4].
- `G`: The NIST curve `secp256r1` (P-256) [SEC2] with:
  - `HashToScalar(msg)`: Implemented by computing `hash_to_field(msg, 1)` with the parameters:
    - `DST`: `DST`
    - `F`: GF(EC-Order()), the scalar field of the prime order subgroup of `G`
    - `p`: EC-Order()
    - `m`: 1
    - `L`: 48
    - `expand_message`: `expand_message_xmd` with `H`
- `KEM`: DHKEM(P-256, HKDF-SHA256) [RFC9180].

# Concrete HDK instantiations

The RECOMMENDED instantiation is the HDK-ECDH-P256. This avoids the risk of having the holder unknowingly producing a potentially non-repudiable signature over reader-provided data. Secure cryptographic devices that enable a high level of assurance typically support managing ECDH keys with the P-256 elliptic curve.

## HDK-ECDH-P256

This instantiation [uses P-256](#using-p-256) and [uses ECDH shared secrets](#using-ecdh-shared-secrets).

- `DST`: `"ECDH Key Blind"`
- `DH`: ECKA-DH with curve `EC`.

## HDK-ECDSA-P256

This instantiation [uses P-256](#using-p-256) and [uses digital signatures](#using-digital-signatures).

- `DST`: `"ECDSA Key Blind"` as specified in [I-D.draft-irtf-cfrg-signature-key-blinding-07].
- `DSA`: ECDSA [TR03111] with curve `G`.

## HDK-ECSDSA-P256

This instantiation [uses P-256](#using-p-256) and [uses EC-SDSA signatures](#using-ec-sdsa-signatures).

- `DST`: `"EC-SDSA Key Blind"`
- `DSA`: EC-SDSA-opt (the optimised EC-SDSA) with curve `G`.

# Application considerations

## Secure cryptographic device

The HDK approach assumes that the holder controls a secure cryptographic device that protects the device key pair `(sk_device, pk_device)`. The device key is under sole control of the holder.

In the context of [EU2024-1183], this device is typically called a Wallet Secure Cryptographic Device (WSCD), running a personalised Wallet Secure Cryptographic Application (WSCA) that exposes a Secure Cryptographic Interface (SCI) to a Wallet Instance (WI) running on a User Device (UD). The WSCD is certified to protect access to the device private key with high attack potential resistance to achieve high level of assurance authentication as per [EU2015-1502]. This typically means that the key is associated with a strong possession factor and with a rate-limited Personal Identification Number (PIN) check as a knowledge factor, and the verification of both factors actively involve the WSCD.

An example deployment of HDK in this context is illustrated below.

~~~
+---------------------+          +----------------------+
|Issuer infrastructure|          |User Device (UD)      |
|                     |          |                      |
|+-------------------+|OpenID4VCI|+--------------------+|
||Issuer service     |<----------++Wallet Instance (WI)||
||                   ||          |++-------------------+|
||Optionally an      ||          +-+--------------------+
||ARKG subordinate   ||            |Secure
||party              ||            |Cryptographic
|+-------------------+|            |Interface (SCI)
+---------------------+           +v-------------------+
                                  |Wallet Secure       |
                                  |Cryptographic       |
          Internal     Manages    |Application (WSCA)  |
          registry    <-----------+                    |
                                  |Optionally an       |
                                  |ARKG delegating     |
                                  |party               |
                                  ++-------------------+
                                   |Uses
                                  +v-------------------+
                       Protects   |Wallet secure       |
          Device keys <-----------+cryptographic       |
                                  |device (WSCD)       |
                                  +--------------------+
~~~

The WSCA could be a single program or could be deployed in a distributed architecture, as illustrated below.

~~~
+--------------+
|User device   |
|+------------+|
||WI          ||
|++-----------+|
| |SCI         |
|+v-----------+|
||WSCA agent  ||
|++-----------+|
+-+------------+
  |WSCA protocol
 +v-----------+
 |WSCA service|
 +------------+
~~~

In the case of a distributed WSCA, the UD contains a local component, here called WSCA agent, accessing an external and possibly remote WSCA service from one or more components over a WSCA protocol. For example, the WSCA agent may be a local web API client and the WSCA service may be provided at a remote web API server. In such cases, typically the WSCA service receives a high-assurance security evaluation, while the WSCA agent is assessed to not be able to compromise the system's security guarantees.

The internal registry can be managed by the WSCA agent, by the WSCA service, or by the combination. When the user device is a natural person’s mobile phone, WSCA agent management could provide better confidentiality protection against compromised WSCA service providers. When the user device is a cloud server used by a legal person, and the legal person deploys its own WSCD, WSCA service management could provide better confidentiality protection against compromised Wallet Instance cloud providers.

In a distributed WSCA architecture, the WSCA could internally apply distributed key generation. A description of this is out of scope for the current document.

The solution proposal discussed herein works in all any WSCD architecture that supports the required cryptographic primitives:

- In the case of HDK-ECDH-P256 (see [HDK-ECDH-P256](#hdk-ecdh-p256)):
  - P-256 ECDH key pair generation
  - P-256 ECDH key agreement
- In the case of HDK-ECDSA-P256 (see [HDK-ECDSA-P256](#hdk-ecdsa-p256)):
  - P-256 ECDSA blinding key pair generation
  - P-256 ECDSA blinded signature creation
- In the case of HDK-ECSDSA-P256 (see [HDK-ECSDSA-P256](#hdk-ecsdsa-p256)):
  - P-256 EC-SDSA key pair generation
  - P-256 EC-SDSA signature creation

The other HDK operations can be performed in a WSCA or WSCA agent running on any UD, including hostile ones with limited sandboxing capabilities, such as in a smartphone's rich execution environment or in a personal computer web browser.

## Trust evidence

Some issuers could require evidence from a solution provider of the security of the holder's cryptographic device. This evidence can in the context of [EU2024-1183] be divided into initial "Wallet Trust Evidence" and related "Issuer Trust Evidence". Each is a protected document that contains a trust evidence public key associated with a private key that is protected in the secure cryptographic device. With HDK, these public keys are specified as follows.

### Wallet Trust Evidence

The Wallet Trust Evidence public key is the first level 0 HDK public key. To achieve reader unlinkability, the wallet SHOULD limit access to a trusted person identification document provider only.

To prevent association across identities, the solution provider MUST before issuing Wallet Trust Evidence ensure that (a) a newly generated device key pair is used and (b) the wallet follows the protocol so that the HDK output is bound to exactly this key. For (a), the solution provider could rely on freshness of a key attestation and ensure that each device public key is attested only once. For (b), the wallet could proof knowledge of the blinding factor `bf` with a Schnorr non-interactive zero-knowledge proof [RFC8235] with base point `pk_device`. This would ensure that the root blinding key `bf` is not shared with the solution provider to reduce the risk of the solution provider unblinding future derived keys.

### Issuer Trust Evidence

The Issuer Trust Evidence public key can be any other HDK public key. The solution provider MUST verify that the wallet knows the associated private key before issuing Issuer Trust Evidence. The solution provider MUST ensure that `sk_device` is under sole control of the unit holder. To achieve reader unlinkability, the unit MUST limit access of Issuer Trust Evidence to a single issuer. Subsequent issuers within the same HDK tree do not need to receive any Issuer Trust Evidence, since they can derive equally secure keys by applying the remote HDK protocol to presented keys attested by trusted (other) issuers.

## Applying HDK in OpenID for Verifiable Credential Issuance

In [draft-OpenID4VCI], the following terminology applies:

| OpenID4VCI        | HDK               |
| ----------------- | ----------------- |
| Credential        | document          |
| Credential Issuer | issuer            |
| Verifier          | reader            |
| Wallet            | unit              |

HDK enables unit and issuers cooperatively to establish the cryptographic key material that issued documents will be bound to.

For the remote HDK protocol, HDK proposes an update to the OpenID4VCI endpoints. This proposal is under discussion in [openid/OpenID4VCI#359](https://github.com/openid/OpenID4VCI/issues/359). In the update, the unit shares a key encapsulation public key with the issuer, and the issuer returns a key handle. Then documents can be re-issued, potentially in batches, using synchronised indices. Alternatively, re-issued documents can have their own key handles.

# Security considerations

## Confidentiality of key handles

The key handles MUST be considered confidential, since they provide knowledge about the blinding factors. Compromise of this knowledge could introduce undesired linkability. In HDK, both the holder and the issuer know the key handle during issuance.

In an alternative to HDK, the holder independently generates blinded key pairs and proofs of association, providing the issuer with zero knowledge about the blinding factors. However, this moves the problem: the proofs of association would now need to be considered confidential.

--- back

# Acknowledgements
{:numbered="false"}

This design is based on ideas introduced to the EU Digital Identity domain by Peter Lee Altmann.

Helpful feedback came from Emil Lundberg, John Bradley and Remco Schaar.
