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
    RFC7800:
    RFC8017:
    RFC8235:
    RFC9380:
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
    Verheul2024:
        title: Attestation Proof of Association – provability that attestation keys are bound to the same hardware and person
        target: https://eprint.iacr.org/2024/1444
        author:
            - name: E. Verheul
        date: 2024-09-18

--- abstract

Hierarchical Deterministic Keys enables managing large sets of keys bound to a secure cryptographic device that protects a single key. This enables the development of secure digital identity wallets providing many one-time-use public keys.

--- middle

# Introduction

This document specifies the algorithms to apply Hierarchical Deterministic Keys (HDKeys). The purpose of an HDK architecture is to manage large sets of keys bound to a secure cryptographic device that protects a single key. This enables the development of secure digital identity wallets providing many one-time-use public keys.

The core idea has been introduced in [BIP32] to create multiple cryptocurrency addresses in a manageable way. The present document extends the idea towards devices commonly used for digital wallets, and towards common interaction patterns for document issuance and authentication.

To store many HDKeys, only a seed string needs to be confidentially stored, associated with a device private key. Each HDK is then deterministically defined by a path of indices, optionally alternated by key handles provided by another party. Such a path can efficiently be stored and requires less confidentiality than the seed.

To prove possession of many HDKeys, the secure cryptographic device only needs to perform common cryptographic operations on a single key. The HDK acts as a blinding factor that enables blinding the device public key.

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
                          +----+
Confidential static data: |seed|
                          +-+--+
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

The unit computes a Level 0 HDK at the root node using a deterministic function: `(bf0, salt0) = hdk0 = HDK(seed, 0)`. The HDK consists of a first blinding factor `bf0` and a first byte string `salt0` to derive next-level keys. Using `bf0` and the device key pair, the unit can compute blinded public and private keys and proofs of possession.

The unit computes any Level `n > 0` HDK from any other HDK `(bf, salt)` using the same deterministic function: `(bf', salt') = hdk' = HDK(salt, index)`. The function takes the previous-level `salt` as input, and an `index` starting at 0. The function returns a new HDK as output, which can be used in the same way as the root HDK.

### Remote deterministic key derivation

Instead of local derivation, an HDK salt can also be derived using a key handle that is generated remotely. Using the derived salt, the local and remote parties can derive the same new HDKeys. The remote party can use these to derive public keys. The local party can use these to derive associated private keys for proof of possession.

This approach is similar to Asynchronous Remote Key Generation (ARKG) [I-D.draft-bradleylundberg-cfrg-arkg-02], but not the same since ARKG does not enable distributed proof of possession with deterministic hierarchies. This makes it difficult to implement with cryptographic devices that lack specific firmware support.

To enable remote derivation of child HDKeys, the unit uses the parent HDKey to derive the parent public key and a second public key for key encapsulation. The issuer returns a key handle, using which both parties can derive a sequence of child HDKeys. Key encapsulation prevents other parties from discovering a link between the public keys of the parent and the children, even if the other party knows the parent HDK or can eavesdrop communications.

Locally derived parents can have remotely derived children. Remotely derived parents can have locally derived children.

### Blinded proof of possession

The next concept to illustrate is blinded proof of possession. This enables a unit to prove possession of a (device) private key without disclosing the directly associated public key. This way, solutions can avoid linkability across readers of a digital document that is released with proof of possession.

In this example, a document is issued with binding to a public key `pk'`, which is a blinding public key `pk` blinded with the blinding factor `bf` in some HDK `hdk = (bf, salt)`. The unit can present the document with a proof of possession of the corresponding blinded private key, which is the blinding private key `sk` blinded with `bf`. The unit applies some authentication function `device_data = authenticate(sk, reader_data, bf)` to the blinding private key, reader-provided data and the blinding factor. The unit can subsequently use the output `device_data` to prove possession to the reader using common algorithms.

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

- `ID`: A domain separation tag, represented as a string of ASCII bytes.
- `Ns`: The amount of bytes of a salt value with sufficient entropy.
- `H`: A cryptographic hash function.
  - H1(msg): Outputs `Ns` bytes.
- `BL`: An asymmetric key blinding scheme with opaque blinding factors and algebraic properties, consisting of the functions:
  - BL-Generate-Blinding-Key-Pair(): Outputs a blinding key pair `(pk, sk)`.
  - BL-Derive-Blinding-Factor(msg, ctx): Outputs a blinding factor `bf` based on two byte string inputs, message `msg` and domain separation parameter `ctx`.
  - BL-Blind-Public-Key(pk, bf): Outputs the result `pk'` of blinding `pk` with `bf`. This again is a blinding public key.
  - BL-Blind-Private-Key(sk, bf): Outputs the result `sk'` of blinding `sk` with `bf`. This again is a blinding private key.
  - BL-Combine-Blinding-Factors(bf1, bf2): Outputs a blinding factor `bf` such that for all blinding key pairs `(pk, sk)`:
    - `BL-Blind-Public-Key(pk, bf) == BL-Blind-Public-Key(BL-Blind-Public-Key(pk, bf1), bf2)`
    - `BL-Blind-Private-Key(pk, bf) == BL-Blind-Private-Key(BL-Blind-Private-Key(pk, bf1), bf2)`
- `KEM`: A key encapsulation mechanism, consisting of the functions:
    - KEM-Derive-Key-Pair(msg, ctx): Outputs a key encapsulation key pair `(pk, sk)`.
    - KEM-Encaps(pk, ctx): Outputs `(k, c)` consisting of a shared secret `k` and a ciphertext `c`, taking key encapsulation public key `pk` and domain separation parameter `ctx`, a byte string.
    - KEM-Decaps(sk, c, ctx): Outputs shared secret `k`, taking key encapsulation private key `sk` and domain separation `ctx`, a byte string.
- `Authenticate(sk_device, reader_data, bf)`: Outputs `device_data` for use in a protocol for proof of possession, taking a BL blinding private key `sk_device`, remotely received `reader_data`, and a BL blinding factor `bf`.

An HDK instantiation MUST specify the instantiation of each of the above functions and values.

An HDK instantiation MUST define Authenticate such that the `device_data` can be verified using the blinded public key `pk = BL-Blind-Public-Key(sk, bf)`. The reader does not need to know that HDK was applied: the public key will look like any other public key used for proofs of possession.

## The HDK function

A local unit or a remote party deterministically computes an HDK from a salt and an index. The salt can be an initial seed value of `Ns` bytes or it can be taken from another parent HDK. The secure generation of the seed is out of scope for this specification.

~~~
Inputs:
- salt, a string of Ns bytes.
- index, an integer between 0 and 2^32-1 (inclusive).

Outputs:
- bf, the blinding factor at the provided index.
- salt', the salt for HDK derivation at the provided index.

def HDK(salt, index):
    msg = salt || I2OSP(index, 4)
    bf = BL-Derive-Blinding-Factor(msg, ID)
    salt' = H1(msg)
    return (bf, salt')
~~~

## The local HDK procedure

This is a procedure executed locally by a unit.

To begin, the unit securely generates a `seed` salt of `Ns` bytes and a device key pair:

~~~
seed = random(Ns) # specification of random out of scope
(pk_device, sk_device) = BL-Generate-Blinding-Key-Pair()
~~~

The unit MUST generate `sk_device` within a secure cryptographic device.

Whenever the unit requires the HDK with some `index` at level 0, the unit computes:

~~~
(bf, salt) = HDK(seed, index)

pk = BL-Blind-Public-Key( pk_device, bf) # optional
sk = BL-Blind-Private-Key(sk_device, bf) # optional
~~~

Now the unit can use the blinded key pair `(pk, sk)` or derive child HDKeys.

Whenever the unit requires the HDK with some `index` at level `n > 0` based on a parent HDK `hdk = (bf, salt)` with blinded key pair `(pk, sk)` at level `n`, the unit computes:

~~~
(bf', salt') = HDK(salt, index)

pk' = BL-Blind-Public-Key( pk, bf') # optional
sk' = BL-Blind-Private-Key(sk, bf') # optional
~~~

Now the unit can use the blinded key pair `(pk', sk')` or derive child HDKeys.

## The remote HDK protocol

This is a protocol between a local unit and a remote issuer.

As a prerequisite, the unit possesses a `salt` of `Ns` bytes associated with a parent blinding key pair `(pk, sk)` generated using the local HDK procedure.

~~~
# 1. Unit computes:
(pk_kem, sk_kem) = KEM-Derive-Key-Pair(salt, ID)

# 2. Unit shares with issuer: (pk, pk_kem)

# 3. Issuer computes:
(salt, kh) = KEM-Encaps(pk_kem, ID)

# 4. Issuer shares with unit: kh

# Subsequently, for any index known to both parties:

# 5. Issuer computes:
(bf, salt') = HDK(salt, index)
pk' = BL-Blind-Public-Key(pk, bf)

# 6. Issuer shares with unit: pk'

# 7. Unit verifies integrity:
salt' = KEM-Decaps(sk_kem, kh, ID)
(bf, salt'') = HDK(salt', index)
pk' == BL-Blind-Public-Key(pk, bf)

# 8. Unit computes:
sk' = BL-Blind-Private-Key(sk, bf)
~~~

After step 7, the unit can use the value of `salt''` to derive next-level HDKeys.

Step 4 MAY be postponed to be combined with step 6. Steps 5 to 8 MAY be combined in concurrent execution for multiple indices.

## Combining blinding factors

A unit MUST not persist a blinded private key. Instead, if persistence is needed, a unit can persist either the blinding factor of each HDK, or a path consisting of the seed salt, indices and key handles. In both cases, the unit needs to combine parent blinding factor `bf1` with child blinding factor `bf2` before blinding the parent private key `sk`:

~~~
bf = BL-Combine-Blinding-Factors(bf1, bf2)
~~~

Subsequently, the unit can apply the Authenticate function to the parent blinding key. The unit can combine multiple blinding factors in the HDK path.

If the unit uses the blinded private key directly, the unit MUST use it within the secure cryptographic device protecting the device private key.

If the unit uses the blinded private key directly, the unit MUST ensure the secure cryptographic device deletes it securely from memory after usage.

When presenting multiple documents, a reader can require a proof that multiple keys are associated to a single device. Several protocols for a cryptographic proof of association are possible, such as [Verheul2024]. For example, a unit could prove in a zero-knowledge protocol knowledge of the association between two elliptic curve keys `B1 = [bf1]D` and `B2 = [bf2]D`, where `bf1` and `bf2` are multiplicative blinding factors for a common blinding public key `D`. In this protocol, the association is known by the discrete logarithm of `B2 = [bf2/bf1]B1` with respect to generator `B1`. The unit can apply BL-Combine-Blinding-Factors to obtain values to compute this association.

# Generic HDK instantiations

## Using elliptic curves

Instantiations of HDK using elliptic curves require the following cryptographic constructs:

- `EC`: An elliptic curve with elements of type Element and scalars of type Scalar, consisting of the functions:
  - EC-Random(): Outputs a random Scalar `k`.
  - EC-Add(A, B): Outputs the sum between Elements `A` and `B`.
  - EC-Scalar-Mult(A, k): Outputs the scalar multiplication between Element `A` and Scalar `k`.
  - EC-Scalar-Base-Mult(k): Outputs the scalar multiplication between the base Element and Scalar `k`.
  - EC-Order(): Outputs the order of the base Element.
  - EC-Serialize-Element(A): Outputs a byte string representing Element `A`.
- `H2C`: A hash-to-curve suite [RFC9380] for EC, providing the function:
  - hash_to_field(msg, count): Outputs `count` EC Elements based on the result of cryptographically hashing `msg` (see [RFC9380], Section 5.2).

~~~
def BL-Generate-Blinding-Key-Pair():
    sk = EC-Random()
    pk = EC-Scalar-Base-Mult(sk)
    return (pk, sk)

def BL-Derive-Blinding-Factor(msg, ctx):
    bf = hash_to_field(msg, count) with the parameters:
        DST: ID || ctx
        F: GF(EC-Order()), the scalar field
            of the prime order subgroup of EC
        p: EC-Order()
        m: 1
        L: as defined in H2C
        expand_message: as defined in H2C
    return bf
~~~

## Using EC multiplicative blinding

Such instantations of HDK use elliptic curves (see [Using elliptic curves](#using-elliptic-curves)) and instantiate the following:

~~~
def BL-Blind-Public-Key(pk, bf):
    pk' = EC-Scalar-Mult(pk, bf)
    return pk

def BL-Blind-Private-Key(sk, bf):
    sk' = sk * bf mod EC-Order()
    return sk

def BL-Combine-Blinding-Factors(bf1, bf2):
    bf = bf1 * bf2 mod EC-Order()
    return bf
~~~

## Using EC additive blinding

Such instantations of HDK use elliptic curves (see [Using elliptic curves](#using-elliptic-curves)) and instantiate the following:

~~~
def BL-Blind-Public-Key(pk, bf):
    pk' = EC-Add(pk, EC-Scalar-Base-Mult(bf))
    return pk

def BL-Blind-Private-Key(sk, bf):
    sk' = sk + bf mod EC-Order()
    return sk

def BL-Combine-Blinding-Factors(bf1, bf2):
    bf = bf1 + bf2 mod EC-Order()
    return bf
~~~

## Using ECDH shared secrets

Such instantiations of HDK use EC multiplicative blinding (see [Using EC multiplicative blinding](#using-ec-multiplicative-blinding)) and require the following cryptographic construct:

- `ECDH`: An Elliptic Curve Key Agreement Algorithm - Diffie-Hellman (ECKA-DH) [TR03111] with elliptic curve `EC`, consisting of the functions:
  - ECDH-Create-Shared-Secret(sk_self, pk_other): Outputs a shared secret byte string representing an Element.

In such instantiations, the reader provides an ephemeral public key `reader_data`. The Authenticate function returns shared secret `device_data` consisting of a binary encoded x-coordinate `Z_AB` of an ECDH operation with the blinded private key. Subsequently, the unit creates a message authentication code (MAC), such as in ECDH-MAC authentication defined in [ISO18013-5]. The reader verifies this MAC by performing an ECDH operation with its ephemeral private key and the blinded public key.

These instantiations instantiate the following:

~~~
def Authenticate(sk_device, reader_data, bf):
    P' = EC-Scalar-Mult(reader_data, bf)

    # Compute Z_AB within the secure cryptographic device.
    Z_AB = ECDH-Create-Shared-Secret(sk_device, P')

    return Z_AB
~~~

## Using EC digital signatures

Such instantiations of HDK use EC additive blinding (see [Using EC additive blinding](#using-ec-additive-blinding)) and require the following cryptographic construct:

- `DSA`: An EC digital signature algorithm , consisting of the functions:
  - DSA-Sign(sk, msg): Outputs the signature `(c, r)` created using private signing key `sk` over byte string `msg`.
  - DSA-Verify(signature, pk, msg): Outputs whether `signature` is a signature over `msg` using public verification key `pk`.
  - DSA-Serialize(c, r): Outputs the byte array serialization of the signature `(c, r)`.
  - DSA-Deserialize(bytes): Outputs the signature `(c, r)` represented by byte string `bytes`.

The reader is expected to create an input byte string `reader_data` with sufficient entropy for each challenge.

The reader is expected to verify the proof `device_data` using DSA-Verify with the blinded public key.

## Using EC-SDSA signatures

Such instantiations of HDK use EC digital signatures (see [Using EC digital signatures](#using-ec-digital-signatures)) and EC digital and instantiate the following:

- `DSA`: An EC-SDSA (Schnorr) digital signature algorithm [TR03111].

~~~
def Authenticate(sk_device, reader_data, bf):
    # Compute signature within the secure cryptographic device.
    signature = DSA-Sign(sk_device, reader_data)

    (c, s) = DSA-Deserialize(proof)
    s' = s + c * bf mod EC-Order()
    device_data = DSA-Serialize(c, s')
    return device_data
~~~

## Using ECDSA signatures

Such instantiations of HDK use EC digital signatures (see [Using EC digital signatures](#using-ec-digital-signatures)) and instantiate the following:

- `DSA`: An ECDSA digital signature algorithm [TR03111].

~~~
def Authenticate(sk_device, reader_data, bf):
    # Blind private key and create signature
    # within the secure cryptographic device.
    sk' = BL-Blind-Private-Key(sk_device, bf)
    device_data = DSA-Sign(sk', reader_data)
    return device_data
~~~

Due to potential patent claims, this document does not specify an instantiation with multi-party ECDSA signing, even though this would be theoretically possible using EC multiplicative blinding.

# Concrete HDK instantiations

The RECOMMENDED instantiation is the HDK-ECDH-P256. This avoids the risk of having the holder unknowingly producing a potentially non-repudiable signature over reader-provided data. Secure cryptographic devices that enable a high level of assurance typically support managing ECDH keys with the P-256 elliptic curve.

## HDK-ECDH-P256

This instantiation uses ECDH for proof of possession (see [Using ECDH shared secrets](#using-ecdh-shared-secrets)) and for `KEM`.

- `ID`: `"HDK-ECDH-P256-v1"`
- `Ns`: 32
- `H`: SHA-256 [FIPS180-4] with:
  - `H1(msg)`: Implemented by computing `H(ID || msg)`.
- `EC`: The NIST curve `secp256r1` (P-256) [SEC2]
- `ECDH`: ECKA-DH with curve `EC`
- `KEM`: ECKA-DH with curve `EC`

## HDK-ECDSA-P256

This instantiation uses ECDSA for proof of possession (see [Using ECDSA signatures](#using-ecdsa-signatures)) and ECDH for `KEM`.

- `ID`: `"HDK-ECSDSA-P256-v1"`
- `Ns`: 32
- `H`: SHA-256 [FIPS180-4] with:
  - `H1(msg)`: Implemented by computing `H(ID || msg)`.
- `EC`: The NIST curve `secp256r1` (P-256) [SEC2]
- `DSA`: ECDSA with curve `EC`.
- `KEM`: ECKA-DH with curve `EC`

## HDK-ECSDSA-P256

This instantiation uses EC-SDSA for proof of possession (see [Using EC-SDSA signatures](#using-ec-sdsa-signatures)) and ECDH for `KEM`.

- `ID`: `"HDK-ECSDSA-P256-v1"`
- `Ns`: 32
- `H`: SHA-256 [FIPS180-4] with:
  - `H1(msg)`: Implemented by computing `H(ID || msg)`.
- `EC`: The NIST curve `secp256r1` (P-256) [SEC2]
- `DSA`: EC-SDSA-opt (the optimised EC-SDSA) with curve `EC`.
- `KEM`: ECKA-DH with curve `EC`

# Application considerations

## Secure cryptographic device

The HDK approach assumes that the holder controls a secure cryptographic device that protects the device key pair `(pk_device, sk_device)`. The device key is under sole control of the holder.

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
