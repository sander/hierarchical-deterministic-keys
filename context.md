# Privacy-preserving key management in the EU Digital Identity Wallet

> [!NOTE]
> These are notes by Peter Lee Altmann and Sander Dijkhuis from an initial exploration during March 2024. We keep these notes in temporarily for in-depth context in addition to the [README](README.md), until the other documents are more complete.

## Context

Relevant EUDIW solution security components (uncontested in ARF v1.3):

- WDA: Software component running in a rich execution environment
- WCA: Software component running in a rich execution environment
- WSCD: Hardware-backed secure cryptographic environment
- WSCA: Software provisioned within WSCD

Relevant data objects:

- WIA: Wallet Instance Attestation issued by EUDIW Solution Provider (details pending)
- PID: Person Identification Data (an attestation)
- QEAA: Qualified Electronic Attestation of Attributes
- PIN: Personal Identification Number (knowledge factor)

Security objectives:

- **LoA-High**: Meet LoA High requirements for cross-border eID schemes, meaning as per [[EU2015-1502]]. These requirements are divided into enrolment, eID means management, authentication, and management and organization. This text focuses on meeting LoA High requirements. In particular, the text discusses the following requirements:
  1. The PID provider ensures that the issued PID attestation is cryptographically bound to the tamper-protected WSCD from which keys cannot be extracted.
  2. The user demonstrates control of an eID means comprising a WSCD and WSCA that are configured to meet LoA High requirements.
  3. The eID means utilizes at least two authentication factors from different categories (both during issuance and presentation).
- **Binding-to-PID**: Enable a PID/(Q)EAA Provider to issue an attestation that includes a public proof of possession (PoP, see [[RFC7800]]) key with the corresponding private key being secured in the same WSCD as the one that secures the key material included in the PID used during authentication to the Provider.
- **RP-Unlinkability**: Relying Parties cannot use the PoP key to determine if an attribute presentation belongs to the same identity subject as a previous attribute presentation. In practice, with today’s supported cryptography, this implies that each issued attestation includes a unique one-time-use PoP key, which prevents correlation across presentations.
- **Weak-Issuer-Unlinkability**: Potentially colluding (Q)EAA Providers cannot determine if an attestation issued by one Provider describes the same identity subject as another attestation issued by another Provider on the basis of any PoP key (i.e., both the key the Provider saw when authenticating the user, and the key the Provider includes in the issued attestation).
- **QES-Control**: Enable creation of qualified electronic signatures and seals under sole control of the signatory.

> [!NOTE]
> The Binding-to-PID objective does not include PoP keys similarly bound to (Q)EAA used during authentication to the (Q)EAA Provider. That is, the EUDI Framework does not aim to provide assurance to a (Q)EAA Provider about operational wallets that are not valid. Also, for privacy reasons, an EUDIW does not provide assurance to a (Q)EAA Provider about the WSCD other than by releasing PID attributes.

> [!NOTE]
> This text does not consider security against an attacker equipped with a quantum resource since PID/(Q)EAA PoP keys are not meant to protect confidentiality, and since quantum resistance for signatures can be achieved using one time use keys derived in a quantum resistant way and with appropriate event logging.

Regulatory objectives:

- Interfaces between EUDIW, QEAA Providers and Relying Parties must be standardised in a way that allows solutions from different WSCA/WSCD vendors.
- The EUDIW Solution Provider must ensure that the eID means provides LoA High, and not put this burden on PID/(Q)EAA Providers or on Relying Parties. That is, they should only need to verify a PoP of the root key associated with the attested verifying key, for example using ECDH or EC(S)DSA.

With the objectives detailed and requirements listed, this text next describes EUDIW key management when using hierarchical deterministic key derivation (HDKD). First, the concept of HDKD is briefly described. Then four core issues related to HDKD are detailed. The three first issues relates to key management for PID/(Q)EAA. The last issue relates to key management for qualified electronic signatures and seals.

## Issue 1: root key control

To achieve **LoA-High** in practice, the EUDIW instance can rely on a PoP key  associated with:

- A strong possession factor;
- A rate-limited PIN check as a knowledge factor.

To resist high attack potential, the verification of both factors must actively involve the WSCD.

The following include possible WSCD architectures:

1. Local external standalone device, for example:
    - Smart card, such as PIV Card, with WSCA applet
    - Secure element, with WSCA applet
2. Local internal standalone programmable cryptographic chip, for example:
    - Smartphone eUICC with WSCA applet
    - Smartphone eSIM with WSCA applet
    - Smartphone eSE with WSCA applet
3. Local internal preprogammed security platform, for example:
    - Android trusted execution environment acting as WSCA
    - Android StrongBox secure element acting as WSCA
    - iOS Secure Enclave system-on-chip acting as WSCA
    - TPM acting as WSCA
4. Remote HSM, for example:
    - QSCD with a local client application acting as WSCA, authorizing operations using options 1, 2 or 3 above, for example using:
        - PIV card as possession factor and PIN verification using a HSM-backed Device-Enhanced Augmented PAKE (an approach proposed by Sweden)
        - Android/iOS security platform using SECDSA, described in [[SECDSA]] (granted patent claim by Wellet), applying asymmetric cryptography to enable detection of remote HSM corruption as described in [[SCAL3]]
        - Secure element contained in passkey device with Universal Authentication Framework support for PIN verification, described in [[SCAL3-UAF]] (no patent claims known)
        - Android/iOS security platform using threshold signatures, described in [[SCAL3-Thresholds]] (pending patent claim by Cleverbase)

The solution proposal discussed herein works in all four WSCD architectures that support the required cryptographic primitives. All operations critical for security need to be performed in the WSCD. Non-critical operations can be performed in a WCD or a WCA running in any environment (including hostile ones with limited sandboxing capabilities) such as in a smartphone’s rich execution environment or in a web browser.

If the user enters the PIN in the WDA or WCA instead of in the WSCD, the WDA or WCA must process it directly after entering, the WDA or WCA must keep the plaintext PIN confidential, and the WDA or WCA must delete the PIN from memory as soon as the encrypted PIN or data derived from the PIN is passed to the WSCD.

The rate-limiting of the PIN check may happen in the WCA instead of the WSCD only if this WCA capability is securely managed, e.g., under the ISMS of the EUDIW Solution Provider and not in local software that an attacker could modify undetectably.

Assuming that the root key control is proven, the PID Provider may now derive PoP keys using the (long term) WSCD root key.

## Issue 2: The HDKD approach

To achieve **RP-Unlinkability**, **Weak-Issuer-Unlinkability**, and **Binding-to-PID** at scale, the following is necessary:

1. The EUDIW Solution needs to act as a HDKD wallet. This includes a capability to:
    * Perform HDKD
    * Manage non-secret information (e.g., index values, domain separation data, suite identifiers etc.) required for the HDKD.
    * Manage relationships with the PID/(Q)EAA provider, such as storing the identifier (which is different from its signature verification key included in the issued attestation), if this is not part of the issued attestation itself.
2. The PID Provider must verify the WSCD binding of the long term root key and cryptographically bind every PID derived PoP key to the same WSCD.
3. Any (Q)EAA Provider who supports HDKD may use the PID-derived PoP key either to:
    * Cryptographically bind the derived (Q)EAA PoP key to the PID-derived PoP key. This ensures that the (Q)EAA PoP key enjoys the same WSCD protection as the long term root key.
    * Ask the user to use the PID PoP key to authenticate a new (not necessarily PID-derived) PoP key the user wants to use for key derivation, e.g. using HMAC with an ECDH-derived key or using a digital signature with EC(S)DSA. While out of scope for the text herein, this option may be suitable for LoA Substantial use cases where the user relies on a LoA Substantial device (such as a standalone smartphone) to derive a PoP key that is not bound to the PID PoP key.
    * Use a WSCD protected key to attest another key derived from the WSCD root key (cf., Eric Verheul’s approach).

Using HDKD enables concurrent issuance of a set of PIDs, using a single root key (level 0 key), where each PID has a derived PoP key (level 1). Subsequent issuance of (Q)EAAs can use the level 1 derived PoP keys to derive attestation unique level 2 PoP keys. At every level, the keys are crytographically bound to the same WSCD that protects the root key.

> [!NOTE]
> Only the PID Provider needs to verify the validity of the EUDIW and ensure that the root key is bound to the WSCD. For derived PID/(Q)EAA keys, there is no need to validate binding to either the WSCD, the root key, or any other derived key.

A coherent solution applying the HDKD approach must consist of the following components:

- Open standard EUDIW-(Q)EAA Provider protocol for diversification, with mandatory support for SOG-IS approved algorithms as listed in [[SOG-IS-1.3]], and optionally with algorithm support for suites supported by the Cryptographic Service Provider 2 (CSP2) as listed in [[TR03181]]
- Open standard EUDIW-Relying Party protocol for PoP, with mandatory support for SOG-IS approved algorithms, and optional support for CSP2 suites.
    - MSO or SD-JWT with ECDSA
    - MSO or SD-JWT with ECSDSA (Schnorr)
    - MSO or SD-JWT with ECDH
- Multi-vendor solutions for EUDIW key management in WCA, based on a root key that cannot be extracted from a WSCD
    - Local threshold/aggregated ECDSA (several patent claims apply)
    - Local threshold/aggregated ECSDSA (unlikely to be under patent claims, investigation required)
    - Local ECDH (unlikely to be under patent claims, investigation required)

[HDKD_specs.md](HDKD_specs.md) details a proposal for a HDKD. Next, current work on how to utilize the HDKD in deriving PoP keys is presented.

## Issue 3: Deriving PoP keys

* MulSign and AddSign
* Threshold signatures

## Issue 4: Qualified signatures and seals

To achieve **QES-Control** at scale, the EUDIW needs to support either:

- Local QSCD (e.g. WSCD == QSCD, or QSCD with interface to the WDA)
- Remote QSCD (see Potential UC5)

An open challenge in the WSCD == QSCD case is: should the QES key be diversified from the same root key as PID/QEAA keys? If so, how does this affect the requirements for the QES to be created within the QSCD? If not, how does the QTSP know that the key is properly secured (cf. QEAA-Binding)? Maybe using a WIA?

## References

### Informative References

<dl>
  <dt id=EU2015-1502>[EU2015-1502]<dd>

[EU2015-1502]: #EU2015-1502
European Commission, “Commission Implementing Regulation (EU) 2015/1502 of 8 September 2015 on setting out minimum technical specifications and procedures for assurance levels for electronic identification means”, [(EU) 2015/1502](https://eur-lex.europa.eu/legal-content/TXT/?uri=CELEX%3A32015R1502), September 2015.

  <dt id=RFC7800>[RFC7800]<dd>

[RFC7800]: #RFC7800
Jones, M., Bradley, J., and H. Tschofenig, “Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)”, [RFC 7800](https://www.rfc-editor.org/info/rfc7800), DOI 10.17487/RFC7800, April 2016.

  <dt id=SCAL3>[SCAL3]<dd>

[SCAL3]: #SCAL3
Cleverbase ID B.V., [“SCAL3: Verify that systems operate under your sole control”](https://github.com/cleverbase/scal3) version de8c5ae, March 2024.

  <dt id=SCAL3-Thresholds>[SCAL3-Thresholds]<dd>

[SCAL3-Thresholds]: #SCAL3-Thresholds
Dijkhuis, S., [“SCAL3 with Thresholds”](https://github.com/cleverbase/scal3/blob/main/docs/schemes/thresholds.md) version de8c5ae, March 2024.

  <dt id=SCAL3-UAF>[SCAL3-UAF]<dd>

[SCAL3-UAF]: #SCAL3-UAF
Dijkhuis, S., [“SCAL3 with UAF”](https://github.com/cleverbase/scal3/blob/main/docs/schemes/uaf.md) version de8c5ae, March 2024.

  <dt id=SECDSA>[SECDSA]<dd>

[SECDSA]: #SECDSA
Verheul, E., “SECDSA: Mobile signing and authentication under classical ‘sole control’”, [Cryptology ePrint Archive Paper 2021/910](https://eprint.iacr.org/2021/910) version 2024-03-16, March 2024.

  <dt id=SOGIS-1.3>[SOG-IS-1.3]<dd>

[SOG-IS-1.3]: #SOG-IS-1.3
SOG-IS Crypto Working Group, [“Agreed Cryptographic Mechanisms” version 1.3](https://www.sogis.eu/documents/cc/crypto/SOGIS-Agreed-Cryptographic-Mechanisms-1.3.pdf), February 2023.

  <dt id=TR03181>[TR03181]<dd>

[TR03181]: #TR03181
BSI, “Cryptographic Service Provider 2, Part 1: Architecture and Concepts”, [TR-03181-1](https://www.bsi.bund.de/dok/TR-03181-en) version 0.94, April 2023.

</dl>
