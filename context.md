# Privacy-preserving key management in the EU Digital Identity Wallet

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

The rate-limiting of the PIN check may happen in the WCA instead of the WSCD only if this WCA capability is securely managed, e.g., under the ISMS of the EUDIW Solution Provider and not in local software that an attacker could modify undetectably.

The following include possible WSCD architectures:

1. External (smart card, e.g., PIV)
2. Smartphone internal (eUICC, eSIM, eSE)
3. Remote HSM (requires 1 or 2 above to authenticate to HSM)
4. Internal Native for Android and iOS

The solution proposal discussed herein works in all four WSCD architectures that support the required cryptographic primitives. All operations critical for security need to be performed in the WSCD, but non-critical operations can be performed in any environment (including hostile ones) such as the smartphone's memory or in a browser.

Solutions considered to date by potential EUDIW Solution / PID Providers:

- Local WSCD-based
  - SE with WSCA applet (requires platform license)
  - eSIM with WSCA applet (requires telco license)
- Remote WSCD-based
  - SCAL3 with UAF: QSCD HSM controlled using passkey with UAF support (no patent claims known)
  - SCAL3 with SECDSA: QSCD HSM controlled using mobile endpoint (granted patent claim by Wellet)
  - SCAL3 with Thresholds: QSCD HSM controlled using mobile endpoint (pending patent claim by Cleverbase)
- Hybrid WSCD-based
  - Possession using a local PIV card, and PIN verification using a remote HSM with a Device-Enhanced augmented PAKE (an approach proposed by Sweden).

Assuming that the root key control is proven, the PID Provider may now derive PoP keys using the WSCD root key.

## Issue 2: The HDKD approach

To achieve **RP-Unlinkability** and **PID/(Q)EAA-Binding** at scale, the following is necessary:

1. The EUDIW Solution needs to act as a HDKD wallet. This includes a capability to:
  * Perform HDKD
  * Manage non-secret information (e.g., index values, domain separation data, suite identifiers etc.) required for the HDKD.
  * Manage relationships with the PID/(Q)EAA provider if this entity uses an identifier that is different from its signature verification key included in the issued attestation.
2. The PID Provider must verify the WSCD binding of the long term root key and cryptographically bind every PID derived PoP key to the same WSCD.
3. Any (Q)EAA Provider who supports HDKD will use the PID derived PoP key either to:
  * Cryptographically bind the derived (Q)EAA PoP key to the PID derived PoP key. This ensures that the (Q)EAA PoP key enjoyes the same WSCD protection as the long term root key.
  * Ask the user to create a signature using the PID PoP key over the PoP key the user wants to use for key derivation. While out of scope for the text herein, this option may be suitable for LoA Substantial use cases where the user relies on a LoA Substantial device (e.g., smartphone) to derive a PoP key that is not bound to the PID PoP key.
  * Use a WSCD protected key to attest another WSCD derived key (cf., Eric Verheul's approach)

Using HDKD enables concurrent issuance of a set of PIDs, using a single root key (level 0 key), where each PID has a derived PoP key (level 1). Subsequent issuance of (Q)EAAs can use the level 1 derived PoP keys to derive attestation unique level 2 PoP keys. At every level, the keys are crytographically bound to the same WSCD that protects the root key.

> NOTE 2: It is only the PID Provider who needs to verify the validity of the EUDIW and ensure that the root key is bound to the WSCD. For derived keys, there is no need to validate binding to either the WSCD, the root key, or any other derived key.

Components of a coherent solution:

- Open standard EUDIW-(Q)EAA Provider protocol for diversification, with mandatory support for [SIG-IS approved algorithms](https://www.sogis.eu/documents/cc/crypto/SOGIS-Agreed-Cryptographic-Mechanisms-1.2.pdf) (tbd), and optional algorithm support for suites listed in [BSI TR-03181](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03181/BSI-TR-03181.pdf?__blob=publicationFile&v=5).
- Open standard EUDIW-Relying Party protocol for PoP, with mandatory support for SOG-IS approved algorithms, and optional support for BSI TR-03181 suites.
  - MSO or SD-JWT with ECDSA
  - MSO or SD-JWT with ECSDSA (Schnorr)
  - MSO or SD-JWT with ECDH
- Multi-vendor solutions for EUDIW key management in WCA, based on root key that cannot be extracted from a WSCD
  - Local threshold/aggregated ECDSA (several patent claims apply)
  - Local threshold/aggregated ECSDSA (unlikely to be under patent claims, investigation required)
  - Local ECDH (unlikely to be under patent claims, investigation required)

Appendix A details a proposal for a HDKD. Next, current work on how to utilize the HDKD in deriving PoP keys is presented.

## Issue 3: Deriving PoP keys

* MulSign and AddSign
* Threshold signatures

## Issue 4: Qualified signatures and seals

To achieve **QES-Control** at scale, the EUDIW needs to support either:

- Local QSCD (e.g. WSCD == QSCD, or QSCD with interface to the WDA)
- Remote QSCD (see Potential UC5)

An open challenge in the WSCD == QSCD case is: should the QES key be diversified from the same root key as PID/QEAA keys? If so, how does this affect the requirements for the QES to be created within the QSCD? If not, how does the QTSP know that the key is properly secured (cf. QEAA-Binding)? Maybe using a WIA?

## References

<dl>
  <dt id=EU2015-1502>[EU2015-1502]<dd>

[EU2015-1502]: #EU2015-1502
European Commission, “Commission Implementing Regulation (EU) 2015/1502 of 8 September 2015 on setting out minimum technical specifications and procedures for assurance levels for electronic identification means”, [(EU) 2015/1502](https://eur-lex.europa.eu/legal-content/TXT/?uri=CELEX%3A32015R1502), September 2015.

  <dt id=RFC7800>[RFC7800]<dd>

[RFC7800]: #RFC7800
Jones, M., Bradley, J., and H. Tschofenig, “Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)”, [RFC 7800](https://www.rfc-editor.org/info/rfc7800), DOI 10.17487/RFC7800, April 2016.

</dl>
