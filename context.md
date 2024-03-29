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

## References

<dl>
  <dt id=EU2015-1502>[EU2015-1502]<dd>

[EU2015-1502]: #EU2015-1502
European Commission, “Commission Implementing Regulation (EU) 2015/1502 of 8 September 2015 on setting out minimum technical specifications and procedures for assurance levels for electronic identification means”, [(EU) 2015/1502](https://eur-lex.europa.eu/legal-content/TXT/?uri=CELEX%3A32015R1502), September 2015.

  <dt id=RFC7800>[RFC7800]<dd>

[RFC7800]: #RFC7800
Jones, M., Bradley, J., and H. Tschofenig, “Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)”, [RFC 7800](https://www.rfc-editor.org/info/rfc7800), DOI 10.17487/RFC7800, April 2016.

</dl>
