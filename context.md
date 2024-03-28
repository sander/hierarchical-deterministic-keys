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

- **LoA-High**: Meet LoA High requirements for cross-border eID schemes, meaning as per (EU) 2015/1502. These requirements are divided into enrolment, eID means management, authentication, and management and organization. This text focuses on meeting LoA High requirements. In particular, the text discusses the following requirements:
  1. The PID provider ensures that the issued PID attestation is cryptographically bound to the tamper and duplication proof WSCD.
  2. The user demonstrates control of an eID means where the WSCD and WSCA is configured to meet LoA High requirements.
  3. The eID means utilizes at least two authentication factors from different categories (both during issuance and presentation).
- **PID/(Q)EAA-Binding**: Enable a PID/(Q)EAA Provider to issue an attestation that includes a public proof of possession (PoP) key with the corresponding private key being secured in the same WSCD as the one that secures the key material included in the PID used during authentication to the Provider.
- **RP-Unlinkability**: Each issued attestation includes a unique single use PoP key, which prevents correlation across presentations.
- **Weak Issuer-Unlinkability**: Potentially colluding (Q)EAA Providers cannot determine if an attestation issued by one Provider describes the same identity subject as another attestation issued by another Provider on the basis of any PoP key (i.e., both the key the Provider saw when authenticating the user, and the key the Provider includes in the issued attestation).
- **QES-Control**: Enable creation of qualified electronic signatures and seals under sole control of the signatory.

> NOTE 1: This text does not consider security against an attacker equipped with a quantum resource since PID/(Q)EAA PoP keys are not meant to protect confidentiality, and since quantum resistance for signatures can be achieved using one time use keys derived in a quantum resistant way and with appropriate event logging. 

Regulatory objectives:

- Interfaces between EUDIW, QEAA Providers and Relying Parties must be standardised in a way that allows solutions from different WSCA/WSCD vendors.
- The EUDIW Solution Provider must ensure that the eID means provides LoA High, and not put this burden on PID/(Q)EAA Providers or on Relying Parties. That is, they should only need to verify a PoP of the root key associated with the attested verifying key, for example using ECDH or EC(S)DSA. 

With the objectives detailed and requirements listed, this text next describes EUDIW key management when using hierarchical deterministic key derivation (HDKD). First, the concept of HDKD is briefly described. Then four core issues related to HDKD are detailed. The three first issues relates to key management. The last issue relates to signatures and seals.
