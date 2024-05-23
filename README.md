# Hierarchical Deterministic Keys for the European Digital Identity Wallet

The [EU Digital Identity Regulation](https://eur-lex.europa.eu/eli/reg/2024/1183/oj) requires privacy-preserving cryptography in wallet solutions. The regulatory requirements bring several implementation challenges:

1. How might a wallet solution protect a root key with a high level of assurance?
2. How might an issuer protect many identity document presentations with this root key in an unlinkable way?
3. How might a wallet solution present such protected documents?
4. How might a relying party verify that such a presentation describes a single subject?
5. How might a wallet solution protect qualified electronic signature or seal creation data using the root key?

The European Commission and Member States are developing a Wallet Toolbox to enable interoperable solutions to challenges such as these. This Toolbox includes the [Architecture and Reference Framework](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/latest/arf/). The Large Scale Pilots are implementing and testing the wallet to generate feedback on this Toolbox.

In this repository, Pilot participants contribute to a concrete interoperable solution based on the idea of Hierarchical Deterministic Keys (HDKs). This approach is being considered for the an update to the Analysis of selective disclosure and zero-knowledge proofs (ETSI TR 119476, work item [RTR/ESI-0019476v121](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=69479)). The Pilot participants aim to evaluate various options, present an appropriate solution, and develop a common specification to enable testing interoperability.

## Approach

We aim to specify minimum requirements to address challenge 1. To illustrate these requirements, we may refer to some example solutions. Several solutions involve proprietary technologies. A complete discussion is out of scope for this repository.

To address challenges 2–4, we aim to specify an HDK architecture. Quality criteria for this architecture are:

- Must be interoperable with [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).
- Must contain freely accessible, unencumbered profiles of:
    - PID Issuance Interface
    - Attestation Issuance Interface
    - Presentation Interface
- Must contain freely accessible, unencumbered algorithms to blind keys and proofs.
- Should reuse existing open standards where appropriate.

Challenge 5 is out of scope at the moment since the Pilots currently focus on remote qualified signature creation devices. Such solutions may already be built upon the existing common standards. However, the insights regarding challenge 1–4 may lead to valuable insights about alternative solutions to challenge 5.

The technical reports and specifications in this repository may eventually be used to contribute to open standards. For the current repository, we apply practices inspired by the [Community Cryptography Specification Project](https://github.com/C2SP/C2SP).

To enable reuse, new contributions to the technical reports and specifications must be provided under either [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) or [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).

## Contents

- Previous introduction: [Privacy-preserving key management in the EU Digital Identity Wallet](context.md)
- Specification: [Hierarchical Deterministic Keys](keys.md)
