# Hierarchical Deterministic Keys for the European Digital Identity Wallet

The [EU Digital Identity Regulation](https://eur-lex.europa.eu/eli/reg/2024/1183/oj) requires privacy-preserving cryptography in wallet solutions. The regulatory requirements bring several implementation challenges:

1. How might a wallet solution protect a root key with a high level of assurance?
2. How might an issuer protect many identity document presentations with this root key in an unlinkable way?
3. How might a wallet solution present such protected documents?
4. How might a relying party verify that such a presentation describes a single subject?
5. How might a wallet solution protect qualified electronic signature or seal creation data using the root key?

The European Commission and Member States are developing a Wallet Toolbox to enable interoperable solutions to challenges such as these. This Toolbox includes the [Architecture and Reference Framework](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/latest/arf/). The Large Scale Pilots are implementing and testing the wallet to generate feedback on this Toolbox.

In this repository, Pilot participants contribute to a concrete interoperable solution based on the idea of Hierarchical Deterministic Keys (HDKs) and blinded key proof of possession. This approach is introduced in the Analysis of selective disclosure and zero-knowledge proofs ([ETSI TR 119476 version 1.2.1](https://www.etsi.org/deliver/etsi_tr/119400_119499/119476/01.02.01_60/tr_119476v010201p.pdf)). The Pilot participants aim to evaluate various options, present an appropriate solution, and develop a common specification to enable testing interoperability.

> [!NOTE]
> This information is shared by participants of the [Digital Credentials for Europe (DC4EU) Consortium](https://www.dc4eu.eu), the [EU Digital Identity Wallet Consortium (EWC)](https://eudiwalletconsortium.org), and the [Potential Consortium](https://www.digital-identity-wallet.eu). Views and opinions expressed are those of the authors only and do not necessarily reflect those of all Potential members.

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

The challenge of revoking identity documents is relevant to take into account, but designing revocation solutions is out of scope for this work.

The technical reports and specifications in this repository may eventually be used to contribute to open standards. For the current repository, we apply practices inspired by the [Community Cryptography Specification Project](https://github.com/C2SP/C2SP).

To enable reuse, new contributions to the technical reports and specifications must be provided under either [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) or [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).

## Contents

- Previous introduction: [Privacy-preserving key management in the EU Digital Identity Wallet](context.md)
- Specification: [Hierarchical Deterministic Keys](keys.md)
  - Prototype: [prototype.worksheet.sc](prototype.worksheet.sc) to open in [Visual Studio Code](https://code.visualstudio.com) with [Scala (Metals)](https://marketplace.visualstudio.com/items?itemName=scalameta.metals)
- Feedback: [Feedback to enable Hierarchical Deterministic Keys in the Wallet Toolbox](feedback.md)
