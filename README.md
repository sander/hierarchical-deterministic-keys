# Hierarchical Deterministic Keys for the European Digital Identity Wallet

## Background

The [EU Digital Identity Regulation](https://eur-lex.europa.eu/eli/reg/2024/1183/oj) requires secure cryptography in wallet solutions. The regulatory requirements bring several implementation challenges:

1. How might an issuer protect document authenticity?
2. How might an issuer prevent tracking based on document authenticity signatures?
3. How might a wallet solution enable binding documents to a WSCD with a high level of assurance?
4. How might a wallet solution enable relying parties to verify WSCD binding?
5. How might a wallet solution blind verification keys for each attestation?
6. How might a wallet solution prove possession of blinded keys?
7. How might a wallet solution create qualified electronic signatures or seals?

The European Commission and Member States are developing a Wallet Toolbox to enable interoperable solutions to challenges such as these. This Toolbox includes the [Architecture and Reference Framework](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/latest/arf/) (ARF). The Large Scale Pilots are implementing and testing the wallet to generate feedback on this Toolbox.

In this repository, Pilot participants contribute to concrete interoperable solutions based on the ideas of Hierarchical Deterministic Keys (HDKs) and blinded key proof of possession. This approach is introduced in the Analysis of selective disclosure and zero-knowledge proofs ([ETSI TR 119476 version 1.2.1](https://www.etsi.org/deliver/etsi_tr/119400_119499/119476/01.02.01_60/tr_119476v010201p.pdf)). The Pilot participants aim to evaluate various options, present an appropriate solution, and develop a common specification to enable testing interoperability.

> [!NOTE]
> This information is shared by participants of the [Digital Credentials for Europe (DC4EU) Consortium](https://www.dc4eu.eu), the [EU Digital Identity Wallet Consortium (EWC)](https://eudiwalletconsortium.org), and the [Potential Consortium](https://www.digital-identity-wallet.eu). Views and opinions expressed are those of the authors only and do not necessarily reflect those of all consortium members.

## Position

The participants share the following position.

As of today, ARF 1.4 provides no complete and interoperable solution for key management, that can be industrially deployed at scale and used across the whole ecosystem.

HDK is a viable solution to some EU Digital Identity Wallet key management challenges. It enables the management of an unlimited amount of keys using a single secret. It also allows the use of existing secure cryptographic devices with common algorithms.

HDK is applicable to specific credential schemes, including one-time-use attestations and BBS#.

We want to start a dialogue with the European Commission about the proposed solution in this document, and how to include this in the Toolbox. We have specific feedback on the ARF high-level requirements to make sure that the EU Digital Identity implementation addresses the key management challenges in an interoperable and scalable way. This should provide a solid basis for legislation in the Implementing Acts.

Expert participants from DC4EU:

- John Bradley (Yubico)
- Leif Johansson (Sunet)
- Nikos Voutsinas (GUnet)

Expert participants from Potential:

- Antoine Dumanois (Orange)
- Sander Dijkhuis (Cleverbase)
- Zeff Sherriff (Bundesdruckerei)

## Contents

To address challenges 5 and 6, this repository contains a freely accessible, unencumbered specification of **[Hierarchical Deterministic Keys](draft-dijkhuis-cfrg-hdkeys.md)**. This enables an EU Digital Identity Wallet deployment that distributes key management efficiently:

To illustrate and validate the specifications, this repository contains a **[Prototype worksheet](prototype.worksheet.sc)**. This is easiest to run in [Visual Studio Code](https://code.visualstudio.com) with [Scala (Metals)](https://marketplace.visualstudio.com/items?itemName=scalameta.metals).

To inform further standardisation and legislation, this repository contains **[Feedback to enable Hierarchical Deterministic Keys in the Wallet Toolbox](feedback.md)**. It also contains **[Feedback to resolve HDK and PoA issues in the ARF](feedback-poa.md)**.

The repository does not contain details about the implementation of HDK for key management in credential schemes, such as one-time-use document schemes for relying party unlinkability and weak issuer unlinkability, or [BBS#](https://github.com/user-attachments/files/15905230/BBS_Sharp_Short_TR.pdf) for full unlinkability. Credential schemes have not currently been analysed by the working group. When such analysis is carried out, it might result in changes to the specification. For example, delegated key generation only seems to have use cases for batch one-time-use document issuance, and not for BBS#.

## Contributing

Feedback and other input is easiest to discuss in [GitHub issues](https://github.com/sander/hierarchical-deterministic-keys/issues).

The technical reports and specifications in this repository may eventually be used to contribute to open standards. For the current repository, we apply practices inspired by the [Community Cryptography Specification Project](https://github.com/C2SP/C2SP).

To enable reuse, new contributions to the technical reports and specifications must be provided under either [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) or [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).
