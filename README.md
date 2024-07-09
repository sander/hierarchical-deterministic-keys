# Hierarchical Deterministic Keys for the European Digital Identity Wallet

## Context

The [EU Digital Identity Regulation](https://eur-lex.europa.eu/eli/reg/2024/1183/oj) requires secure cryptography in wallet solutions. The regulatory requirements bring several implementation challenges:

1. How might an issuer protect document authenticity?
2. How might an issuer prevent tracking based on document authenticity signatures?
3. How might a wallet solution enable binding documents to a WSCD with a high level of assurance?
4. How might a wallet solution enable relying parties to verify WSCD binding?
5. How might a wallet solution blind verification keys for each attestation?
6. How might a wallet solution prove possession of blinded keys?
7. How might a wallet solution create qualified electronic signatures or seals?

The European Commission and Member States are developing a Wallet Toolbox to enable interoperable solutions to challenges such as these. This Toolbox includes the [Architecture and Reference Framework](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/latest/arf/). The Large Scale Pilots are implementing and testing the wallet to generate feedback on this Toolbox.

In this repository, Pilot participants contribute to concrete interoperable solutions based on the ideas of Hierarchical Deterministic Keys (HDKs) and blinded key proof of possession. This approach is introduced in the Analysis of selective disclosure and zero-knowledge proofs ([ETSI TR 119476 version 1.2.1](https://www.etsi.org/deliver/etsi_tr/119400_119499/119476/01.02.01_60/tr_119476v010201p.pdf)). The Pilot participants aim to evaluate various options, present an appropriate solution, and develop a common specification to enable testing interoperability.

> [!NOTE]
> This information is shared by participants of the [Digital Credentials for Europe (DC4EU) Consortium](https://www.dc4eu.eu), the [EU Digital Identity Wallet Consortium (EWC)](https://eudiwalletconsortium.org), and the [Potential Consortium](https://www.digital-identity-wallet.eu). Views and opinions expressed are those of the authors only and do not necessarily reflect those of all consortium members.

## Contents

To address challenges 5 and 6, this repository contains a freely accessible, unencumbered specification of **[Hierarchical Deterministic Keys](keys.md)**. This enables an EU Digital Identity Wallet deployment that distributes key management efficiently:

![A wallet architecture using Hierarchical Deterministic Keys associated with keys protected using a wallet secure cryptographic device, optionally using Asynchronous Remote Key Generation (ARKG).](media/deployment.svg)

To illustrate and validate the specifications, this repository contains a **[Prototype worksheet](prototype.worksheet.sc)**. This is easiest to run in [Visual Studio Code](https://code.visualstudio.com) with [Scala (Metals)](https://marketplace.visualstudio.com/items?itemName=scalameta.metals).

To inform further standardisation and legislation, this repository contains **[Feedback to enable Hierarchical Deterministic Keys in the Wallet Toolbox](feedback.md)**.

This document does not contain details about the implementation of HDK type pseudonymous random generation for BBS# key management because the author prioritized HDK. However, [BBS#](https://github.com/user-attachments/files/15905230/BBS_Sharp_Short_TR.pdf) would in theory present many advantages over the proposed HDK implementations:
- a single parameter is needed (a random), not 3 (public_key, private_key, salt)
- only local derivation is needed (no need for remote derivation)
- seed sharing between holder and issuer is not needed ==> much reduced overhead of the issuer (no need to store and secure one seed per holder)
- BBS# is designed from the ground up for full unlinkability which is not achievable with only HDK
- Privacy and security proofs are provided

## Contributing

Feedback and other input is easiest to discuss in [GitHub issues](https://github.com/sander/hierarchical-deterministic-keys/issues).

The technical reports and specifications in this repository may eventually be used to contribute to open standards. For the current repository, we apply practices inspired by the [Community Cryptography Specification Project](https://github.com/C2SP/C2SP).

To enable reuse, new contributions to the technical reports and specifications must be provided under either [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) or [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).
