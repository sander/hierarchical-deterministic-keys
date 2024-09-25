# HDK and PoA for the EUDIW

## Context

The binding of attestation (PID, QEAA, PuB-EAA, EAA) keys to critical assets in certified WSCDs, and the ability to prove this binding is critical for security of EUDI wallets. Relying party unlinkability is critical to its privacy. Several experts are proposing solutions that could work for the first wallet deployments.

The Commission and standardisation organisations are looking into two documents related to these subjects:

- [Attestation Proof of Association](https://eprint.iacr.org/2024/1444) (PoA)
- [Hierarchical Deterministic Keys](https://github.com/sander/hierarchical-deterministic-keys) (HDK)

The first is prepared in collaboration between experts from Member State. The second is prepared in an informal collaboration between experts from public and private sector participants in Large Scale Pilots. Both PoA and HDK propose concrete short-term considerations in two areas:

- implementation of the wallet solution internally
- interoperability between wallet units and other entities

Both of these types are relevant to security and interface requirements in law and standards. This document analyses the common ground and contentious issues and proposes next steps.

## Implementation considerations

### Common grounds on implementation

#### Verifiable association of public keys to a single attested WSCD

Both docs suggest applications of key blinding for unlinkability between presentations, based on a single WSCD key pair. At least one trusted issuer should receive trust evidence issued by the wallet provider, which attests this WSCD key pair, potentially with blinding. This is an important requirement to protect against unauthorised use of attestations.

To follow up:

- Ensure the ARF and implementing acts continue to contain this requirement.

#### Distributed WSCA deployment

Both docs suggest that a WSCA can be distributed across the user device and an external, possibly remote WSCD. They apply threshold signatures or multiple-ECDH schemes, performing the critical security functions in an off-the-shelf WSCD. This may be the only way to meet the regulation deadlines, since developing and certifying new WSCDs will take too much time in practice.

Related ARF issue: [#283](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/issues/283). Method to resolve the issue:

- Update the ARF and implementing act text to acknowledge that the WSCA does not need to be hosted on the WSCD, but can for example be distributed.

### Contentious issues on implementation

#### Patent risks to wallet providers

In practice, EUDI wallets would use either ECDSA or ECDH-MAC, which are widely supported by off-the-shelf WSCDs and can be applied in a distributed WSCA deployment. Several patent claims seem to apply to the new and innovative ECDSA option. While HDK could be extended to support ECDSA, it is left out of the doc to leave any commercial interests out of the informal cross-LSP working group. If ECDSA becomes the de-facto standard, this would require all wallet providers using off-the-shelf WSCDs to deal with these patents. Experts so far do not see similar risk with ECDH-MAC.

Related ARF issue: [#286](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/issues/286). Options to resolve this issue:

- Investigate the patents and potentially negotiate licensing conditions at the EU-level.
- Mandate the use of at least ECDH-MAC to enable at least one open standards-based route.
- Leave the risk to the individual wallet providers.

## Interoperability considerations

### Common grounds on interoperability

#### Cryptographic proofs of association to relying parties

Both approaches enable the construction of a cryptographic proof of association based on zero-knowledge proofs. This enables proving association between attestations towards relying parties. The method is complementary to other methods for proof of association. These should co-exist since parties are also working on WSCAs that cannot create the zero-knowledge proof but will have other certified ways to assure relying parties of association.

To follow up:

- Require attestation protocols to provide sufficient flexiblity to support zero-knowledge proof of association.

### Contentious issues on interoperability

#### Proof of association requirements to attestation providers

Both PoA and HDK convince attestation providers that a newly generated key is associated with a previously attested key. But the methods are different:

- PoA provides the same zero-knowledge proof as to relying parties.
- HDK applies key share agreement with the wallet unit, which directly proves to the attestation provider association with a previously presented key.

There is a tradeoff to make. Arguably, HDK is simpler and enables other features such as delegated key share generation. However, it is not in zero-knowledge, which at least theoretically reduces confidentiality. So far, no concrete abuse scenarios are known.

Options to resolve the issue:

- Leave the ARF and implementing acts open towards the method of proving association.
- With an advisory group, analyse the pros and cons of each approach and select one.

#### Delegated key share generation

By applying key share agreement, HDK can delegate the generation of additional association key shares to the attestation provider. This enables more efficient batch re-issuance. For example, the provider could periodically issue a new batch, without wallet unit interaction, while still being sure that the new public keys are bound to the same WSCD. In the PoA approach, this would generate periodic interaction with the wallet unit, or the wallet unit should pre-generate a high number of keys and proofs of association.

Related ARF issue: [#284](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/issues/284). Options to resolve the issue:

- Update the ARF and implementing acts to enable delegated key share generation.
- With an advisory group, analyse concrete re-issuance scenarios and decide whether the pros outweigh the cons.

#### Use of implicit trust evidence

One driver for development of HDK is to enable attestation providers to rely on PID presentation not only for identity verification, but also for assurance of WSCD binding. If the attestation provider can generate a new public key based on a previously presented PID key, they do not need additional trust evidence. This could simplify the process for non-PID issuers and reduce dependence on wallet provider availability. The current ARF and implementing act texts instead make the use of trust evidence mandatory, and the PoA document focuses on methods to apply this trust evidence in combination with proof of association.

Related ARF issues: [#285](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/issues/285), [#286](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/issues/286). Options to resolve the issue:

- Update the ARF and implementing acts to enable the use of implicit trust evidence.
- With an advisory group, analyse pros and cons of each approach to the verify-PID-then-issue-EAA use case.
- Leave explicit trust evidence mandatory, even when it is not needed for attestation issuers.

## Proposed next steps

1. Discuss these issues with the Commission and ARF authors for shared understanding, and triage if some may have already been resolved.
2. Organise an ad-hoc technical advisory group to analyse the remaining issues.
3. Present the results to an expert group for Member State feedback.
4. Record the conclusions and any remaining open issues in the ARF project on GitHub.
