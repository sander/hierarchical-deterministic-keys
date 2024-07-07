# Feedback to enable Hierarchical Deterministic Keys in the Wallet Toolbox

**Version:** 0.1.0-SNAPSHOT

**Authors:** Sander Dijkhuis (Cleverbase, editor)

**License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

## Context

For a general introduction, see [Hierarchical Deterministic Keys for the European Digital Identity Wallet](README.md). In the current document, the authors develop and share structured feedback on one part of the Wallet Toolbox: the [Architecture and Reference Framework](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/latest/arf/) (ARF). The purpose of this feedback is to enable implementation of [Hierarchical Deterministc Keys](keys.md) (HDKs).

By enabling Hierarchical Deterministic Keys, we aim for interoperability with a concrete and desirable cryptographic architecture in the context of person identification data and some (qualified) electronic attestations of attributes. We do not suggest to mandate the application of this cryptographic architecture for all digital identity documents. Instead, we aim to address two risks to the ARF and subsequently the implementing acts: the risk of accidentally disabling desirable technical solutions, and the risk of accidentally requiring undesirable technical solutions.

> [!NOTE]
> This information is shared by participants of the [Digital Credentials for Europe (DC4EU) Consortium](https://www.dc4eu.eu), the [EU Digital Identity Wallet Consortium (EWC)](https://eudiwalletconsortium.org), and the [Potential Consortium](https://www.digital-identity-wallet.eu). Views and opinions expressed are those of the authors only and do not necessarily reflect those of all consortium members.

## Feedback on the high level requirements

The original requirement texts are copied from ARF 1.4.0.

### Topic 9 - Wallet Trust Evidence

This topic currently specifies a very specific technical solution. To be applicable to HDKs, the requirements need to be either at a higher level, or more open to different technical solutions. The feedback below proposes more open requirements in Topic 9.

|Index|Proposed change|Rationale|
|--|--|--|
|WTE_*|Split WTE requirements into WTE requirements and Issuer Trust Evidence (ITE) requirements. Limit the WTE audience to authorised Person Identification Data (PID) Providers. Make requesting ITE optional to other providers.|Splitting requirements makes explicit the associated security and privacy conditions. HDK splits the WTE and ITE solutions as well. Splitting the requirements does not preclude solutions other than HDK from applying a single solution to create both WTE and ITE.|
|WTE_01–09|None.|N/A|
|WTE_10|Modify: “A WSCA SHALL generate a new key pair for a new WTE on request of the Wallet Provider via the Wallet Instance. The <del>WSCA</del> <ins>Wallet Instance</ins> SHALL register <ins>a unique identifier of</ins> the new key as a WTE key in an internal registry. The <del>WSCA</del> <ins>Wallet Instance</ins> SHALL register the WTE key as an independent (i.e., non-associated) key in an internal registry.”<br><br>Add: “<ins>A Wallet Instance SHALL generate a new key pair for a new ITE on request of the Wallet Provider, with the same WSCA-enforced access controls (see WTE_02) as a valid WTE key. The Wallet Instance SHALL register the new key in an internal registry. The Wallet Instance SHALL register the ITE key as associated with the WTE in an internal registry.</ins>”|This change is essential to the HDK architecture, where the WSCA is responsible only for device key pairs, and the other keys are managed as HDKs within the Wallet Instance. This change does not preclude solutions other than HDK from having the Wallet Instance delegate this functionality to a WSCA.|
|WTE_10–11|None.|N/A|
|WTE_13|Modify: “During PID or attestation issuance, a <del>WSCA</del> <ins>Wallet Instance</ins> SHALL generate a new key pair for a new PID or attestation, on request of the PID Provider or Attestation Provider <del>via the Wallet Instance</del>. <ins>The attestation key MUST be protected using the same WSCA-enforced access controls (see WTE_02) as a valid WTE key. The Wallet Instance MAY delegate key generation to the PID Provider or Attestation Provider.</ins> The PID Provider or Attestation Provider SHALL indicate a single WTE public key (see WTE_10) with which the new PID or attestation key must be associated<ins>, along with data identifying the method to be used for association</ins>. This indication can either be direct, by providing the WTE public key value, or indirect, by providing a public key value that has been associated with the WTE key previously. <del>In the latter case, the WSCA SHALL look up the associated WTE key in its internal registry.</del><br>The <del>WSCA</del> <ins>Wallet Instance</ins> SHALL register the new key in an internal registry as an attestation key. The <del>WSCA</del> <ins>Wallet Instance</ins> SHALL register the association between the new <del>private</del> key and the WTE <del>private</del> key in an internal registry.”|In HDK, the Wallet Provider, PID Provider, or Attestation Provider may asynchronously, remotely generate batches of single-use keys. These keys are under sole control of the User by association to a WTE key. Other proposed modifications are required to remove non-essential implementation details and thereby to enable HDK as in WTE_10.|
|WTE_14|Modify: “During PID or attestation issuance, a <del>WSCA</del> <ins>Wallet Instance</ins> SHALL prove possession of the private key corresponding to the new PID or attestation public key, <ins>or, in the case of delegated key generation, by proving possession of the key indicated in WTE_13</ins>, on request of the PID Provider or Attestation Provider <del>via the Wallet Instance</del>, for example by signing a challenge with that private key. <ins>Note that by design, this proof of possession implies that the WSCA has authenticated the user.</ins>”|In HDK, a single proof of possession to the PID or (Q)EAA Provider is sufficient to enable multiple unique one-time-use keys.|
|WTE_15–16|None.|N/A|
|WTE_17|Modify: “During PID <del>or attestation</del> issuance, a <del>WSCA</del> <ins>Wallet Instance</ins> SHALL prove possession of the private key corresponding to a WTE public key on request of a PID Provider <del>or Attestation Provider via the Wallet Instance</del>, for example by signing a challenge with that private key.”|With HDK, there is no need for roles other than PID Providers to learn wallet metadata. Therefore, disclosing an ITE is no requirement for issuance. Users may choose to disclose ITE data as part of releasing attributes, which is sufficiently covered by other requirements.|
|WTE_18|Modify: “During PID or attestation issuance, a <del>WSCA</del> <ins>Wallet Instance</ins> SHOULD generate a proof of association <del>for two or more public keys</del> <ins>whenever two or more public keys are disclosed</ins>, if and only if the corresponding private keys are protected by the same WSCA and the <del>WSCA</del> <ins>Wallet Instance</ins> has internally registered an association between these private keys.”|In HDK, typically only one public key is provided for issuance. In such cases, a proof of association is not applicable.|
|WTE_19|Modify: “During PID or attestation issuance, the PID Provider or Attestation Provider SHALL verify that:<br>• The <del>WSCA</del> <ins>Wallet Instance</ins> described in the WTE<ins>, if any, or ITE, if any,</ins> received from the Wallet Instance has proven possession of the private key corresponding to the public key in the WTE <ins>or ITE</ins> (see WTE_17),<br>•The <del>WSCA has proven possession of</del> <ins>Wallet Instance possesses</ins> the new PID or attestation private key (see WTE_14)<br>In addition, the PID Provider or Attestation Provider SHOULD verify that:<br>• The WSCA <del>has proven association (see WTE_18) between</del> <ins>protects with the same access controls</ins> the new PID or attestation public key and the public key requested by the PID Provider or Attestation Provider according to WTE_15 or WTE_16.”|In HDK, the PID Provider or Attestation Provider can apply HDK instead of a proof of association to verify equivalent WSCA protection between two keys.|
|WTE_20|Modify: “During PID <del>or attestation</del> issuance, a Wallet Instance SHALL provide the PID Provider <del>or Attestation Provider</del> with the WTE describing the properties of the WSCA that generated the new PID <del>or attestation</del> private key and protects it.”|In HDK, only PID Providers require WTE, and Attestation Providers do not require WTE or ITE. This modification does not preclude other technical solutions from still providing ITE to Attestation Providers over the same interface.|
|WTE_21–22|None.|N/A|
|WTE_23|Modify: “The common OpenID4VCI protocol defined in requirement ISSU_01 SHALL enable a Wallet Instance to transfer a WTE to a PID Provider <del>or Attestation Provider</del>.”|See WTE_20.|
|WTE_24|Modify: “A Wallet Instance SHALL release a WTE only to a PID Provider <del>or Attestation Provider</del>, and not to a <ins>Attestation Provider</ins> or Relying Party or any other party.”<br><br>Add: “<ins>A Wallet Instance SHALL release a ITE only to an Attestation Provider, and not to a Relying Party or any other party.</ins>”|See WTE_20.|
|WTE_25–26|None.|N/A|
|WTE_27|Add: “The common OpenID4VCI protocol SHALL enable a PID Provider or Attestation Provider to indicate in the Token Response:<br><ins>• in the case of delegated key generation, data enabling the Wallet Instance to prove possession of the private key associated with the new PID or attestation key</ins>”|This is essential to enable application of HDK to batch issuance.|
|WTE_28–30|None.|N/A|
|WTE_31|A <del>WSCA</del> <ins>Wallet Instance</ins> SHALL register each newly generated key pair as either a WTE key or an attestation key<del>, depending on information provided by the Wallet Instance in the key generation request</del>. The internal registry used by the <del>WSCA</del> <ins>Wallet Instance</ins> for this purpose SHALL be protected against modification by external parties.|See WTE_10.|
|WTE_32|None.|N/A|
|WTE_33|Modify: “A <del>WSCA</del> <ins>Wallet Instance</ins> SHALL associate each newly generated attestation key with a WTE key <del>indicated by the Wallet Instance</del>. The <del>WSCA</del> <ins>Wallet Instance</ins> SHALL record the association between these keys in an internal registry, which SHALL be protected against modification by external parties.”|In HDK, the Wallet Instance maintains the associations.|
|WTE_34|Drop.|This is an implementation detail only to some technical solutions.|
|WTE_35|A <del>WSCA</del> <ins>Wallet Instance</ins> SHALL consider two keys to be associated if they are associated to a common WTE key.|See WTE_10.|
|WTE_36|Modify: “A <del>WSCA</del> <ins>Wallet Instance</ins> SHOULD be able to generate a proof of association for two or more public keys. The <del>WSCA</del> <ins>Wallet Instance</ins> SHALL generate such a proof <del>if and</del> only if the corresponding private keys are protected by <del>that</del> <ins>a single</ins> WSCA, and the <del>WSCA</del> <ins>Wallet Instance</ins> has internally registered an association between these private keys.”|In HDK, the Wallet Instance manages such associations. This does not preclude solutions other than HDK to delegate this to the WSCA.|
|WTE_+|New: “<ins>A PID Provider SHALL for newly generated attestation keys only support cryptographic algorithms and parameters as agreed in SOG-IS. A PID Provider SHALL support ECDH-MAC. A PID Provider MAY support EC-SDSA-opt.|With the currently more common ECDSA algorithm, Wallet Providers can in practice only implement the WTE and ACP requirements with licenses to (pending) patents. In contrast, ECDH-MAC appears unencumbered, and also provides better privacy. In case the PID Provider requires non-repudiation, EC-SDSA-opt is an agreed algorithm that also provides a viable unencumbered alternative.|

### Topic 18 - Relying Party handling EUDI Wallet attribute combined presentation

With HDK, document readers do not need the proof of association, as they may instead rely on attributes attested by issuers. Since the issuers apply HDK, they can for example ensure binding to PID.

To enable HDK, the following changes to Topic 18 are needed.

|Index|Proposed change|Rationale|
|--|--|--|
|ACP_01–03|None.|N/A|
|ACP_04|Drop or modify: “If (as a result of ACP_03) a Wallet Instance determines it must release multiple attestations to a Relying Party in a combined presentation of attributes, it <del>SHALL request</del><ins>MAY generate</ins> a proof of association between the public keys of these attestations<del> from the WSC</del>.”|Proof of association is not necessary in the case of attribute-based binding. It could introduce disproportional complications. For example, depending on the proof mechanism, this could produce a potentially non-repudiable proof that a certain combination of documents was revealed. Also, by disclosing public keys related to blinding scalars, it will be more difficult for solutions to guarantee unconditional privacy.|
|ACP_05|Drop.|It is up to the User whether to authorise sharing a proof of association with another party.|
|ACP_06–08|None.|N/A|
|ACP_09|Drop.|With HDK, proof of association is not essential.|

## Feedback on proof of association

This feedback is based on a information on “proof of association”, which is closely related to the high level requirements related to Wallet Trust Evidence (WTE) and Attribute Combined Presentation (ACP). The information is also valuable to the design of HDK.

To summarise the feedback:

- The proof of association proposal introduces one useful WSCD security requirement, and two WSCD security requirements that are too complicated for the European Digital Identity Wallet.
    - Only the proposed InCertWSCD (ICW) requirement should be mandatory for WSCD certification.
    - The proposed SameWSCD1 (SW1) requirement should be optional for WSCD certification. Instead, HDK enables a similar objective without the complexity of SW1.
    - The proposed SameWSCD2 (SW2) requirement should be optional for WSCD certification.  We have not yet seen a solid use case.
- The proof of association proposal consequentially introduces a solution with too complicated WSCD instructions. Only the generation and deletion of attested device keys, and the basic operations with these keys are necessary. The wallet application can build upon these device keys the necessary WTE keys and other keys. Using HDK, issuers and readers can derive the necessary associations without the need for proof of association.
- The proof of association proposal, if fully implemented with ICW+SW1+SW2, has consequences for interoperability and for WSCD implementation cost.
    - Since the proof of association is only defined for multiplicative key blinding, only ECDH-MAC could be implemented using HDK. However, HDK requires the WSCD to support “full Diffie-Hellman” with the device key, which cannot be met with SW2.
    - If the proof of association would also be defined for additive key blinding, also EC-Schnorr (EC-SDSA and EC-SDSA-opt) could be implemented using HDK. Note that EC-Schnorr is unsupported in mdoc.
    - It is not possible to implement the proof of association with EdDSA using HDK, because the algorithm includes hashing the original public key. Note that EdDSA is not agreed by SOG-IS so it would be difficult to certify a WSCD for EdDSA within the EU.
    - Implementing ECDSA using HDK or another scalable approach would require one or more patent licenses, incurring risk and cost to WSCD implementers.
    - Implementations that do not use HDK or a similar approach would be expensive, since they would require either:
        - Cryptographic modules with native key blinding support, which no existing solutions have.
        - Generating dedicated one-time-use keys within the cryptographic module, which limits the ability to store many documents, and which may create a bad user experience.

### Context

We follow the interpretation that the Wallet Secure Cryptographic Device (WSCD) must be Common Criteria certified at assurance level EAL4+.

We follow the envisioned WSCD architecture classification: External, Internal, Remote HSM, Internal Native.

### Security problem

We follow the argument that mobile app attestation is insufficient to protect the issuance process against a high attack potential. At least evidence based on key attestation is required.

Proof of association relates to three WSCD security requirements:

|ID|Requirement|Comment|
|--|--|--|
|ICW|**InCertWSCD:** Enable issuers to verify that a new PoP public key is bound to a certified WSCD.|HDK is designed to meet this requirement. Note that likely only PID issuers need direct verification based on key attestation.|
|SW1|**SameWSCD1:** Enable issuers to verify that a new PoP public key is bound to the same certified WSCD as the PoP public key of the PID.|HDK is designed to meet this requirement. It should be considered beyond PID as well: for example, to enable attestation issuance with equivalent hardware protection as a previous attestation but without binding to PID data.|
|SW2|**SameWSCD2:** Enable readers to verify that two PoP public keys are bound to a certified WSCD, and to the same certified WSCD as a PID PoP public key.|HDK is not designed to meet this requirement, but it could be applied in a way that meets it. But as explained in [Proofs of association](keys.md#proofs-of-association), the requirement of cryptographic binding is problematic. SameWSCD2 should be optional.|

Requirement SW2 is intended to address the threat of credential pooling with app hooking used to achieve unauthorised transactions. Instead of SW2, we suggest a mitigation based on a hybrid of cryptographic and claim-based binding, without the use of SW2. Based on the example of a minor attacker buying alcohol using an older sibling’s 18+ and Photo ID in a physical shop:

- The minor attacker has:
    - a PID bound to their own WSCD;
    - a Photo ID bound to the same WSCD (SW1), including all PID claims.
- The older sibling has:
    - a PID bound to their own WSCD;
    - an 18+ ID bound to the same WSCD (SW1), including all PID claims.
- Indeed, if the reader would just ask for the photo and 18+ claim, the minor attacker could deceive the reader by hooking both wallet apps together.
- However, the reader can request:
    - Photo ID presentation, including:
        - the photo
        - sufficient PID
        - proof of possession
    - 18+ ID presentation, including:
        - 18+ claim
        - sufficient PID
        - proof of possession
- What “sufficient PID” entails, depends on the domain’s and the local circumstances and implementation of privacy requirements. For example, some EU member states have more people sharing given and family names than others.
- In this example, the proof of possession mitigates the threat of cloning. The claim-based binding mitigates the threat of hooking.
- If the reader would also request a proof of association (SW2), this introduces two disproportional new problems:
    - It creates non-repudiable evidence of each time the combination of Photo ID and 18+ ID was presented. The privacy impact of such evidence has been insufficiently studied.
    - It complicates the trust model and associated liability. Without proof of association, the issuer trusts the wallet and the reader trusts the issuer. With proof of association, the reader also trusts the wallet. It is unclear if wallet providers will assume liability towards readers for correct creation of proofs of association, or if readers will otherwise be covered in the case of incorrect binding. Either way, the additional risk assessment will be costly to the alcohol shop owner. Note that zero-knowledge proofs as in Algorithm 2 may lack a solid EU-wide legal foundation.
- In case it is desirable to fully hide any PID from the reader, a trusted issuer can instead issue a single (derived) document containing both the photo and the 18+ claim. This provider would refuse issuance to the minor attacker.

The proof of association proposal includes three WSCD instructions:

|ID|WSCD instruction|Comment|
|--|--|--|
|1|Generate attested WTE key|HDK implementations benefit from having this instruction in a certified WSCD. It enables a PID issuer to verify that an HDK device key is protected within the WSCD upon wallet validation.<br><br>The WSCD relies upon attestation of the device key and proof of knowledge of the root key blinding key, and issues a WTE document containing the blinded key. Indeed, the WSCD should be audited to perform this process correctly.<br><br>Note that the wallet provider should additionally be audited to configure the WSCD appropriately, such as setting a valid root store policy for key attestation.|
|2|Generate key associated to WTE|HDK instead applies ARKG outside of the WSCD, delegating key generation to the document issuer, without requiring re-authentication of the user each time. This enables issuers to create batches of one-time-use documents with unique, associated PoP keys. Therefore instruction 2 should be optional.|
|3|Generate proof of association|HDK does not maintain an association file within the WSCD. Instead, HDK requires the wallet application on top of the WSCD to record key blinding keys. Using these records, a wallet solution implementing HDK could also generate a proof of association. Therefore instruction 3 should be optional.|

### Cryptography proposal

In the proposal based on elliptic curve cryptography, a proof of association between keys `P` and `Q` enables verification that its generator knows an association key `z` such that `Q=[z]P`. This proof could for example be an EC-SDSA signature with a custom base point (“EC-Schnorr”). In HDK, the keys would be based on a device key `D=[d]G` such that `P=[p]D` and `Q=[q]D`, so `z=q/p`.

The proposal includes the concept of “distributed WSCD” based on malleability-based threshold cryptography. Instead of certifying a “distributed WSCD”, it is simpler to reduce the scope of the WSCD certification to the component that is responsible for managing what is in HDK called the device key, including user access control. Indeed, HDK-ECDH-P256 applies “Split-ECDH-MAC”. Note that application of “Split-ECDSA” requires at least the wallet provider to obtain patent licenses as per the Stack Exchange article [Blinding an ECDSA private key without learning the private key](https://crypto.stackexchange.com/questions/110997/blinding-an-ecdsa-private-key-without-learning-the-private-key).

The proposal includes a mitigation to association forgery attacks, which affect ECDSA and ECDH-MAC when used with proof of association. A malicious issuer who knows a victim’s PoP public key could forge a second PoP key and a proof of association between both. In the case of ECDSA, because of signature malleability, the attacker could also abuse a previously obtained PoP signature to forge a PoP signature for the forged key. By doing both on a chosen message containing forged claims, the attacker could make readers believe that the user has presented these claims with WSCD-binding and PID-binding. The proposed mitigation is to require the WSCD to pre-process or post-process WTE key operations using a cryptographically secure hash, and not exposing “raw” operations for WTE keys. Instead, we suggest to avoid this complexity by not relying upon proof of association.

Note that ECDH-MAC proof of association may also be possible using additive blinding, as specified in ARKG. The proof could for example be a Schnorr non-interactive zero-knowledge proof of knowledge of the discrete logarithm of the difference between the two public keys.

### Implementation

The proposal is demonstrated by three example WTE architectures: Optimally Efficient, Privacy Friendly, PID-Bound. The HDK architecture enables a variant of the PID-Bound WTE architecture:

- WSCDs issue WTE for PID issuers bound to blinded root keys, based on a wallet instance’s proof of knowledge of the associated root key blinding key;
- Any issuer can generate keys associated with any previously presented attestation’s key (Parent-Binding), without requiring additional metadata such as WTE or ITE or a proof of association.
