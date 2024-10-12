# Feedback to enable Hierarchical Deterministic Keys in the Wallet Toolbox

**Version:** 0.2.0-SNAPSHOT

**Editor:** Sander Dijkhuis (Cleverbase)

**License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

**Discussion:** [eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework#282](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/discussions/282)

## Context

For a general introduction, see [Hierarchical Deterministic Keys for the European Digital Identity Wallet](README.md). In the current document, the authors develop and share structured feedback on one part of the Wallet Toolbox: the [Architecture and Reference Framework](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/latest/arf/) (ARF). The purpose of this feedback is to enable implementation of [Hierarchical Deterministc Keys](draft-dijkhuis-cfrg-hierarchical-deterministic-keys.md) (HDKs).

By enabling Hierarchical Deterministic Keys, we aim for interoperability with a concrete and desirable cryptographic architecture in the context of person identification data and some (qualified) electronic attestations of attributes. We do not suggest to mandate the application of this cryptographic architecture for all digital identity documents. Instead, we aim to address two risks to the ARF and subsequently the implementing acts: the risk of accidentally disabling desirable technical solutions, and the risk of accidentally requiring undesirable technical solutions.

> [!NOTE]
> This feedback document is a first version, and requires detailed exchanges to understand each other’s detailed points of view. This information is shared by participants of the [Digital Credentials for Europe (DC4EU) Consortium](https://www.dc4eu.eu), the [EU Digital Identity Wallet Consortium (EWC)](https://eudiwalletconsortium.org), and the [Potential Consortium](https://www.digital-identity-wallet.eu). Views and opinions expressed are those of the authors only and do not necessarily reflect those of all consortium members.

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
