# Key management challenges for the European Digital Identity Wallet

**Version:** 0.1.0-SNAPSHOT

**Authors:** Sander Dijkhuis (Cleverbase, editor)

**License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

For a general introduction, see [Hierarchical Deterministic Keys for the European Digital Identity Wallet](README.md). The current document provides an overview of key management challenges and viable solution directions. This provides an application context to the [Hierarchical Deterministic Keys](draft-dijkhuis-cfrg-hdkeys.md) specification.

Solutions marked with * are in scope for that specification.

<table><thead>
  <tr>
    <th>Feature</th>
    <th>Quality</th>
    <th>Solution</th>
    <th>Comment</th>
  </tr></thead>
<tbody>
  <tr>
    <td rowspan="2"><b>1. Document authenticity</b></td>
    <td>Qualified</td>
    <td>Provider-controlled QSCD</td>
    <td>Required for QEAA and PuB-EAA. Typically supports the RSA-PSS, ECDSA, and EC-SDSA algorithms.</td>
  </tr>
  <tr>
    <td>Non-qualified</td>
    <td>Provider-controlled cryptographic module</td>
    <td>For example, an EN 419221-5 certified HSM.</td>
  </tr>
  <tr>
    <td rowspan="2"><b>2. Prevention of tracking based on metadata</b></td>
    <td>Weak</td>
    <td>One-time-use documents</td>
    <td>Users could still be tracked across colluding data providers and readers, whether they are colluding intentionally or not, using the provider’s document authenticity seal and potentially other data provider’s metadata.</td>
  </tr>
  <tr>
    <td>Full</td>
    <td>Anonymous credentials</td>
    <td>E.g. <a href="https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/issues/193#issuecomment-2179355934">BBS#</a>, which requires a solution for document authenticity protection that supports the BBS+ algorithm.</td>
  </tr>
  <tr>
    <td rowspan="4"><b>3. WSCD binding</b> with attested keys</td>
    <td rowspan="3">Local</td>
    <td>External standalone device</td>
    <td rowspan="4">Also called “cryptographic holder binding”, since the device authenticates its holder. In ARF 1.4, these keys are WTE keys. Required for meeting High Level of Assurance requirements for PID. Typically certified for ECDSA, EC-SDSA, or ECDH. See specification section “Secure cryptographic device”.</td>
  </tr>
  <tr>
    <td>Internal standalone programmable cryptographic chip</td>
  </tr>
  <tr>
    <td>Internal preprogammed security platform</td>
  </tr>
  <tr>
    <td>Remote</td>
    <td>Hardware security module</td>
  </tr>
  <tr>
    <td rowspan="2"><b>4. Proving WSCD binding</b></td>
    <td>Non-repudiable</td>
    <td>Digital signature algorithm</td>
    <td>E.g. ECDSA, EC-SDSA.</td>
  </tr>
  <tr>
    <td>Repudiable</td>
    <td>Designated verifier signatures</td>
    <td>E.g. ECDH-MAC.</td>
  </tr>

  <tr>
    <td rowspan="3"><b>5. Per-attestation key blinding</b> for relying party unlinkability</td>
    <td>Synchronous</td>
    <td>Flat key registry with mandatory proof of association</td>
    <td>See whitepaper on proof of association.</td>
  </tr>
  <tr>
    <td rowspan="2">Asynchronous</td>
    <td>Hierarchical Deterministic Keys with optional proof of association*</td>
    <td>Provides pseudonymous diversification of device keys. Performed or delegated by the Wallet Instance. See <a href="keys.md">specification</a>.</td>
  </tr>
  <tr>
    <td>Multi-message signature scheme</td>
    <td>E.g. BBS+. Enables blinding a proof of possession key after issuance, locally in the wallet. Requires standardisation, development and certification of supporting QSCD solutions.</td>
  </tr>
  <tr>
    <td rowspan="2"><b>6. Proving blinded key possession</b></td>
    <td>Centralised</td>
    <td>Key blinding for signature schemes</td>
    <td>Requires standardisation, development and certification of WSCD solutions with key blinding support.</td>
  </tr>
  <tr>
    <td>Distributed</td>
    <td>Threshold signing*</td>
    <td>Distributed across WSCD and Wallet Instance. See specification section “Generic HDK instantiations”.</td>
  </tr>
  <tr>
    <td rowspan="2"><b>7. Qualified signature and seal</b> creation using a Wallet Instance</td>
    <td>Local</td>
    <td>Signer-controlled internal or external QSCD</td>
    <td>Typically accessed by the Wallet Instance over an PKCS#11 interface.</td>
  </tr>
  <tr>
    <td>Remote</td>
    <td>Signer-controlled remote QSCD</td>
    <td>Typically accessed by the Wallet Instance or Relying Party over a CSC interface, with enrolment using PID.</td>
  </tr>
</tbody></table>