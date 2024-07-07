# Key management challenges for the European Digital Identity Wallet

<table><thead>
  <tr>
    <th>Feature</th>
    <th>Quality</th>
    <th>Option</th>
    <th>Comment</th>
  </tr></thead>
<tbody>
  <tr>
    <td rowspan="2">Document authenticity</td>
    <td>Qualified</td>
    <td>Provider-controlled QSCD</td>
    <td>Required for QEAA and PuB-EAA. Typically supports RSA-PSS, ECDSA, EC-SDSA.</td>
  </tr>
  <tr>
    <td>Non-qualified</td>
    <td>Provider-controlled cryptographic module</td>
    <td>For example, an EN 419221-5 certified HSM.</td>
  </tr>
  <tr>
    <td rowspan="4">Device binding with attested keys</td>
    <td rowspan="3">Local</td>
    <td>External standalone device</td>
    <td rowspan="4">In ARF 1.4, these are WTE keys. Required for meeting High Level of Assurance requirements for PID. Typically certified for ECDSA, EC-SDSA, or ECDH. See specification section “Secure cryptographic device”.</td>
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
    <td rowspan="3">Managing many associated keys</td>
    <td>Synchronous</td>
    <td>Flat key registry with proof of association</td>
    <td>See whitepaper on proof of association.</td>
  </tr>
  <tr>
    <td rowspan="2">Asynchronous</td>
    <td>Hierarchical Deterministic Keys</td>
    <td>Performed or delegated by the Wallet Instance. See specification.</td>
  </tr>
  <tr>
    <td>BBS signature scheme</td>
    <td>Requires standardisation, development and certification of WSCD solutions with BBS+ support.</td>
  </tr>
  <tr>
    <td rowspan="2">Proving possession of device keys</td>
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
    <td rowspan="2">Proving possession of associated keys</td>
    <td>Central blinding</td>
    <td>Key blinding for signature schemes</td>
    <td>Requires standardisation, development and certification of WSCD solutions with key blinding support.</td>
  </tr>
  <tr>
    <td>Distributed blinding</td>
    <td>Threshold signing</td>
    <td>Distributed across WSCD and Wallet Instance. See specification section “Generic HDK instantiations”. </td>
  </tr>
  <tr>
    <td rowspan="2">Privacy across interactions</td>
    <td>Weak unlinkability</td>
    <td>One-time-use documents</td>
    <td>Users could still be tracked across corrupt data providers and readers.</td>
  </tr>
  <tr>
    <td>Full unlinkability</td>
    <td>BBS# anonymous credentials</td>
    <td>Requires document authenticity protection with BBS+.</td>
  </tr>
  <tr>
    <td rowspan="2">Creating electronic signatures or seals</td>
    <td>Local</td>
    <td>Signer-controlled internal or external QSCD</td>
    <td>Typically accessed by the Wallet Instance over an PKCS#11 interface.</td>
  </tr>
  <tr>
    <td>Remote</td>
    <td>Signer-controlled remote QSCD</td>
    <td>Typically accessed by the Wallet Instance over a CSC interface, with enrolment using PID.</td>
  </tr>
</tbody></table>