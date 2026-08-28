# AGENTS.md

## Editing the Internet-Draft

When editing `draft-dijkhuis-hdk.md`, follow the principles in *Guidelines for Writing Cryptography Specifications* (`draft-irtf-cfrg-cryptography-specification`), without citing that document from the Internet-Draft merely as a style guide.

In particular:

- State the problem and scope before the mechanism.
- Prefer simple, precise, consistent terminology and notation; define acronyms on first use.
- Reuse standard primitives, encodings, and terminology instead of inventing aliases.
- Explicitly define custom operations, inputs, outputs, encodings, validation, errors, and exceptional cases.
- Keep dependencies and assumptions clear, and distinguish imported standard operations from operations defined by this specification.
- Avoid unnecessary branching or multiple valid implementation behaviors.
- Explain deviations from related constructions and their interoperability and security consequences.
- Include concrete examples and, before publication, reproducible test vectors covering normal operation and reachable error paths.
- State security goals, assumptions, limitations, relevant attacks, and implementation/deployment considerations explicitly.
- Keep random generation at protocol boundaries where practical so deterministic derivation can be tested independently.

Review these points after substantive cryptographic changes rather than treating them only as prose guidance.
