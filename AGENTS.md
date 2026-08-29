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

## Git and Pull Requests

When making repository changes or preparing a pull request:

- Start the working branch directly from the current target branch, normally `main`.
- Keep the branch history minimal and limited to intentional changes. Do not create temporary, probe, placeholder, or cleanup commits to test repository access or tooling.
- If a branch accidentally acquires unrelated or temporary commits, rewrite/reset it onto the target branch before opening or updating the pull request.
- Before considering a pull request ready, compare the branch against its target and verify that only the intended files and changes are present.
- Preserve repository formatting, including a final newline in text files.
- Run the repository's build and lint checks when possible. If CI is used, inspect failures and fix them before considering the pull request complete.
- Do not report a pull request as complete merely because it was opened; verify its diff/history and build status first.
