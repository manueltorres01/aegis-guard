# Contributing to Aegis Guard

Thank you for helping improve defensive security. By participating, you agree to keep contributions safe, testable and auditable.

## Development workflow

1. Fork the repository and create a focused branch.
2. Run `npm ci` (or `npm install` when no lockfile exists).
3. Make the smallest useful change and add tests.
4. Run `npm run ci`.
5. Open a pull request describing security impact and false-positive risk.

## Safety rules

- Never commit live malware, weaponized proof-of-concepts, credentials or personal data.
- Use the built-in harmless simulator or the standard EICAR test string.
- Detection rules must include benign and positive test cases.
- Quarantine and restoration changes must remain fail-closed and must never overwrite files.
- Report exploitable vulnerabilities privately according to `SECURITY.md`.

By contributing, you license your contribution under the MIT License.
