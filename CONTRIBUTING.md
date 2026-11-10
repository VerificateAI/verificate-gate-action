# Contributing

Thanks for helping. This repository is the public client for the hosted Verificate Gate; the gate engine
itself is not open source, so changes here are about the integration: install paths, client behaviour,
documentation and examples.

## Issues

- **Bugs:** say what you ran, what you expected, what happened, and your client (Claude Code, Cursor, VS Code,
  GitHub Actions…) and version. Remove tokens and private code from anything you paste.
- **A verdict you disagree with** (false positive / false negative): include the smallest snippet that
  reproduces it. These reports directly improve the gate.
- **Security issues:** never in a public issue — see [SECURITY.md](SECURITY.md).

## Pull requests

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Keep a PR to one change. Add or update a test when behaviour changes.
3. Run the repository's checks locally before pushing (see the workflow files under `.github/workflows/`).
4. `main`/`master` is protected: CI must pass and a maintainer must review.

By contributing you agree that your contribution is licensed under this repository's [LICENSE](LICENSE).

## Conduct

Be respectful and assume good faith. Harassment or abuse is not tolerated; maintainers may remove comments,
close issues, or block accounts that do not meet that bar. Report concerns to info@verificate.ai.
