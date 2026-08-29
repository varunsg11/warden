# Security Policy

## Status

Warden is a **research and educational prototype** that demonstrates a defense
against indirect prompt injection for LLM agents. It is not a hardened, production
security product, and it should not be relied upon as your only control.

Notably, the demo uses:
- an in-memory, single-key Supervisor (no key rotation, HSM, or distribution),
- a small static policy and a simple statistical drift baseline,
- symmetric trust between the Supervisor and gate within one process.

Containment is only as strong as the least-privilege policy you write — see the
limitations in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Reporting a vulnerability

If you find a security issue in this code, please open a GitHub issue, or for
anything sensitive, contact the maintainer privately rather than filing a public
issue. Please include steps to reproduce and the impact.

## Secrets

Never commit real secrets. `.env` is git-ignored; use `.env.example` as the template.
`OPENAI_API_KEY` is only needed to run the demos against a real model — the entire
test suite and the offline demos run with `WARDEN_FAKE_LLM=1` and no key.
