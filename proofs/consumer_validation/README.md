# Consumer-side propagation validation

This bounded harness executes the production matcher inside the real Provider
`/access` route, passes the returned OTK to the real receiver handshake, and checks
that a token is sent and stored in `active_tokens`. It does not execute message
acceptance, `local_agent.run`, an LLM, or tools. No bridge, ProVerif, paper, or
production source modifications are required.

## Run

Use Python 3.10+ (validated environment is recorded in each manifest), the packages
in `requirements.txt`, and a local MongoDB `mongod` executable supporting aggregation
update pipelines. From repository root:

```text
python -m venv proofs/consumer_validation/.runtime/venv
<venv-python> -m pip install -r proofs/consumer_validation/requirements.txt
<venv-python> -B proofs/consumer_validation/run_phase1.py --mongod <path-to-mongod>
```

The runner starts its own loopback-only MongoDB on a dynamically chosen port, uses
temporary keys/data under `.runtime`, and terminates that process and removes those
temporary resources on exit. It never attaches to an existing database. Runtime
dependencies are ignored by Git. No externally hosted CA, Provider, or model is used.
The socket port reservation has a small release/start race: a collision fails startup
rather than attaching to the existing listener. A child process must remain alive.

The runner first executes the harness unit tests, then A/A, D/D and D/A sequentially.
Each case has a fresh database, Agent state, signing material and OTK. Budgets are
10 and -1. Zero-budget receiver/Provider differences are outside this experiment.
The D/D receiver path is **not reached**, not an observed receiver rejection.

## Boundaries

Fixture registration records have genuine signatures and certificates. Production
Provider and Agent constructors, route, matcher, signature/certificate checks, MongoDB
pipeline, receiver OTK deletion, X25519/HKDF and token encryption/storage are real.
CA download construction and Provider certificate retrieval are replaced by local
fixtures. Flask supplies the TLS certificate environment; MemoryConnection supplies
the peer DER certificate and framed bytes. TLS handshakes and registration are not
tested. Initiator handshake construction is a script, not Agent.connect execution.

Only `Agent.receive_conversation` is truncated. Its stub records whether the token
has already been sent/stored and initializes empty timing records needed by the
handler epilogue. It executes no conversation logic. The LocalAgent implementation
counts and raises on every run call. No conversation frames exist in the connection;
an extra read raises and is counted. Matcher spies preserve inputs, results and
exceptions at both production consumer import sites.

Allow-case success requires: matching actual policies/identities; observed matcher
budgets; HTTP 200 with the correct OTK; Provider OTK/signature consumption and counter
9; receiver OTK consumption; one sent token; the same token in active_tokens; matching
initiator-side decryption, PAC, initial quota and validity interval; exactly one
boundary call; zero backend calls and zero conversation reads. Denial requires HTTP
403, one Provider matcher observation, unchanged state, and no downstream execution.

## Evidence

Archives exist only under this directory's `evidence/`. Creation is exclusive and an
existing name/file is never overwritten. `--archive-name NAME` selects a new name.
Failure archives are retained and the runner exits nonzero. Random keys/nonces mean
reproduction compares assertions, not ciphertext byte equality.

- `run-start.json`: initial source hashes, Git state, environment and declared mocks.
- `manifest.json`: run status, independent expectations status, source before/after
  hashes, actual MongoDB version/executable hash, dependency versions and artifact hashes.
- `cases/<id>/input.json`: concrete identities, ordered policies, read-only bridge
  evaluate result, context fingerprint, certificate fingerprints and quota.
- `cases/<id>/events.jsonl`: ordered case/attempt-bound matcher, HTTP, handshake,
  token-send, boundary and issuance-check events. OTK/token hashes join the stages.
- `cases/<id>/result.json`: real HTTP response, handshake, before/after state, decoded
  token metadata, assertions, outcome and exceptions. Private keys/SDHK are excluded.
- `tests-stdout.txt`, `tests-stderr.txt`, `stdout.txt`, `stderr.txt`, `summary.txt`:
  actual execution output. ANSI escapes and SDHK/generated-token log values are removed.

`not_reached` is distinct from rejection or success. The manifest does not hash itself;
all other archive files are hashed. Archive-local `.gitattributes` preserves bytes.
Hashes bind evidence for inspection; they are not signatures or independent attestations.
The policy owner is a concrete fixture receiver, not a deployed ownership observation.
Current dirty Git state is recorded honestly; actual source bytes are hashed separately.

## Claim boundary

These experiments support only bounded consumer propagation to token issuance under
the listed fixtures and transport substitutes. They add execution evidence beyond a
matcher-only observation. They do not prove message acceptance, deployment exploitation,
Python/ProVerif equivalence, universal policy correctness, concurrency properties, or
production TLS security. They do not expand the conclusions of the formal models.
