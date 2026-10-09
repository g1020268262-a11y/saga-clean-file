# Authorization Decision Bridge

The Decision Bridge is an executable finite-semantics layer for the recorded
SAGA matcher counterexample. It produces a checked specification/implementation
decision pair and can reconstruct the fixed scenario region of the retained
ProVerif template.

It does not import the production matcher during replay, prove the evaluator
correct, model arbitrary `fnmatch` policies, execute a service, or establish an
implementation-to-model refinement theorem.

## Inputs

The default replay uses:

- the archived production observation at
  `proofs/evidence/authz-stage1-20260916T123834944479Z/policy-matcher-sanity.json`;
- the pinned upstream matcher source revision
  `7372111bea150e32cee390a616849316d2780bfc`;
- the fixed model template
  `proofs/proverif/agent_communication_authz_chat_turepass.pv`; and
- the concrete ordered policy, initiator identity, symbolic receiver binding,
  source hash, and observation reference recorded in `input.json`.

The local Git object database must contain the revisions named by the observation
archives. The main counterexample uses original SAGA revision
`7372111bea150e32cee390a616849316d2780bfc`; the normal allow/deny controls use
`b5d0a6365d40fdeff240e54cce5ef7572f01808a` from the development fork's
`my-modification` branch. They are distinct commits containing the same matcher
Git blob. Fetch and verify both histories in a fresh clone:

```text
git remote add saga-upstream https://github.com/gsiros/saga.git
git remote add saga-development https://github.com/g1020268262-a11y/saga.git
git fetch saga-upstream main
git fetch saga-development my-modification
git cat-file -e 7372111bea150e32cee390a616849316d2780bfc:saga/common/contact_policy.py
git cat-file -e b5d0a6365d40fdeff240e54cce5ef7572f01808a:saga/common/contact_policy.py
```

The bridge checks each source blob against the archived source hash under
explicitly enumerated raw, LF, and CRLF encodings and fails closed on missing or
mismatched provenance. The root `.gitattributes` fixes the frozen model to LF
and preserves the exact archive-specific LF/CRLF bytes on Windows; archived
evidence must not be renormalized.

## Finite specification semantics

Supported patterns are `*`, an exact lowercase ASCII AID, or a lowercase UID
followed by `:*`. The evaluator assigns numerical specificity, retains rule
order in the context hash, and selects the unique maximum. Equal maximum ranks,
unsupported patterns, or malformed fields do not produce a deny decision; they
produce `Unsupported` or `Invalid`.

Budgets are integers greater than or equal to `-1`. A positive budget maps to
`Allow`; zero or a negative budget maps to `Deny`. This convention is scoped to
the recorded Provider contact-permission interpretation.

## Run

From the repository root:

```text
python -B -m unittest discover -s proofs/decision_bridge -p test_bridge.py -v
python -B proofs/decision_bridge/run_bridge.py --output .runtime/bridge-replay-check
```

The command above explicitly selects a temporary output path. The replay writes
its five output files to the specified Git-ignored
`.runtime/bridge-replay-check/` directory:

- `input.json`;
- `bridge-result.json`;
- `scenario_turepass_from_bridge.inc`;
- `summary.txt`; and
- `manifest.json`.

The directory must not already exist; use a different output name for subsequent
runs. Existing archived evidence is never overwritten. Without `--output`,
`run_bridge.py` retains its default behavior of creating a new timestamped
directory under `proofs/decision_bridge/evidence/`. A saved input can be replayed
with `--input`.

For a clean-checkout reconstruction and ProVerif execution:

```text
python -B proofs/decision_bridge/run_verification.py --proverif proverif
```

The command creates `proofs/evidence/authz-bridge-turepass-<timestamp>/` with the
generated full model, bridge result, raw ProVerif output, tests, and manifest.
The runner requires a clean Git tree before it starts.

## Outputs and expected decision

For the pinned recorded case, the independent specification evaluator selects
the specific deny rule while the bound production observation records the later
wildcard allow. The result is:

```text
SpecDecision = Deny
ImplObserved = Allow
divergence = true
```

Only this checked `Deny/Allow` pair emits the scenario facts used by the formal
adapter. The `.inc` fragment is an integrity artifact and is not standalone
ProVerif input.

## Formal adapter

`generate_model.py` re-evaluates the context, reloads the hashed observation,
checks the decision pair, validates the frozen template structure, and
reconstructs the designated scenario block. The resulting model contains the
same protocol body and queries outside the audited transformation surface.

The scenario-local labels `aid_A`, `aid_B`, and `BuggyPolicy` are symbolic model
identifiers. They do not assert a deployed receiver, policy owner, session, or
service request. `ChatAccept` reachability in the generated model is a symbolic
consequence under the explicit divergence facts, not a production exploit.

## Fixed observations and representative evidence

`observations/` contains immutable direct calls of the unchanged production
matcher for normal allow/deny controls. `collect_controls.py` is the only bridge
component that imports the production matcher; it is not invoked by replay or
tests.

The retained lightweight replay is
`evidence/20260922T064302235212Z/`. The retained full formal archive is
`../evidence/authz-bridge-turepass-20260922T111657792091Z/`. Manifests bind the
inputs, outputs, source/model hashes, tool identity, and command for each run.
