# SAGA Authorization Analysis Artifact

This repository contains the research artifact for an analysis of an authorization decision inconsistency in SAGA.

Upstream project:
https://github.com/gsiros/saga

Upstream revision analyzed:
7372111bea150e32cee390a616849316d2780bfc

This is a derived research artifact, not the official SAGA repository. The
production matcher comes from the pinned upstream revision. The analyzed
production matcher is unchanged from the pinned upstream revision. The original
license and attribution are preserved in [`LICENSE`](LICENSE).

## Overview

The artifact has three primary parts:

1. an implementation-level reproduction of the order-dependent matcher result;
2. a formal consequence analysis under an explicit specification-deny /
   implementation-allow divergence scenario; and
3. a consumer-side validation of propagation through Provider authorization,
   receiver processing, and token issuance/storage.

The Decision Bridge is a supporting component. It independently evaluates the
recorded policy input, binds that result to the archived production observation,
and reconstructs the fixed ProVerif scenario region. It is not a general
implementation-to-model refinement proof.

## Repository layout

- `saga/` and `agent_backend/`: retained upstream implementation code required by
  the matcher and consumer validation paths.
- `proofs/reproduce_matcher.py`: read-only direct invocation of the production
  matcher for the recorded counterexample.
- `proofs/proverif/`: baseline and authorization-analysis ProVerif models.
- `proofs/decision_bridge/`: finite specification evaluator, provenance checks,
  scenario generator, tests, fixed observations, and one representative replay.
- `proofs/consumer_validation/`: bounded consumer harness, fixtures, tests,
  cases, and one representative successful archived run.
- `proofs/evidence/`: representative matcher and formal-analysis archives,
  including raw ProVerif output, manifests, and summaries.

## Requirements

- Python 3.10 or newer. The retained consumer archive used Python 3.12.7.
- The Python packages pinned in
  `proofs/consumer_validation/requirements.txt` for consumer tests and runs.
  The matcher runner and Decision Bridge use only the standard library plus the
  retained local SAGA modules.
- ProVerif 2.05 for reproducing the archived formal results.
- A local `mongod` executable for consumer validation. The retained successful
  run used MongoDB 8.0.17. The harness starts an isolated loopback-only instance
  and never attaches to an existing database.
- Git history containing the revisions named by the Decision Bridge observation
  archives. The primary matcher observation is pinned to the original SAGA
  revision `7372111bea150e32cee390a616849316d2780bfc`. The normal allow/deny
  controls are pinned to `b5d0a6365d40fdeff240e54cce5ef7572f01808a`, a
  historical commit from the development fork's `my-modification` branch. These
  are different commits with the same matcher Git blob. In a fresh clone, fetch
  and verify both sources with:

  ```text
  git remote add saga-upstream https://github.com/gsiros/saga.git
  git remote add saga-development https://github.com/g1020268262-a11y/saga.git
  git fetch saga-upstream main
  git fetch saga-development my-modification
  git cat-file -e 7372111bea150e32cee390a616849316d2780bfc:saga/common/contact_policy.py
  git cat-file -e b5d0a6365d40fdeff240e54cce5ef7572f01808a:saga/common/contact_policy.py
  ```

On Windows, the root `.gitattributes` keeps the frozen ProVerif template in LF
form and preserves the exact LF/CRLF bytes bound by archived manifests. Do not
renormalize archived evidence.

Install the consumer-validation dependencies from the repository root:

```text
python -m venv .venv
<venv-python> -m pip install -r proofs/consumer_validation/requirements.txt
```

The root `requirements.txt` and `setup.py` describe the retained broader SAGA
implementation. They are not required by the matcher-only or Decision Bridge
checks.

## Reproduction

Run all commands from the repository root.

### 1. Reproduce the matcher inconsistency

```text
python -B proofs/reproduce_matcher.py
```

Expected result: for the ordered policy containing a specific deny followed by a
wildcard allow, the intended most-specific result is budget `-1` (`Deny`) while
the unchanged production matcher returns budget `10` (`Allow`). Reversing the
rules returns `-1`. The first command invokes
`saga/common/contact_policy.py` directly and writes no files. The corresponding
archived production observation is under
`proofs/evidence/authz-stage1-20260916T123834944479Z/`.

### 2. Run the Decision Bridge and scenario generation

```text
python -B -m unittest discover -s proofs/decision_bridge -p test_bridge.py -v
python -B proofs/decision_bridge/run_bridge.py --output .runtime/bridge-replay-check
```

Expected result: the tests pass, and the replay reports `SpecDecision = Deny`,
`ImplObserved = Allow`, and `divergence = true`. The `.runtime/` directory is a
Git-ignored location for temporary output, so this replay leaves the Git worktree
clean and does not overwrite any archived evidence.

To reconstruct the full scenario and run ProVerif in one provenance-checked
workflow, use a clean Git checkout:

```text
python -B proofs/decision_bridge/run_verification.py --proverif proverif
```

This creates a new `proofs/evidence/authz-bridge-turepass-<timestamp>/`
directory containing the generated model, raw output, tests, and manifest.

### 3. Run the ProVerif analysis

The final bridge-derived model can be checked directly:

```text
proverif proofs/evidence/authz-bridge-turepass-20260922T111657792091Z/agent_communication_authz_chat_bridge.pv
```

Expected results include:

```text
RESULT event(ChatAccept(receiver,sender_1,tok,msg)) ==> event(TokenIssue(receiver,sender_1,tok)) is true.
RESULT not event(ChatAccept(receiver,sender_1,tok,msg)) is false.
```

The second result establishes `ChatAccept` reachability in the modeled divergence
scenario. It is not a cryptographic failure result. The independent Provider /
receiver gate controls can be rerun with:

```text
proverif proofs/proverif/agent_communication_authz_chat_p_allow_r_allow.pv
proverif proofs/proverif/agent_communication_authz_chat_p_deny_r_allow.pv
proverif proofs/proverif/agent_communication_authz_chat_p_allow_r_deny.pv
```

Archived outputs and expected gate reachability results are in
`proofs/evidence/authz-chat-gates-20260918T023621017067Z/`.

### 4. Run consumer-side propagation validation

Run the unit tests first:

```text
<venv-python> -B -m unittest proofs.consumer_validation.test_harness -v
```

Then supply a local MongoDB server executable:

```text
<venv-python> -B proofs/consumer_validation/run_phase1.py --mongod <path-to-mongod>
```

Expected result: A/A, D/D, and D/A complete with all expectations met. The allow
paths reach token transmission and storage before the deliberately imposed
conversation boundary; the deny path stops at the Provider. A new timestamped
archive is written to `proofs/consumer_validation/evidence/`. The retained
representative run is
`20260926T070021921746Z-d64c8064`.

## Scope

- The implementation matcher inconsistency is reproduced for the recorded
  ordered rulebook and identity.
- The formal consequence analysis runs under an explicit divergence scenario.
- The consumer validation reaches token issuance and storage using the real
  Provider route, matcher calls, cryptographic checks, and receiver token path,
  with the documented fixture and transport substitutions.
- The artifact does not claim end-to-end message acceptance in a production
  deployment.
- The artifact does not establish Python-to-ProVerif refinement, general matcher
  correctness, a deployed-policy ownership fact, or a production service exploit.

Consumer-side validation is intentionally bounded at token issuance/storage.

## Retained evidence

- `authz-stage1-20260916T123834944479Z`: direct production matcher observation
  plus baseline and authorization-diagnostic formal evidence.
- `authz-chat-gates-20260918T023621017067Z`: final independent gate comparison.
- `authz-turepass-20260919T090826295518Z`: complete independent run of the fixed
  divergence model.
- `authz-bridge-turepass-20260922T111657792091Z`: final Decision Bridge v1.1.1
  reconstruction and ProVerif run.
- `decision_bridge/evidence/20260922T064302235212Z`: representative checked
  decision-pair replay without a ProVerif invocation.
- `consumer_validation/evidence/20260926T070021921746Z-d64c8064`: complete A/A,
  D/D, and D/A consumer run with passing assertions.

## Provenance

The upstream implementation is attributed to the SAGA authors and is retained
under the original license. Research additions are concentrated in `proofs/`:
the matcher witnesses, authorization models and runners, Decision Bridge,
consumer validation harness, and archived evidence. The default endpoints in
`config.yaml` are normalized to loopback values for safe local use; this does not
change the matcher. Manifests bind archived runs
to source/model hashes and tool versions. Archived run metadata records the state
that existed when each run was captured; it should not be interpreted as a claim
that every retained file belongs to the upstream revision. Declared publication
redactions normalize machine-local paths and omit unrelated writing-file names;
they do not alter query results, event traces, policy inputs, or decisions.
