# Authorization analysis and reproduction

This directory contains the executable witnesses, formal models, supporting
Decision Bridge, bounded consumer validation, and representative evidence for
the SAGA authorization analysis.

## Components

- `reproduce_matcher.py` invokes the unchanged production matcher directly for
  the recorded ordered-rule counterexample and writes no files.
- `proverif/` contains the retained baseline, authorization, gate-control, and
  divergence-scenario models.
- `decision_bridge/` evaluates the finite specification for the recorded input,
  checks the archived production observation and upstream source provenance,
  and reconstructs the formal scenario region.
- `consumer_validation/` follows the Provider and receiver consumers to token
  issuance/storage using isolated fixtures and MongoDB.
- `evidence/` contains representative archived formal executions and the direct
  matcher observation.

## Quick checks

From the repository root:

```text
python -B proofs/reproduce_matcher.py
python -B -m unittest discover -s proofs/decision_bridge -p test_bridge.py -v
<venv-python> -B -m unittest proofs.consumer_validation.test_harness -v
```

Decision Bridge tests require local Git history containing the revisions bound
by the archived observations: `7372111bea150e32cee390a616849316d2780bfc`
from original SAGA and `b5d0a6365d40fdeff240e54cce5ef7572f01808a`
from the development fork's `my-modification` branch. They are distinct commits
with the same matcher Git blob. For a fresh clone, run:

```text
git remote add saga-upstream https://github.com/gsiros/saga.git
git remote add saga-development https://github.com/g1020268262-a11y/saga.git
git fetch saga-upstream main
git fetch saga-development my-modification
git cat-file -e 7372111bea150e32cee390a616849316d2780bfc:saga/common/contact_policy.py
git cat-file -e b5d0a6365d40fdeff240e54cce5ef7572f01808a:saga/common/contact_policy.py
```

The root `.gitattributes` fixes the frozen model to LF and preserves the exact
archive-specific LF/CRLF bytes on Windows. Do not renormalize evidence. Consumer
tests require the packages in `consumer_validation/requirements.txt` but do not
require a running MongoDB.

## Formal reproduction

ProVerif 2.05 is the archived tool version. Run the final bridge-derived model:

```text
proverif proofs/evidence/authz-bridge-turepass-20260922T111657792091Z/agent_communication_authz_chat_bridge.pv
```

The archived result establishes `ChatAccept` reachability under the explicit
divergence scenario and the correspondence `ChatAccept ==> TokenIssue`. Gate
comparisons are provided by the three
`agent_communication_authz_chat_p_*_r_*.pv` models and their retained archive.

The formal scenario contains checked symbolic facts derived from the recorded
decision pair. ProVerif does not execute the Python matcher, and the bridge does
not prove a Python-to-ProVerif refinement relation.

## Consumer validation

```text
<venv-python> -B proofs/consumer_validation/run_phase1.py --mongod <path-to-mongod>
```

The harness creates an isolated loopback MongoDB instance and a new evidence
archive. Consumer-side validation is intentionally bounded at token
issuance/storage. It does not execute application-message acceptance, an LLM, or
external tools, and it is not a deployed-service exploit.

## Representative evidence

- `evidence/authz-stage1-20260916T123834944479Z/`
- `evidence/authz-chat-gates-20260918T023621017067Z/`
- `evidence/authz-turepass-20260919T090826295518Z/`
- `evidence/authz-bridge-turepass-20260922T111657792091Z/`
- `decision_bridge/evidence/20260922T064302235212Z/`
- `consumer_validation/evidence/20260926T070021921746Z-d64c8064/`

Each archive documents its own command, inputs, tool version, scope, and hashes.
The root [`README.md`](../README.md) gives the complete reproduction order and
expected results.
