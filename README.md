# Runner network diagnostics

Isolated investigation for [lgtm-ci incident 1203](https://github.com/lgtm-hq/lgtm-ci/issues/1203).
This repository does not deliver a fix or establish vendor responsibility.
Existing personal-fixture evidence and releases remain unchanged.

## First experiment

One manual dispatch, **24 jobs maximum**, max parallelism 4, 8-minute timeout per
job. No retries, automatic triggers, or replenishment. Maximum scheduled job-time
budget is 192 minutes, excluding queueing. Early screening reduces work, but does
not promise a particular bill or region placement. Public-repository execution
uses lgtm-hq's Actions context, not the personal fixture's Actions allowance.

Before the hardener pre hook, collect only compute region from IMDS, resolver
file topology, experiment service state, listener presence and effective resolver
configuration. Retain detailed capture when region is westus2, resolver topology
is non-stub, an experiment marker is present, or screening information is unknown.
This is a **suspect setup filter**, not proof a runner is affected. A screened-out
job says NOT_SAMPLED; it cannot establish enforcement health or incident recovery.

On selected runners, preserve the original pre-hardener passive DNS capture,
post-hardener topology, real checkout, public API read, synthetic artifact
roundtrip and strict denied-destination control. Capture native nftables through
the original snapshots. Do not perform resolver, firewall or service changes.
Passive capture includes TCP/53; no active TCP/53 tests are made. The original
finish step includes explicitly labelled active local-resolver comparisons after
freezing the passive window; these are not part of its baseline.

All helper pre hooks are ordered ahead of harden-runner's pre hook. Early screening
runs there, not after checkout. The wrapper emits its selection during its main
step, then the workflow gates expensive steps. Harden-runner's pre hook may still
initialize on screened-out runners, and final artifact publication still runs.

Record actual engine selection, agent hashes, both setup-log and in-VM image
versions, region, experiment markers, resolver routing, timestamped wire evidence,
application/destination/drop matches, strict control and external terminal status.
TLS engine selection may make the strict control inconclusive; do not relax it.
No affected samples means inconclusive: stop rather than dispatch again.
Healthy checkout alone is not evidence of active enforcement or path recovery.

A job timeout can prevent final artifact publication. Console logs and outside API
receipts must also be retained; missing evidence remains missing, never a pass.
Artifact retention is 90 days; freeze analyzed evidence in a new durable bundle.
Do not alter previous bundles. No vendor posts are authorized.

## Source provenance

`vendor/network-probe/` is a byte-identical copy from public
`TurboCoder13/lgtm-ci-consumer-fixture/scripts/network-probe` at commit
`41ccbb0e34f7522f231bb5ac1853b67fcda22ba8`, approved in prior independent Sol reviews.
`vendor/SHA256SUMS` records copied source hashes. The wrapper adds screening and
resolver configuration capture; it keeps the original evidence-completeness and
strict negative-control logic. Copying this source into HQ removes runtime code
availability dependence on the personal repository; its public API metadata read
is retained and does not dispatch personal workflows.

Every source change requires an independent Sol review before publication or
execution. Pins in the workflow must identify the reviewed helper commit exactly.
Do not add paid AI review workflows or weaken egress enforcement.

## Local checks

```sh
node --test scripts/runner-probe/screen.test.cjs vendor/network-probe/capture.test.cjs
bats vendor/network-probe/negative-verdict.bats
lintro fmt
lintro chk
actionlint
shellcheck scripts/runner-probe/topology.sh vendor/network-probe/probe.sh
shfmt -d scripts/runner-probe/topology.sh vendor/network-probe/probe.sh
sha256sum -c vendor/SHA256SUMS
```

All checks on a PR must pass under the owner's merge policy, including checks
GitHub does not designate required. This experiment changes no production repos.
