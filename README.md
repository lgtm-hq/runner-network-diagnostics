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

## Counterfactual candidate (local draft)

The first run is complete: five affected westus2 captures, one full ordinary
control, and eighteen screening-only jobs. Both independent causality reviews
confirm an existing `90-egress-proxy.conf` empty `DNS=` reset overrides the
hardener's main-file global DNS setting. This establishes an interaction, not
exclusive vendor responsibility or a validated fix.

`dns-counterfactual.yml` is a separate, unpublished candidate. The original
workflow and vendored probe remain unchanged. Its new helper pins identify
signed local source awaiting independent Sol verification.
The original dispatch allowance is spent; no second execution is authorized.

Odd samples are treatment, even samples unchanged controls. Before hardener pre,
treatment requires the exact captured topology and empty DNS reset; unknown or
different setups are `NOT_APPLICABLE`. It atomically adds only an owned later
`DNS=127.0.0.1` drop-in and relies on the hardener's normal restart. No allowlist,
firewall, experiment service, resolver symlink or original config is changed.
Successful checkout alone never demonstrates a healthy DNS path.

An action without pre registers a guard post during main, above the hardener's
pre-registered post in the runner's LIFO stack. It removes the override without
restarting resolved, preserving the live agent path until hardener cleanup.
An earlier action's fallback post executes after the hardener. Unless guard
removal was positively acknowledged and saved, it treats the durable mutation
intent as requiring a reload. A lost unlink acknowledgement is
reconciled by ownership-aware absence inspection and at most one more removal
attempt. Once absence is established, it reloads resolved and preserves the
original error as a failed job. It verifies original main/platform config hashes
and original effective global DNS. Failures
remain failures, including partial hardener initialization that cannot restore.
Post receipts are hashed and printed to console separately from frozen probe
files; collect terminal logs, not just the pre-post diagnostic artifact.

This ordering follows `actions/runner` v2.338.0 `ActionRunner.RunAsync`
(post registered before pre/main handler execution), and
`ExecutionContext.RegisterPostJobStep` (first registration wins; LIFO stack).
Local lifecycle tests simulate these paths; hosted ordering remains unproven.

A future treatment pass needs fresh agent-path wire evidence, successful
checkout/API/artifact roundtrip, the unchanged strict denied-destination control,
verified full evidence upload, cleanup receipts and externally confirmed prompt
completion. Require affected captures in both arms; an unbalanced or empty
sample is inconclusive and does not authorize replenishment or rollout.

Additional local tests:

```sh
node --test --experimental-test-coverage scripts/resolver-counterfactual/control.test.cjs
```
