# Investigation runs

Each experiment has its own evidence requirements and result. No run supplies replacement jobs for
another. A green GitHub conclusion is not proof of a remedy. The [source ledger](provenance.md)
identifies the exact code for every HQ run.

## Capturing affected runners

[Run 40294837589](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589)
started at 08:48:26 UTC on 26 October 2026. It dispatched 24 jobs. Five westus2 jobs retained the
affected configuration and bypassed DNS path. One westus3 job provided a complete healthy control.
Eighteen jobs were screened out.

The affected samples are 8, 9, 11, 12 and 19. A passing checkout in an affected sample did not
establish a healthy path. It could use an address the agent had already allowed while other
application and runner connections still failed.

The run ended as cancelled. This does not invalidate retained captures whose bytes match the
checksums printed by the job. It also does not establish what caused the completion delays. See the
[sample references](evidence.md#affected-samples).

## Native counterfactual

[Run 40304555915](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40304555915)
started at 10:04:46 UTC on 26 October 2026. All 24 jobs passed, but none had the affected topology.
The helper installed no override.

The remedy result is inconclusive. This run cannot demonstrate recovery. Its unchanged native
cleanup also has the incorrect vendor-revert assumption found later. Do not repeat its treatment
workflow before a separate correction and review.

## First controlled reproduction

[Run 40313241012](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40313241012)
started at 11:11:49 UTC on 26 October 2026. Its 16 jobs tested the four groups described in the
[methodology](methodology.md#controlled-reproduction).

The result is inconclusive. One baseline job measured before agent initialization, so only three of
four baseline measurements were valid. Two induced-fault jobs also missed their first oracle. The
induced group had no artifacts, which its predefined evidence rules required. Console recovery does
not change that rule.

Cleanup checks failed in all 16 jobs because this repository incorrectly assumed that hardener post
restores the main resolver file. The agent leaves that file changed. The corrected helper checks
removal of its own temporary files instead. These were diagnostic defects. They are not additional
vendor findings.

## Corrected controlled reproduction

[Run 40324625326](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40324625326)
uses the corrected readiness wait, cleanup checks and complete console evidence copy. It dispatched
once. All 16 terminal logs and full console copies are complete. All 476 files with artifact
counterparts match byte-for-byte.

The baseline passed four of four. Three induced jobs reproduced the bypass. The
[fourth job](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40324625326/job/121578043570)
landed on a real westus2 runner that already had the affected topology. The screen excluded it
without mutation. The protocol requires four induced replicates and permits no replacement, so the
result is inconclusive.

The override and same-host comparisons are descriptive observations, not primary passes. Cleanup
passed every recorded condition in the 15 measured jobs. Baseline jobs removed nothing and did not
restart the resolver. The excluded job created no owned files.

<details>
<summary>Timing and evidence limits</summary>

Three treatment query timestamps fall less than one millisecond beyond the oracle's
millisecond-truncated end. The assessment notes their relation to the recorded responses, but they
do not establish a predefined primary pass. No baseline or induced-group decision depends on a
timing tolerance.

The excluded real-host job finished all its recorded steps at 12:43:33 UTC. GitHub recorded it
cancelled at 12:56:15 UTC. The collected record does not explain that delay. Its passive DNS capture
ends before agent initialization, so it adds configuration observations, not another complete
post-hardener wire capture.

The original native run's five affected captures remain the direct real-host bypass evidence. No
result here demonstrates a remedy on an affected host.

</details>

## Earlier fixture experiments

The fixture retains two releases with unchanged assets and checksum files. These experiments did not
sample the affected setup and do not demonstrate recovery.

<details>
<summary>Fixture run and release history</summary>

| Run                                                                                              | Purpose                    | Result                                                                                            |
| ------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------------------- |
| [40231423680](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/actions/runs/40231423680) | Initial two-job diagnostic | Connection controls unconfirmed; no affected setup                                                |
| [40232166028](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/actions/runs/40232166028) | Corrected control          | Two unaffected jobs passed the strict controls                                                    |
| [40232289237](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/actions/runs/40232289237) | Regional sample            | Two unaffected jobs                                                                               |
| [40232419966](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/actions/runs/40232419966) | Regional sample            | Two unaffected jobs                                                                               |
| [40238317870](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/actions/runs/40238317870) | Matched action-pin sample  | Eight allowed-operation successes; one TLS-selected strict control unconfirmed; no affected setup |

The first four runs share the
[first evidence release](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/releases/tag/diagnostic-1203-20261025).
The eight-job sample has its own
[second evidence release](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/releases/tag/diagnostic-1203-20261025-phase2).
Their immutable reports are
[first phase](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/blob/6ec3a6cca07e4fc8d9916bdabbf7ee31fe78b98a/docs/diagnostics/1203-evidence-20261025.md)
and
[second phase](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/blob/23cce1caaf6355076b6f38484ce60900a30548ae/docs/diagnostics/1203-phase2-evidence-20261025.md).

</details>

## Related consumer records

The [reference inventory](references.json) lists all 25 inspected issues and PRs, 86 comments, 78
runs and 43 exact job references. It distinguishes investigated failures, dependencies, merged
history and separate failure classes. Its audit snapshot is dated. It is not a fleet-wide affected
list or PR clearance.

<details>
<summary>Issue and PR reference index</summary>

| Record                                                                                                         | Relationship to this investigation         |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| [lgtm-hq/lgtm-ci#1203](https://github.com/lgtm-hq/lgtm-ci/issues/1203)                                         | canonical incident                         |
| [TurboCoder13/lgtm-ci-consumer-fixture#44](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/pull/44)   | Reported consumer failure                  |
| [TurboCoder13/lgtm-ci-consumer-fixture#41](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/pull/41)   | dependency only                            |
| [TurboCoder13/lgtm-ci-consumer-fixture#43](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/pull/43)   | dependency / separate network symptom      |
| [actions/runner-images#14925](https://github.com/actions/runner-images/issues/14925)                           | external reference only                    |
| [lgtm-hq/Rustume#1077](https://github.com/lgtm-hq/Rustume/issues/1077)                                         | Reported main-branch failure               |
| [lgtm-hq/lgtm-ci#1184](https://github.com/lgtm-hq/lgtm-ci/issues/1184)                                         | related canary-coordination work           |
| [lgtm-hq/lgtm-ci#1201](https://github.com/lgtm-hq/lgtm-ci/pull/1201)                                           | Linked through an exact canary child run   |
| [lgtm-hq/lgtm-ci#1204](https://github.com/lgtm-hq/lgtm-ci/pull/1204)                                           | Reported PR and canary failure             |
| [lgtm-hq/lgtm-ci#1206](https://github.com/lgtm-hq/lgtm-ci/issues/1206)                                         | separate invalid endpoint issue            |
| [lgtm-raycast/.github#2](https://github.com/lgtm-raycast/.github/pull/2)                                       | historically affected, merged              |
| [lgtm-raycast/brew#8](https://github.com/lgtm-raycast/brew/pull/8)                                             | historical mitigation PR                   |
| [lgtm-raycast/brew#11](https://github.com/lgtm-raycast/brew/pull/11)                                           | historically affected, merged              |
| [lgtm-raycast/brew#12](https://github.com/lgtm-raycast/brew/pull/12)                                           | merged context only                        |
| [step-security/harden-runner#679](https://github.com/step-security/harden-runner/issues/679)                   | external historical reference only         |
| [step-security/harden-runner#705](https://github.com/step-security/harden-runner/issues/705)                   | external reference only                    |
| [lgtm-hq/lgtm-ci#1178](https://github.com/lgtm-hq/lgtm-ci/pull/1178)                                           | Linked through an exact canary child run   |
| [lgtm-hq/lgtm-ci#1195](https://github.com/lgtm-hq/lgtm-ci/pull/1195)                                           | Linked through an exact canary child run   |
| [lgtm-raycast/brew#13](https://github.com/lgtm-raycast/brew/pull/13)                                           | direct incident-signature evidence         |
| [lgtm-raycast/brew#18](https://github.com/lgtm-raycast/brew/pull/18)                                           | direct incident-signature evidence         |
| [lgtm-raycast/brew#19](https://github.com/lgtm-raycast/brew/pull/19)                                           | merely considered / not confirmed affected |
| [lgtm-hq/Rustume#1078](https://github.com/lgtm-hq/Rustume/pull/1078)                                           | merged historical reference                |
| [TurboCoder13/lgtm-ci-consumer-fixture#42](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/issues/42) | separate prerequisite                      |
| [lgtm-hq/holy-grail#310](https://github.com/lgtm-hq/holy-grail/issues/310)                                     | Reported recurrent main-branch failure     |
| [lgtm-hq/hass-turbo-themes#40](https://github.com/lgtm-hq/hass-turbo-themes/issues/40)                         | separate failure class / mention only      |

</details>
