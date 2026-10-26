# Source provenance

Every run points to its dispatched workflow commit. The workflow pins its helpers to immutable
commits. Documentation updates do not change the code that ran.

| Run                                                                                           | Workflow source                                                                                                  | Helper source                                                                                                                                      |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| [40294837589](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589) | [b5db7b0](https://github.com/lgtm-hq/runner-network-diagnostics/commit/b5db7b0d419c14163d9795728003f01c211dd1d6) | [28541b5](https://github.com/lgtm-hq/runner-network-diagnostics/commit/28541b502cbb4938c0d049da06123b8dea0fcf97)                                   |
| [40304555915](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40304555915) | [b59c1c7](https://github.com/lgtm-hq/runner-network-diagnostics/commit/b59c1c7f355a01450f273f2c4c4b45b96fee05d2) | [8a92446](https://github.com/lgtm-hq/runner-network-diagnostics/commit/8a924461ab16efc41b71b18e38af21e1b5f6dbbd), plus the original capture helper |
| [40313241012](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40313241012) | [c3040da](https://github.com/lgtm-hq/runner-network-diagnostics/commit/c3040da0967e2b726a6d5020377e3095f3b27550) | [79bfdde](https://github.com/lgtm-hq/runner-network-diagnostics/commit/79bfdde9f1c18b1d8368964c35eac43a372bc836)                                   |
| [40324625326](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40324625326) | [8bb9643](https://github.com/lgtm-hq/runner-network-diagnostics/commit/8bb9643914ce2799cdd44a39d24e6f21e371fd28) | [2a200f1](https://github.com/lgtm-hq/runner-network-diagnostics/commit/2a200f13f51248ecdb2e0198c2555b785f72242b)                                   |

## Original capture helper

The [vendored probe](../vendor/network-probe) is an unchanged copy from
[the original fixture source](https://github.com/TurboCoder13/lgtm-ci-consumer-fixture/tree/41ccbb0e34f7522f231bb5ac1853b67fcda22ba8/scripts/network-probe).
[SHA256SUMS](../vendor/SHA256SUMS) records those file hashes. Screening and synthetic experiments
wrap that probe; they do not change its capture parser or strict connection control.

The helpers received independent source and signed-object review before their respective dispatches.
The corrected helper's local checks passed 131 Node tests and 20 Bats tests, with 95.35% aggregate
line coverage. Those checks establish local validation only. Hosted observations determine each
run's result.

The [evidence index](evidence.md) links durable run records and their checksums.
[Local validation commands](methodology.md#reproduction-and-local-checks) run the current helper
suite.
