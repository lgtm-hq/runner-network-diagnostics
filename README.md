# Runner network diagnostics

This repository investigates one problem: on some GitHub-hosted `ubuntu-24.04` runners in `westus2`,
jobs that use [step-security/harden-runner](https://github.com/step-security/harden-runner) in block
mode lose their DNS path through the hardener's agent. Git, API and runner result traffic is then
dropped. The tracking issue is
[lgtm-hq/lgtm-ci#1203](https://github.com/lgtm-hq/lgtm-ci/issues/1203).

This repository holds diagnostics only. It ships no fix, and it does not assign the fault to any
vendor.

## Current status

- Mechanism: observed on five affected runners (see below).
- Remedy: untested on an affected runner.
- Controlled reproduction: the
  [corrected run](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40324625326) is
  inconclusive. Its baseline passed four of four; its induced group has three of four because the
  screen excluded one real westus2 host.
- Production changes, vendor reports and merge clearance: none made from this work.

## Observed mechanism

On five `westus2` runners in
[run 40294837589](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589),
the following was captured before and after the hardener started:

1. Before the first workflow step, the runner already has
   `/etc/systemd/resolved.conf.d/90-egress-proxy.conf` with an empty `DNS=` line, and a resolver
   forwarder at `127.0.0.100`. This repository did not create either. Their origin is not
   established here.
2. The hardener writes `DNS=127.0.0.1` and `Domains=~.` to `/etc/systemd/resolved.conf` and restarts
   systemd-resolved.
3. systemd-resolved reads drop-ins after the main file, so the empty `DNS=` clears the global DNS
   list. `resolvectl` shows no global DNS server. The `~.` routing domain remains.
4. Packet captures show application lookups going through `127.0.0.100`, then `127.0.0.53`, then
   Azure DNS (`168.63.129.16`, answered over TCP), with zero queries to the agent on `127.0.0.1:53`.
5. When Azure's answer differs from the address the agent learned, the agent has not allowed that
   address and the connection is dropped. Checkout succeeds only when the two answers happen to
   match.

The affected jobs also dropped runner result traffic and later ended as cancelled. The cause of the
completion delays remains unproven.

What this does not show: which component should change, whether restoring global DNS alone fixes the
affected runners, or whether every hardener security property holds. See
[docs/evidence.md](docs/evidence.md) for the per-sample references and verification.

<details>
<summary>Versions on the affected runners</summary>

| Component    | Value                                                                                                                                                                                                             |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Region       | `westus2`                                                                                                                                                                                                         |
| Runner image | `ubuntu-24.04`, setup log `20261012.334.1`, in-VM `ImageVersion=20261023.334.3`                                                                                                                                   |
| Runner       | `2.338.0`                                                                                                                                                                                                         |
| Hardener     | [dc2769a](https://github.com/step-security/harden-runner/commit/dc2769abcc0fcfbadfc1df54081c1608579ef6b2), [v2.22.2](https://github.com/step-security/harden-runner/releases/tag/v2.22.2), `egress-policy: block` |
| Agent        | [community agent v0.17.0 source](https://github.com/step-security/agent/tree/f4d56dfedf8e7c4a1808719fc7792ea69be22e31), binary SHA-256 `ea7bcabe6f72949e4e68f4feb57f83b6f63b4e1bff8b90d4af5952df48b46d99`         |

The healthy `westus3` control in the same run used the same image, runner and pins, without the
drop-in or `127.0.0.100`.

</details>

## Run ledger

Each run is reported on its own. Results are never pooled across runs, and a reviewed source change
is not a result.

| Run                                                                                           | Date       | Purpose                           | Jobs | Outcome                                                                                  |
| --------------------------------------------------------------------------------------------- | ---------- | --------------------------------- | ---- | ---------------------------------------------------------------------------------------- |
| [40294837589](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589) | 2026-10-26 | Passive capture                   | 24   | 5 affected `westus2` captures, 1 healthy control, 18 screened out                        |
| [40304555915](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40304555915) | 2026-10-26 | Native counterfactual             | 24   | Inconclusive: no affected runner was placed, no override installed                       |
| [40313241012](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40313241012) | 2026-10-26 | Controlled reproduction           | 16   | Inconclusive: baseline 3 of 4 valid, induced arm invalid, cleanup checks failed 16 of 16 |
| [40324625326](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40324625326) | 2026-10-26 | Corrected controlled reproduction | 16   | Inconclusive: baseline 4/4, induced 3/4; one real-host exclusion                         |

Screened-out jobs did not run the diagnostic checks. Their green status says nothing about runner
health. The cleanup failures in run 40313241012 came from a wrong assumption in this repository's
test code, not from a vendor defect. [docs/runs.md](docs/runs.md) has per-run detail, limits and the
earlier runs in the personal fixture repository.

## Evidence

Each run has a checksummed bundle with raw job logs, GitHub API records, artifacts and recovered
console files. The index with download links and SHA-256 values is
[docs/evidence.md](docs/evidence.md). Where an artifact upload failed, files were rebuilt from
console output only when they matched the hash the job printed.

## Open questions

- What writes `90-egress-proxy.conf` and the `127.0.0.100` forwarder, and on which runners.
- Whether a later `DNS=127.0.0.1` drop-in, placed before the hardener starts, restores the agent
  path on an affected runner.
- Whether the dropped runner result traffic causes the 13-minute cancellations.

## Reproducing

All workflows are manual (`workflow_dispatch`) with no automatic retries. Read
[docs/methodology.md](docs/methodology.md) before requesting a dispatch.

- [`dns-path.yml`](.github/workflows/dns-path.yml) collects observations without changing the
  resolver configuration. Runner placement is random.
- [`dns-synthetic.yml`](.github/workflows/dns-synthetic.yml) creates the empty `DNS=` drop-in on
  ordinary runners and compares four arms.
- `dns-counterfactual.yml` must not be run again. Its cleanup code relies on the same wrong
  assumption and has not been corrected.

[docs/provenance.md](docs/provenance.md) lists the exact commits and the vendored probe source.
