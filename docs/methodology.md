# Methodology

This investigation tests a DNS configuration conflict under the pinned harden-runner block policy.
The workflow does not change the endpoint allowlist.

## Capturing a failure

The first action captures the runner before harden-runner starts. It records the region, resolver
file, resolver configuration and experiment services. A passive capture retains timestamped DNS
traffic. Later steps record effective settings, application connections, the agent's destination
mappings and rejected traffic.

A successful checkout alone cannot establish a healthy DNS path. Two resolvers can return the same
address by chance. The path test requires fresh queries to the agent on `127.0.0.1:53`, together
with the effective resolver configuration.

The connection control uses an address resolved before hardening. A pass requires a matching
rejection for the exact curl process and destination. A generic connection error is insufficient.

## Controlled reproduction

The [synthetic workflow](../.github/workflows/dns-synthetic.yml) has four groups with four jobs
each. It admits only positively identified ordinary GitHub-hosted Ubuntu 24.04 runners. It leaves
real experiment hosts and unknown setups alone.

| Group | Change before measurement                                                  | Purpose                              |
| ----- | -------------------------------------------------------------------------- | ------------------------------------ |
| C0    | None                                                                       | Establish a working baseline         |
| I1    | An owned `90-egress-proxy.conf` with empty `DNS=`                          | Reproduce the configuration conflict |
| I2    | The same reset plus a later `DNS=127.0.0.1` override                       | Test the override before hardening   |
| I3    | Reproduce the conflict, measure, then add the override and reload resolved | Compare the DNS path on one host     |

The primary result requires four valid baseline jobs, four jobs that reproduce the fault, and four
override jobs that match the baseline. Missing measurements make the affected group inconclusive.
The same-host comparison is supporting evidence and cannot replace a primary group. Its first
measurement does not include a connection-blocking control. That control runs after the repair.

A 20-second readiness deadline precedes the first measurement. Failure to observe initialization
produces a failed readiness record, not an oracle result. Each oracle records its query window,
resolver process, effective DNS and main-file content and hash.

The synthetic reset tests systemd configuration precedence on the ordinary stub resolver. It does
not emulate GitHub's forwarding service or outbound proxy. A synthetic pass cannot establish that an
override repairs a real affected runner.

## Evidence and completion

For every job, retain the terminal GitHub API record and raw log through all post hooks. Download
available artifacts and compare their ZIP digests with GitHub's API. Verify each internal checksum
manifest.

The revised workflow also prints the complete upload file set as checksummed base64 chunks. This
preserves evidence when the induced fault blocks artifact upload. Reconstruct every job's copy,
including manifests and the closing inventory. Where an artifact exists, every reconstructed byte
must agree. A missing chunk, refused file or disagreement invalidates that evidence route.

The console copy has limits of 64 files, 256 KiB per file and 1 MiB per job. It refuses symlinks,
unexpected files and token-like content. Its checksums are records made by the job and stored by
GitHub. They are not a separate attestation of the measurements.

This route applies only to the corrected experiment. Earlier experiments retain the evidence
requirements set before their dispatch. Results from separate runs are never pooled to replace
missing jobs.

<details>
<summary>Cleanup checks</summary>

The hardener leaves its main resolver configuration in place at the end of a normal Linux job. The
diagnostic helpers remove only files they created.

The guard removes the owned override without a restart. After hardener post, the fallback checks
ownership again, removes any remaining owned override and reloads resolved while the synthetic reset
remains. The final post removes that reset and reloads once more. Foreign files prevent a restart.

Receipts record file absence, main-file equality with the first oracle, the phase-specific Global
DNS expectation, Azure link DNS, resolver process changes and the final application lookup
separately. These checks do not assert that the host returns to its pre-hardener configuration.

The earlier native counterfactual has a known incorrect cleanup assumption. Do not repeat its
treatment workflow until that cleanup receives a separate revision and independent review.

</details>

## Reproduction and local checks

Read the [workflow](../.github/workflows/dns-synthetic.yml) and its immutable helper references
before requesting a dispatch. Every batch is manual and bounded. The workflow has no scheduled
trigger or automatic replacement jobs.

Local checks cover the helpers and failure paths. They do not establish hosted resolver behavior.

```sh
node --test --experimental-test-coverage scripts/*/*.test.cjs vendor/network-probe/capture.test.cjs
bats vendor/network-probe/negative-verdict.bats
uv run lintro chk
actionlint
shasum -a 256 -c vendor/SHA256SUMS
```

The actions use Node 24. The reviewed local suite used Node 26.12.1.
