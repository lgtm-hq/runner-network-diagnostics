# Evidence

These public bundles preserve run records, raw logs, available artifacts and console recovery. Each
release includes an archive and an external checksum file. The archive has its own file manifest.
`SOURCE.json` maps retained bytes back to the unchanged frozen source archive. Internal assessment
notes are excluded.

| Run                                                                                                    | Evidence archive                                                                                                                     | Checksum file                                                                                                         |
| ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| [40294837589](https://github.com/lgtm-hq/runner-network-diagnostics/releases/tag/evidence-40294837589) | [Download](https://github.com/lgtm-hq/runner-network-diagnostics/releases/download/evidence-40294837589/evidence-40294837589.tar.gz) | [SHA256SUMS](https://github.com/lgtm-hq/runner-network-diagnostics/releases/download/evidence-40294837589/SHA256SUMS) |
| [40304555915](https://github.com/lgtm-hq/runner-network-diagnostics/releases/tag/evidence-40304555915) | [Download](https://github.com/lgtm-hq/runner-network-diagnostics/releases/download/evidence-40304555915/evidence-40304555915.tar.gz) | [SHA256SUMS](https://github.com/lgtm-hq/runner-network-diagnostics/releases/download/evidence-40304555915/SHA256SUMS) |
| [40313241012](https://github.com/lgtm-hq/runner-network-diagnostics/releases/tag/evidence-40313241012) | [Download](https://github.com/lgtm-hq/runner-network-diagnostics/releases/download/evidence-40313241012/evidence-40313241012.tar.gz) | [SHA256SUMS](https://github.com/lgtm-hq/runner-network-diagnostics/releases/download/evidence-40313241012/SHA256SUMS) |
| [40324625326](https://github.com/lgtm-hq/runner-network-diagnostics/releases/tag/evidence-40324625326) | [Download](https://github.com/lgtm-hq/runner-network-diagnostics/releases/download/evidence-40324625326/evidence-40324625326.tar.gz) | [SHA256SUMS](https://github.com/lgtm-hq/runner-network-diagnostics/releases/download/evidence-40324625326/SHA256SUMS) |

<details>
<summary>Archive SHA-256 values</summary>

```text
c7a34f6f6647b4bbe27936803e55e0ec99132d39a4c5132d69e6febbd24ec057  evidence-40294837589.tar.gz
7fa848f252c9633c5fc892477b2caf3a0dbdb39e1c756e1aa783bd3f0fe1f311  evidence-40304555915.tar.gz
41d54c054731b1900525e6d87388b9be93a75fb386bc182dfb5d1eea7e290caf  evidence-40313241012.tar.gz
9edb5f39421141e33273699b3a74300d3956159cbc665ab7aad5063f7e915d74  evidence-40324625326.tar.gz
```

</details>

## Verification

ZIP digests match GitHub's artifact API. Internal manifests verify extracted files. Console recovery
verifies the exact bytes against checksums printed by the job. The corrected experiment also
reconstructs every upload file from its complete console copy and compares all available artifact
counterparts.

The first controlled run retains its original artifact requirement. Recovering its console bytes
does not turn that run into a pass. The corrected run's console route applies only to that
experiment.

Each public selection has a `SCREENING.json` record. A credential scan found only known
temporary-file ownership nonces, including their encoded copies. Each exception names an exact
finding; no general token rule was disabled. The new archives preserve selected evidence bytes and
leave all original archives unchanged.

## Affected samples

[Run 40294837589](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589)
contains the five complete real-host captures. The linked jobs show the original build context. The
durable archive retains the raw logs and recovered wire files.

| Sample | Original job                                                                                                        | Wire file inside the archive       |
| ------ | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| 8      | [Job 121478274755](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589/job/121478274755) | `recovered/sample-8/dns-wire.txt`  |
| 9      | [Job 121478274824](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589/job/121478274824) | `recovered/sample-9/dns-wire.txt`  |
| 11     | [Job 121478274777](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589/job/121478274777) | `recovered/sample-11/dns-wire.txt` |
| 12     | [Job 121478274818](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589/job/121478274818) | `recovered/sample-12/dns-wire.txt` |
| 19     | [Job 121478276919](https://github.com/lgtm-hq/runner-network-diagnostics/actions/runs/40294837589/job/121478276919) | `recovered/sample-19/dns-wire.txt` |

<details>
<summary>Reading a trace</summary>

Start with sample 8's before and hardened configuration, effective DNS state and wire file. The
application queries `127.0.0.100`, which forwards to `127.0.0.53`. The resolver then queries Azure
DNS. No post-hardener query reaches the agent on `127.0.0.1:53` in the five affected captures.

DNS query identifiers stay the same across the loopback forwarding hops, but systemd-resolved uses a
new identifier toward Azure. Correlation across that hop uses the name, connection, timestamp and
answer, not an identical identifier.

Samples with a passing checkout still use the bypassed path. A coincidentally matching address can
make one application connection succeed.

The different-topology healthy control is sample 4 in westus3. Eighteen other jobs were screened out
and did not exercise the full diagnostics.

</details>

## Related upstream discussion

[runner-images#14925](https://github.com/actions/runner-images/issues/14925) and
[harden-runner#705](https://github.com/step-security/harden-runner/issues/705) describe related
runner DNS and port-binding observations. Their earlier port fix does not establish a fix for the
empty-DNS drop-in interaction. This investigation does not establish who created the drop-in or
assign responsibility for a change.
