# Native DNS workaround canary

This is the prospective execution protocol. The frozen registration identifies the signed workflow and
helper commits before the first dispatch. Run outcomes are recorded separately.

This tests one intervention on disposable GitHub-hosted Ubuntu 24.04 runners: an owned late DNS configuration
file installed before harden-runner's pre hook. It tests neither a repair after hardening nor a change to the
hardener, firewall policy or endpoint allowlist.

## Workaround lifecycle

The action applies only to positively identified hosted Linux runners outside containers, with a complete
successful configuration read and the observed empty-DNS drop-in conflict. The action independently enumerates
the four systemd drop-in directories, including same-name precedence and masking, and cross-checks them
against the complete merged read. The `.100` resolver topology and services must be present, and live DNS and
routing domains must agree with the pre-hardener configuration. Unknown or unrecognized configuration is never
permission to write. Region is recorded but is not an applicability requirement.

The action atomically creates `/etc/systemd/resolved.conf.d/99-lgtm-agent-dns.conf` with an ownership nonce
and these settings:

```ini
[Resolve]
DNS=
DNS=127.0.0.1
```

It does not edit the main configuration, the existing platform drop-in, resolver files, agent, firewall or
platform services. It does not restart DNS on the success path. The hardener's restart applies the file.

After the pre hooks, it waits at most 30 seconds for initialized enforcement. It verifies the live DNS
setting, routing domain, listener, owned file and resolver restart. Verification failures fail the action. If
the agent is positively absent, rollback removes only the owned file and reloads DNS only when necessary to
recover resolution. Successful rollback restores connectivity; it does not turn an uninitialized hardener into
a passing security check.

At job end, the action retains the file while the agent is serving. It records the final DNS and agent state
and performs a bounded resolution check. It never removes the working agent route before the runner reports
completion. Hosted VMs are disposable; returning the VM to its original configuration is not a claim of this
test. Self-hosted or persistent runners are excluded.

## Assignment and placement

Each dispatch has 24 probe jobs, with arms `T` and `C` and replicates 1 through 12. Assignment occurs in the
matrix before placement. `T` applies the workaround; `C` observes the same configuration and runs the hardener
without changing DNS. Jobs use `ubuntu-24.04`, an eight-minute job timeout and maximum parallelism of 24. The
experiment is manual, on the diagnostics repository's main branch.

The hardener remains pinned to `dc2769abcc0fcfbadfc1df54081c1608579ef6b2` in block mode. Its endpoint
allowlist remains:

```text
github.com:443
api.github.com:443
codeload.github.com:443
objects.githubusercontent.com:443
results-receiver.actions.githubusercontent.com:443
```

Before the workaround, the probe classifies each runner from configuration alone. An affected fingerprint
requires hosted Linux, `/etc/resolv.conf` resolving to itself and listing `127.0.0.100`, active experimental
resolver and proxy units, their DNS listener, and the observed main-file plus `90-egress-proxy.conf` empty-DNS
configuration. The region is a recorded covariate. Partial or unknown fingerprints are reported separately and
do not count as unaffected controls. A positively ordinary topology remains eligible for the unaffected pool
even in westus2 or when region discovery fails; region alone cannot exclude it. The pre-hardener configuration
has exactly one active DNS-routing assignment: the empty `DNS=` in the known platform drop-in. Any other
active `DNS=` or `Domains=` source causes refusal.

A disagreement between the probe's eligibility and the workaround's applicability invalidates the instrument.
Any write on a partial or unaffected host, or in observe mode, stops the experiment as a failure.

## Measurements

| Phase                      | Measurement                                                                                                                                         |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Before hardening           | Configuration, DNS, routing domain, resolver PID/start time, main and platform-file hashes, allowed lookup and fresh `p-<16hex>.example.com` lookup |
| Before hardening, repeated | Repeat the same baseline nonce after one second to describe forwarder caching                                                                       |
| After initialization       | Configuration and fresh `a-<16hex>.example.com` lookup, plus `api.github.com`                                                                       |
| After application checks   | Repeat with fresh `z-<16hex>.example.com`                                                                                                           |
| Post hooks                 | Owned-file identity, live DNS, routing domain, agent listener/status and resolution result                                                          |
| External terminal API      | Job conclusion and time between the last recorded step and job completion                                                                           |

Every nonce is fresh to that phase. An NXDOMAIN baseline is expected and supplies no security evidence. Each
affected observation requires a fresh P-nonce packet toward the forwarding path or Azure; missing that
pre-treatment packet invalidates the observation. A wildcard public answer is recorded and must be disjoint
from the later sinkhole reference. SERVFAIL or timeout is descriptive, with the same packet requirement. The
recorded DNS windows use UTC timestamps with a predefined one-millisecond boundary tolerance. Retransmissions
and different hops are not collapsed into one query.

Unaffected runners take a short path. They verify that the workaround wrote nothing, record initialized DNS
and an allowed and denied lookup, and preserve evidence. Their denied answers form the same-dispatch sinkhole
reference only if at least two initialized, positively unaffected jobs return the same nonempty IPv4 set, and
all such jobs agree. The set must be disjoint from every pre-hardener public answer and every strict
negative-control address in that dispatch. Otherwise, the affected treatment observations in that dispatch are
invalid. A partial, unknown or uninitialized runner cannot supply that reference.

## Treatment gates

Every valid affected treatment observation must pass all of these:

- The action reports effective enforcement. Global DNS is exactly `127.0.0.1`, `~.` remains, the local agent
  listener exists, and the hardener's resolver restart occurred after file creation.
- The platform drop-in is unchanged. The owned override remains intact at both measurement phases.
- Each fresh nonce has a query to and response from the agent listener within its recorded window. The
  response must carry the dispatch sinkhole address. At both A and Z, zero packets for that exact phase nonce
  may reach Azure DNS or leave `127.0.0.100` toward any upstream. Separately, no captured DNS traffic from any
  process, on any protocol, may reach Azure DNS after verification and before capture freeze.
- The denied nonce resolves to the same-dispatch sinkhole reference and the agent records its denial. Its
  answer is outside the baseline public-answer set, which may be empty for NXDOMAIN.
- The existing strict negative connection control reports `CONFIRMED_BLOCK` for its exact address and curl
  process. This deliberately forced connection is excluded from the empty-domain gate only when all seven
  checks hold: its own pre-hardener address, port 443, its exact curl PID and process name, the negative step
  interval, a matching drop in that interval, the record in `negative-agent.txt`, and `CONFIRMED_BLOCK`.
  Agent-log seconds are compared against the whole second containing verification, so boundary uncertainty
  fails closed. The authoritative records come from hardener post, deduplicated only by identical lines in
  that block. Any other empty-domain connection after verification fails. Missing the excluded control record
  is an integrity mismatch and invalidates the observation.
- Real checkout succeeds, the public API returns HTTP 200, and the payload upload/download verifies
  `ROUNDTRIP_OK`. The diagnostic evidence artifact also uploads.
- Complete console evidence reconstructs exactly and matches every artifact counterpart.
- The final post receipt confirms the agent DNS path remains available.
- GitHub reports terminal success within 120 seconds of the last step's completion.

A control observation counts as affected confirmation only when global DNS is empty, `~.` remains, the
resolver restarted, and its fresh nonce reaches Azure DNS without reaching the agent listener. Its application
failures, upload failures and delayed cancellation are recorded rather than used as control pass requirements.
Control jobs are not repaired.

Every positively unaffected treatment runner must show no write, initialized global DNS at `127.0.0.1`,
successful verification and prompt terminal completion.

## Rollback drills

A dispatch may include two separate drill jobs without harden-runner. Enable them while fewer than two
safe-host drills have executed, and disable them thereafter. A drill runs only on a positively ordinary hosted
runner with no existing override or agent listener. It imports the workaround implementation unchanged,
bypasses only applicability to install an owned override, and restarts the resolver to exercise the
missing-agent rollback path.

Each drill must verify removal of its owned file, a changed resolver PID, its original global DNS value and
successful resolution. The action's main failure is expected when enforcement is absent; the drill passes only
by verifying the separate rollback safety receipt. A refused or unexecuted drill is a placement exclusion, not
a pass or a failed rollback. It supplies no success evidence and may be followed by drills in a later
identical-head dispatch within the same budget. Between dispatches, the `include_drills` decision reads only
collected drill dispositions, independently of treatment outcomes; overall safety stops still apply. A refused
drill job is red, so placement exclusions are classified by `DRILL_NOT_EXECUTED`, not the job conclusion.
Every executed drill is retained and must pass, including
surplus executions in the final drill-bearing batch. A rollback failure stops the experiment.

## Evidence and invalid observations

Raw logs, terminal API records, artifact metadata and ZIPs, receipts and complete console copies are retained
for every job. Before outcomes are read, classify eligibility from pre-hook receipts. Verify collection,
provenance and integrity first. Read control path confirmation, treatment gates, unaffected checks and drills
in that order. Job timing comparisons are descriptive.

Only these instrument failures can invalidate an observation:

- Missing terminal API record or raw log after two hours of collection.
- Capture-engine health failure reported by the engine.
- Console reconstruction or manifest mismatch.
- Missing pre-treatment nonce query or the dispatch sinkhole reference.
- No initialized treatment agent within 30 seconds, provided the matching safety receipts pass.
- No initialized affected control agent within 30 seconds.

Any other missed treatment gate is a failure. Failed rollback is always a failure. More than one invalid
treatment observation, or more than two invalid eligible observations overall, makes the experiment
inconclusive. An invalid observation is retained and never relabeled as a success. An uninitialized unaffected
job with no write is descriptive and excluded from the no-op count, rather than a gate failure or an eligible
invalid observation. A failed action main is expected on a safely rolled-back uninitialized treatment host;
the first failure must be that main step. A live-listener timeout retains the owned file and requires no Azure
DNS after main, owned bytes at post and no final agent-path loss. Otherwise it is a failure.

Post-hook receipts written after upload are verified from the console. They are not expected to appear in an
earlier artifact. Each version of an updated state file is checked against its own printed hash. Agent-log
coverage ends when hardener post prints the log; later coverage consists of the action post receipt and the
external terminal timing, not further agent-log evidence.

## Sampling budget and stopping

At most ten identical-head dispatches may run within 48 hours of the first, one at a time, with no reruns.
Dispatch starts are at least 30 minutes apart and span UTC hours. The next dispatch starts only after the
previous run is terminal and collection is complete. The total budget is 260 jobs: at most 240 probe jobs and
20 drill jobs. Fewer drills run when the minimum is reached earlier. Counts may accumulate across these
dispatches only.

A pass requires all of these:

- At least three valid affected treatment hosts across at least two dispatches, all passing.
- At least two valid affected controls showing the bypass, with at least one in a dispatch that also contains
  a valid affected treatment observation.
- At least 30 positively unaffected treatment hosts passing their no-op and completion checks.
- At least two executed rollback drills, every executed drill passing, no eligibility disagreements, and
  complete integrity/provenance.

Evaluate stopping only at run boundaries:

| Condition                                                                          | Outcome                                           |
| ---------------------------------------------------------------------------------- | ------------------------------------------------- |
| Any treatment gate failure, unsafe mutation of an unaffected host, or failed drill | Stop; fail; no rollout                            |
| All minimum observations and gates satisfied                                       | Stop; pass for an engineering canary              |
| Eligible control does not show the expected bypass                                 | Stop; inconclusive; the platform may have changed |
| Invalid-observation cap or eligibility disagreement                                | Stop; inconclusive                                |
| Time or placement budget exhausted before the minimum                              | Stop; inconclusive                                |

Every failed treatment observation names its failing gate and separately reports the wire and terminal gates.
A failure confined to an instrument self-check still stops the experiment and prevents rollout; it does not
establish that the DNS intervention itself failed. Instrument correction requires a new registration. Refused
drills are recorded separately from executed drill failures.

A source change ends this experiment and requires a separate registration. Earlier runs 40294837589,
40304555915, 40313241012 and 40324625326 supply context only. Their observations cannot replace or supplement
this experiment's observations.

## Conditional adoption

A pass supports a staged engineering canary for this action on the measured hosted topology and agent version.
It does not establish a fleet failure rate, vendor responsibility, the origin of the platform files, or the
cause of prior cancellations. Independent assessment precedes adoption.

If it passes, copy the portable action byte-for-byte into `lgtm-ci`, independently review the full integration
and its narrow workflow-order validator exception, and require green CI before merge. Keep the hardener pin,
policy and endpoint grants unchanged. Start with one consumer canary before wider adoption. Scorecard
publishing jobs that forbid additional actions remain explicitly uncovered; they must not silently lose
publishing or enforcement.

Monitor adoption for at least 48 hours and 150 hardened hosted Linux jobs. Any ineffective or unverified
action, failed rollback, failure on an unaffected host, or affected job with failed final verification or
delayed cancellation triggers a reviewed signed revert. Other agent versions and self-hosted runners require
separate validation.
