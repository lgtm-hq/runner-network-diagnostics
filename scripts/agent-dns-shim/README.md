# Agent DNS shim

Portable, dependency-free Node 24 action. Place this action as a **direct step
immediately before harden-runner**, so its pre hook installs before the
hardener's pre hook, and its post hook observes after hardener post. Pass
`hosted: ${{ runner.environment }}` explicitly. `mode` defaults to `apply`;
`observe` records the same applicability decision without acquiring any file
ownership. Pin the action to the reviewed full commit SHA at the call site.

The recognized configuration is intentionally narrow: a main
`/etc/systemd/resolved.conf` with a `[Resolve]` section and no active settings,
followed only by `/etc/systemd/resolved.conf.d/90-egress-proxy.conf`, whose only
active setting is an empty `[Resolve]` `DNS=`. Other settings, other sources,
ambiguous syntax, failed/truncated reads, stderr, an existing owned path, and
unknown DNS or Domains sources produce reasoned no-ops. An independent inventory
reads all four drop-in directories (`/etc`, `/run`, `/usr/local/lib`, `/usr/lib`),
applies same-name precedence and `/dev/null` masks, and compares the effective
paths and bodies to `cat-config`. Unreadable, changing or unsafe files/listings
and unexpected symlinks are refused. It reads shadowed files conservatively too.
Main and post repeat this check, accepting the owned `99` as the third source.
Region is irrelevant.
Non-Linux, containers, missing passwordless sudo, and any value other than
explicit `github-hosted` are excluded. This trusts the caller to supply the
actual runner environment; it is not a persistence detector for arbitrary hosts.
Pre independently requires a systemd PID 1 and runtime, active resolved,
`egress-dns-resolver` and `egress-outbound-proxy`, a regular `/etc/resolv.conf`
resolving to itself with a `.100` nameserver, and an explicit `.100:53` UDP
listener. Live Global DNS and Global Domains must both be empty. Unknown facts
are no-ops. Observe mode runs the same checks and reports `WOULD_APPLY` or the
refusal reason, then records bounded agent readiness without DNS writes.

Apply installs only `/etc/systemd/resolved.conf.d/99-lgtm-agent-dns.conf`, with
an explicit DNS reset followed by `127.0.0.1`. It does not change platform files,
the main config, domains, firewall, proxies, agent files or `/etc/resolv.conf`.
The normal path never restarts resolved. Main waits at most 30 seconds, then
checks agent initialization, Global DNS, Global `~.`, the local UDP listener,
owned identity/hash, platform hash, agent-written main content, source snapshots,
and resolved's start after installation. A boot-relative upper bound sampled
after creation is compared to `ExecMainStartTimestampMonotonic`; inode ctime is
also recorded. Post compares the verified main hash and runs bounded local
`getent ahostsv4 github.com`.

Post **retains the owned file while the listener is alive or its inspection is
unknown**. Only positively absent listeners allow owned-file removal, with
status checks before removal. Main also requires uninitialized/terminal status;
post accepts stale Initialized status with a dead listener. A restart is allowed
only if the live Global DNS still contains `127.0.0.1` after removal. Every
restart, removal and connectivity check is recorded. Foreign files are refused.

The R9 amendment's failure rules apply:

- `ROLLED_BACK_UNINITIALIZED` means connectivity safety only. Main fails because
  initialization was not verified; it grants no policy clearance.
- Adverse post checks fail the action instead of warning. Dead-agent recovery
  also fails post even if connectivity was restored, with
  `POST_AGENT_PATH_LOST` and nested recovery evidence. Post after a successful
  main rollback records the prior rollback without another removal or restart
  while no new dead local DNS path has appeared.

Rollback also independently reads the remaining merged configuration and
requires live Global DNS to match its implied DNS list. It records the current
main file; it never claims to restore pre-hardener bytes. The strict recognizer
may refuse extra harmless configuration sources or unsupported syntax.

State (including durable pre-create intent), bounded pre config/main/platform
snapshots and phase JSON receipts live under
`$RUNNER_TEMP/lgtm-agent-dns-shim/`. Console receipts contain the SHA-256 of the
exact saved JSON line including its trailing newline, and print before failure.
Main appends `applicable`, `applied` and `disposition` to `$GITHUB_OUTPUT`.
`applied` means pre acknowledged installation, even if later rollback removed it;
inspect the disposition and checks for the outcome. Only one invocation per job
is supported. A killed privileged create is recovered with its durable owner
token, including an interrupted temporary hard link.

Import interfaces for the external drill are `pre(r)`, `install(r, state)`,
`main(r, state)`, `post(r, state)` and `runPhase(phase, r)` from `control.cjs`;
`runtime()` and its identical alias `createRuntime()` from `runtime.cjs`.
`install` is the exact function called by pre. It requires fresh apply state,
sets/persists token and mutation intent, creates through the fixed root helper,
then persists owned identity, creation time and `applied`. It mutates `state`
and returns the pre result (check `failed`); it never restarts resolved. The
drill constructs and saves its own state before calling it, bypassing only
applicability. There is no portable-action bypass input. The runtime interface
adds read-only `topology()` and `files()` to R1's injection methods.

The root helper is an attributed self-contained adaptation of the existing
exclusive-link primitive; it imports no frozen experimental helpers. Its CLI
accepts only fixed operations and a validated token, never an alternate path or
command. Alternate roots/uids are available only through imports for local tests.

Run focused checks without an install:

```sh
node --test --experimental-test-coverage scripts/agent-dns-shim/*.test.cjs
prettier --check 'scripts/agent-dns-shim/*.{cjs,yml,md}'
```

Local tests exercise mocks and unprivileged temporary files only. They do not
establish efficacy on hosted runners. Real placement, agent timing, wire paths,
rollback drills and terminal completion remain canary requirements.
