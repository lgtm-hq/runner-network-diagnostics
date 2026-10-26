"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { waitInitialized, rollback } = require("./lifecycle.cjs");
const { pre, install, main, post, runPhase } = require("./control.cjs");
const { runtime, createRuntime } = require("./runtime.cjs");
const { HEADER, LIVE, ok, harness, files, snap } = require("./fixtures.cjs");

test("pre persists intent before create and normal main/post retain without restarting", () => {
  const r = harness();
  runPhase("pre", r);
  assert.equal(r.load().applied, true);
  assert.equal(r.events[r.events.indexOf("create") - 1], "save-intent");
  assert.equal(r.events.includes("restart"), false);
  r.initialized();
  assert.equal(runPhase("main", r).disposition, "SHIM_EFFECTIVE");
  assert.equal(r.output.disposition, "SHIM_EFFECTIVE");
  assert.deepEqual(r.output, { applicable: true, applied: true, disposition: "SHIM_EFFECTIVE" });
  assert.equal(runPhase("post", r).disposition, "POST_AGENT_PATH_RETAINED");
  assert.equal(r.events.includes("remove"), false);
  assert.equal(r.events.includes("restart"), false);
  assert.ok(r.events.includes("getent"));
});
test("wait uses 2s probe budgets, 250ms pause and strict 30s monotonic deadline", () => {
  const r = harness();
  let elapsed = 0;
  let attempts = 0;
  r.now = () => elapsed;
  r.pause = (ms) => {
    assert.ok(ms <= 250);
    elapsed += ms;
  };
  r.status = (budget) => {
    assert.ok(budget <= 2000 && budget > 0);
    attempts += 1;
    elapsed += budget;
    return { ...ok(), status: null, error: "ETIMEDOUT" };
  };
  const result = waitInitialized(r);
  assert.equal(result.outcome, "DEADLINE_EXPIRED");
  assert.equal(result.elapsedMs, 30000);
  assert.ok(attempts > 10 && attempts < 16);
});
test("terminal status stops immediately; a ready response past deadline is rejected", () => {
  const r = harness();
  r.status = () => ok("Error: initialization failed\n");
  assert.equal(waitInitialized(r).attempts, 1);
  let elapsed = 0;
  r.now = () => elapsed;
  r.status = () => {
    elapsed = 30001;
    return ok("Initialized");
  };
  assert.equal(waitInitialized(r).ready, false);
});
for (const [name, modify] of [
  ["wrong global DNS", (r) => r.setDns("Global:\nLink 2: 127.0.0.1\n")],
  ["multiple global DNS", (r) => r.setDns("Global: 127.0.0.1 8.8.8.8\n")],
  [
    "missing route domain",
    (r) => {
      r.domains = () => "Global:\nLink 2: ~.\n";
    },
  ],
  [
    "listener absent",
    (r) => {
      r.listener = () => ok(HEADER);
    },
  ],
  [
    "listener unknown",
    (r) => {
      r.listener = () => ({ ...ok(HEADER), status: 1 });
    },
  ],
  [
    "wildcard not explicit agent",
    (r) => {
      r.listener = () => ok(LIVE.replace("127.0.0.1", "0.0.0.0"));
    },
  ],
  [
    "no later resolved start",
    (r) => {
      r.service = () => "ExecMainPID=1\nExecMainStartTimestampMonotonic=100\n";
    },
  ],
  [
    "invalid start timestamp",
    (r) => {
      r.service = () => "ExecMainStartTimestampMonotonic=n/a\n";
    },
  ],
  [
    "changed platform",
    (r) => {
      r.platform = () => ({ content: "[Resolve]\nDNS=8.8.8.8\n", sha256: "different" });
    },
  ],
  [
    "changed main",
    (r) => {
      r.main = () => ({ content: "[Resolve]\nDNS=1.1.1.1\n", sha256: "different" });
    },
  ],
  [
    "foreign owned inode",
    (r) => {
      const root = r.root;
      r.root = (mode, token) => ({ ...root(mode, token), ino: "foreign" });
    },
  ],
  [
    "config read warning",
    (r) => {
      const config = r.config;
      r.config = () => ({ ...config(), stderr: "permission denied" });
    },
  ],
  [
    "new config source",
    (r) => {
      const config = r.config;
      r.config = () => ({
        ...config(),
        stdout: `${config().stdout}\n# /run/systemd/resolved.conf.d/99-z.conf\n[Resolve]\nDNS=\n`,
      });
    },
  ],
]) {
  test(`initialized verification fails with granular evidence and retains: ${name}`, () => {
    const r = harness();
    runPhase("pre", r);
    r.initialized();
    modify(r);
    assert.throws(() => runPhase("main", r), /SHIM_INEFFECTIVE/);
    const receipt = r.receipts.at(-1);
    assert.ok(Object.values(receipt.checks).includes(false));
    assert.equal(r.events.includes("remove"), false);
    assert.equal(r.events.includes("restart"), false);
    assert.equal(r.events.at(-2), "receipt-main");
    assert.equal(r.events.at(-1), "outputs");
  });
}
for (const status of [
  ok("Error: setup failed"),
  ok("Starting"),
  { status: 1, stdout: "", stderr: "cat: No such file or directory", error: null },
]) {
  test(`agent-dead rollback is connectivity-only and fails main: ${JSON.stringify(status)}`, () => {
    const r = harness();
    runPhase("pre", r);
    r.initialized();
    r.status = () => status;
    r.listener = () => ok(HEADER);
    assert.throws(() => runPhase("main", r), /ROLLED_BACK/);
    assert.equal(r.receipts.at(-1).disposition, "ROLLED_BACK_UNINITIALIZED");
    assert.equal(r.receipts.at(-1).failed, true);
    assert.equal(r.receipts.at(-1).policyClearance, false);
    assert.equal(r.receipts.at(-1).checks.removalVerified, true);
    assert.equal(r.events.filter((event) => event === "restart").length, 1);
    assert.equal(r.root("inspect", r.load().token).present, false);
  });
}
test("uninitialized startup rollback removes without reload if local DNS was never applied", () => {
  const r = harness();
  runPhase("pre", r);
  r.status = () => ok("Initializing");
  r.listener = () => ok(HEADER);
  assert.throws(() => runPhase("main", r), /ROLLED_BACK/);
  assert.equal(r.events.includes("restart"), false);
});
for (const listener of [ok(LIVE), { ...ok(HEADER), status: 1 }, ok("")]) {
  test(`late status plus live or unknown listener never removes: ${JSON.stringify(listener)}`, () => {
    const r = harness();
    runPhase("pre", r);
    r.status = () => ok("Starting");
    r.listener = () => listener;
    assert.throws(() => runPhase("main", r), /SHIM_UNVERIFIED/);
    assert.equal(r.events.includes("remove"), false);
  });
}
test("rechecks absence at removal so startup listener appearing during rollback is retained", () => {
  const r = harness();
  runPhase("pre", r);
  r.status = () => ok("Starting");
  let calls = 0;
  r.listener = () => ok(calls++ ? LIVE : HEADER);
  const result = rollback({ r, state: r.load() });
  assert.equal(result.disposition, "SHIM_UNVERIFIED");
  assert.equal(r.events.includes("remove"), false);
});
test("unknown status and positively absent listener fail closed", () => {
  const r = harness();
  runPhase("pre", r);
  r.status = () => ok("unrecognized vendor state");
  r.listener = () => ok(HEADER);
  assert.equal(rollback({ r, state: r.load(), post: true }).refused, true);
  assert.equal(r.events.includes("remove"), false);
});
test("lost create acknowledgement is cleaned using durable token and still fails pre", () => {
  const r = harness();
  const root = r.root;
  r.root = (mode, token) => {
    const result = root(mode, token);
    if (mode === "create") throw new Error("lost ack");
    return result;
  };
  r.status = () => ok("Starting");
  r.listener = () => ok(HEADER);
  assert.throws(() => runPhase("pre", r), /PRE_INSTALL_FAILED/);
  assert.equal(r.receipts[0].recovery.disposition, "ROLLED_BACK_UNINITIALIZED");
  assert.equal(r.load().mutationIntent, true);
  assert.equal(r.root("inspect", r.load().token).present, false);
});
test("durable intent failure prevents privileged create", () => {
  const r = harness();
  const save = r.save;
  r.save = (state, exclusive) => {
    if (state.mutationIntent) throw new Error("disk fsync failed");
    save(state, exclusive);
  };
  assert.throws(() => runPhase("pre", r), /disk fsync failed/);
  assert.equal(r.events.includes("create"), false);
  assert.equal(r.events.at(-1), "receipt-pre");
});
test("foreign inode blocks rollback and preserves diagnostic details in receipt", () => {
  const r = harness();
  runPhase("pre", r);
  r.status = () => ok("Error: no setup");
  r.listener = () => ok(HEADER);
  const root = r.root;
  r.root = (mode, token) => ({ ...root(mode, token), ino: "replaced" });
  assert.throws(() => runPhase("main", r), /replaced owned inode/);
  assert.equal(r.receipts.at(-1).disposition, "ROLLBACK_FAILED");
  assert.equal(r.events.includes("remove"), false);
  assert.equal(r.receipts.at(-1).observations.ownedBefore.ino, "replaced");
});
test("retries one lost remove acknowledgement, verifies absence, and checks getent", () => {
  const r = harness();
  runPhase("pre", r);
  r.status = () => ok("Stopped");
  r.listener = () => ok(HEADER);
  const root = r.root;
  let removes = 0;
  r.root = (mode, token) => {
    if (mode === "remove" && removes++ === 0) throw new Error("temporary sudo failure");
    return root(mode, token);
  };
  assert.equal(rollback({ r, state: r.load() }).disposition, "ROLLED_BACK_UNINITIALIZED");
  assert.equal(removes, 2);
});
test("rollback failure remains red if removal, PID change, DNS safety or getent fails", () => {
  for (const fault of ["remove", "pid", "dns", "getent"]) {
    const r = harness();
    runPhase("pre", r);
    r.initialized();
    r.status = () => ok("Stopped");
    r.listener = () => ok(HEADER);
    if (fault === "remove") {
      const root = r.root;
      r.root = (mode, token) => {
        if (mode === "remove") throw new Error("failure");
        return root(mode, token);
      };
    }
    if (fault === "pid") r.service = () => "ExecMainPID=10\n";
    if (fault === "dns") r.restart = () => {};
    if (fault === "getent") r.getent = () => ({ ...ok(), status: 2 });
    assert.equal(rollback({ r, state: r.load() }).disposition, "ROLLBACK_FAILED", fault);
  }
});
test("post retains on unknown status and unknown inspection, and adverse checks fail", () => {
  for (const unknown of ["status", "listener", "getent"]) {
    const r = harness();
    runPhase("pre", r);
    r.initialized();
    runPhase("main", r);
    if (unknown === "status") r.status = () => ({ ...ok(), error: "ETIMEDOUT" });
    if (unknown === "listener") r.listener = () => ({ ...ok(), error: "ETIMEDOUT" });
    if (unknown === "getent") r.getent = () => ({ ...ok(), status: 2 });
    assert.throws(() => runPhase("post", r), /POST_AGENT_PATH_LOST/);
    assert.equal(r.events.includes("remove"), false);
    assert.equal(r.events.includes("restart"), false);
  }
});
test("post agent dead permits rollback even when stale status says Initialized; post fails", () => {
  const r = harness();
  runPhase("pre", r);
  r.initialized();
  runPhase("main", r);
  r.listener = () => ok(HEADER);
  assert.throws(() => runPhase("post", r), /POST_AGENT_PATH_LOST/);
  assert.ok(r.events.includes("remove"));
  assert.equal(r.receipts.at(-1).recovery.checks.getentSucceeded, true);
});
test("post after main rollback verifies already absent ownership without a second restart", () => {
  const r = harness();
  runPhase("pre", r);
  r.initialized();
  r.status = () => ok("Stopped");
  r.listener = () => ok(HEADER);
  assert.throws(() => runPhase("main", r), /ROLLED_BACK/);
  assert.throws(() => runPhase("post", r), /POST_AGENT_PATH_LOST/);
  assert.equal(r.receipts.at(-1).priorRollback.checks.removalVerified, true);
  assert.equal(r.events.filter((event) => event === "remove").length, 1);
  assert.equal(r.events.filter((event) => event === "restart").length, 1);
});
test("a newly dead local DNS path after main rollback still receives post connectivity recovery", () => {
  const r = harness();
  runPhase("pre", r);
  r.status = () => ok("Stopped");
  r.listener = () => ok(HEADER);
  assert.throws(() => runPhase("main", r), /ROLLED_BACK_UNINITIALIZED/);
  r.setDns("Global: 127.0.0.1\n");
  assert.throws(() => runPhase("post", r), /POST_AGENT_PATH_LOST/);
  assert.equal(r.receipts.at(-1).recovery.checks.restartVerified, true);
  assert.equal(r.events.filter((event) => event === "restart").length, 1);
});
test("observe sees affected bypass without any mutation, restart, ownership inspection or failure", () => {
  const r = harness();
  r.mode = "observe";
  runPhase("pre", r);
  r.setDns("Global:\n");
  assert.equal(runPhase("main", r).disposition, "WOULD_APPLY");
  assert.equal(runPhase("post", r).disposition, "POST_OBSERVE");
  assert.equal(r.output.applied, false);
  assert.equal(r.output.applicable, true);
  for (const event of ["create", "inspect", "remove", "restart"])
    assert.equal(r.events.includes(event), false);
});
test("unaffected APPLY is a write-free no-op with initialized state recorded", () => {
  const r = harness();
  r.config = () => ok("# /etc/systemd/resolved.conf\n[Resolve]\n");
  assert.equal(runPhase("pre", r).disposition, "NOT_APPLICABLE");
  const main = runPhase("main", r);
  assert.equal(main.disposition, "NOT_APPLICABLE");
  assert.equal(main.readiness.ready, true);
  assert.equal(main.checks.agentInitialized, true);
  runPhase("post", r);
  for (const event of ["create", "inspect", "remove", "restart"])
    assert.equal(r.events.includes(event), false);
});
test("excluded hosts never probe privileged DNS or agent state", () => {
  const r = harness();
  r.environment = () => ({ allowed: false, reason: "SELF_HOSTED" });
  for (const name of ["config", "main", "platform", "status", "listener", "dns", "root", "getent"])
    r[name] = () => assert.fail(`unexpected ${name}`);
  for (const phase of ["pre", "main", "post"])
    assert.equal(runPhase(phase, r).disposition, "NOT_APPLICABLE");
});
test("missing pre state produces receipt before throwing", () => {
  const r = harness();
  assert.throws(() => runPhase("main", r));
  assert.equal(r.receipts.length, 1);
  assert.equal(r.receipts[0].disposition, "SHIM_UNVERIFIED");
});
test("portable exported installer is pre's installer and permits a drill to bypass only applicability", () => {
  for (const fn of [pre, install, main, post, runPhase, runtime, createRuntime])
    assert.equal(typeof fn, "function");
  const r = harness();
  // This is the drill's only deviation: state is constructed without the
  // platform/config applicability predicate. All mutations use install.
  const state = {
    schema: 1,
    mode: "apply",
    environment: { allowed: true },
    applicable: false,
    applied: false,
    mutationIntent: false,
  };
  r.save(state, true);
  assert.equal(install(r, state).disposition, "APPLIED_PENDING_AGENT_RESTART");
  assert.equal(r.load().applied, true);
  assert.equal(r.events[r.events.indexOf("create") - 1], "save-intent");
  r.setDns("Global: 127.0.0.1\n");
  r.status = () => ok("Starting");
  r.listener = () => ok(HEADER);
  assert.throws(() => runPhase("main", r), /ROLLED_BACK_UNINITIALIZED/);
  const receipt = r.receipts.at(-1);
  assert.equal(receipt.disposition, "ROLLED_BACK_UNINITIALIZED");
  assert.equal(receipt.failed, true);
  assert.equal(receipt.policyClearance, false);
  assert.equal(receipt.checks.remainingConfigDnsMatches, true);
  assert.throws(() => install(r, state), /fresh apply/);
  assert.throws(
    () => install({ ...r, mode: "observe" }, { ...state, mode: "observe", mutationIntent: false }),
    /fresh apply/,
  );
});
for (const reason of [
  "topology-false",
  "topology-unknown",
  "environment-unknown",
  "inventory-unreadable",
  "config-unreadable",
  "live-dns",
  "live-domains",
]) {
  test(`pre never installs when independent proof fails: ${reason}`, () => {
    const r = harness();
    if (reason === "topology-false") r.topology = () => ({ allowed: false });
    if (reason === "topology-unknown")
      r.topology = () => {
        throw new Error("topology unreadable");
      };
    if (reason === "environment-unknown")
      r.environment = () => {
        throw new Error("platform unreadable");
      };
    if (reason === "inventory-unreadable")
      r.files = () => {
        throw new Error("directory unreadable");
      };
    if (reason === "config-unreadable")
      r.config = () => {
        throw new Error("cat-config unreadable");
      };
    if (reason === "live-dns") r.setDns("Global: 8.8.8.8\n");
    if (reason === "live-domains") r.domains = () => "Global: ~.\n";
    const record = runPhase("pre", r);
    assert.equal(record.disposition, "NOT_APPLICABLE");
    assert.equal(r.events.includes("create"), false);
    assert.equal(r.load().mutationIntent, false);
  });
}
for (const phase of ["main", "post"]) {
  for (const partial of [false, true]) {
    test(`${phase} refuses added routing source even when cat-config ${partial ? "omits" : "includes"} it`, () => {
      const r = harness();
      runPhase("pre", r);
      r.initialized();
      if (phase === "post") runPhase("main", r);
      const content = `${r.config().stdout}\n# /run/systemd/resolved.conf.d/70-extra.conf\n[Resolve]\nDomains=~corp\n`;
      r.files = () => files(content);
      if (!partial) r.config = () => ok(content);
      assert.throws(
        () => runPhase(phase, r),
        phase === "main" ? /SHIM_INEFFECTIVE/ : /POST_AGENT_PATH_LOST/,
      );
      assert.equal(r.receipts.at(-1).checks.effectiveSourcesUnchanged, false);
      assert.equal(r.events.includes("remove"), false);
      assert.equal(r.events.includes("restart"), false);
    });
  }
}
test("post compares main against verified main, not pre-hardener main", () => {
  const r = harness();
  runPhase("pre", r);
  r.initialized();
  runPhase("main", r);
  const main = r.main();
  assert.notEqual(main.sha256, r.load().main.sha256);
  r.main = () => snap(`# changed comment\n${main.content}`);
  assert.throws(() => runPhase("post", r), /POST_AGENT_PATH_LOST/);
  assert.equal(r.receipts.at(-1).checks.verifiedMainUnchanged, false);
});
test("post with dead listener and unknown status fails while conservatively retaining ownership", () => {
  const r = harness();
  runPhase("pre", r);
  r.initialized();
  r.status = () => ok("unknown state");
  r.listener = () => ok(HEADER);
  assert.throws(() => runPhase("post", r), /POST_AGENT_PATH_LOST/);
  assert.equal(r.receipts.at(-1).recovery.refused, true);
  assert.equal(r.events.includes("remove"), false);
});
test("post rollback errors retain the adverse post disposition and diagnostic details", () => {
  const r = harness();
  runPhase("pre", r);
  r.initialized();
  r.listener = () => ok(HEADER);
  const root = r.root;
  r.root = (mode, token) => ({ ...root(mode, token), ino: "replaced" });
  assert.throws(() => runPhase("post", r), /POST_AGENT_PATH_LOST/);
  assert.equal(r.receipts.at(-1).recovery.disposition, "ROLLBACK_FAILED");
  assert.match(r.receipts.at(-1).recovery.error, /replaced/);
});
test("controls and unaffected hosts record readiness failure without failing or writing", () => {
  for (const mode of ["apply", "observe"]) {
    const r = harness();
    r.mode = mode;
    if (mode === "apply") r.topology = () => ({ allowed: false });
    runPhase("pre", r);
    r.status = () => ok("Starting");
    const result = runPhase("main", r);
    assert.equal(result.readiness.ready, false);
    assert.equal(result.failed, undefined);
    runPhase("post", r);
    for (const event of ["create", "remove", "inspect", "restart"])
      assert.equal(r.events.includes(event), false);
  }
});
test("rollback rejects a live/config disagreement even if live DNS no longer names the dead agent", () => {
  const r = harness();
  runPhase("pre", r);
  r.status = () => ok("Stopped");
  r.listener = () => ok(HEADER);
  r.setDns("Global: 8.8.8.8\n");
  const record = rollback({ r, state: r.load() });
  assert.equal(record.disposition, "ROLLBACK_FAILED");
  assert.equal(record.checks.noDeadLocalDns, true);
  assert.equal(record.checks.remainingConfigDnsMatches, false);
  assert.equal(r.events.includes("restart"), false);
});
