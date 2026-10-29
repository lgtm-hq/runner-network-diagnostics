"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  waitForAgent,
  treatmentCleanup,
  observeCleanup,
  verifyCleanup,
} = require("./lifecycle.cjs");

test("oracle readiness tolerates missing status until initialization, recording elapsed time", () => {
  let clock = 0;
  const result = waitForAgent({
    now: () => clock,
    pause: () => {
      clock += 250;
    },
    read: () =>
      clock < 500
        ? { status: 1, stdout: "", stderr: "missing", error: null }
        : { status: 0, stdout: "Initialized\n", stderr: "", error: null },
  });
  assert.equal(result.ready, true);
  assert.equal(result.attempts, 3);
  assert.equal(result.elapsedMs, 500);
});

test("a terminal agent status fails immediately rather than waiting out the deadline", () => {
  let attempts = 0;
  const result = waitForAgent({
    read: () => {
      attempts += 1;
      return { status: 0, stdout: "Error reading config file", error: null };
    },
    pause: () => {
      throw new Error("must not pause");
    },
  });
  assert.equal(result.ready, false);
  assert.equal(result.outcome, "TERMINAL_STATUS_ERROR");
  assert.equal(result.counts.terminalError, 1);
  assert.equal(attempts, 1);
});

test("fallback recovers a failed owned-file guard but refuses a foreign reset before restart", () => {
  for (const foreign of [false, true]) {
    let override = true;
    let firstRemoval = true;
    let restarts = 0;
    const state = {
      mutationIntent: true,
      token: "override",
      platformToken: "reset",
      originalPlatform: "reset-hash",
      observedMainAtOracleA: { sha256: "main-hash" },
    };
    const io = {
      root(mode, token, profile) {
        if (profile === "reset") {
          assert.equal(token, "reset");
          if (foreign) throw new Error("foreign reset");
          return { present: true };
        }
        assert.equal(token, "override");
        if (mode === "remove") {
          override = false;
          if (firstRemoval) {
            firstRemoval = false;
            throw new Error("lost acknowledgement");
          }
          return { removed: false };
        }
        return { present: override };
      },
      pid: () => String(10 + restarts),
      restart() {
        restarts += 1;
      },
      hash: (f) => (f.endsWith("90-egress-proxy.conf") ? "reset-hash" : "main-hash"),
      dns: () => "Global:\nLink 2: 168.63.129.16\n",
    };
    assert.throws(() => treatmentCleanup({ phase: "guard", state, io }), /lost acknowledgement/);
    if (foreign) {
      assert.throws(() => treatmentCleanup({ phase: "fallback", state, io }), /foreign reset/);
      assert.equal(restarts, 0);
    } else {
      assert.equal(
        treatmentCleanup({ phase: "fallback", state, io }).disposition,
        "SYNTHETIC_OVERRIDE_REMOVED",
      );
      assert.equal(restarts, 1);
    }
    assert.equal(override, false);
  }
});

test("readiness expires and never treats partial or failed observations as initialized", () => {
  for (const observation of [
    { status: 1, stdout: "Initialized", error: null },
    { status: 0, stdout: "Initialized", error: "timed out" },
  ]) {
    let clock = 0;
    const result = waitForAgent({
      timeoutMs: 1000,
      now: () => clock,
      pause: () => {
        clock += 250;
      },
      read: () => observation,
    });
    assert.equal(result.ready, false);
    assert.equal(result.elapsedMs, 1000);
    assert.ok(result.attempts <= 5);
  }
});

test("fallback reloads after a successful guard because hardener post does not reload", () => {
  let present = true;
  let global = "127.0.0.1";
  let restarts = 0;
  const state = {
    mutationIntent: true,
    token: "owned",
    observedMainAtOracleA: { sha256: "agent-written" },
    originalPlatform: "reset",
  };
  const io = {
    root(mode, token, profile) {
      if (profile === "reset") return { present: true };
      if (mode === "remove") {
        present = false;
        return { removed: true };
      }
      return { present };
    },
    pid: () => String(100 + restarts),
    restart() {
      restarts += 1;
      global = "";
    },
    hash: (file) => (file.endsWith("90-egress-proxy.conf") ? "reset" : "agent-written"),
    dns: () => `Global: ${global}\nLink 2: 168.63.129.16\n`,
  };
  assert.equal(
    treatmentCleanup({ phase: "guard", state, io }).disposition,
    "REMOVED_WITHOUT_RESTART",
  );
  assert.equal(restarts, 0);
  const result = treatmentCleanup({ phase: "fallback", state, io });
  assert.equal(result.disposition, "SYNTHETIC_OVERRIDE_REMOVED");
  assert.equal(restarts, 1);
  assert.equal(result.observations.beforeCleanup.globalDns, "127.0.0.1");
  assert.equal(result.observations.globalDns, "");
  assert.equal(result.checks.oracleAMainUnchanged, true);
});

test("cleanup reports every failed condition rather than accepting an unknown baseline", () => {
  const result = observeCleanup({
    state: {},
    expectedDns: "127.0.0.1",
    overrideAbsent: false,
    expectedPlatform: "reset",
    io: {
      hash() {
        throw new Error("unreadable");
      },
      dns: () => "unavailable",
    },
  });
  assert.throws(
    () => verifyCleanup(result),
    (error) => {
      for (const check of [
        "overrideAbsent",
        "platformUnchanged",
        "oracleAMainBaselineKnown",
        "oracleAMainUnchanged",
        "expectedGlobalDns",
        "azureLinkRetained",
      ])
        assert.ok(error.details.failures.includes(check));
      assert.equal(error.details.observations.mainHashError, "unreadable");
      return true;
    },
  );
});

test("lost removal acknowledgement remains a failed cleanup after a verified reload", () => {
  let present = true;
  let restarted = false;
  const io = {
    root(mode, token, profile) {
      if (profile === "reset") return { present: true };
      if (mode === "remove") {
        present = false;
        throw new Error("lost ack");
      }
      return { present };
    },
    pid: () => (restarted ? "101" : "100"),
    restart() {
      restarted = true;
    },
    dns: () => "Global:\nLink 2: 168.63.129.16\n",
    hash: (f) => (f.endsWith("90-egress-proxy.conf") ? "reset" : "hardened"),
  };
  assert.throws(
    () =>
      treatmentCleanup({
        phase: "fallback",
        io,
        state: {
          mutationIntent: true,
          token: "owned",
          observedMainAtOracleA: { sha256: "hardened" },
          originalPlatform: "reset",
        },
      }),
    /lost ack/,
  );
  assert.equal(restarted, true);
  assert.equal(present, false);
});

test("actual induce main records readiness before an oracle and refuses measurement on expiry", (t) => {
  const { entry } = require("./control.cjs");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-ready-entry-"));
  const keys = ["RUNNER_TEMP", "PATH", "GITHUB_OUTPUT"];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const oldExit = process.exitCode;
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    process.exitCode = oldExit;
    fs.rmSync(root, { recursive: true, force: true });
  });
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  fs.mkdirSync(path.join(root, "ci1203"));
  for (const [name, program] of Object.entries({
    sudo: 'case "$*" in *agent.status*) printf "Initialized\\n";; *) printf "Global: ~.\\n";; esac',
    systemctl: 'printf "1234\\n"',
    timeout: "exit 2",
    bash: 'printf "snapshot\\n" > "$RUNNER_TEMP/ci1203/topology-snapshot.txt"',
  }))
    fs.writeFileSync(path.join(bin, name), `#!/bin/sh\n${program}\n`, { mode: 0o755 });
  process.env.PATH = `${bin}:${previous.PATH}`;
  process.env.RUNNER_TEMP = root;
  process.env.GITHUB_OUTPUT = path.join(root, "output");
  for (const ready of [false, true]) {
    process.exitCode = undefined;
    const receipts = [];
    let saved;
    entry("main", () => ({
      out: root,
      observeMain: () => ({
        sha256: "agent-written",
        content: "[Resolve]\nDNS=127.0.0.1\nDomains=~.\n",
      }),
      load: () => ({ arm: "C0", inScope: true }),
      io: {
        hash: () => "agent-written",
        dns: () => "Global: 127.0.0.1\n",
        save(value) {
          saved = value;
        },
      },
      waitForAgent: () => ({ ready, attempts: 3, elapsedMs: 500 }),
      receipt: (phase, data) => receipts.push({ phase, data }),
    }));
    assert.equal(receipts[0].phase, "agent-readiness");
    if (ready) {
      assert.equal(process.exitCode, undefined);
      assert.equal(saved.observedMainAtOracleA.sha256, "agent-written");
      assert.equal(receipts[1].phase, "oracle-A");
    } else {
      assert.equal(process.exitCode, 1);
      assert.equal(saved, undefined);
      assert.equal(receipts.length, 1);
    }
  }
});
