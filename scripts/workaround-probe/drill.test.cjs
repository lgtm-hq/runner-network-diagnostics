"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { runDrill } = require("./drill.cjs");
const control = require("../agent-dns-shim/control.cjs");
const { DIRECTORIES } = require("../agent-dns-shim/config-files.cjs");

function fixture() {
  let state;
  let present = false;
  let value = "";
  let servicePid = 100;
  let clock = 0;
  const receipts = [];
  const content = "[Resolve]\n# ordinary default\n";
  const owned = { present: true, ino: "1", dev: "1", ctimeNs: "1", sha256: "owned" };
  const r = {
    mode: "apply",
    token: () => "a".repeat(64),
    environment: () => ({ allowed: true }),
    listener: () => ({
      status: 0,
      stdout: "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n",
      stderr: "",
      error: null,
    }),
    status: () => ({
      status: 1,
      stdout: "",
      stderr: "cat: No such file or directory",
      error: null,
    }),
    config: () => ({
      status: 0,
      stdout: `# /etc/systemd/resolved.conf\n${content}`,
      stderr: "",
      error: null,
    }),
    main: () => ({ present: true, content, sha256: "main" }),
    files: () => ({
      directories: DIRECTORIES.map((entry) => ({ path: entry, absent: true })),
      effective: [],
    }),
    pathPresent: () => present,
    dns: () => `Global: ${value}\nLink 2 (eth0): 168.63.129.16\n`,
    service: () => `ExecMainPID=${servicePid}\nExecMainStartTimestampMonotonic=100000\n`,
    getent: () => ({
      status: 0,
      stdout: "140.82.1.1 STREAM github.com\n",
      stderr: "",
      error: null,
    }),
    save: (s) => {
      state = s;
    },
    load: () => state,
    root: (mode) => {
      if (mode === "create") present = true;
      if (mode === "remove") present = false;
      return present ? owned : { present: false };
    },
    restart: () => {
      servicePid += 1;
      value = present ? "127.0.0.1" : "";
    },
    now: () => clock,
    pause: (ms) => {
      clock += ms;
    },
    bootMicros: () => 1,
    receipt: (phase, record) => receipts.push({ phase, ...record }),
    outputs: () => {},
  };
  const probe = (command, args) => ({
    status: 0,
    stdout: args.includes("readlink")
      ? "/run/systemd/resolve/stub-resolv.conf\n"
      : args.includes("systemd-resolved")
        ? "active\n"
        : "inactive\n",
    stderr: "",
    error: null,
  });
  const install = control.install;
  const runMain = (runtime) => control.runPhase("main", runtime);
  return { r, probe, install, runMain, receipts };
}

test("drill passes only with verified safety and deliberately failing real shim main", () => {
  const f = fixture();
  const record = runDrill(f);
  assert.equal(record.disposition, "DRILL_PASS");
  assert.equal(record.mainFailedAsExpected, true);
  assert.equal(record.after.owned.present, false);
  assert.equal(record.checks.dnsRestored, true);
});

test("a green main never makes a rollback drill pass", () => {
  const f = fixture();
  const realMain = f.runMain;
  f.runMain = (r) => {
    try {
      realMain(r);
    } catch {
      /* Deliberately simulate a broken fail-open wrapper. */
    }
  };
  const record = runDrill(f);
  assert.equal(record.passed, false);
  assert.equal(record.checks.failClosedMain, false);
  assert.equal(record.recovery.disposition, "ALREADY_RESTORED");
});

test("native/unknown host, live listener and missing installer are inconclusive with no install", () => {
  for (const change of [
    { environment: () => ({ allowed: false }) },
    {
      listener: () => ({
        status: 0,
        stdout:
          "State Recv-Q Send-Q Local Address:Port Peer Address:Port\nUNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n",
        stderr: "",
      }),
    },
    { config: () => ({ status: 1, stdout: "", stderr: "failure" }) },
    { pathPresent: () => true },
    {
      config: () => ({
        status: 0,
        stdout: "# /etc/systemd/resolved.conf\n[Resolve]\nDNS=1.1.1.1\n",
        stderr: "",
      }),
    },
  ]) {
    const f = fixture();
    Object.assign(f.r, change);
    f.install = () => assert.fail("unsafe drill attempted installation");
    assert.equal(runDrill(f).disposition, "DRILL_NOT_EXECUTED");
  }
  const f = fixture();
  f.install = null;
  assert.match(runDrill(f).reason, /interface gap/);
});

test("unexpected restart failure attempts only shim-owned recovery and stays failed", () => {
  const f = fixture();
  f.r.restart = () => {
    throw new Error("restart failed");
  };
  const record = runDrill(f);
  assert.equal(record.passed, false);
  assert.equal(record.error, "restart failed");
  assert.equal(f.r.pathPresent(), false);
  assert.equal(record.recovery.disposition, "ROLLED_BACK_UNINITIALIZED");
});

test("an installer failure result stops induction and recovers owned intent", () => {
  const f = fixture();
  const install = f.install;
  f.install = (r, state) => ({ ...install(r, state), failed: true });
  const record = runDrill(f);
  assert.equal(record.passed, false);
  assert.equal(record.error, "portable installer reported failure");
  assert.equal(record.inducedService, undefined);
  assert.equal(f.r.pathPresent(), false);
});
