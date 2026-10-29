"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { nonce } = require("./support.cjs");
const { queryWindow, measure, afterHardener } = require("./oracle.cjs");

test("nonce names are fresh, phase-specific, fixed 16-hex labels", () => {
  const names = new Set();
  for (const label of ["p", "a", "z", "u"])
    for (let i = 0; i < 32; i += 1) {
      const name = nonce(label);
      assert.match(name, new RegExp(`^${label}-[a-f0-9]{16}\\.example\\.com$`));
      names.add(name);
    }
  assert.equal(names.size, 128);
  assert.throws(() => nonce("x"), /invalid nonce/);
  assert.throws(() => nonce("a", () => Buffer.from("short")), /entropy/);
});

test("P repeats only its own nonce after one second and retains NXDOMAIN/query errors", () => {
  const calls = [];
  const r = {
    nonce,
    pause: (ms) => calls.push(ms),
    probe: (command, args) => {
      calls.push(args.at(-1));
      return { status: 2, stdout: "", stderr: "", error: null };
    },
  };
  const record = queryWindow({ label: "P", r });
  assert.equal(record.allowedName, "objects.githubusercontent.com");
  assert.deepEqual(calls, ["objects.githubusercontent.com", record.nonce, 1000, record.nonce]);
  assert.equal(record.denied.status, 2);
  assert.equal(record.publicBaselineRequiresWire, true);
  assert.equal(record.windowToleranceMs, 1);
  assert.ok(Date.parse(record.oracleEnd) >= Date.parse(record.oracleStart));
  assert.ok(BigInt(record.elapsedNs) >= 0n);
  for (const label of ["A", "Z", "U"]) {
    const next = queryWindow({ label, r });
    assert.equal(next.allowedName, "api.github.com");
    assert.equal(next.repeat, undefined);
    assert.notEqual(next.nonce, record.nonce);
  }
});

function fixture() {
  const records = {};
  const r = {
    out: "/not-used-for-U",
    nonce,
    probe: (command, args) => ({
      status: 0,
      stdout: args.includes("ahostsv4") ? "54.185.253.63 STREAM\n" : "Initialized\n",
      stderr: "",
      error: null,
    }),
    file: (file) =>
      file.includes("99-lgtm")
        ? { present: false }
        : { present: true, sha256: file, content: "[Resolve]\n" },
    read: () => ({
      classification: "UNAFFECTED",
      main: { sha256: "before" },
      platform: { sha256: "/etc/systemd/resolved.conf.d/90-egress-proxy.conf" },
    }),
    write: (name, record) => {
      records[name] = record;
    },
  };
  return { r, records };
}

test("U records raw command failures and no owned file without invoking topology or capture", () => {
  const { r, records } = fixture();
  r.probe = () => ({ status: null, stdout: "", stderr: "", error: "timeout" });
  const record = measure({ label: "U", r, readiness: { ready: false } });
  assert.equal(record.observations.dns.error, "timeout");
  assert.equal(record.denied.error, "timeout");
  assert.equal(record.observations.owned.present, false);
  assert.equal(records["oracle-U.json"], record);
  assert.throws(() => measure({ label: "invalid", r }), /invalid oracle/);
});

test("readiness terminal failure still preserves post-hardener U evidence before failing", () => {
  const { r, records } = fixture();
  const probe = r.probe;
  r.probe = (command, args) =>
    args.includes("/home/agent/agent.status")
      ? { status: 0, stdout: "Error initializing", stderr: "", error: null }
      : probe(command, args);
  assert.throws(() => afterHardener({ label: "U", r }), /readiness failed/);
  assert.equal(records["readiness-U.json"].outcome, "TERMINAL_STATUS_ERROR");
  assert.equal(records["oracle-U.json"].readiness.ready, false);
});

test("unaffected owned-file presence fails after retaining its nonce reference", () => {
  const { r, records } = fixture();
  r.file = () => ({ present: true, sha256: "changed" });
  assert.throws(() => afterHardener({ label: "U", r }), /owned path present/);
  assert.match(records["oracle-U.json"].nonce, /^u-/);
});

test("partial and uninitialized U observations never advertise a same-dispatch reference candidate", () => {
  const { r } = fixture();
  const read = r.read;
  r.read = (name) => ({ ...read(name), classification: "PARTIAL" });
  assert.equal(
    measure({ label: "U", r, readiness: { ready: true } }).sinkholeReferenceCandidate,
    false,
  );
  r.read = read;
  assert.equal(
    measure({ label: "U", r, readiness: { ready: false } }).sinkholeReferenceCandidate,
    false,
  );
  assert.equal(
    measure({ label: "U", r, readiness: { ready: true } }).sinkholeReferenceCandidate,
    true,
  );
});
