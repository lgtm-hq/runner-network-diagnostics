"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { finish, manifest } = require("./finish.cjs");
const { negative } = require("./negative.cjs");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "native-finish-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of ["ci1203", "ci1203-workaround", "lgtm-agent-dns-shim"])
    fs.mkdirSync(path.join(root, name));
  const out = path.join(root, "ci1203-workaround");
  t.mock.method(console, "log", () => {});
  fs.writeFileSync(path.join(root, "ci1203", "selection.json"), "{}\n");
  fs.writeFileSync(
    path.join(root, "lgtm-agent-dns-shim", "state.json"),
    '{"mutationIntent":false}\n',
  );
  return {
    root,
    out,
    write: (name, record) => {
      fs.writeFileSync(path.join(out, name), `${JSON.stringify(record)}\n`, { flag: "wx" });
      return record;
    },
    read: (name) =>
      name === "selection.json"
        ? { classification: "UNAFFECTED" }
        : JSON.parse(fs.readFileSync(path.join(out, name), "utf8")),
    topology: () => "passive",
    vendor: () => assert.fail("unexpected vendor operation on ordinary host"),
  };
}

test("unaffected finish preserves no-op states and json inventory with capture completeness false", (t) => {
  const r = fixture(t);
  finish(r);
  assert.equal(r.read("finish.json").captureCompleteness, false);
  const inventory = fs.readFileSync(path.join(r.root, "ci1203", "SHA256SUMS"), "utf8");
  assert.match(inventory, /selection\.json/);
  assert.match(inventory, /completeness\.txt/);
  assert.match(
    fs.readFileSync(path.join(r.root, "ci1203", "completeness.txt"), "utf8"),
    /NOT_CAPTURED/,
  );
});

test("candidate finish freezes directly and records failure without invoking legacy vendor finish", (t) => {
  const r = fixture(t);
  r.write("capture-intent.json", { requested: true });
  r.topology = () => {
    throw new Error("topology failed");
  };
  let finished = false;
  r.freeze = () => {
    finished = true;
    return { status: 1, error: null };
  };
  r.vendor = (mode) => {
    assert.equal(mode, "snapshot");
    return { status: 0, error: null };
  };
  assert.throws(() => finish(r), /topology failed/);
  assert.equal(finished, true);
  assert.equal(r.read("finish.json").capture.status, 1);
  assert.ok(fs.existsSync(path.join(r.out, "SHA256SUMS")));
});

test("healthy direct freeze with fresh P can finish without any GitHub wire packet", (t) => {
  const r = fixture(t);
  r.write("capture-intent.json", { requested: true });
  r.write("oracle-P.json", {
    nonce: "p-0123456789abcdef.example.com",
    oracleStart: "2026-10-26T12:00:00.100Z",
    oracleEnd: "2026-10-26T12:00:00.200Z",
    windowToleranceMs: 1,
  });
  const calls = [];
  r.freeze = () => {
    calls.push("freeze");
    fs.writeFileSync(
      path.join(r.root, "ci1203", "capture-status.txt"),
      JSON.stringify({ stage: "frozen", healthyAtFreeze: true, freezeOutcome: "acknowledged" }),
    );
    fs.writeFileSync(
      path.join(r.root, "ci1203", "dns-wire.txt"),
      "2026-10-26 12:00:00.123456 IP (proto UDP (17), length 60)\n    127.0.0.1.40000 > 127.0.0.100.53: 1234+ A? p-0123456789abcdef.example.com. (32)\n",
    );
    return { status: 0, error: null };
  };
  r.vendor = (mode) => {
    calls.push(mode);
    assert.equal(mode, "snapshot");
    return { status: 0, error: null };
  };
  r.topology = () => {
    calls.push("topology");
  };
  finish(r);
  assert.deepEqual(calls, ["freeze", "snapshot", "topology"]);
  assert.equal(r.read("native-completeness.json").complete, true);
  assert.equal(r.read("finish.json").captureCompleteness, true);
});

test("native manifest refuses symlink files and cannot silently omit uploadable json", (t) => {
  const r = fixture(t);
  fs.symlinkSync("/etc/hosts", path.join(r.out, "foreign.json"));
  assert.throws(() => manifest(r.out));
  fs.unlinkSync(path.join(r.out, "foreign.json"));
  r.write("added.json", { native: true });
  manifest(r.out);
  assert.match(fs.readFileSync(path.join(r.out, "SHA256SUMS"), "utf8"), /added\.json/);
});

test("strict-negative wrapper retains exact IP/PID and time evidence while vendor status controls failure", (t) => {
  const r = fixture(t);
  r.vendor = (mode) => {
    assert.equal(mode, "negative");
    fs.writeFileSync(
      path.join(r.root, "ci1203", "negative.txt"),
      "verdict=CONFIRMED_BLOCK curl_rc=7 address=104.20.23.154 pid=1234 agent=active\n",
    );
    return { status: 0, error: null };
  };
  negative(r);
  const record = r.read("strict-negative-window.json");
  assert.deepEqual(record.selectedControl, {
    verdict: "CONFIRMED_BLOCK",
    curlRc: 7,
    address: "104.20.23.154",
    pid: 1234,
    agent: "active",
  });
  assert.equal(record.windowToleranceMs, 1);
  assert.ok(Date.parse(record.end) >= Date.parse(record.start));
});

test("strict-negative failure preserves its envelope without inventing an exclusion", (t) => {
  const r = fixture(t);
  r.vendor = () => ({ status: 1, error: "failed" });
  assert.throws(() => negative(r), /strict negative failed/);
  assert.equal(r.read("strict-negative-window.json").selectedControl, null);
});
