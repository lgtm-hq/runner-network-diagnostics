"use strict";
// Exercise real child-process timeout validation with fractional monotonic clocks.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { probe } = require("./runtime.cjs");
const { probe: syntheticProbe } = require("../synthetic-induce/support.cjs");
const { waitInitialized } = require("./lifecycle.cjs");
const { waitForAgent } = require("../synthetic-induce/lifecycle.cjs");
const control = require("./control.cjs");
const { harness } = require("./fixtures.cjs");
const NODE = process.execPath;
const ABSENT = "process.stderr.write('cat: No such file or directory\\n');process.exit(1)";
const SLEEP = "setTimeout(() => {}, 5000)";

for (const budget of [1970.6619759999994, 1999.999, 1.5, 0.4, 1e-9, 0, -0.5, -1, NaN, -Infinity]) {
  test(`shim probe budget ${budget} is a valid bounded integer timeout`, () => {
    const start = performance.now();
    const result = probe(NODE, ["-e", SLEEP], budget);
    assert.ok(performance.now() - start < 2500, "timeout 0/unbounded trap");
    assert.equal(result.error, "ETIMEDOUT");
  });
}
for (const budget of [Infinity, 1e12]) {
  test(`shim probe accepts oversized budget ${budget} without a range error`, () => {
    assert.equal(probe(NODE, ["-e", ""], budget).status, 0);
  });
}
for (const budget of [1970.66, 0.4, 0, -1, NaN, -Infinity]) {
  test(`synthetic/oracle probe budget ${budget} is a valid bounded timeout`, () => {
    const start = performance.now();
    const result = syntheticProbe(NODE, ["-e", SLEEP], { timeoutMs: budget });
    assert.ok(performance.now() - start < 2500);
    assert.ok(result.error);
  });
}
// Model production sub-millisecond clock readings through the actual process launcher.
function fractional(r, step = 250.137) {
  let clock = 1000.3141592;
  r.now = () => clock;
  r.pause = (ms) => {
    clock += ms + 0.0137;
  };
  r.status = (remainingMs = 2000) => {
    clock += step;
    return probe(NODE, ["-e", ABSENT], Math.min(2000, remainingMs));
  };
  return r;
}
test("waitInitialized reaches DEADLINE_EXPIRED through real spawnSync with fractional clock", () => {
  const result = waitInitialized(fractional(harness()));
  assert.equal(result.outcome, "DEADLINE_EXPIRED");
});
test("apply main rolls back fail-closed when an agent never initializes (fractional clock)", () => {
  const r = harness();
  control.runPhase("pre", r);
  fractional(r);
  r.listener = () => ({
    status: 0,
    stdout: "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n",
    stderr: "",
    error: null,
  });
  assert.throws(() => control.runPhase("main", r), /ROLLED_BACK_UNINITIALIZED/);
  assert.ok(r.events.includes("remove"));
});
test("apply main still rolls back if the wait itself throws", () => {
  const r = harness();
  control.runPhase("pre", r);
  r.status = (budget) => {
    if (budget !== undefined) throw new Error("injected wait fault");
    return { status: 1, stdout: "", stderr: "cat: No such file or directory", error: null };
  };
  r.listener = () => ({
    status: 0,
    stdout: "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n",
    stderr: "",
    error: null,
  });
  assert.throws(() => control.runPhase("main", r), /ROLLED_BACK_UNINITIALIZED/);
  assert.ok(r.events.includes("remove"));
  assert.equal(r.receipts.at(-1).readiness.outcome, "WAIT_ERROR");
  assert.equal(r.receipts.at(-1).policyClearance, false);
});
test("oracle-style waitForAgent reaches DEADLINE_EXPIRED through real spawnSync", () => {
  let clock = 0.271828;
  const result = waitForAgent({
    timeoutMs: 30000,
    now: () => clock,
    pause: () => {
      clock += 250.0731;
    },
    read: (remainingMs) => {
      clock += 9.377;
      return syntheticProbe(NODE, ["-e", ABSENT], {
        timeoutMs: Math.max(1, Math.min(2000, remainingMs)),
      });
    },
  });
  assert.equal(result.outcome, "DEADLINE_EXPIRED");
});

for (const budget of [Infinity, 1e12]) {
  test(`oracle probe accepts oversized budget ${budget} with its fixed cap`, () => {
    assert.equal(syntheticProbe(NODE, ["-e", ""], { timeoutMs: budget }).status, 0);
  });
}
for (const mode of ["apply", "observe"]) {
  test(`wait exception remains a diagnostic readiness failure on an unowned ${mode} host`, () => {
    const r = harness();
    r.mode = mode;
    r.topology = () => ({ allowed: false });
    control.runPhase("pre", r);
    const status = r.status;
    r.status = (budget) => {
      if (budget !== undefined) throw new Error("injected wait fault");
      return status();
    };
    const record = control.runPhase("main", r);
    assert.equal(record.readiness.outcome, "WAIT_ERROR");
    assert.equal(record.readiness.ready, false);
    assert.equal(record.failed, undefined);
    assert.equal(r.events.includes("remove"), false);
  });
}
