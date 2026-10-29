"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const {
  environmentGate,
  topologyGate,
  runtime,
  createRuntime,
  consoleReceipt,
  durableWrite,
  probe,
  checked,
} = require("./runtime.cjs");
const { runPhase } = require("./control.cjs");
const { ok, harness, snap, HEADER } = require("./fixtures.cjs");
function gate(overrides = {}) {
  return environmentGate({
    platform: "linux",
    runnerOs: "Linux",
    hosted: "github-hosted",
    exists: (file) => file === "/run/systemd/system",
    run: (command) => (command === "cat" ? ok("systemd\n") : { ...ok(), status: 1 }),
    sudo: () => ok(),
    ...overrides,
  });
}
test("host gate requires explicit ephemeral GitHub-hosted Linux plus positive non-container and sudo evidence", () =>
  assert.equal(gate().allowed, true));
for (const overrides of [
  { platform: "darwin" },
  { runnerOs: "Windows" },
  { hosted: "self-hosted" },
  { hosted: "persistent" },
  { hosted: undefined },
  { exists: () => false },
  { exists: (file) => file === "/.dockerenv" },
  { exists: (file) => file === "/run/.containerenv" },
  { run: () => ok() },
  { run: () => ({ ...ok(), status: 127 }) },
  { run: () => ({ ...ok(), status: 1, stderr: "warning" }) },
  { run: () => ({ ...ok(), status: 1, error: "ENOENT" }) },
  { sudo: () => ({ ...ok(), status: 1 }) },
  { sudo: () => ({ ...ok(), stderr: "sudo diagnostic" }) },
]) {
  test(`host gate refuses ${Object.keys(overrides).join()}: ${String(Object.values(overrides)[0])}`, () =>
    assert.equal(gate(overrides).allowed, false));
}
test("PID 1 must positively be systemd, including a successful empty or unreadable probe", () => {
  for (const value of [ok(""), ok("init\n"), { ...ok("systemd\n"), stderr: "warning" }])
    assert.equal(
      gate({ run: (command) => (command === "cat" ? value : { ...ok(), status: 1 }) }).allowed,
      false,
    );
});
function topology(overrides = {}) {
  return topologyGate({
    resolv: {
      canonical: "/etc/resolv.conf",
      file: { present: true, ...snap("nameserver 127.0.0.100\n") },
    },
    services: Object.fromEntries(
      ["systemd-resolved", "egress-dns-resolver", "egress-outbound-proxy"].map((name) => [
        name,
        ok("active\n"),
      ]),
    ),
    listener: ok(`${HEADER}UNCONN 0 0 127.0.0.100:53 0.0.0.0:*\n`),
    ...overrides,
  });
}
test("known topology requires all three active services, self resolv.conf, .100 nameserver and exact listener", () => {
  assert.equal(topology().allowed, true);
  for (const resolv of [
    undefined,
    { canonical: "/run/systemd/resolve/stub-resolv.conf" },
    {
      canonical: "/etc/resolv.conf",
      file: { present: true, content: "# nameserver 127.0.0.100\n" },
    },
  ])
    assert.equal(topology({ resolv }).allowed, false);
  for (const name of ["systemd-resolved", "egress-dns-resolver", "egress-outbound-proxy"]) {
    const services = topology().services;
    for (const value of [
      ok("inactive\n"),
      { ...ok("active\n"), stderr: "warning" },
      { ...ok("active\n"), status: 1 },
      undefined,
    ]) {
      services[name] = value;
      assert.equal(topology({ services }).allowed, false);
    }
  }
  for (const listener of [
    ok(HEADER),
    ok(`${HEADER}UNCONN 0 0 0.0.0.0:53 *:*\n`),
    { ...ok(HEADER), error: "ETIMEDOUT" },
  ])
    assert.equal(topology({ listener }).allowed, false);
  assert.equal(createRuntime, runtime);
});
test("excluded OS/host/container never attempts sudo", () => {
  for (const overrides of [
    { platform: "win32" },
    { hosted: "self-hosted" },
    { exists: () => true },
  ])
    assert.equal(gate({ ...overrides, sudo: () => assert.fail("unexpected sudo") }).allowed, false);
});
test("receipt hash covers the exact one-line JSON plus newline", () => {
  const printed = [];
  const content = consoleReceipt(
    { phase: "main", disposition: "SHIM_UNVERIFIED", failed: true },
    (line) => printed.push(line),
  );
  assert.equal(printed.length, 2);
  assert.equal(
    printed[0],
    `lgtm-agent-dns-shim RECEIPT ${content.trimEnd()} sha256=${createHash("sha256").update(content).digest("hex")}`,
  );
  assert.equal(printed[1], "lgtm-agent-dns-shim: SHIM_UNVERIFIED");
});
test("console receipt is printed before a main failure is thrown, and outputs append before throw", () => {
  const r = harness();
  runPhase("pre", r);
  r.initialized();
  r.service = () => "ExecMainStartTimestampMonotonic=0\n";
  const lines = [];
  r.receipt = (phase, record) => consoleReceipt({ phase, ...record }, (line) => lines.push(line));
  try {
    runPhase("main", r);
    assert.fail("main unexpectedly passed");
  } catch (error) {
    assert.match(error.message, /SHIM_INEFFECTIVE/);
    assert.match(lines[0], /^lgtm-agent-dns-shim RECEIPT /);
    assert.match(lines[0], /sha256=[a-f0-9]{64}$/);
    assert.equal(r.output.disposition, "SHIM_INEFFECTIVE");
  }
});
test("durable exclusive writes refuse overwrite and leave no temp files", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agent-dns-state-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, "state.json");
  durableWrite({ file, content: "intent", exclusive: true });
  assert.throws(() => durableWrite({ file, content: "overwritten", exclusive: true }), /EEXIST/);
  assert.equal(fs.readFileSync(file, "utf8"), "intent");
  durableWrite({ file, content: "acknowledged" });
  assert.equal(fs.readFileSync(file, "utf8"), "acknowledged");
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(root), ["state.json"]);
});
test("native probes report failed, bounded, timed out and stderr-bearing commands", () => {
  const script = (code, timeout) => probe(process.execPath, ["-e", code], timeout);
  assert.equal(script("process.stdout.write('fine')").stdout, "fine");
  assert.equal(script("process.exit(7)").status, 7);
  assert.throws(() => checked(script("process.stderr.write('diagnostic')")), /diagnostic/);
  assert.ok(script("process.stdout.write('x'.repeat(300000))").error);
  assert.ok(script("setTimeout(() => {}, 10000)", 50).error);
});
test("actual entry points persist three receipt phases and append no-op outputs without external commands", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agent-dns-entry-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const output = path.join(root, "outputs");
  fs.writeFileSync(output, "prior=value\n");
  const env = {
    ...process.env,
    RUNNER_TEMP: root,
    RUNNER_OS: "Linux",
    INPUT_HOSTED: "self-hosted",
    INPUT_MODE: "apply",
    GITHUB_OUTPUT: output,
    PATH: "/nonexistent",
  };
  for (const phase of ["pre", "main", "post"]) {
    const result = spawnSync(process.execPath, [path.join(__dirname, `${phase}.cjs`)], {
      env,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    const receipt = fs.readFileSync(
      path.join(root, "lgtm-agent-dns-shim", `${phase}.json`),
      "utf8",
    );
    assert.match(
      result.stdout,
      new RegExp(`sha256=${createHash("sha256").update(receipt).digest("hex")}`),
    );
    assert.equal(JSON.parse(receipt).disposition, "NOT_APPLICABLE");
  }
  assert.equal(
    fs.readFileSync(output, "utf8"),
    "prior=value\napplicable=false\napplied=false\ndisposition=NOT_APPLICABLE\n",
  );
});
test("runtime initialization failure prints hashed receipt before error annotation", () => {
  const result = spawnSync(process.execPath, [path.join(__dirname, "main.cjs")], {
    env: { ...process.env, RUNNER_TEMP: "relative" },
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.match(result.stdout, /RUNTIME_UNAVAILABLE.*sha256=[a-f0-9]{64}/);
  assert.match(result.stderr, /::error::/);
});
