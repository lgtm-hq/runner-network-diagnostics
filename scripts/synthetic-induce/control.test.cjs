"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { ordinaryConfig, inducibility, prepare, restore } = require("./control.cjs");
const treatment = require("../synthetic-treatment/control.cjs");
const { treatmentCleanup: cleanup } = require("./lifecycle.cjs");
const { operate, bytes } = require("../resolver-counterfactual/root-file.cjs");
const { mainConfig } = require("./support.cjs");
const token = "a".repeat(64);
const facts = {
  region: "eastus",
  target: "/run/systemd/resolve/stub-resolv.conf",
  resolverUnit: "inactive",
  proxyUnit: "inactive",
  listener: "absent",
};
const config =
  "EFFECTIVE RESOLVED CONFIG (DNS fields only)\n# /etc/systemd/resolved.conf\n\nUNIT systemd-resolved\n";
const dns = "Global:\nLink 2 (eth0): 168.63.129.16\n";
const configObservation = {
  status: 0,
  error: null,
  stderr: "",
  stdout: "# /etc/systemd/resolved.conf\n# Ordinary defaults\n[Resolve]\n#DNS=\n",
};
const baseline = {
  configObservation,
  arm: "I1",
  facts,
  config,
  selection: { candidate: false, facts },
  hosted: "github-hosted",
  platformExists: false,
  overrideExists: false,
};
function mock() {
  const present = { reset: false, override: false };
  const events = [];
  let state;
  let hardened = false;
  let pid = 100;
  const io = {
    save(value) {
      state = structuredClone(value);
      events.push("save");
    },
    token: () => token,
    hash: (file) => (file === mainConfig ? (hardened ? "hardened" : "original") : "reset-hash"),
    dns: () =>
      hardened && (present.override || !present.reset)
        ? dns.replace("Global:", "Global: 127.0.0.1")
        : dns,
    pid: () => String(pid),
    restart() {
      pid += 1;
      events.push("restart");
    },
    root(mode, value, profile = "override") {
      assert.equal(value, token);
      events.push(`${mode}:${profile}`);
      if (mode === "create") {
        if (present[profile]) throw new Error("exists");
        present[profile] = true;
        return { created: true };
      }
      if (mode === "inspect") return { present: present[profile] };
      const removed = present[profile];
      present[profile] = false;
      return { removed };
    },
  };
  return {
    io,
    events,
    present,
    load: () => state,
    harden: () => {
      hardened = true;
    },
    hardenerPost: () => {
      events.push("hardener-post");
      // The actual hardener post signals done; it does not revert DNS.
    },
  };
}
function induce(m, arm = "I1") {
  return prepare({ ...baseline, arm, io: m.io });
}
function restoreState(m, state) {
  // Simulate the ready agent and its measured main file before the post hook.
  m.harden();
  state.observedMainAtOracleA = { sha256: "hardened" };
  return restore({
    state,
    io: m.io,
    overrideExists: () => m.present.override,
    resolve: () => ({ status: 0, stdout: "140.82.112.4 STREAM github.com\n" }),
  });
}
test("ordinary positive topology is inducible independent of region", () => {
  for (const region of ["eastus", "westus2", "unknown"])
    assert.deepEqual(inducibility({ ...baseline, facts: { ...facts, region }, dns }), []);
});
test("self-hosted, unknown topology, existing paths and active settings never authorize induction", () => {
  for (const change of [
    { hosted: "self-hosted" },
    { hosted: undefined },
    { configObservation: { ...configObservation, stdout: "" } },
    { platformExists: true },
    { overrideExists: true },
    { configObservation: { ...configObservation, stdout: `${configObservation.stdout}\nDNS=\n` } },
    {
      configObservation: {
        ...configObservation,
        stdout: `${configObservation.stdout}\nDomains=~.\n`,
      },
    },
    { dns: dns.replace("Global:", "Global: 127.0.0.1") },
    { dns: "Global:\nLink 2: 1.1.1.1\n" },
    ...["target", "resolverUnit", "proxyUnit", "listener"].map((k) => ({
      facts: { ...facts, [k]: "unknown" },
    })),
  ]) {
    const m = mock();
    const state = prepare({
      ...baseline,
      ...change,
      io: change.dns ? { ...m.io, dns: () => change.dns } : m.io,
    });
    assert.equal(state.inScope, false);
    assert.equal(state.disposition, "SYNTHETIC_NOT_INDUCIBLE");
    assert.equal(m.present.reset, false);
  }
});
test("real captured topology is observed without mutation", () => {
  const realFacts = {
    region: "westus2",
    target: "/etc/resolv.conf",
    resolverUnit: "active",
    proxyUnit: "active",
    listener: "present",
  };
  const m = mock();
  const state = prepare({
    ...baseline,
    facts: realFacts,
    selection: { candidate: true, facts: realFacts },
    config:
      "EFFECTIVE RESOLVED CONFIG (DNS fields only)\n# /etc/systemd/resolved.conf\n# /etc/systemd/resolved.conf.d/90-egress-proxy.conf\nDNS=\n\nUNIT systemd-resolved\n",
    io: m.io,
  });
  assert.equal(state.disposition, "REAL_TOPOLOGY_ENCOUNTERED");
  assert.equal(m.present.reset, false);
});
test("C0 baseline does not induce a config and preserves distinct disposition", () => {
  const m = mock();
  const s = induce(m, "C0");
  assert.equal(s.disposition, "SYNTHETIC_BASELINE");
  assert.equal(m.present.reset, false);
  assert.ok(!m.events.includes("restart"));
});
test("induction persists intent before exclusive creation and never restarts", () => {
  const m = mock();
  const root = m.io.root;
  m.io.root = (...args) => {
    assert.equal(m.load().mutationIntent, true);
    return root(...args);
  };
  const s = induce(m);
  assert.equal(s.disposition, "SYNTHETIC_INDUCED");
  assert.equal(m.present.reset, true);
  assert.ok(!m.events.includes("restart"));
});
test("lost induction acknowledgement leaves enough durable state for cleanup", () => {
  const m = mock();
  const root = m.io.root;
  m.io.root = (...args) => {
    const result = root(...args);
    if (args[0] === "create") throw new Error("lost create ack");
    return result;
  };
  assert.throws(() => induce(m));
  assert.equal(m.present.reset, true);
  assert.equal(restoreState(m, m.load()).disposition, "SYNTHETIC_FILES_REMOVED");
  assert.equal(m.present.reset, false);
});
test("invalid arm fails before mutation", () => assert.throws(() => induce(mock(), "invalid")));
test("synthetic restoration removes reset and verifies original state", () => {
  const m = mock();
  const s = induce(m);
  assert.equal(restoreState(m, s).disposition, "SYNTHETIC_FILES_REMOVED");
  assert.equal(m.present.reset, false);
  assert.equal(m.events.filter((e) => e === "restart").length, 1);
});

test("missing oracle baseline fails without leaving the owned synthetic reset behind", () => {
  const m = mock();
  const state = induce(m);
  m.harden();
  assert.throws(
    () =>
      restore({
        state,
        io: m.io,
        overrideExists: () => false,
        resolve: () => ({ status: 0, stdout: "address" }),
      }),
    (error) => {
      assert.ok(error.details.failures.includes("oracleAMainBaselineKnown"));
      assert.equal(error.details.checks.platformAbsent, true);
      return true;
    },
  );
  assert.equal(m.present.reset, false);
  assert.equal(m.events.filter((e) => e === "restart").length, 1);
});
test("lost unlink acknowledgement restores but remains failed", () => {
  const m = mock();
  const s = induce(m);
  const root = m.io.root;
  m.io.root = (...args) => {
    const result = root(...args);
    if (args[0] === "remove") throw new Error("lost unlink ack");
    return result;
  };
  assert.throws(() => restoreState(m, s), /synthetic cleanup failed: lost unlink ack/);
  assert.equal(m.present.reset, false);
  assert.equal(m.events.filter((e) => e === "restart").length, 1);
});
test("remaining override refuses restart and success receipt", () => {
  const m = mock();
  const s = induce(m);
  m.present.override = true;
  assert.throws(() => restoreState(m, s), /refusing restart/);
  assert.ok(!m.events.includes("restart"));
});
test("foreign reset or malformed absence never restarts", () => {
  for (const response of [{ present: "unknown" }, { present: true }]) {
    const m = mock();
    const s = induce(m);
    m.io.root = () => response;
    assert.throws(() => restoreState(m, s));
    assert.ok(!m.events.includes("restart"));
  }
});
test("no mutation, DNS drift, failed resolution and original hash drift are not passes", () => {
  assert.equal(restore({ state: null }).disposition, "SYNTHETIC_NO_MUTATION");
  for (const change of [
    { dns: () => "Global: 1.1.1.1\nLink 2: 168.63.129.16\n" },
    { hash: () => "changed" },
  ]) {
    const m = mock();
    const s = induce(m);
    Object.assign(m.io, change);
    assert.throws(() => restoreState(m, s));
  }
  const m = mock();
  const s = induce(m);
  assert.throws(() =>
    restore({
      state: s,
      io: m.io,
      overrideExists: () => false,
      resolve: () => ({ status: 2, stdout: "" }),
    }),
  );
});
test("I2 cleans owned files while the real hardener post retains its main file", () => {
  const m = mock();
  const induction = induce(m, "I2");
  const s = treatment.prepare({ induction, io: m.io });
  assert.equal(m.present.override, true);
  m.harden();
  s.observedMainAtOracleA = { sha256: "hardened" };
  assert.match(m.io.dns(), /Global: 127.0.0.1/);
  assert.equal(
    cleanup({ phase: "guard", state: s, io: m.io }).disposition,
    "REMOVED_WITHOUT_RESTART",
  );
  m.hardenerPost();
  assert.equal(
    cleanup({ phase: "fallback", state: s, io: m.io }).disposition,
    "SYNTHETIC_OVERRIDE_REMOVED",
  );
  assert.equal(m.present.reset, true);
  assert.equal(restoreState(m, induction).disposition, "SYNTHETIC_FILES_REMOVED");
});
test("I3 prepares without override, then permits a separately measured late install", () => {
  const m = mock();
  const induction = induce(m, "I3");
  const s = treatment.prepare({ induction, io: m.io });
  assert.equal(m.present.override, false);
  m.harden();
  assert.equal(m.io.dns(), dns);
  treatment.install(s, m.io);
  m.io.restart();
  assert.match(m.io.dns(), /Global: 127.0.0.1/);
});
test("treatment does not run for baseline, induced-only, or unselected hosts", () => {
  for (const s of [
    null,
    { arm: "I2", inScope: false },
    { arm: "C0", inScope: true },
    { arm: "I1", inScope: true },
  ]) {
    const m = mock();
    assert.equal(
      treatment.prepare({ induction: s, io: m.io }).disposition,
      "SYNTHETIC_NO_MUTATION",
    );
    assert.equal(m.present.override, false);
  }
});
test("incomplete induction or lost ownership refuses treatment", () => {
  const m = mock();
  const induction = induce(m, "I2");
  assert.throws(() =>
    treatment.prepare({ induction: { ...induction, disposition: "unknown" }, io: m.io }),
  );
  m.present.reset = false;
  assert.throws(() => treatment.prepare({ induction, io: m.io }));
});
for (const profile of ["reset", "override"])
  test(`actual ${profile} inode enforces ownership and exclusive creation`, (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-synthetic-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const args = { root, uid: process.getuid(), token, profile };
    const file = path.join(
      root,
      profile === "reset" ? "90-egress-proxy.conf" : "99-ci1203-counterfactual.conf",
    );
    assert.deepEqual(operate({ ...args, mode: "create" }), { created: true });
    assert.equal(fs.readFileSync(file, "utf8"), bytes(token, profile));
    assert.throws(() => operate({ ...args, mode: "create" }));
    assert.throws(() => operate({ ...args, token: "b".repeat(64), mode: "remove" }));
    assert.deepEqual(operate({ ...args, mode: "inspect" }), { present: true });
    assert.deepEqual(operate({ ...args, mode: "remove" }), { removed: true });
    assert.deepEqual(operate({ ...args, mode: "inspect" }), { present: false });
    fs.symlinkSync(path.join(root, "nonexistent"), file);
    assert.throws(() => operate({ ...args, mode: "create" }));
    assert.throws(() => operate({ ...args, mode: "remove" }));
    assert.equal(fs.lstatSync(file).isSymbolicLink(), true);
  });
test("unknown file profile rejected", () => assert.throws(() => bytes(token, "anything")));

test("synthetic runtime persists separate receipts and uses bounded fixed root argv", (t) => {
  const support = require("./support.cjs");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-synthetic-runtime-"));
  const old = { temp: process.env.RUNNER_TEMP, path: process.env.PATH };
  t.after(() => {
    if (old.temp === undefined) delete process.env.RUNNER_TEMP;
    else process.env.RUNNER_TEMP = old.temp;
    process.env.PATH = old.path;
    fs.rmSync(root, { recursive: true, force: true });
  });
  process.env.RUNNER_TEMP = root;
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(
    path.join(bin, "sudo"),
    "#!/bin/sh\ncase \"$*\" in *root-file.cjs*) printf '{\"present\":false}\\n';; *resolvectl*dns*) printf 'Global:\\nLink 2: 168.63.129.16\\n';; *) exit 2;; esac\n",
    { mode: 0o755 },
  );
  process.env.PATH = `${bin}:${old.path}`;
  const r = support.runtime("ci1203-synthetic-test");
  assert.equal(r.load(), null);
  r.io.save({ arm: "C0" });
  assert.deepEqual(r.load(), { arm: "C0" });
  assert.deepEqual(r.io.root("inspect", token, "reset"), { present: false });
  assert.equal(r.io.dns(), "Global:\nLink 2: 168.63.129.16\n");
  r.receipt("test", { disposition: "SYNTHETIC_NO_MUTATION" });
  assert.equal(JSON.parse(fs.readFileSync(path.join(r.out, "test.json"), "utf8")).synthetic, true);
  assert.throws(() => r.receipt("test", {}));
  assert.equal(support.exists(path.join(root, "missing")), false);
  assert.equal(support.exists(bin), true);
  assert.throws(() => support.checked("sudo", ["bad"]));
  assert.equal(support.probe(path.join(root, "nonexistent"), []).status, null);
});

test("entry dispatch preserves missing-state failures and unselected-host observations", (t) => {
  const induction = require("./control.cjs");
  const m = mock();
  const receipts = [];
  const old = process.exitCode;
  t.after(() => {
    process.exitCode = old;
  });
  const setup = () => ({ io: m.io, load: m.load, receipt: (...r) => receipts.push(r) });
  process.exitCode = undefined;
  induction.entry("main", setup);
  assert.equal(process.exitCode, 1);
  process.exitCode = undefined;
  treatment.entry("main", setup);
  assert.equal(process.exitCode, 1);
  process.exitCode = undefined;
  treatment.entry("register-guard", setup);
  assert.equal(receipts.at(-1)[0], "register-guard");
  treatment.entry("guard", setup);
  assert.equal(receipts.at(-1)[1].disposition, "NO_MUTATION");
  treatment.entry("fallback", setup);
  assert.equal(receipts.at(-1)[1].disposition, "NO_MUTATION");
  induction.entry("invalid", setup);
  assert.equal(process.exitCode, 1);
  process.exitCode = undefined;
  m.io.save({ disposition: "SYNTHETIC_NO_MUTATION" });
  treatment.entry("main", setup);
  assert.equal(receipts.at(-1)[1].disposition, "SYNTHETIC_NO_MUTATION");
  m.io.save({ arm: "I2", disposition: "SYNTHETIC_OVERRIDE_INSTALLED" });
  treatment.entry("main", setup);
  assert.equal(process.exitCode, 1);
});

test("oracle records resolver windows and failed resolutions without claiming path success", (t) => {
  const support = require("./support.cjs");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-oracle-"));
  const old = { path: process.env.PATH, temp: process.env.RUNNER_TEMP };
  t.after(() => {
    process.env.PATH = old.path;
    if (old.temp === undefined) delete process.env.RUNNER_TEMP;
    else process.env.RUNNER_TEMP = old.temp;
    fs.rmSync(root, { recursive: true, force: true });
  });
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  fs.mkdirSync(path.join(root, "ci1203"));
  fs.writeFileSync(
    path.join(bin, "sudo"),
    "#!/bin/sh\ncase \"$*\" in *agent.status*) printf 'Initialized\\n';; *) printf 'Global: ~.\\n';; esac\n",
    { mode: 0o755 },
  );
  fs.writeFileSync(path.join(bin, "systemctl"), "#!/bin/sh\nprintf '1234\\n'\n", { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "timeout"), "#!/bin/sh\nexit 2\n", { mode: 0o755 });
  fs.writeFileSync(
    path.join(bin, "bash"),
    "#!/bin/sh\nprintf 'mock topology\\n' > \"$RUNNER_TEMP/ci1203/topology-$2.txt\"\n",
    { mode: 0o755 },
  );
  process.env.RUNNER_TEMP = root;
  process.env.PATH = `${bin}:${old.path}`;
  const r = support.runtime("ci1203-synthetic-oracle-test");
  r.io.save({ arm: "I1" });
  r.observeMain = () => ({ sha256: "hardened", content: "[Resolve]\nDNS=127.0.0.1\nDomains=~.\n" });
  r.io.dns = () => dns;
  support.measure("A", r);
  const oracle = JSON.parse(fs.readFileSync(path.join(r.out, "oracle-A.json"), "utf8"));
  assert.equal(oracle.allowed.status, 2);
  assert.equal(oracle.denied.status, 2);
  assert.equal(oracle.synthetic, true);
  assert.ok(oracle.oracleStart <= oracle.oracleEnd);
  assert.equal(oracle.pid, "1234");
  fs.writeFileSync(path.join(bin, "sudo"), "#!/bin/sh\nprintf 'Unavailable\\n'\n", { mode: 0o755 });
  assert.throws(() => support.measure("B", r), /not initialized/);
  assert.equal(fs.existsSync(path.join(r.out, "oracle-B.json")), false);
});

test("I3 entry requires a retained oracle A before changing the same host", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-I3-entry-"));
  const old = { temp: process.env.RUNNER_TEMP, exit: process.exitCode };
  t.after(() => {
    if (old.temp === undefined) delete process.env.RUNNER_TEMP;
    else process.env.RUNNER_TEMP = old.temp;
    process.exitCode = old.exit;
    fs.rmSync(root, { recursive: true, force: true });
  });
  process.env.RUNNER_TEMP = root;
  const m = mock();
  const induction = induce(m, "I3");
  treatment.prepare({ induction, io: m.io });
  m.harden();
  const setup = () => ({ out: root, io: m.io, load: m.load, receipt: () => {} });
  process.exitCode = undefined;
  treatment.entry("main", setup);
  assert.equal(process.exitCode, 1);
  assert.equal(m.present.override, false);
  assert.ok(!m.events.includes("restart"));
});

test("full configuration gate rejects failed, spaced, foreign and unknown configuration", () => {
  assert.equal(ordinaryConfig(configObservation), true);
  for (const change of [
    { status: 1 },
    { status: 124 },
    { status: null, error: "ETIMEDOUT" },
    { stderr: "could not read drop-in" },
    { stdout: null },
    { stderr: null },
    { stdout: "" },
    { stdout: `${configObservation.stdout}DNS = 1.1.1.1\n` },
    { stdout: `${configObservation.stdout}\tDomains\t= ~.\n` },
    { stdout: `${configObservation.stdout}DNSStubListenerExtra = 127.0.0.100\n` },
    { stdout: `${configObservation.stdout}[Other]\n` },
    { stdout: `${configObservation.stdout}unparsed continuation\n` },
    { stdout: `${configObservation.stdout}# /etc/systemd/resolved.conf.d/95-other.conf\n` },
  ])
    assert.equal(ordinaryConfig({ ...configObservation, ...change }), false);
  assert.equal(ordinaryConfig(undefined), false);
});

for (const scenario of ["ordinary", "partial", "timeout", "spaced", "warning"]) {
  test(`actual synthetic pre uses the checked full read: ${scenario}`, (t) => {
    const support = require("./support.cjs");
    const { entry } = require("./control.cjs");
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-full-pre-"));
    const keys = ["RUNNER_TEMP", "PATH", "INPUT_ARM", "INPUT_HOSTED", "CI1203_CONFIG_SCENARIO"];
    const previous = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
    const previousExit = process.exitCode;
    t.after(() => {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      process.exitCode = previousExit;
      fs.rmSync(root, { recursive: true, force: true });
    });
    const bin = path.join(root, "bin");
    fs.mkdirSync(bin);
    const program = `#!/bin/sh
case "\${0##*/}" in
  sudo) [ "$1" = -n ] || exit 3; shift; exec "$@" ;;
  timeout) case "$1" in ''|*[!0-9]*) exit 3;; esac; shift; exec "$@" ;;
  systemd-analyze)
    printf '%s\\n' '# /etc/systemd/resolved.conf' '# Standard ordinary defaults' '[Resolve]' '#DNS='
    case "$CI1203_CONFIG_SCENARIO" in
      partial) printf '%s\\n' 'failed after header' >&2; exit 1 ;;
      timeout) printf '%s\\n' 'bounded observation timeout' >&2; exit 124 ;;
      spaced) printf '%s\\n' '# /etc/systemd/resolved.conf.d/95-other.conf' '[Resolve]' 'DNS = 1.1.1.1' ;;
      warning) printf '%s\\n' 'unreadable foreign drop-in' >&2 ;;
    esac ;;
  curl) printf '%s\\n' eastus ;;
  readlink) printf '%s\\n' /run/systemd/resolve/stub-resolv.conf ;;
  systemctl) case "$*" in *ExecMainPID*) printf '%s\\n' 1234;; *) printf '%s\\n' inactive;; esac ;;
  resolvectl) printf '%s\\n' 'Global:' 'Link 2 (eth0): 168.63.129.16' ;;
  ss) printf '%s\\n' 'Netid State Local Address:Port' ;;
  date) printf '%s\\n' '2026-10-26T10:00:00+00:00' ;;
  *) exit 3 ;;
esac
`;
    for (const name of [
      "sudo",
      "timeout",
      "systemd-analyze",
      "curl",
      "readlink",
      "systemctl",
      "resolvectl",
      "ss",
      "date",
    ])
      fs.writeFileSync(path.join(bin, name), program, { mode: 0o755 });
    process.env.PATH = `${bin}:${previous.PATH}`;
    process.env.RUNNER_TEMP = root;
    process.env.INPUT_ARM = "I1";
    process.env.INPUT_HOSTED = "github-hosted";
    process.env.CI1203_CONFIG_SCENARIO = scenario;
    process.exitCode = undefined;
    const m = mock();
    const r = support.runtime("ci1203-synthetic-induce");
    const setup = () => ({ ...r, io: m.io, load: m.load, pathExists: () => false });
    entry("pre", setup, () => {});
    assert.equal(process.exitCode, undefined);
    const state = m.load();
    const observation = JSON.parse(
      fs.readFileSync(path.join(r.out, "config-observation.json"), "utf8"),
    );
    const full = fs.readFileSync(path.join(r.out, "resolved-config-before.txt"), "utf8");
    assert.equal(observation.stdout, full);
    assert.equal(
      observation.sha256,
      require("node:crypto").createHash("sha256").update(full).digest("hex"),
    );
    assert.deepEqual(observation.command, [
      "timeout",
      "5",
      "systemd-analyze",
      "cat-config",
      "systemd/resolved.conf",
    ]);
    assert.equal(state.configObservation.sha256, observation.sha256);
    if (scenario === "ordinary") {
      assert.equal(state.disposition, "SYNTHETIC_INDUCED");
      assert.equal(m.present.reset, true);
      restoreState(m, state);
    } else {
      assert.equal(state.disposition, "SYNTHETIC_NOT_INDUCIBLE");
      assert.equal(state.inScope, false);
      assert.equal(m.present.reset, false);
      assert.ok(!m.events.some((event) => event.startsWith("create") || event === "restart"));
      assert.equal(
        observation.status,
        scenario === "partial" ? 1 : scenario === "timeout" ? 124 : 0,
      );
      if (scenario === "spaced") assert.ok(full.includes("DNS = 1.1.1.1"));
    }
  });
}
