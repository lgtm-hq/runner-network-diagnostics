"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { operate, bytes, filename } = require("./root-file.cjs");
const { prepare, cleanup, applicable, globalDns, entry } = require("./control.cjs");
const token = "a".repeat(64);
const selection = {
  candidate: true,
  facts: {
    region: "westus2",
    target: "/etc/resolv.conf",
    resolverUnit: "active",
    proxyUnit: "active",
    listener: "present",
  },
};
const topology =
  "EFFECTIVE RESOLVED CONFIG (DNS fields only)\n# /etc/systemd/resolved.conf\n# /etc/systemd/resolved.conf.d/90-egress-proxy.conf\nDNS=\n\nUNIT systemd-resolved\n";
function mock() {
  const events = [];
  let state,
    present = false,
    dns = "",
    main = "original-main";
  const io = {
    save(value) {
      state = structuredClone(value);
      events.push(`save:${state.mutationIntent || false}`);
    },
    dns: () => `Global: ${dns}\nLink 2 (eth0): 168.63.129.16\n`,
    hash: (file) => (file.endsWith("90-egress-proxy.conf") ? "original-platform" : main),
    token: () => token,
    root(mode) {
      events.push(mode);
      if (mode === "inspect") return { present };
      if (mode === "create") {
        present = true;
        return { created: true };
      }
      const removed = present;
      present = false;
      return { removed };
    },
    restart() {
      events.push("restart");
      dns = main === "original-main" ? "" : "127.0.0.1";
    },
  };
  return {
    io,
    events,
    load: () => state,
    present: () => present,
    harden() {
      main = "hardener-main";
      dns = present ? "127.0.0.1" : "";
    },
    hardenerPost() {
      events.push("hardener-post");
      main = "original-main";
      dns = present ? "127.0.0.1" : "";
    },
    badDns() {
      dns = "8.8.8.8";
    },
  };
}
function install(m, sample = "1") {
  return prepare({ sample, selection, topology, io: m.io });
}
test("captured empty reset is eligible, unknown/inexact settings are not", () => {
  assert.equal(applicable(selection, topology), true);
  for (const field of Object.keys(selection.facts))
    assert.equal(
      applicable({ ...selection, facts: { ...selection.facts, [field]: "unknown" } }, topology),
      false,
    );
  assert.equal(applicable({ ...selection, candidate: false }, topology), false);
  assert.equal(applicable({ candidate: true }, topology), false);
  for (const text of [
    "",
    topology.replace("DNS=\n", "DNS=8.8.8.8\n"),
    topology.replace("DNS=\n", "DNS=\nFallbackDNS=1.1.1.1\n"),
    topology.replace("# /etc/systemd/resolved.conf\n", "DNS=1.1.1.1\n"),
  ])
    assert.equal(applicable(selection, text), false);
});
test("global DNS parser does not accept missing/duplicate observations", () => {
  assert.equal(globalDns("Global: 127.0.0.1\nLink 2: 168.63.129.16"), "127.0.0.1");
  assert.throws(() => globalDns("Link 2: 127.0.0.1"));
  assert.throws(() => globalDns("Global:\nGlobal: 127.0.0.1"));
});
test("unchanged arm performs no privileged operation or DNS mutation", () => {
  const m = mock();
  const state = install(m, "2");
  assert.equal(state.disposition, "CONTROL_UNCHANGED");
  assert.equal(cleanup({ phase: "fallback", state, io: m.io }).disposition, "NO_MUTATION");
  assert.deepEqual(m.events, ["save:false", "save:false"]);
});
test("unknown treatment topology records not applicable without mutation", () => {
  const m = mock();
  const state = prepare({ sample: "1", selection, topology: "unknown", io: m.io });
  assert.equal(state.disposition, "NOT_APPLICABLE");
  assert.equal(m.present(), false);
});
for (const sample of ["0", "25", "-1", "1; true", "", undefined])
  test(`reject invalid sample ${sample}`, () =>
    assert.throws(() => install(mock(), sample === undefined ? "undefined" : sample)));
test("intent is persisted before root create, no setup restart", () => {
  const m = mock();
  install(m);
  assert.deepEqual(m.events, ["save:false", "save:true", "create", "save:true"]);
});
test("nonempty baseline DNS refuses mutation", () => {
  const m = mock();
  m.badDns();
  assert.throws(() => install(m));
  assert.equal(m.present(), false);
});
test("lost creation acknowledgement still has durable cleanup intent", () => {
  const m = mock();
  const root = m.io.root;
  m.io.root = (mode, value) => {
    const result = root(mode, value);
    if (mode === "create") throw new Error("lost ack");
    return result;
  };
  assert.throws(() => install(m));
  assert.equal(m.present(), true);
  m.harden();
  m.hardenerPost();
  const result = cleanup({ phase: "fallback", state: m.load(), io: m.io });
  assert.equal(result.disposition, "RESTORATION_VERIFIED");
  assert.equal(result.restarted, true);
});
test("guard removes file before hardener post, keeps live route until normal restoration", () => {
  const m = mock();
  const state = install(m);
  m.harden();
  cleanup({ phase: "guard", state, io: m.io });
  assert.equal(globalDns(m.io.dns()), "127.0.0.1");
  m.hardenerPost();
  assert.equal(cleanup({ phase: "fallback", state, io: m.io }).disposition, "RESTORATION_VERIFIED");
  assert.equal(m.events.includes("restart"), false);
  assert.equal(m.present(), false);
});
test("cancellation during pre: missing guard is repaired after hardener cleanup", () => {
  const m = mock();
  const state = install(m);
  m.harden();
  m.hardenerPost();
  assert.equal(globalDns(m.io.dns()), "127.0.0.1");
  assert.equal(cleanup({ phase: "fallback", state, io: m.io }).restarted, true);
  assert.equal(globalDns(m.io.dns()), "");
});
test("partial hardener initialization cannot claim restoration with its main config left behind", () => {
  const m = mock();
  const state = install(m);
  m.harden();
  cleanup({ phase: "guard", state, io: m.io });
  assert.throws(() => cleanup({ phase: "fallback", state, io: m.io }), /not restored/);
});
test("failed fallback restart cannot report restoration", () => {
  const m = mock();
  const state = install(m);
  m.harden();
  m.hardenerPost();
  m.io.restart = () => {
    throw new Error("restart failed");
  };
  assert.throws(() => cleanup({ phase: "fallback", state, io: m.io }), /restart failed/);
});
test("platform or main config drift fails restoration even if DNS matches", () => {
  const m = mock();
  const state = install(m);
  m.harden();
  cleanup({ phase: "guard", state, io: m.io });
  m.hardenerPost();
  m.io.hash = () => "changed";
  assert.throws(() => cleanup({ phase: "fallback", state, io: m.io }), /not restored/);
});
test("cleanup is idempotent and missing mutation state is harmless", () => {
  const m = mock();
  const state = install(m);
  cleanup({ phase: "guard", state, io: m.io });
  cleanup({ phase: "guard", state, io: m.io });
  assert.equal(cleanup({ phase: "fallback", state, io: m.io }).restarted, false);
  assert.equal(cleanup({ phase: "fallback", state: null, io: m.io }).disposition, "NO_MUTATION");
  assert.throws(() => cleanup({ phase: "invalid", state, io: m.io }));
});
function withRoot(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-root-test-"));
  const op = (mode, value = token) => operate({ mode, token: value, root, uid: process.getuid() });
  try {
    fn({ root, op, target: path.join(root, filename) });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
test("real file create publishes exact bytes and duplicate create never overwrites", () =>
  withRoot(({ op, target }) => {
    op("create");
    assert.equal(fs.readFileSync(target, "utf8"), bytes(token));
    assert.throws(() => op("create"), /EEXIST/);
    assert.equal(fs.readFileSync(target, "utf8"), bytes(token));
    assert.equal(op("remove").removed, true);
    assert.equal(op("remove").removed, false);
  }));
test("existing foreign file cannot be replaced or removed", () =>
  withRoot(({ op, target }) => {
    fs.writeFileSync(target, "foreign");
    assert.throws(() => op("create"));
    assert.throws(() => op("remove"), /ownership/);
    assert.equal(fs.readFileSync(target, "utf8"), "foreign");
  }));
test("symlink target cannot be replaced or followed for cleanup", () =>
  withRoot(({ op, root, target }) => {
    const foreign = path.join(root, "foreign");
    fs.writeFileSync(foreign, bytes(token));
    fs.symlinkSync(foreign, target);
    assert.throws(() => op("create"));
    assert.throws(() => op("remove"), /symlink/);
    assert.equal(fs.readFileSync(foreign, "utf8"), bytes(token));
  }));
test("changed owner token refuses cleanup and preserves changed file", () =>
  withRoot(({ op, target }) => {
    op("create");
    fs.writeFileSync(target, bytes("b".repeat(64)));
    assert.throws(() => op("remove"));
    assert.equal(fs.existsSync(target), true);
  }));
test("root operation rejects malformed tokens and unknown operations", () =>
  withRoot(({ op }) => {
    for (const value of ["", "../x", "x".repeat(64)]) assert.throws(() => op("create", value));
    assert.throws(() => op("restart"), /invalid root/);
  }));
test("complete orphan temp inode is safely cleaned without touching another file", () =>
  withRoot(({ op, target }) => {
    fs.writeFileSync(`${target}.${token}.tmp`, bytes(token));
    assert.equal(op("remove").removed, false);
    assert.equal(fs.existsSync(`${target}.${token}.tmp`), false);
  }));
test("guard has no pre and always remains eligible after main failures", () => {
  const guard = fs.readFileSync(
    path.join(__dirname, "../resolver-cleanup-guard/action.yml"),
    "utf8",
  );
  const early = fs.readFileSync(path.join(__dirname, "action.yml"), "utf8");
  assert.doesNotMatch(guard, /^  pre:/m);
  assert.match(guard, /^  post-if: always\(\)$/m);
  assert.match(early, /^  pre:/m);
  assert.match(early, /^  post-if: always\(\)$/m);
  const workflow = fs.readFileSync(
    path.join(__dirname, "../../.github/workflows/dns-counterfactual.yml"),
    "utf8",
  );
  assert.match(workflow, /- name: Register cleanup before hardener post\n        if: always\(\)/);
});
test("main validation fails closed and still permits later guard registration", () => {
  const m = mock();
  install(m);
  const receipts = [];
  const setup = () => ({ ...m, receipt: (phase, data) => receipts.push({ phase, ...data }) });
  const previous = process.exitCode;
  try {
    entry("main", setup);
    assert.equal(process.exitCode, 1);
    entry("register-guard", setup);
    assert.equal(receipts[0].disposition, "GUARD_MAIN_REACHED");
    m.harden();
    process.exitCode = undefined;
    entry("main", setup);
    assert.equal(process.exitCode, undefined);
    assert.equal(receipts[1].arm, "treatment");
  } finally {
    process.exitCode = previous;
  }
});

test("runtime bridge uses bounded fixed argv and persists separate console cleanup receipts", () => {
  const { runtime } = require("./control.cjs");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-runtime-"));
  const previous = { RUNNER_TEMP: process.env.RUNNER_TEMP, PATH: process.env.PATH };
  try {
    process.env.RUNNER_TEMP = root;
    const bin = path.join(root, "bin");
    fs.mkdirSync(bin);
    fs.writeFileSync(
      path.join(bin, "sudo"),
      `#!${process.execPath}
const fs = require("node:fs"), path = require("node:path");
const args = process.argv.slice(2);
fs.appendFileSync(path.join(process.env.RUNNER_TEMP, "calls"), JSON.stringify(args) + "\\n");
if (fs.existsSync(path.join(process.env.RUNNER_TEMP, "command-fails"))) process.exit(1);
if (args.includes("resolvectl")) console.log("Global: 127.0.0.1");
else if (args.includes("create")) console.log('{"created":true}');
else if (args.includes("remove")) console.log('{"removed":true}');
`,
    );
    fs.chmodSync(path.join(bin, "sudo"), 0o755);
    process.env.PATH = `${bin}:${previous.PATH}`;
    const r = runtime();
    assert.equal(r.load(), null);
    r.io.save({ mutationIntent: true, token });
    assert.equal(r.load().token, token);
    assert.equal(globalDns(r.io.dns()), "127.0.0.1");
    assert.equal(r.io.token().length, 64);
    assert.deepEqual(r.io.root("create", token), { created: true });
    assert.deepEqual(r.io.root("remove", token), { removed: true });
    r.io.restart();
    assert.equal(r.io.hash(path.join(r.out, "state.json")).length, 64);
    r.receipt("test", { disposition: "TEST" });
    assert.equal(JSON.parse(fs.readFileSync(path.join(r.out, "test.json"))).disposition, "TEST");
    assert.throws(() => r.receipt("test", {}), /EEXIST/);
    const calls = fs
      .readFileSync(path.join(root, "calls"), "utf8")
      .trim()
      .split("\n")
      .map(JSON.parse);
    assert.ok(calls.every((args) => args.slice(0, 3).join(" ") === "-n timeout 10"));
    assert.ok(calls.some((args) => args.includes(path.join(__dirname, "root-file.cjs"))));
    fs.writeFileSync(path.join(root, "command-fails"), "1");
    assert.throws(() => r.io.dns(), /sudo failed/);
    delete process.env.RUNNER_TEMP;
    assert.throws(() => runtime(), /RUNNER_TEMP/);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("real action entry consumes saved preselection and records control and post phases", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-entry-"));
  const previous = {
    RUNNER_TEMP: process.env.RUNNER_TEMP,
    INPUT_SAMPLE: process.env.INPUT_SAMPLE,
    exit: process.exitCode,
  };
  try {
    process.env.RUNNER_TEMP = root;
    process.env.INPUT_SAMPLE = "2";
    const dir = path.join(root, "ci1203");
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, "selection.json"), JSON.stringify(selection));
    fs.writeFileSync(path.join(dir, "topology-before.txt"), topology);
    const m = mock(),
      receipts = [];
    const setup = () => ({ ...m, receipt: (phase, data) => receipts.push({ phase, ...data }) });
    entry("pre", setup);
    assert.equal(m.load().disposition, "CONTROL_UNCHANGED");
    entry("main", setup);
    entry("guard", setup);
    entry("fallback", setup);
    assert.equal(receipts.at(-1).disposition, "NO_MUTATION");
    entry("pre", setup);
    assert.equal(process.exitCode, 1);
    process.exitCode = undefined;
    entry("main", () => ({ ...setup(), load: () => null }));
    assert.equal(process.exitCode, 1);
  } finally {
    for (const key of ["RUNNER_TEMP", "INPUT_SAMPLE"]) {
      if (previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    }
    process.exitCode = previous.exit;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

for (const sample of [8, 9, 11, 12, 19]) {
  test(`verbatim affected capture ${sample} receives the intended treatment`, () => {
    const capturedSelection = JSON.parse(
      fs.readFileSync(path.join(__dirname, "fixtures", `sample-${sample}-selection.txt`), "utf8"),
    );
    const capturedTopology = fs.readFileSync(
      path.join(__dirname, "fixtures", `sample-${sample}-topology.txt`),
      "utf8",
    );
    const m = mock();
    assert.equal(applicable(capturedSelection, capturedTopology), true);
    const state = prepare({
      sample: "1",
      selection: capturedSelection,
      topology: capturedTopology,
      io: m.io,
    });
    assert.equal(state.disposition, "OVERRIDE_INSTALLED_NO_RESTART");
    assert.equal(m.present(), true);
    assert.equal(
      applicable(capturedSelection, capturedTopology.replace("DNS=\n", "DNS=8.8.8.8\n")),
      false,
    );
    assert.equal(
      applicable(
        capturedSelection,
        capturedTopology.replace("DNS=\n", "DNS=\n# /etc/systemd/resolved.conf.d/95-other.conf\n"),
      ),
      false,
    );
    assert.equal(
      applicable(capturedSelection, capturedTopology.replace("DNS=\n", "DNS=\nDomains=~.\n")),
      false,
    );
  });
}
test("lost fallback remove acknowledgement reloads live DNS and retains failure", () => {
  withRoot(({ op, target }) => {
    const m = mock();
    const bridge = m.io.root;
    m.io.root = (mode, value) => {
      const real = op(mode, value);
      bridge(mode, value);
      if (mode === "remove") throw new Error("lost remove acknowledgement");
      return real;
    };
    const state = install(m);
    m.harden();
    m.hardenerPost();
    assert.equal(globalDns(m.io.dns()), "127.0.0.1");
    assert.throws(
      () => cleanup({ phase: "fallback", state, io: m.io }),
      /original DNS restored after cleanup error: lost remove acknowledgement/,
    );
    assert.equal(fs.existsSync(target), false);
    assert.equal(globalDns(m.io.dns()), "");
    assert.equal(m.events.filter((event) => event === "restart").length, 1);
  });
});
test("failed guard acknowledgement also leaves durable reload intent", () => {
  const m = mock();
  const state = install(m);
  m.harden();
  const root = m.io.root;
  m.io.root = (mode, value) => {
    const result = root(mode, value);
    if (mode === "remove") throw new Error("lost guard acknowledgement");
    return result;
  };
  assert.throws(() => cleanup({ phase: "guard", state, io: m.io }), /lost guard/);
  assert.equal(m.load().guardRemovalVerified, undefined);
  m.io.root = root;
  m.hardenerPost();
  assert.equal(cleanup({ phase: "fallback", state: m.load(), io: m.io }).restarted, true);
});
test("failed removal before unlink is reconciled once after positive ownership inspection", () => {
  const m = mock();
  const state = install(m);
  m.harden();
  m.hardenerPost();
  const root = m.io.root;
  let attempts = 0;
  m.io.root = (mode, value) => {
    if (mode === "remove" && ++attempts === 1) throw new Error("first removal failed");
    return root(mode, value);
  };
  assert.throws(
    () => cleanup({ phase: "fallback", state, io: m.io }),
    /original DNS restored after cleanup error/,
  );
  assert.equal(attempts, 2);
  assert.equal(m.present(), false);
  assert.equal(globalDns(m.io.dns()), "");
});
test("persistent removal failure is bounded and does not reload with an owned file remaining", () => {
  const m = mock();
  const state = install(m);
  m.harden();
  m.hardenerPost();
  const root = m.io.root;
  let attempts = 0;
  m.io.root = (mode, value) => {
    if (mode === "remove") {
      attempts++;
      throw new Error("blocked unlink");
    }
    return root(mode, value);
  };
  assert.throws(() => cleanup({ phase: "fallback", state, io: m.io }), /override remains/);
  assert.equal(attempts, 2);
  assert.equal(m.events.includes("restart"), false);
});
test("foreign replacement after unlink is preserved and does not trigger blind reload", () => {
  withRoot(({ op, target }) => {
    const m = mock();
    const bridge = m.io.root;
    m.io.root = (mode, value) => {
      const result = op(mode, value);
      bridge(mode, value);
      if (mode === "remove") {
        fs.writeFileSync(target, "foreign replacement");
        throw new Error("lost acknowledgement");
      }
      return result;
    };
    const state = install(m);
    m.harden();
    m.hardenerPost();
    assert.throws(() => cleanup({ phase: "fallback", state, io: m.io }), /ownership/);
    assert.equal(fs.readFileSync(target, "utf8"), "foreign replacement");
    assert.equal(m.events.includes("restart"), false);
  });
});
test("unavailable or malformed absence inspection cannot report restoration", () => {
  for (const malformed of [false, true]) {
    const m = mock();
    const state = install(m);
    m.harden();
    m.hardenerPost();
    const root = m.io.root;
    m.io.root = (mode, value) => {
      if (mode === "inspect") {
        if (malformed) return {};
        throw new Error("inspection failed");
      }
      return root(mode, value);
    };
    assert.throws(
      () => cleanup({ phase: "fallback", state, io: m.io }),
      /inspection failed|absence unverified/,
    );
    assert.equal(m.events.includes("restart"), false);
  }
});
test("entry keeps failed status after lost unlink acknowledgement is repaired", () => {
  const m = mock();
  install(m);
  m.harden();
  m.hardenerPost();
  const root = m.io.root;
  const previous = process.exitCode;
  const receipts = [];
  m.io.root = (mode, value) => {
    const result = root(mode, value);
    if (mode === "remove") throw new Error("lost acknowledgement");
    return result;
  };
  try {
    entry("fallback", () => ({
      ...m,
      receipt: (phase, value) => receipts.push({ phase, ...value }),
    }));
    assert.equal(process.exitCode, 1);
    assert.equal(globalDns(m.io.dns()), "");
    assert.equal(
      receipts.some((r) => r.disposition === "RESTORATION_VERIFIED"),
      false,
    );
  } finally {
    process.exitCode = previous;
  }
});
test("failed guard-state persistence conservatively reloads in fallback", () => {
  const m = mock();
  const state = install(m);
  m.harden();
  const save = m.io.save;
  m.io.save = () => {
    throw new Error("state write failed");
  };
  assert.throws(() => cleanup({ phase: "guard", state, io: m.io }), /state write/);
  assert.equal(m.load().guardRemovalVerified, undefined);
  m.io.save = save;
  m.hardenerPost();
  assert.equal(cleanup({ phase: "fallback", state: m.load(), io: m.io }).restarted, true);
});
