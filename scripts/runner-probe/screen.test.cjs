"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { classify } = require("./screen.cjs");
const ordinary = {
  region: "eastus",
  target: "/run/systemd/resolve/stub-resolv.conf",
  resolverUnit: "inactive",
  proxyUnit: "inactive",
  listener: "absent",
};
test("ordinary setup is screened out without a recovery claim", () => {
  assert.equal(classify(ordinary).candidate, false);
});
for (const [key, value] of [
  ["region", "westus2"],
  ["region", "unknown"],
  ["region", ""],
  ["target", "/etc/resolv.conf"],
  ["target", "unknown"],
  ["resolverUnit", "active"],
  ["proxyUnit", "active"],
  ["resolverUnit", "unknown"],
  ["listener", "present"],
  ["listener", "unknown"],
]) {
  test(`retain suspect or unknown ${key}=${value}`, () => {
    assert.equal(classify({ ...ordinary, [key]: value }).candidate, true);
  });
}

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
for (const key of ["resolverUnit", "proxyUnit"]) {
  test(`retain failed experiment ${key}`, () => {
    assert.equal(classify({ ...ordinary, [key]: "failed" }).candidate, true);
  });
}
function withScreen(fn) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "runner-screen-"));
  try {
    const out = path.join(temp, "ci1203");
    fs.mkdirSync(out);
    fs.writeFileSync(path.join(out, "selection.json"), JSON.stringify(classify(ordinary)));
    const run = (mode) =>
      spawnSync(process.execPath, [path.join(__dirname, "main.cjs")], {
        env: {
          ...process.env,
          RUNNER_TEMP: temp,
          INPUT_MODE: mode,
          GITHUB_OUTPUT: path.join(temp, "output"),
        },
        encoding: "utf8",
      });
    fn({ out, temp, run });
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}
test("main prepare emits false for screened-out runner", () =>
  withScreen(({ temp, run }) => {
    assert.equal(run("prepare").status, 0);
    assert.equal(fs.readFileSync(path.join(temp, "output"), "utf8"), "candidate=false\n");
  }));
test("screened-out finish retains honest disposition and hashes JSON", () =>
  withScreen(({ out, run }) => {
    assert.equal(run("finish").status, 0);
    assert.match(fs.readFileSync(path.join(out, "disposition.txt"), "utf8"), /^NOT_SAMPLED:/);
    assert.equal(fs.existsSync(path.join(out, "completeness.txt")), false);
    const manifest = fs.readFileSync(path.join(out, "SHA256SUMS"), "utf8");
    const digest = createHash("sha256")
      .update(fs.readFileSync(path.join(out, "selection.json")))
      .digest("hex");
    assert.ok(manifest.includes(`${digest}  selection.json\n`));
  }));
test("screened-out runner cannot execute payload", () =>
  withScreen(({ run }) => {
    assert.notEqual(run("payload").status, 0);
  }));
test("missing screening cannot report successful finish", () =>
  withScreen(({ out, run }) => {
    fs.unlinkSync(path.join(out, "selection.json"));
    assert.notEqual(run("finish").status, 0);
  }));

function withMockRunner(fn) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "runner-pre-"));
  try {
    const bin = path.join(temp, "bin");
    const out = path.join(temp, "ci1203");
    fs.mkdirSync(bin);
    const bash = path.join(bin, "bash");
    fs.writeFileSync(
      bash,
      `#!${process.execPath}
const fs = require("node:fs"), path = require("node:path");
const out = path.join(process.env.RUNNER_TEMP, "ci1203");
fs.mkdirSync(out, { recursive: true });
if (process.argv[2].endsWith("topology.sh")) {
  fs.appendFileSync(path.join(out, "order.txt"), "topology:" + process.argv[3] + "\\n");
  if (process.env.FAIL_FINISH === "true" && process.argv[3] === "finish") process.exit(1);
  for (const [name, value] of Object.entries({ region: "westus2", "resolver-target": "/etc/resolv.conf", "resolver-unit": "active", "proxy-unit": "inactive", listener: "present" }))
    fs.writeFileSync(path.join(out, name + ".txt"), value);
} else {
  fs.appendFileSync(path.join(out, "order.txt"), "probe:" + process.env.PROBE_MODE + "\\n");
  if (process.env.FAIL_PROBE === process.env.PROBE_MODE) process.exit(1);
}
`,
    );
    fs.chmodSync(bash, 0o755);
    const env = {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      RUNNER_TEMP: temp,
      GITHUB_OUTPUT: path.join(temp, "output"),
    };
    const run = (file, mode, extra = {}) =>
      spawnSync(process.execPath, [path.join(__dirname, file)], {
        env: { ...env, INPUT_MODE: mode, ...extra },
        encoding: "utf8",
      });
    fn({ out, temp, run });
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}
test("pre hook screens before original capture and main confirms selection", () =>
  withMockRunner(({ out, temp, run }) => {
    assert.equal(run("pre.cjs", "prepare").status, 0);
    assert.equal(run("main.cjs", "prepare").status, 0);
    assert.equal(
      fs.readFileSync(path.join(out, "order.txt"), "utf8"),
      "topology:before\nprobe:prepare\nprobe:confirm\n",
    );
    assert.equal(fs.readFileSync(path.join(temp, "output"), "utf8"), "candidate=true\n");
  }));
test("later pre hooks do not reset capture", () =>
  withMockRunner(({ out, run }) => {
    assert.equal(run("pre.cjs", "finish").status, 0);
    assert.equal(fs.existsSync(path.join(out, "selection.json")), false);
  }));
test("duplicate prepare fails rather than resetting evidence", () =>
  withMockRunner(({ run }) => {
    assert.equal(run("pre.cjs", "prepare").status, 0);
    assert.notEqual(run("pre.cjs", "prepare").status, 0);
  }));
test("failed final topology still freezes and remains failure", () =>
  withMockRunner(({ out, run }) => {
    assert.equal(run("pre.cjs", "prepare").status, 0);
    assert.notEqual(run("main.cjs", "finish", { FAIL_FINISH: "true" }).status, 0);
    assert.match(
      fs.readFileSync(path.join(out, "order.txt"), "utf8"),
      /topology:finish\nprobe:finish\n$/,
    );
    assert.equal(fs.existsSync(path.join(out, "SHA256SUMS")), true);
  }));

// Check the actual workflow's failure eligibility, then exercise real wrapper
// entry points. This is a local lifecycle regression, not a hosted scheduler.
function conditionFor(name) {
  const workflow = fs.readFileSync(
    path.join(__dirname, "../../.github/workflows/dns-path.yml"),
    "utf8",
  );
  const step = workflow
    .split(/\n(?=      - name:)/)
    .find((block) => block.startsWith(`      - name: ${name}\n`));
  assert.ok(step, `workflow step missing: ${name}`);
  return step.match(/^        if: (.+)$/m)?.[1];
}
function verifyCandidateFailurePath({ out, temp, run }) {
  assert.equal(conditionFor("Screen before hardening; capture suspect setup"), "always()");
  assert.equal(run("main.cjs", "prepare").status, 0);
  assert.equal(fs.readFileSync(path.join(temp, "output"), "utf8"), "candidate=true\n");
  for (const [name, mode] of [
    ["Capture effective resolver before checkout", "snapshot"],
    ["Read public GitHub API independently of checkout", "api"],
    ["Verify explicitly unallowed traffic is locally blocked", "negative"],
  ]) {
    assert.equal(conditionFor(name), "always() && steps.screen.outputs.candidate == 'true'");
    assert.equal(run("main.cjs", mode).status, 0);
  }
  assert.equal(conditionFor("Freeze diagnostic evidence even on failure"), "always()");
  assert.equal(run("main.cjs", "finish").status, 0);
  assert.match(
    fs.readFileSync(path.join(out, "order.txt"), "utf8"),
    /probe:negative\ntopology:finish\nprobe:finish\n$/,
  );
}
test("selection and candidate diagnostics remain eligible after hardener pre failure", () =>
  withMockRunner((context) => {
    assert.equal(context.run("pre.cjs", "prepare").status, 0);
    // Represent a failing intervening hardener pre without running that action.
    assert.equal(spawnSync(process.execPath, ["-e", "process.exit(1)"]).status, 1);
    verifyCandidateFailurePath(context);
  }));
test("saved selection survives failed capture preparation for failure diagnostics", () =>
  withMockRunner((context) => {
    assert.notEqual(context.run("pre.cjs", "prepare", { FAIL_PROBE: "prepare" }).status, 0);
    assert.equal(
      JSON.parse(fs.readFileSync(path.join(context.out, "selection.json"), "utf8")).candidate,
      true,
    );
    verifyCandidateFailurePath(context);
  }));
test("candidate output survives confirm failure without masking its failing status", () =>
  withMockRunner(({ temp, run }) => {
    assert.equal(run("pre.cjs", "prepare").status, 0);
    assert.notEqual(run("main.cjs", "prepare", { FAIL_PROBE: "confirm" }).status, 0);
    assert.equal(fs.readFileSync(path.join(temp, "output"), "utf8"), "candidate=true\n");
  }));
test("missing selection cannot publish a candidate or success in always-eligible main", () =>
  withScreen(({ out, temp, run }) => {
    fs.unlinkSync(path.join(out, "selection.json"));
    assert.notEqual(run("prepare").status, 0);
    assert.equal(fs.existsSync(path.join(temp, "output")), false);
  }));
