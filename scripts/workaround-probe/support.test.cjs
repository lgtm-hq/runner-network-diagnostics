"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { runtime, readFile, fileObservation } = require("./support.cjs");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "native-support-"));
  const previous = process.env.RUNNER_TEMP;
  process.env.RUNNER_TEMP = root;
  t.after(() => {
    if (previous === undefined) delete process.env.RUNNER_TEMP;
    else process.env.RUNNER_TEMP = previous;
    fs.rmSync(root, { recursive: true, force: true });
  });
  return root;
}

test("early receipts commit to raw bytes without printing configuration or token-like data", (t) => {
  fixture(t);
  const lines = [];
  t.mock.method(console, "log", (line) => lines.push(line));
  const r = runtime();
  const record = {
    classification: "PARTIAL",
    config: { stdout: "Authorization: Bearer never-print-this" },
  };
  r.write("selection.json", record);
  assert.deepEqual(r.read("selection.json"), record);
  assert.ok(!lines.join("\n").includes("never-print-this"));
  assert.ok(!lines.join("\n").includes("Authorization"));
  assert.match(lines[0], /"classification":"PARTIAL"/);
  assert.match(lines[0], /"sha256":"[a-f0-9]{64}"/);
  assert.throws(() => r.write("selection.json", record), /EEXIST/);
  assert.throws(() => r.write("../outside.json", record), /invalid receipt/);
});

test("raw observations are bounded regular files and never follow symlinks", (t) => {
  const root = fixture(t);
  const file = path.join(root, "sample.txt");
  fs.writeFileSync(file, "[Resolve]\n");
  assert.equal(readFile(file).content, "[Resolve]\n");
  fs.symlinkSync(file, path.join(root, "symlink.txt"));
  assert.throws(() => readFile(path.join(root, "symlink.txt")));
  assert.equal(fileObservation(path.join(root, "absent.txt")).present, false);
  fs.writeFileSync(file, Buffer.alloc(256 * 1024 + 1));
  assert.equal(fileObservation(file).present, null);
  assert.throws(() => readFile(root), /nonregular/);
});

test("runtime refuses ambiguous relative temporary roots", (t) => {
  fixture(t);
  process.env.RUNNER_TEMP = "relative";
  assert.throws(() => runtime(), /absolute RUNNER_TEMP/);
});
