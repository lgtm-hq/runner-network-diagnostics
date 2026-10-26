"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { printEvidence, copyEvidence } = require("./evidence.cjs");

function fixture(t, data) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-console-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "sample.txt"), data);
  const manifest = `${createHash("sha256").update(data).digest("hex")}  ./sample.txt\n`;
  fs.writeFileSync(path.join(directory, "SHA256SUMS"), manifest);
  return {
    directory,
    name: "ci1203",
    manifest,
  };
}

test("complete console chunks reconstruct bytes and hashes despite timestamp framing", (t) => {
  const data = Buffer.concat([
    Buffer.from('\u0000\r\nquoted \\" bytes\n'),
    Buffer.alloc(19000, 255),
  ]);
  const f = fixture(t, data);
  const lines = [];
  printEvidence({ ...f, emit: (line) => lines.push(`2026-10-26T11:00:00.0000000Z ${line}`) });
  assert.ok(lines.length > 1);
  const records = lines
    .filter(
      (l) =>
        l.includes("ci1203-synthetic-FILE ") &&
        JSON.parse(l.split("ci1203-synthetic-FILE ")[1]).name === "sample.txt",
    )
    .map((l) => JSON.parse(l.split("ci1203-synthetic-FILE ")[1]));
  const recovered = Buffer.from(records.map((r) => r.base64).join(""), "base64");
  assert.deepEqual(recovered, data);
  assert.equal(records[0].sha256, createHash("sha256").update(recovered).digest("hex"));
  assert.equal(records.length, records[0].parts);
  assert.ok(lines.every((l) => l.length < 9000));
});

test("missing, mutated, oversized, symlinked and traversing evidence cannot claim preservation", (t) => {
  const f = fixture(t, Buffer.from("original\n"));
  const emit = () => {};
  fs.writeFileSync(path.join(f.directory, "sample.txt"), "changed\n");
  assert.throws(() => printEvidence({ ...f, emit }), /changed after freeze/);
  fs.unlinkSync(path.join(f.directory, "sample.txt"));
  assert.throws(() => printEvidence({ ...f, emit }));
  fs.symlinkSync("/etc/hosts", path.join(f.directory, "sample.txt"));
  assert.throws(() => printEvidence({ ...f, emit }));
  fs.unlinkSync(path.join(f.directory, "sample.txt"));
  fs.writeFileSync(path.join(f.directory, "sample.txt"), Buffer.alloc(1024 * 1024 + 1));
  assert.throws(() => printEvidence({ ...f, emit }), /bounded regular file/);
  assert.throws(
    () =>
      printEvidence({ ...f, emit, manifest: f.manifest.replace("./sample.txt", "../sample.txt") }),
    /invalid evidence/,
  );
  assert.throws(() => printEvidence({ ...f, emit, name: "other" }), /unknown evidence/);
});

test("empty files remain reconstructable and excessive manifest entries fail closed", (t) => {
  const f = fixture(t, Buffer.alloc(0));
  const lines = [];
  printEvidence({ ...f, emit: (line) => lines.push(line) });
  const record = JSON.parse(
    lines
      .find(
        (l) =>
          l.startsWith("ci1203-synthetic-FILE ") &&
          JSON.parse(l.split("ci1203-synthetic-FILE ")[1]).name === "sample.txt",
      )
      .split("ci1203-synthetic-FILE ")[1],
  );
  assert.equal(record.bytes, 0);
  assert.equal(record.parts, 1);
  assert.equal(record.base64, "");
  assert.throws(() => printEvidence({ ...f, budget: { files: 64, bytes: 0 } }), /file-count limit/);
});

function jobFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-whole-copy-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of ["ci1203", "ci1203-synthetic-induce", "ci1203-synthetic-treatment"]) {
    const dir = path.join(root, name);
    fs.mkdirSync(dir);
    const content = Buffer.from(`${name}\n`);
    fs.writeFileSync(path.join(dir, "sample.txt"), content);
    fs.writeFileSync(
      path.join(dir, "SHA256SUMS"),
      `${createHash("sha256").update(content).digest("hex")}  sample.txt\n`,
    );
  }
  return root;
}

test("whole-job copy rebuilds every upload file and authenticates the closing inventory", (t) => {
  const root = jobFixture(t);
  const lines = [];
  const receipt = copyEvidence({ root, emit: (line) => lines.push(line) });
  const begins = lines.filter((l) => l.startsWith("ci1203-synthetic-FILE-BEGIN "));
  assert.equal(receipt.files, 6);
  assert.equal(receipt.complete, true);
  assert.equal(
    receipt.beginsSha256,
    createHash("sha256")
      .update(begins.join("\n") + "\n")
      .digest("hex"),
  );
  for (const line of begins) {
    const begin = JSON.parse(line.split("ci1203-synthetic-FILE-BEGIN ")[1]);
    const chunks = lines
      .filter((l) => l.startsWith("ci1203-synthetic-FILE "))
      .map((l) => JSON.parse(l.split("ci1203-synthetic-FILE ")[1]))
      .filter((r) => r.directory === begin.directory && r.name === begin.name);
    assert.equal(chunks.length, begin.parts);
    const data = Buffer.from(chunks.map((r) => r.base64).join(""), "base64");
    assert.deepEqual(data, fs.readFileSync(path.join(root, begin.directory, begin.name)));
    assert.equal(data.length, begin.bytes);
    assert.equal(createHash("sha256").update(data).digest("hex"), begin.sha256);
  }
});

test("token-like bytes are never base64 printed, and the closing copy is incomplete", (t) => {
  const root = jobFixture(t);
  const data = Buffer.from("Authorization: Bearer sensitive-value\n");
  const dir = path.join(root, "ci1203");
  fs.writeFileSync(path.join(dir, "sample.txt"), data);
  fs.writeFileSync(
    path.join(dir, "SHA256SUMS"),
    `${createHash("sha256").update(data).digest("hex")}  sample.txt\n`,
  );
  const lines = [];
  assert.throws(() => copyEvidence({ root, emit: (line) => lines.push(line) }), /incomplete/);
  assert.ok(lines.some((l) => l.startsWith("ci1203-synthetic-FILE-REFUSED ")));
  assert.equal(JSON.parse(lines.at(-1).split("ci1203-synthetic-COPY ")[1]).complete, false);
  assert.ok(!lines.join("\n").includes("sensitive-value"));
  assert.ok(!lines.join("\n").includes(data.toString("base64")));
});

test("extra upload files and unknown synthetic directories cannot be omitted silently", (t) => {
  const root = jobFixture(t);
  const extra = path.join(root, "ci1203", "extra.txt");
  fs.writeFileSync(extra, "uncommitted");
  assert.throws(() => copyEvidence({ root, emit: () => {} }), /upload set differs/);
  fs.unlinkSync(extra);
  fs.mkdirSync(path.join(root, "ci1203-synthetic-unknown"));
  assert.throws(() => copyEvidence({ root, emit: () => {} }), /unknown synthetic upload directory/);
});

test("default synthetic console bytes equal the frozen cab5432 golden transcript", (t) => {
  const root = jobFixture(t);
  const implicit = [];
  const explicit = [];
  copyEvidence({ root, emit: (line) => implicit.push(line) });
  copyEvidence({ root, profile: "synthetic", emit: (line) => explicit.push(line) });
  assert.deepEqual(implicit, explicit);
  // Generated from evidence.cjs at cab5432 using jobFixture, before extension.
  assert.equal(
    createHash("sha256")
      .update(implicit.join("\n") + "\n")
      .digest("hex"),
    "6bad6aba742be10b2a259472d63ef284580101bd0a8663aee043c25033313135",
  );
});

function nativeFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci1203-native-copy-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of ["ci1203", "ci1203-workaround", "lgtm-agent-dns-shim"]) {
    const dir = path.join(root, name);
    fs.mkdirSync(dir);
    const data = Buffer.from(
      JSON.stringify({ owner: "f".repeat(64), nonce: "u-0123456789abcdef.example.com" }) + "\n",
    );
    fs.writeFileSync(path.join(dir, "state.json"), data);
    fs.writeFileSync(
      path.join(dir, "SHA256SUMS"),
      `${createHash("sha256").update(data).digest("hex")}  state.json\n`,
    );
  }
  return root;
}

test("native profile copies every json in fixed directories with native-only labels", (t) => {
  const root = nativeFixture(t);
  const lines = [];
  assert.equal(
    copyEvidence({ root, profile: "native", emit: (line) => lines.push(line) }).complete,
    true,
  );
  assert.ok(lines.every((line) => line.startsWith("ci1203-workaround-")));
  const chunks = lines
    .filter((line) => line.startsWith("ci1203-workaround-FILE "))
    .map((line) => JSON.parse(line.split("ci1203-workaround-FILE ")[1]));
  for (const name of ["ci1203", "ci1203-workaround", "lgtm-agent-dns-shim"])
    for (const file of ["state.json", "SHA256SUMS"])
      assert.deepEqual(
        Buffer.from(
          chunks
            .filter((chunk) => chunk.directory === name && chunk.name === file)
            .map((chunk) => chunk.base64)
            .join(""),
          "base64",
        ),
        fs.readFileSync(path.join(root, name, file)),
      );
  assert.throws(() => copyEvidence({ root, emit: () => {} }), /incomplete/);
  assert.throws(
    () => copyEvidence({ root, profile: "arbitrary", emit: () => {} }),
    /unknown evidence profile/,
  );
});

test("native profile rejects leaks, symlinks and any unmanifested json", (t) => {
  const root = nativeFixture(t);
  const dir = path.join(root, "ci1203");
  fs.writeFileSync(path.join(dir, "omitted.json"), "{}\n");
  assert.throws(
    () => copyEvidence({ root, profile: "native", emit: () => {} }),
    /upload set differs/,
  );
  fs.unlinkSync(path.join(dir, "omitted.json"));
  const data = Buffer.from("github_pat_never-print-this\n");
  fs.writeFileSync(path.join(dir, "state.json"), data);
  fs.writeFileSync(
    path.join(dir, "SHA256SUMS"),
    `${createHash("sha256").update(data).digest("hex")}  state.json\n`,
  );
  const lines = [];
  assert.throws(
    () => copyEvidence({ root, profile: "native", emit: (line) => lines.push(line) }),
    /incomplete/,
  );
  assert.ok(!lines.join("\n").includes(data.toString("base64")));
  assert.ok(!lines.join("\n").includes("never-print-this"));
  fs.unlinkSync(path.join(dir, "state.json"));
  fs.symlinkSync("/etc/hosts", path.join(dir, "state.json"));
  assert.throws(() => copyEvidence({ root, profile: "native", emit: () => {} }), /incomplete/);
});

test("native profile accepts empty no-op inventories and shares whole-job caps", (t) => {
  const root = nativeFixture(t);
  const dir = path.join(root, "lgtm-agent-dns-shim");
  fs.unlinkSync(path.join(dir, "state.json"));
  fs.writeFileSync(path.join(dir, "SHA256SUMS"), "");
  assert.equal(copyEvidence({ root, profile: "native", emit: () => {} }).complete, true);
  const manifest = fs.readFileSync(path.join(root, "ci1203", "SHA256SUMS"), "utf8");
  assert.throws(
    () =>
      printEvidence({
        directory: path.join(root, "ci1203"),
        name: "ci1203",
        manifest,
        profile: "native",
        budget: { files: 0, bytes: 1024 * 1024 },
        emit: () => {},
      }),
    /incomplete/,
  );
  assert.throws(
    () =>
      printEvidence({
        directory: path.join(root, "ci1203"),
        name: "ci1203-synthetic-induce",
        manifest,
        profile: "native",
        emit: () => {},
      }),
    /unknown evidence directory/,
  );
});
