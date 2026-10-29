"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { bytes, operate, snapshot } = require("./root-file.cjs");
const { FILENAME } = require("./constants.cjs");
const { TOKEN } = require("./fixtures.cjs");
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "agent-dns-root-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, FILENAME);
  const temporary = `${target}.${TOKEN}.tmp`;
  const run = (mode, token = TOKEN, overrides = {}) =>
    operate({ mode, token, root, boundary: root, uid: process.getuid(), ...overrides });
  return { root, target, temporary, run };
}
test("exclusive fsynced inode has exact reset bytes, identity, mode and stable token", (t) => {
  const f = fixture(t);
  const created = f.run("create");
  assert.equal(
    created.content,
    `# lgtm agent-dns shim; owner ${TOKEN}\n[Resolve]\nDNS=\nDNS=127.0.0.1\n`,
  );
  assert.equal(created.mode, 0o644);
  assert.equal(created.nlink, 1);
  assert.deepEqual(f.run("inspect"), created);
  assert.deepEqual(fs.readdirSync(f.root), [FILENAME]);
  assert.throws(() => f.run("create"), /already present/);
  assert.equal(f.run("remove").present, false);
  assert.equal(f.run("inspect").present, false);
});
test("wx refuses a pre-existing temporary file and does not touch its contents", (t) => {
  const f = fixture(t);
  fs.writeFileSync(f.temporary, "foreign");
  assert.throws(() => f.run("create"), /EEXIST/);
  assert.equal(fs.readFileSync(f.temporary, "utf8"), "foreign");
  assert.equal(fs.existsSync(f.target), false);
});
for (const kind of [
  "foreign",
  "symlink",
  "dangling-symlink",
  "directory",
  "wrong-owner",
  "writable",
  "hardlink",
]) {
  test(`never creates over or removes ${kind}`, (t) => {
    const f = fixture(t);
    if (kind === "directory") fs.mkdirSync(f.target);
    else if (kind.includes("symlink")) {
      const destination = path.join(f.root, "destination");
      if (kind === "symlink") fs.writeFileSync(destination, bytes(TOKEN));
      fs.symlinkSync(destination, f.target);
    } else {
      fs.writeFileSync(f.target, kind === "foreign" ? "foreign" : bytes(TOKEN), {
        mode: kind === "writable" ? 0o666 : 0o644,
      });
      if (kind === "writable") fs.chmodSync(f.target, 0o666);
      if (kind === "hardlink") fs.linkSync(f.target, path.join(f.root, "other"));
    }
    assert.throws(() => f.run("create"));
    const options = kind === "wrong-owner" ? { uid: process.getuid() + 1 } : {};
    assert.throws(() => f.run("inspect", TOKEN, options));
    assert.throws(() => f.run("remove", TOKEN, options));
    assert.ok(fs.lstatSync(f.target));
  });
}
test("symlinked and group-writable directories are refused", (t) => {
  const f = fixture(t);
  const actual = path.join(f.root, "actual");
  const linked = path.join(f.root, "linked");
  fs.mkdirSync(actual);
  fs.symlinkSync(actual, linked);
  assert.throws(
    () => f.run("create", TOKEN, { root: linked, boundary: f.root }),
    /unsafe directory/,
  );
  fs.chmodSync(actual, 0o777);
  assert.throws(
    () => f.run("create", TOKEN, { root: actual, boundary: f.root }),
    /unsafe directory/,
  );
});
test("wrong token and arbitrary root CLI operations/paths are refused", (t) => {
  const f = fixture(t);
  f.run("create");
  assert.throws(() => f.run("remove", "b".repeat(64)), /ownership bytes/);
  for (const token of ["a", "A".repeat(64), `${TOKEN}\n`, "../bad"])
    assert.throws(() => f.run("inspect", token), /invalid ownership token/);
  for (const args of [
    ["arbitrary", TOKEN],
    ["inspect", TOKEN, f.root],
    ["remove", "../bad"],
  ]) {
    const result = spawnSync(process.execPath, [path.join(__dirname, "root-file.cjs"), ...args]);
    assert.equal(result.status, 1);
    assert.equal(result.stdout.toString(), "");
  }
  assert.equal(f.run("inspect").present, true);
});
test("recovers lost acknowledgement including kill between link and temp unlink", (t) => {
  const f = fixture(t);
  fs.writeFileSync(f.temporary, bytes(TOKEN), { mode: 0o644 });
  fs.linkSync(f.temporary, f.target);
  assert.equal(f.run("inspect").pendingTemporary, true);
  assert.equal(f.run("remove").present, false);
  assert.deepEqual(fs.readdirSync(f.root), []);
});
test("cleans only its exact pre-link temporary after interrupted create", (t) => {
  const f = fixture(t);
  fs.writeFileSync(f.temporary, bytes(TOKEN), { mode: 0o644 });
  assert.equal(f.run("inspect").present, false);
  f.run("remove");
  assert.deepEqual(fs.readdirSync(f.root), []);
});
test("foreign and symlinked temporary files are retained and refused", (t) => {
  const f = fixture(t);
  f.run("create");
  fs.writeFileSync(f.temporary, "foreign");
  assert.throws(() => f.run("remove"), /foreign temporary/);
  assert.ok(fs.lstatSync(f.target));
  fs.unlinkSync(f.temporary);
  fs.symlinkSync(f.target, f.temporary);
  assert.throws(() => f.run("remove"), /unsafe file/);
  assert.ok(fs.lstatSync(f.target));
});
test("bounded snapshots refuse large files and report immutable hash observations", (t) => {
  const f = fixture(t);
  fs.writeFileSync(f.target, "a".repeat(300000));
  assert.throws(() => snapshot({ target: f.target, uid: process.getuid() }), /size/);
});

test("a failed link preserves its error after cleaning the owned temporary", (t) => {
  const f = fixture(t);
  const failure = new Error("link failed");
  t.mock.method(fs, "linkSync", () => {
    throw failure;
  });
  try {
    assert.throws(
      () => f.run("create"),
      (error) => error === failure,
    );
    assert.equal(fs.existsSync(f.temporary), false);
    assert.equal(fs.existsSync(f.target), false);
  } finally {
    t.mock.restoreAll();
  }
});

test("creation and cleanup failures are both retained for diagnosis", (t) => {
  const f = fixture(t);
  const creation = new Error("link failed");
  const cleanup = new Error("unlink failed");
  t.mock.method(fs, "linkSync", () => {
    throw creation;
  });
  t.mock.method(fs, "unlinkSync", () => {
    throw cleanup;
  });
  try {
    assert.throws(
      () => f.run("create"),
      (error) =>
        error instanceof AggregateError &&
        error.errors[0] === creation &&
        error.errors[1] === cleanup,
    );
    assert.equal(fs.existsSync(f.temporary), true);
    assert.equal(fs.existsSync(f.target), false);
  } finally {
    t.mock.restoreAll();
  }
  assert.equal(f.run("remove").present, false);
});

test("a lost cleanup acknowledgement retains a recoverable owned inode", (t) => {
  const f = fixture(t);
  const failure = new Error("unlink failed");
  t.mock.method(fs, "unlinkSync", () => {
    throw failure;
  });
  try {
    assert.throws(
      () => f.run("create"),
      (error) => error === failure,
    );
    assert.equal(fs.existsSync(f.target), true);
    assert.equal(fs.existsSync(f.temporary), true);
  } finally {
    t.mock.restoreAll();
  }
  assert.equal(f.run("remove").present, false);
});
