"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { inventory, DIRECTORIES } = require("./config-files.cjs");
const { applicability } = require("./config.cjs");
const { MAIN, PLATFORM } = require("./constants.cjs");
const { MAIN_BEFORE, PLATFORM_BYTES, snap, cat, ok } = require("./fixtures.cjs");

function tree(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "shim-inventory-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directories = DIRECTORIES.map((name) => path.join(root, name));
  for (const directory of directories) fs.mkdirSync(directory, { recursive: true });
  const options = { directories, uid: process.getuid(), boundary: root };
  return {
    root,
    directories,
    options,
    put(index, name, content = PLATFORM_BYTES) {
      const file = path.join(directories[index], name);
      fs.writeFileSync(file, content);
      return file;
    },
    read: (extra = {}) => inventory({ ...options, ...extra }),
    canonical(value) {
      return {
        directories: value.directories.map((record) => ({
          ...record,
          path: record.path.slice(root.length),
        })),
        effective: value.effective.map((entry) => ({
          ...entry,
          path: entry.path.slice(root.length),
        })),
      };
    },
  };
}
function decide(files, stdout = cat()) {
  return applicability({
    config: ok(stdout),
    main: snap(MAIN_BEFORE),
    platform: snap(PLATFORM_BYTES),
    files,
    pathPresent: false,
    dns: "Global:\n",
    domains: "Global:\n",
  });
}
for (let winner = 0; winner < 4; winner += 1) {
  test(`same-name priority selects ${DIRECTORIES[winner]} ahead of all lower priority directories`, (t) => {
    const fixture = tree(t);
    for (let index = winner; index < 4; index += 1)
      fixture.put(
        index,
        "90-egress-proxy.conf",
        index === winner ? PLATFORM_BYTES : "[Resolve]\nDNS=8.8.8.8\n",
      );
    const value = fixture.read();
    assert.equal(value.directories.length, 4);
    assert.equal(value.effective.length, 1);
    assert.equal(
      value.effective[0].path,
      path.join(fixture.directories[winner], "90-egress-proxy.conf"),
    );
    assert.equal(value.effective[0].file.content, PLATFORM_BYTES);
    const canonical = fixture.canonical(value);
    const stdout = `# ${MAIN}\n${MAIN_BEFORE}\n# ${canonical.effective[0].path}\n${PLATFORM_BYTES}`;
    assert.equal(decide(canonical, stdout).applicable, winner === 0);
  });
}
test("lexical order follows basename after precedence, independently of directory order", (t) => {
  const fixture = tree(t);
  fixture.put(0, "90-egress-proxy.conf");
  fixture.put(1, "10-first.conf");
  fixture.put(3, "99-last.conf");
  assert.deepEqual(
    fixture.read().effective.map((entry) => entry.name),
    ["10-first.conf", "90-egress-proxy.conf", "99-last.conf"],
  );
});
test("an /etc /dev/null mask hides a lower-priority routing file without hiding 90", (t) => {
  const fixture = tree(t);
  fixture.put(0, "90-egress-proxy.conf");
  fixture.put(3, "80-unknown.conf", "[Resolve]\nDNS=8.8.8.8\n");
  fs.symlinkSync("/dev/null", path.join(fixture.directories[0], "80-unknown.conf"));
  const value = fixture.read();
  assert.equal(
    value.directories[0].entries.find((entry) => entry.name === "80-unknown.conf").masked,
    true,
  );
  assert.deepEqual(
    value.effective.map((entry) => entry.name),
    ["90-egress-proxy.conf"],
  );
  assert.equal(decide(fixture.canonical(value)).applicable, true);
});
test("a lower-priority mask cannot hide a higher-priority file; masked 90 cannot prove applicability", (t) => {
  const fixture = tree(t);
  fixture.put(0, "90-egress-proxy.conf");
  fs.symlinkSync("/dev/null", path.join(fixture.directories[3], "90-egress-proxy.conf"));
  assert.equal(decide(fixture.canonical(fixture.read())).applicable, true);
  fs.unlinkSync(path.join(fixture.directories[0], "90-egress-proxy.conf"));
  assert.equal(
    decide(fixture.canonical(fixture.read()), `# ${MAIN}\n${MAIN_BEFORE}`).applicable,
    false,
  );
});
for (const content of ["DNS=", "DNS=8.8.8.8", "Domains=", "Domains=~corp"]) {
  test(`independent /run ${content} prevents successful partial cat-config from authorizing installation`, (t) => {
    const fixture = tree(t);
    fixture.put(0, "90-egress-proxy.conf");
    fixture.put(1, "70-extra.conf", `[Resolve]\n${content}\n`);
    const files = fixture.canonical(fixture.read());
    assert.equal(decide(files).reason, "REFUSED_CONFIG_UNREADABLE");
    const stdout = `# ${MAIN}\n${MAIN_BEFORE}\n${files.effective.map((entry) => `# ${entry.path}\n${entry.file.content}`).join("\n")}`;
    assert.equal(decide(files, stdout).reason, "REFUSED_UNKNOWN_DNS_SOURCE");
  });
}
test("missing directories are explicit observations, not skipped listing errors", (t) => {
  const fixture = tree(t);
  fs.rmdirSync(fixture.directories[2]);
  assert.equal(fixture.read().directories[2].absent, true);
  const io = {
    ...fs,
    readdirSync: (target) => {
      if (target === fixture.directories[1])
        throw Object.assign(new Error("unreadable listing"), { code: "EACCES" });
      return fs.readdirSync(target);
    },
  };
  assert.throws(() => fixture.read({ io }), /unreadable listing/);
});
for (const fault of [
  "symlink",
  "relative-mask",
  "directory",
  "writable-file",
  "symlink-directory",
  "writable-directory",
  "bad-name",
  "oversized",
  "too-many",
]) {
  test(`inventory refuses ${fault}, including shadowed sources`, (t) => {
    const fixture = tree(t);
    const target = path.join(fixture.directories[3], "80-bad.conf");
    fixture.put(0, "80-bad.conf");
    if (fault === "symlink") fs.symlinkSync(PLATFORM, target);
    if (fault === "relative-mask") fs.symlinkSync("../../../../../dev/null", target);
    if (fault === "directory") fs.mkdirSync(target);
    if (fault === "writable-file") {
      fs.writeFileSync(target, PLATFORM_BYTES);
      fs.chmodSync(target, 0o666);
    }
    if (fault === "symlink-directory") {
      fs.rmdirSync(fixture.directories[3]);
      fs.symlinkSync(fixture.directories[2], fixture.directories[3]);
    }
    if (fault === "writable-directory") fs.chmodSync(fixture.directories[3], 0o777);
    if (fault === "bad-name") fixture.put(3, "space name.conf");
    if (fault === "oversized") {
      fixture.put(2, "70-large.conf", "x".repeat(150000));
      fixture.put(3, "80-large.conf", "x".repeat(150000));
    }
    if (fault === "too-many")
      for (let index = 0; index < 257; index += 1) fixture.put(3, `${index}.conf`);
    assert.throws(() => fixture.read());
  });
}
test("directory, mask, file, and formerly absent directory changes during enumeration are refused", (t) => {
  for (const fault of ["directory", "mask", "file", "absent"]) {
    const fixture = tree(t);
    const file = fixture.put(0, "90-egress-proxy.conf");
    const mask = path.join(fixture.directories[0], "80-mask.conf");
    fs.symlinkSync("/dev/null", mask);
    if (fault === "absent") fs.rmSync(fixture.directories[0], { recursive: true });
    let changed = false;
    const io = {
      ...fs,
      readdirSync: (target) => {
        if (!changed && target === fixture.directories[3]) {
          changed = true;
          if (fault === "directory") fixture.put(0, "70-new.conf");
          if (fault === "file") fs.writeFileSync(file, "changed\n");
          if (fault === "mask") {
            fs.unlinkSync(mask);
            fs.symlinkSync("/tmp", mask);
          }
          if (fault === "absent") fs.mkdirSync(fixture.directories[0]);
        }
        return fs.readdirSync(target);
      },
    };
    assert.throws(() => fixture.read({ io }));
  }
});

for (const relative of ["usr/local", "usr/local/lib"])
  test(`absent configuration leaf does not impose permissions on ${relative}`, (t) => {
    const fixture = tree(t);
    fixture.put(0, "90-egress-proxy.conf");
    fs.rmdirSync(fixture.directories[2]);
    const ancestor = path.join(fixture.root, relative);
    fs.chmodSync(ancestor, 0o775);
    try {
      const value = fixture.read();
      assert.equal(value.directories[2].absent, true);
      assert.equal(decide(fixture.canonical(value)).applicable, true);
      fs.mkdirSync(fixture.directories[2]);
      assert.throws(() => fixture.read(), /unsafe directory.*uid=.*mode=0775/);
    } finally {
      fs.chmodSync(ancestor, 0o755);
    }
  });
