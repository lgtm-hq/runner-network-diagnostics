"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { effectiveSources } = require("./config.cjs");

function io(entries, links = {}) {
  return {
    readdirSync(directory) {
      if (!(directory in entries)) throw Object.assign(new Error("absent"), { code: "ENOENT" });
      return entries[directory].map(([name, type]) => ({
        name,
        isSymbolicLink: () => type === "link",
        isFile: () => type === "file",
      }));
    },
    readlinkSync: (file) => links[file],
  };
}

test("independent complete-source inventory respects basename precedence and dev-null masking", () => {
  const prefix = "/systemd/resolved.conf.d";
  const source = io(
    {
      [`/etc${prefix}`]: [
        ["90-egress-proxy.conf", "file"],
        ["91-mask.conf", "link"],
      ],
      [`/run${prefix}`]: [
        ["90-egress-proxy.conf", "file"],
        ["91-mask.conf", "file"],
        ["92-run.conf", "file"],
      ],
      [`/usr/lib${prefix}`]: [["95-vendor.conf", "file"]],
    },
    { [`/etc${prefix}/91-mask.conf`]: "/dev/null" },
  );
  assert.deepEqual(effectiveSources(source), [
    "/etc/systemd/resolved.conf",
    `/etc${prefix}/90-egress-proxy.conf`,
    `/run${prefix}/92-run.conf`,
    `/usr/lib${prefix}/95-vendor.conf`,
  ]);
});

test("unreadable listings, nonregular sources and unknown symlinks cannot prove config completeness", () => {
  assert.throws(
    () =>
      effectiveSources({
        readdirSync: () => {
          throw new Error("denied");
        },
      }),
    /denied/,
  );
  assert.throws(
    () => effectiveSources(io({ "/etc/systemd/resolved.conf.d": [["other.conf", "directory"]] })),
    /nonregular/,
  );
  assert.throws(
    () => effectiveSources(io({ "/etc/systemd/resolved.conf.d": [["other.conf", "link"]] })),
    /symlink/,
  );
});
