"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  applicability,
  parseConfig,
  listenerState,
  agentStatus,
  globalValues,
} = require("./config.cjs");
const { MAIN, PLATFORM, FILENAME } = require("./constants.cjs");
const {
  MAIN_BEFORE,
  PLATFORM_BYTES,
  HEADER,
  LIVE,
  ok,
  snap,
  cat,
  files,
} = require("./fixtures.cjs");
function decide({
  main = MAIN_BEFORE,
  platform = PLATFORM_BYTES,
  stdout = cat(main, platform),
  config = ok(stdout),
  pathPresent = false,
  inventory,
  dns = "Global:\n",
  domains = "Global:\n",
} = {}) {
  if (!inventory) {
    try {
      inventory = files(stdout);
    } catch {
      inventory = files();
    }
  }
  return applicability({
    config,
    main: snap(main),
    platform: snap(platform),
    pathPresent,
    files: inventory,
    dns,
    domains,
  });
}
test("only the positively observed empty platform drop-in reset is applicable", () => {
  assert.equal(decide().applicable, true);
  assert.equal(decide({ stdout: `# ${MAIN}\n${MAIN_BEFORE}` }).applicable, false);
});
for (const platform of [
  "[Resolve]\nDNS=8.8.8.8\n",
  "[Resolve]\nDNS=127.0.0.1\n",
  "[Resolve]\n# DNS=\n",
  "[Resolve]\n; DNS=\n",
  "[Resolve]\nDNS= # empty\n",
  "[Resolve]\nDNS=\nDomains=~corp\n",
  "[Resolve]\nDNS=\nFallbackDNS=1.1.1.1\n",
  "[Resolve]\nDNS=\nDNS=\n",
  "[Network]\nDNS=\n",
  "DNS=\n",
  "[Resolve]\nDNS='';\n",
  "[Resolve]\nDNS=\\\n8.8.8.8\n",
  "[Resolve]\nDNS=\\\n",
  "[Resolve]\nDNS=\nUnknownThing=yes\n",
]) {
  test(`refuses false reset proof ${JSON.stringify(platform)}`, () =>
    assert.equal(decide({ platform }).applicable, false));
}
test("whitespace, comment-only continuation lines, CRLF and an empty joined value", () => {
  const main = "# distro\r\n [Resolve] \r\n# DNS=1.1.1.1\r\n";
  const platform =
    " [Resolve] \r\n  DNS  = \\\r\n# ignored continuation comment\r\n; also ignored\r\n   \r\n";
  assert.equal(decide({ main, platform }).applicable, true);
  assert.equal(decide({ platform: " [Resolve] \n DNS =    \n# comment\n" }).applicable, true);
  assert.equal(
    parseConfig(`# ${MAIN}\n[Resolve]\nDNS=127.0.0.1 \\\n# ignored\n 8.8.8.8\n`)[0].assignments[0]
      .value,
    "127.0.0.1   8.8.8.8",
  );
});
test("an empty continuation followed by the next section is not a reset proof", () => {
  assert.equal(decide({ platform: "[Resolve]\nDNS=\\\n[Resolve]\n" }).applicable, false);
});
for (const main of [
  "[Resolve]\nDNS=9.9.9.9\n",
  "[Resolve]\nDomains=~corp\n",
  "[Resolve]\nDNS=\n",
]) {
  test(`preserves pre-existing main intentions ${JSON.stringify(main)}`, () =>
    assert.equal(decide({ main }).applicable, false));
}
for (const prefix of ["/etc", "/run", "/usr/lib", "/usr/local/lib"]) {
  for (const name of [FILENAME, "99-z-platform.conf"]) {
    test(`refuses later or equally named DNS source ${prefix}/${name}`, () => {
      const result = decide({
        stdout: `${cat()}\n# ${prefix}/systemd/resolved.conf.d/${name}\n[Resolve]\nDNS=\n`,
      });
      assert.equal(result.reason, "REFUSED_UNKNOWN_DNS_SOURCE");
    });
  }
  test(`unknown earlier DNS source ${prefix}`, () => {
    assert.equal(
      decide({
        stdout: `${cat()}\n# ${prefix}/systemd/resolved.conf.d/80-other.conf\n[Resolve]\nDNS=1.1.1.1\n`,
      }).applicable,
      false,
    );
  });
}
for (const config of [
  { ...ok(cat()), status: 1 },
  { ...ok(cat()), stderr: "warning: permission denied\n" },
  { ...ok(cat()), error: "ENOBUFS" },
  { ...ok(cat()), error: "ETIMEDOUT" },
  ok(cat().trimEnd()),
  ok(cat().replace("# distro defaults\n", "")),
  ok(`${cat()}\n# /tmp/not-systemd.conf\n[Resolve]\nDNS=\n`),
  ok(`${cat()}\n# ${PLATFORM}\n[Resolve]\nDNS=\n`),
  ok(`warning emitted before source\n${cat()}`),
  ok(`${cat()}\0`),
  ok("a".repeat(300000)),
]) {
  test(`requires complete bounded successful cat-config ${JSON.stringify(config).slice(0, 100)}`, () =>
    assert.equal(decide({ config }).applicable, false));
}
test("existing own path is refused, including observe", () =>
  assert.equal(decide({ pathPresent: true }).reason, "REFUSED_PATH_PRESENT"));
test("complete independent four-directory inventory is required even for successful partial cat-config", () => {
  for (const inventory of [
    {},
    { ...files(), directories: files().directories.slice(1) },
    { ...files(), effective: [] },
  ])
    assert.equal(decide({ inventory }).reason, "REFUSED_CONFIG_UNREADABLE");
  const extra = `${cat()}\n# /run/systemd/resolved.conf.d/70-hidden.conf\n[Resolve]\nDNS=\n`;
  assert.equal(decide({ inventory: files(extra) }).reason, "REFUSED_CONFIG_UNREADABLE");
});
for (const key of ["DNS", "Domains"]) {
  for (const value of ["", "8.8.8.8"]) {
    test(`refuses /run stray ${key}=${value}`, () => {
      const stdout = `${cat()}\n# /run/systemd/resolved.conf.d/70-other.conf\n[Resolve]\n${key}=${value}\n`;
      assert.equal(decide({ stdout }).reason, "REFUSED_UNKNOWN_DNS_SOURCE");
    });
  }
}
test("live Global DNS and Domains must both agree with the empty configuration", () => {
  for (const field of ["dns", "domains"]) {
    for (const value of ["Global: 127.0.0.1\n", "Link 2: empty\n", "Global:\nGlobal:\n"])
      assert.equal(decide({ [field]: value }).reason, "REFUSED_LIVE_MISMATCH");
  }
});
test("global parsing never substitutes a link DNS/domain or accepts duplicate Global", () => {
  assert.deepEqual(globalValues("Global:\nLink 2 (eth0): 127.0.0.1\n"), []);
  assert.throws(() => globalValues("Link 2: 127.0.0.1\n"));
  assert.throws(() => globalValues("Global:\nGlobal: 127.0.0.1\n"));
});
test("socket absence requires a successful recognized listing", () => {
  assert.equal(listenerState(ok(HEADER)), "absent");
  assert.equal(listenerState(ok(`${HEADER}UNCONN 0 0 127.0.0.53:53 0.0.0.0:*\n`)), "absent");
  assert.equal(listenerState(ok(LIVE)), "present");
  for (const local of ["0.0.0.0:53", "*:53", "[::]:53", "[::ffff:127.0.0.1]:53", "127.0.0.1%lo:53"])
    assert.equal(listenerState(ok(`${HEADER}UNCONN 0 0 ${local} *:*\n`)), "present");
  for (const result of [
    ok(""),
    ok("unexpected"),
    ok(`${HEADER}not a socket\n`),
    ok(`${HEADER}UNCONN 0 0 nonsense:53 *:*\n`),
    ok(`${HEADER}UNCONN 0 0 127.0.0.1:65536 *:*\n`),
    { ...ok(HEADER), stderr: "warning" },
    { ...ok(HEADER), status: 1 },
  ])
    assert.equal(listenerState(result), "unknown");
});
test("status classification distinguishes absence/startup, terminal and unknown", () => {
  assert.equal(agentStatus(ok("Initialized\n")), "initialized");
  assert.equal(agentStatus(ok("Initializing\n")), "uninitialized");
  assert.equal(agentStatus(ok("Error: setup failed\n")), "terminal");
  assert.equal(agentStatus(ok("Error-free status")), "unknown");
  assert.equal(
    agentStatus({ status: 1, stdout: "", stderr: "cat: No such file or directory", error: null }),
    "uninitialized",
  );
  assert.equal(agentStatus({ ...ok("Initialized"), error: "ETIMEDOUT" }), "unknown");
  assert.equal(agentStatus({ ...ok("Initialized"), stderr: "warning" }), "unknown");
});
