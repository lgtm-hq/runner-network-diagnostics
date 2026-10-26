"use strict";
// Local deterministic observations; no command execution or frozen imports.
const { createHash } = require("node:crypto");
const { MAIN, PLATFORM, TARGET } = require("./constants.cjs");
const { bytes } = require("./root-file.cjs");
const { parseConfig } = require("./config.cjs");
const { DIRECTORIES } = require("./config-files.cjs");
const TOKEN = "a".repeat(64);
const MAIN_BEFORE = "# distro defaults\n[Resolve]\n#DNS=\n";
const MAIN_AGENT = "[Resolve]\nDNS=127.0.0.1\nDomains=~.\n";
const PLATFORM_BYTES = "[Resolve]\nDNS=\n";
const HEADER = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n";
const LIVE = `${HEADER}UNCONN 0 0 127.0.0.1:53 0.0.0.0:*\n`;
const ok = (stdout = "") => ({ status: 0, stdout, stderr: "", error: null });
const snap = (content) => ({ content, sha256: createHash("sha256").update(content).digest("hex") });
function cat(main = MAIN_BEFORE, platform = PLATFORM_BYTES, owned) {
  return `# ${MAIN}\n${main}\n# ${PLATFORM}\n${platform}${owned ? `\n# ${TARGET}\n${owned}` : ""}`;
}
function files(content = cat()) {
  return {
    directories: DIRECTORIES.map((directory) => ({ path: directory })),
    effective: parseConfig(content)
      .slice(1)
      .map((source) => ({
        path: source.path,
        file: snap(`${source.body.join("\n").trimEnd()}\n`),
      })),
  };
}
function harness() {
  let saved;
  let clock = 0;
  let owned;
  let main = MAIN_BEFORE;
  let dns = "Global:\n";
  let domains = "Global:\n";
  let pid = 10;
  const events = [];
  const receipts = [];
  const r = {
    mode: "apply",
    events,
    receipts,
    environment: () => ({ allowed: true }),
    topology: () => ({ allowed: true }),
    token: () => TOKEN,
    config: () => ok(cat(main, PLATFORM_BYTES, owned?.present ? owned.content : undefined)),
    files: () => files(cat(main, PLATFORM_BYTES, owned?.present ? owned.content : undefined)),
    main: () => snap(main),
    platform: () => snap(PLATFORM_BYTES),
    pathPresent: () => Boolean(owned?.present),
    load: () => saved && structuredClone(saved),
    save(state, exclusive) {
      if (exclusive && saved) throw new Error("state already exists");
      events.push(state.mutationIntent ? "save-intent" : "save");
      saved = structuredClone(state);
    },
    root(mode, token) {
      events.push(mode);
      if (token !== TOKEN) throw new Error("bad token");
      if (mode === "create") {
        if (!saved?.mutationIntent || saved.token !== TOKEN) throw new Error("no durable intent");
        owned = {
          present: true,
          ...snap(bytes(token)),
          ino: "1",
          dev: "1",
          ctimeNs: "100",
          nlink: 1,
          mode: 0o644,
        };
      }
      if (mode === "remove") owned = { present: false };
      return structuredClone(owned || { present: false });
    },
    bootMicros: () => 100,
    status: () => ok("Initialized\n"),
    listener: () => ok(LIVE),
    dns: () => dns,
    domains: () => domains,
    service: () => `ExecMainPID=${pid}\nExecMainStartTimestampMonotonic=200\n`,
    restart: () => {
      events.push("restart");
      pid += 1;
      dns = "Global:\n";
    },
    getent: () => {
      events.push("getent");
      return ok("140.82.114.3 STREAM github.com\n");
    },
    now: () => clock,
    pause: (ms) => {
      clock += ms;
    },
    receipt: (phase, record) => {
      events.push(`receipt-${phase}`);
      receipts.push({ phase, ...structuredClone(record) });
    },
    outputs: (state, disposition) => {
      events.push("outputs");
      r.output = { applicable: state.applicable, applied: state.applied, disposition };
    },
    initialized() {
      main = MAIN_AGENT;
      dns = "Global: 127.0.0.1\n";
      domains = "Global: ~.\nLink 2 (eth0): foo\n";
    },
    setDns(value) {
      dns = value;
    },
  };
  return r;
}
module.exports = {
  TOKEN,
  MAIN_BEFORE,
  MAIN_AGENT,
  PLATFORM_BYTES,
  HEADER,
  LIVE,
  ok,
  snap,
  cat,
  files,
  harness,
};
