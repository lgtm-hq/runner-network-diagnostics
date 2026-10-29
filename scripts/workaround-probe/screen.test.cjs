"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { prepare, main } = require("./screen.cjs");
const { MAIN, PLATFORM, nonce } = require("./support.cjs");

function fixture(t, native = true) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "native-screen-"));
  const out = path.join(root, "ci1203-workaround");
  fs.mkdirSync(out);
  const old = { ...process.env };
  Object.assign(process.env, {
    INPUT_ARM: "T",
    INPUT_HOSTED: "github-hosted",
    RUNNER_OS: "Linux",
    GITHUB_OUTPUT: path.join(root, "outputs"),
  });
  t.after(() => {
    for (const name of Object.keys(process.env)) if (!(name in old)) delete process.env[name];
    Object.assign(process.env, old);
    fs.rmSync(root, { recursive: true, force: true });
  });
  const events = [];
  const config = `# ${MAIN}\n[Resolve]\n${native ? `# ${PLATFORM}\n[Resolve]\nDNS=\n` : ""}`;
  const r = {
    root,
    out,
    nonce,
    pause: () => {},
    effectiveSources: () => (native ? [MAIN, PLATFORM] : [MAIN]),
    topology(stage) {
      const dir = path.join(root, "ci1203");
      fs.mkdirSync(dir, { recursive: true });
      if (stage === "before")
        for (const [name, content] of Object.entries({
          region: "westeurope",
          "resolver-target": native ? "/etc/resolv.conf" : "/run/systemd/resolve/stub-resolv.conf",
          "resolver-unit": native ? "active" : "inactive",
          "proxy-unit": native ? "active" : "inactive",
          listener: native ? "present" : "absent",
        }))
          fs.writeFileSync(path.join(dir, `${name}.txt`), `${content}\n`);
      return `stage=${stage}\n`;
    },
    file(file) {
      if (["/.dockerenv", "/run/.containerenv"].includes(file) || file.includes("99-lgtm"))
        return { present: false };
      return {
        present: true,
        sha256: file,
        content: file === "/proc/1/comm" ? "systemd\n" : "[Resolve]\n",
      };
    },
    probe(command, args) {
      events.push(args.join(" "));
      const result = { status: 0, stdout: "", stderr: "", error: null };
      if (args.includes("cat-config")) result.stdout = config;
      else if (args.includes("systemd-detect-virt")) {
        result.status = 1;
        result.stdout = "";
      } else if (args.includes("/etc/resolv.conf"))
        result.stdout = `nameserver ${native ? "127.0.0.100" : "127.0.0.53"}\n`;
      else if (args.includes("resolvectl")) result.stdout = "Global:\n";
      else if (args.includes("systemctl")) result.stdout = "active\n";
      else if (args.includes("getent")) result.status = 2;
      return result;
    },
    vendor(mode) {
      events.push(`vendor:${mode}`);
      return { status: 0, error: null };
    },
    write(name, record) {
      events.push(`write:${name}`);
      fs.writeFileSync(path.join(out, name), JSON.stringify(record), { flag: "wx" });
      return record;
    },
    read: (name) => JSON.parse(fs.readFileSync(path.join(out, name), "utf8")),
  };
  return { r, events };
}

test("screen freezes classification before capture and P, and main exposes confirmed baseline", (t) => {
  const { r, events } = fixture(t);
  prepare(r);
  main(r);
  assert.equal(r.read("selection.json").eligible, true);
  assert.ok(events.indexOf("write:selection.json") < events.indexOf("vendor:prepare"));
  assert.ok(
    events.indexOf("vendor:prepare") < events.findIndex((event) => event.includes("getent")),
  );
  assert.match(fs.readFileSync(process.env.GITHUB_OUTPUT, "utf8"), /eligible=true/);
});

test("ordinary short path retains hashes but never prepares capture or performs pre DNS queries", (t) => {
  const { r, events } = fixture(t, false);
  prepare(r);
  main(r);
  assert.equal(r.read("selection.json").classification, "UNAFFECTED");
  assert.ok(r.read("baseline.json").main.sha256);
  assert.ok(!events.some((event) => event.startsWith("vendor:") || event.includes("getent")));
});

test("failed capture preparation still preserves selection, P and main outputs before error", (t) => {
  const { r } = fixture(t);
  r.vendor = () => ({ status: 1, error: "capture failed" });
  assert.throws(() => prepare(r), /screen pre incomplete/);
  assert.equal(r.read("capture-intent.json").requested, true);
  assert.ok(r.read("oracle-P.json").nonce);
  assert.throws(() => main(r), /baseline incomplete/);
  assert.match(fs.readFileSync(process.env.GITHUB_OUTPUT, "utf8"), /eligible=true/);
});
