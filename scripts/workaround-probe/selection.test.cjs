"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { select, dnsFields } = require("./selection.cjs");
const config = {
  status: 0,
  stdout:
    "# /etc/systemd/resolved.conf\n[Resolve]\n# /etc/systemd/resolved.conf.d/90-egress-proxy.conf\n[Resolve]\nDNS=\n",
  stderr: "",
  error: null,
};
const native = {
  hosted: "github-hosted",
  os: "Linux",
  container: false,
  facts: {
    region: "unknown",
    target: "/etc/resolv.conf",
    resolverUnit: "active",
    proxyUnit: "active",
    listener: "present",
    resolvConf: "nameserver 127.0.0.100\nnameserver 127.0.0.53\n",
    effectiveSources: [
      "/etc/systemd/resolved.conf",
      "/etc/systemd/resolved.conf.d/90-egress-proxy.conf",
    ],
    resolvedActive: "active",
    sudo: true,
    globalDns: "",
    globalDomains: "",
  },
  config,
};

test("native eligibility ignores region and preserves the pre-outcome facts", () => {
  const record = select(native);
  assert.equal(record.eligible, true);
  assert.equal(record.classification, "ELIGIBLE");
  assert.deepEqual(record.config, config);
  assert.equal(
    select({ ...native, facts: { ...native.facts, region: "westeurope" } }).eligible,
    true,
  );
});

test("unknown/nonhosted/container facts cannot become eligible", () => {
  for (const change of [
    { hosted: "self-hosted" },
    { hosted: "" },
    { os: "Windows" },
    { container: true },
    { container: null },
  ])
    assert.equal(select({ ...native, ...change }).eligible, false);
  for (const [field, value] of Object.entries({
    target: "unknown",
    listener: "unknown",
    resolverUnit: "unknown",
    proxyUnit: "inactive",
    resolvConf: "nameserver 127.0.0.53\n",
  }))
    assert.equal(select({ ...native, facts: { ...native.facts, [field]: value } }).eligible, false);
});

test("complete config failure, truncation, extra headers and DNS fields stay partial", () => {
  for (const change of [
    { status: 1 },
    { error: "ETIMEDOUT" },
    { stderr: "read failed" },
    { stdout: config.stdout.trimEnd() },
    { stdout: `${config.stdout}Domains=~.\n` },
    { stdout: config.stdout.replace("DNS=", "DNS=1.1.1.1") },
    { stdout: `${config.stdout}# /run/systemd/resolved.conf.d/91-other.conf\n` },
  ]) {
    const record = select({ ...native, config: { ...config, ...change } });
    assert.equal(record.eligible, false);
    assert.equal(record.candidate, true);
  }
  assert.equal(dnsFields({ ...config, status: 1 }), null);
});

test("ordinary known topology takes the short path; unknown facts remain candidates", () => {
  const ordinary = {
    ...native,
    config: { ...config, stdout: "# /etc/systemd/resolved.conf\n[Resolve]\n" },
    facts: {
      ...native.facts,
      region: "westeurope",
      target: "/run/systemd/resolve/stub-resolv.conf",
      resolverUnit: "inactive",
      proxyUnit: "inactive",
      listener: "absent",
      resolvConf: "nameserver 127.0.0.53\n",
      effectiveSources: ["/etc/systemd/resolved.conf"],
    },
  };
  assert.equal(select(ordinary).classification, "UNAFFECTED");
  for (const change of [{ hosted: "self-hosted" }, { container: null }, { os: "unknown" }])
    assert.equal(select({ ...ordinary, ...change }).classification, "PARTIAL");
  for (const change of [
    { sudo: false },
    { resolvedActive: "unknown" },
    { resolvConf: "" },
    { effectiveSources: null },
  ])
    assert.equal(
      select({ ...ordinary, facts: { ...ordinary.facts, ...change } }).classification,
      "PARTIAL",
    );
  assert.equal(
    select({ ...ordinary, facts: { ...ordinary.facts, region: "unknown" } }).classification,
    "UNAFFECTED",
  );
});

for (const [label, text] of [
  ["wrong platform section", config.stdout.replace("[Resolve]\nDNS=", "[Other]\nDNS=")],
  ["wrong main section", config.stdout.replace("[Resolve]", "[Other]")],
  ["missing sections", config.stdout.replaceAll("[Resolve]\n", "")],
  [
    "continued main routing assignment",
    config.stdout.replace("[Resolve]\n", "[Resolve]\nDomains \\\n=~.\n"),
  ],
  ["continued platform assignment", config.stdout.replace("DNS=\n", "DNS=\\\n1.1.1.1\n")],
  ["unknown main syntax", config.stdout.replace("[Resolve]\n", "[Resolve]\nUnknownSetting=yes\n")],
])
  test(`${label} cannot certify an affected host`, () => {
    const record = select({ ...native, config: { ...config, stdout: text } });
    assert.equal(record.eligible, false);
    assert.equal(record.classification, "PARTIAL");
    assert.equal(record.dnsFields, null);
  });

for (const body of [
  "[Other]\n",
  "",
  "[Resolve]\nDomains \\\n=~.\n",
  "[Resolve]\nDNS=\\\n1.1.1.1\n",
  "[Resolve]\nUnrecognized=yes\n",
])
  test(`unknown ordinary config stays outside the reference cohort: ${JSON.stringify(body)}`, () => {
    const ordinary = {
      ...native,
      config: { ...config, stdout: `# /etc/systemd/resolved.conf\n${body}` },
      facts: {
        ...native.facts,
        region: "westeurope",
        target: "/run/systemd/resolve/stub-resolv.conf",
        resolverUnit: "inactive",
        proxyUnit: "inactive",
        listener: "absent",
        resolvConf: "nameserver 127.0.0.53\n",
        effectiveSources: ["/etc/systemd/resolved.conf"],
      },
    };
    assert.equal(select(ordinary).classification, "PARTIAL");
  });

test("stock comments and normalized empty assignment retain independent recognition", () => {
  const text = config.stdout
    .replace("[Resolve]\n", "# /etc/ if you need an override\n[Resolve]\n")
    .replace("DNS=\n", "  DNS =  \n");
  assert.equal(select({ ...native, config: { ...config, stdout: text } }).eligible, true);
});

// Test-only interface check. The production screen remains independent and
// never imports or derives its decision from the portable shim recognizer.
for (const [label, mainBody, platformBody, expected] of [
  ["continued key", "[Resolve]\n", "[Resolve]\nDNS \\\n=\n", true],
  ["blank continuation terminator", "[Resolve]\n", "[Resolve]\nDNS=\\\n\n", true],
  ["unterminated continuation", "[Resolve]\n", "[Resolve]\nDNS=\\\n", false],
  ["continued nonempty value", "[Resolve]\n", "[Resolve]\nDNS=\\\n1.1.1.1\n", false],
  ["continued platform domain", "[Resolve]\n", "[Resolve]\nDomains \\\n=~.\n", false],
  ["continued main domain", "[Resolve]\nDomains \\\n=~.\n", "[Resolve]\nDNS=\n", false],
])
  test(`independent predicates and actual pre installation agree: ${label}`, () => {
    const { createHash } = require("node:crypto");
    const { pre } = require("../agent-dns-shim/control.cjs");
    const mainPath = "/etc/systemd/resolved.conf";
    const platformPath = `${mainPath}.d/90-egress-proxy.conf`;
    const snapshot = (content) => ({
      present: true,
      content,
      sha256: createHash("sha256").update(content).digest("hex"),
    });
    const main = snapshot(mainBody);
    const platform = snapshot(platformBody);
    const observation = {
      ...config,
      stdout: `# ${mainPath}\n${mainBody}# ${platformPath}\n${platformBody}`,
    };
    const selected = select({ ...native, config: observation });
    let saved;
    const calls = [];
    const runtime = {
      mode: "apply",
      load: () => saved,
      save: (state) => {
        saved = state;
      },
      environment: () => ({ allowed: true }),
      topology: () => ({ allowed: true }),
      config: () => ({ ...observation }),
      main: () => main,
      platform: () => platform,
      files: () => ({
        directories: ["/etc", "/run", "/usr/local/lib", "/usr/lib"].map((root) => ({
          path: `${root}/systemd/resolved.conf.d`,
        })),
        effective: [{ path: platformPath, file: platform }],
      }),
      dns: () => "Global:\n",
      domains: () => "Global:\n",
      pathPresent: () => false,
      token: () => "a".repeat(64),
      bootMicros: () => 1,
      root: (operation) => {
        calls.push(operation);
        return { present: true, sha256: "mock-owned" };
      },
    };
    const result = pre(runtime);
    assert.equal(selected.eligible, expected);
    assert.equal(result.applicable, expected);
    assert.equal(result.applied, expected);
    assert.deepEqual(calls, expected ? ["create"] : []);
    if (!expected) assert.equal(selected.classification, "PARTIAL");
  });

for (const region of ["westus2", "unknown"])
  test(`positive ordinary proof supplies an unaffected candidate despite region ${region}`, () => {
    const input = {
      ...native,
      config: { ...config, stdout: "# /etc/systemd/resolved.conf\n[Resolve]\n" },
      facts: {
        ...native.facts,
        region,
        target: "/run/systemd/resolve/stub-resolv.conf",
        resolverUnit: "inactive",
        proxyUnit: "inactive",
        listener: "absent",
        resolvConf: "nameserver 127.0.0.53\n",
        effectiveSources: ["/etc/systemd/resolved.conf"],
      },
    };
    const selected = select(input);
    assert.equal(selected.classification, "UNAFFECTED");
    assert.equal(selected.candidate, false);
    assert.equal(
      select({ ...input, facts: { ...input.facts, globalDomains: "~corp" } }).classification,
      "PARTIAL",
    );
    assert.equal(
      select({ ...input, facts: { ...input.facts, globalDns: "8.8.8.8" } }).classification,
      "PARTIAL",
    );
  });
