import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stampReleaseVersion, versionFromTag } from "../../build-helpers/release/version.mjs";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "vpnctl-release-version-"));
  mkdirSync(join(root, "apps/desktop/src-tauri"), { recursive: true });
  writeFileSync(join(root, "Cargo.toml"), '[workspace.package]\nversion = "0.1.0"\nlicense = "MIT"\n\n[workspace.dependencies]\nother = { version = "1.2.3" }\n');
  writeFileSync(join(root, "apps/desktop/package.json"), '{"name":"desktop","version":"0.1.0"}\n');
  writeFileSync(join(root, "apps/desktop/src-tauri/tauri.conf.json"), '{"version":"0.1.0","productName":"VPNCTL"}\n');
  return root;
}

test("release version is derived from bare or full tag refs, including semver suffixes", () => {
  assert.equal(versionFromTag("refs/tags/v0.3.10"), "0.3.10");
  assert.equal(versionFromTag("v12.34.56"), "12.34.56");
  assert.equal(versionFromTag("v1.2.3-rc.1+build.7"), "1.2.3-rc.1+build.7");
});

test("invalid and missing release tags refuse stamping before any file writes", () => {
  const root = fixture();
  try {
    const before = readFileSync(join(root, "Cargo.toml"), "utf8");
    for (const ref of [undefined, "", "refs/heads/main", "0.3.10", "v01.2.3", "v1.2", "v1.2.3-01", "v1.2.3;exit 0"]) {
      assert.throws(() => stampReleaseVersion(root, ref), /release tag/);
      assert.equal(readFileSync(join(root, "Cargo.toml"), "utf8"), before);
    }
  } finally { rmSync(root, { recursive: true }); }
});

test("all package versions agree with the tag and repeat stamping is idempotent", () => {
  const root = fixture();
  try {
    assert.equal(stampReleaseVersion(root, "refs/tags/v0.3.10"), "0.3.10");
    const cargo = readFileSync(join(root, "Cargo.toml"), "utf8");
    assert.match(cargo, /version = "0.3.10"/);
    assert.match(cargo, /other = \{ version = "1.2.3" \}/);
    assert.match(cargo, /license = "MIT"/);
    for (const file of ["apps/desktop/package.json", "apps/desktop/src-tauri/tauri.conf.json"]) {
      assert.equal(JSON.parse(readFileSync(join(root, file), "utf8")).version, "0.3.10");
    }
    const modified = statSync(join(root, "Cargo.toml")).mtimeMs;
    stampReleaseVersion(root, "v0.3.10");
    assert.equal(statSync(join(root, "Cargo.toml")).mtimeMs, modified);
    stampReleaseVersion(root, "v0.3.11");
    assert.match(readFileSync(join(root, "Cargo.toml"), "utf8"), /version = "0.3.11"/);
  } finally { rmSync(root, { recursive: true }); }
});

test("a malformed package leaves the workspace version untouched", () => {
  const root = fixture();
  try {
    writeFileSync(join(root, "apps/desktop/package.json"), "broken JSON");
    assert.throws(() => stampReleaseVersion(root, "v0.3.10"));
    assert.match(readFileSync(join(root, "Cargo.toml"), "utf8"), /version = "0.1.0"/);
  } finally { rmSync(root, { recursive: true }); }
});
