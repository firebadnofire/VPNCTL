import { readFileSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const number = "(?:0|[1-9][0-9]*)";
const prerelease = "(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)";
const tagPattern = new RegExp(`^v(${number}\\.${number}\\.${number}(?:-${prerelease}(?:\\.${prerelease})*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?)$`);

export function versionFromTag(ref) {
  const tag = typeof ref === "string" ? ref.replace(/^refs\/tags\//, "") : "";
  const match = tagPattern.exec(tag);
  if (!match) throw new Error("Expected a v-prefixed semantic version release tag (vMAJOR.MINOR.PATCH).");
  return match[1];
}

export function stampReleaseVersion(root, ref) {
  const version = versionFromTag(ref);
  const cargoPath = resolve(root, "Cargo.toml");
  const cargo = readFileSync(cargoPath, "utf8");
  const section = /(^\[workspace\.package\]\r?\n)([\s\S]*?)(?=^\[|(?![\s\S]))/m;
  const workspace = section.exec(cargo);
  if (!workspace || !/^version\s*=\s*"[^"\r\n]+"\s*$/m.test(workspace[2])) {
    throw new Error("Cargo workspace.package.version is missing.");
  }
  const stampedCargo = cargo.replace(section, (_all, header, body) =>
    header + body.replace(/^version\s*=\s*"[^"\r\n]+"[ \t]*$/m, `version = "${version}"`));
  const updates = [[cargoPath, cargo, stampedCargo]];
  for (const relative of ["apps/desktop/package.json", "apps/desktop/src-tauri/tauri.conf.json"]) {
    const path = resolve(root, relative);
    const original = readFileSync(path, "utf8");
    const data = JSON.parse(original);
    if (typeof data.version !== "string") throw new Error(`Missing version in ${relative}.`);
    data.version = version;
    updates.push([path, original, `${JSON.stringify(data, null, 2)}\n`]);
  }
  // Validate every input before touching files, and replace each file atomically.
  for (const [path, original, stamped] of updates) {
    if (original === stamped) continue;
    const temporary = `${path}.release-version.tmp`;
    try {
      writeFileSync(temporary, stamped);
      renameSync(temporary, path);
    } finally {
      try { unlinkSync(temporary); } catch (error) { if (error.code !== "ENOENT") throw error; }
    }
  }
  return version;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const ref = process.argv[2] || process.env.FORGEJO_REF || process.env.GITHUB_REF;
  console.log(`Release version: ${stampReleaseVersion(root, ref)}`);
}
