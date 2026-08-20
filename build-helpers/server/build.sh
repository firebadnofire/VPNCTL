#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_dir}/../.." && pwd)"
output_root="${VAM_SERVER_OUTPUT_DIR:-${repository_root}/target/vam-server-dist}"

cd -- "${repository_root}"
cargo build --locked --release -p vam-server

host_triple="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "${host_triple}" ]]; then
  echo "Unable to determine the Rust host triple." >&2
  exit 1
fi

destination_dir="${output_root}/${host_triple}"
destination="${destination_dir}/vam-server"
checksum="${destination}.sha256"
checksum_temporary="${checksum}.tmp"

mkdir -p -- "${destination_dir}"
install -m 0755 -- "${repository_root}/target/release/vam-server" "${destination}"
sha256sum -- "${destination}" > "${checksum_temporary}"
mv -f -- "${checksum_temporary}" "${checksum}"

printf '%s\n' "${destination}"
