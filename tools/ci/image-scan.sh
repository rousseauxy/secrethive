#!/bin/sh
# Scans published images with Trivy and reads the .NET runtime out of each, for image-report.mjs.
#
#   sh tools/ci/image-scan.sh <name>=<image reference> [<name>=<image reference> …]
#
# Writes <name>.json (Trivy's operating-system findings) and <name>.runtimes (one "framework version" per line,
# empty when the image has no shared .NET runtime), and prints the --image arguments for the report.
# Needs a Docker daemon and Trivy as ./trivy (osv-scanner until 2026-11-14: it did not see glibc in
# chiseled images). The runtime is read with `docker cp`, not
# by running anything in the image: chiseled images have no shell.
#
# Kept identical in every repository that uses it; TaricHive's copy is the one to change.
set -e
args=""
for spec in "$@"; do
  name=${spec%%=*}; ref=${spec#*=}
  docker pull -q "$ref" > /dev/null
  # Trivy ends 0 with or without findings (no --exit-code), so anything else is a failure. The package
  # list (--list-all-pkgs) is where Trivy names each package's source (libc6 and libc-bin are glibc).
  ./trivy image --quiet --scanners vuln --pkg-types os --list-all-pkgs --format json --output "$name.json" "$ref" 2> "$name.err" \
    || { cat "$name.err" >&2; exit 1; }
  cid=$(docker create "$ref")
  rm -rf "shared-$name"
  : > "$name.runtimes"
  if docker cp "$cid:/usr/share/dotnet/shared" "shared-$name" 2> /dev/null; then
    for dir in "shared-$name"/*/*; do
      [ -d "$dir" ] && echo "$(basename "$(dirname "$dir")") $(basename "$dir")" >> "$name.runtimes"
    done
  fi
  docker rm "$cid" > /dev/null
  args="$args --image $name=$name.json,$name.runtimes"
done
echo "$args"
