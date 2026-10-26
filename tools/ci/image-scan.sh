#!/bin/sh
# Scans published images with osv-scanner and reads the .NET runtime out of each, for image-report.mjs.
#
#   sh tools/ci/image-scan.sh <name>=<image reference> [<name>=<image reference> …]
#
# Writes <name>.json (osv-scanner's findings) and <name>.runtimes (one "framework version" per line,
# empty when the image has no shared .NET runtime), and prints the --image arguments for the report.
# Needs a Docker daemon and osv-scanner as ./osv-scanner. The runtime is read with `docker cp`, not
# by running anything in the image: chiseled images have no shell.
#
# Kept identical in every repository that uses it; TaricHive's copy is the one to change.
set -e
args=""
for spec in "$@"; do
  name=${spec%%=*}; ref=${spec#*=}
  docker pull -q "$ref" > /dev/null
  # Exit code 1 means "vulnerabilities found", which the report weighs; anything else is a failure.
  ./osv-scanner scan image --format json --output-file "$name.json" "$ref" > /dev/null 2> "$name.err" \
    || [ $? -eq 1 ] || { cat "$name.err" >&2; exit 1; }
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
