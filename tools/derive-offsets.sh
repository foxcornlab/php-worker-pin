#!/bin/sh
# extract ps_globals / zif_system offsets from the lab image's libphp.so.
# usage: derive-offsets.sh <container-name> [engine]
#   engine: docker (default) or podman
# writes offsets.json next to this script
set -e
CTR=${1:?container name}
ENGINE=${2:-docker}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
$ENGINE cp "$CTR:/usr/lib/apache2/modules/libphp.so" "$WORK/libphp.so"
PS=$(nm "$WORK/libphp.so" | awk '$3 == "ps_globals" { print $1 }')
ZS=$(nm "$WORK/libphp.so" | awk '$3 == "zif_system" { print $1 }')
[ -n "$PS" ] && [ -n "$ZS" ] || { echo "symbols not found - is libphp.so unstripped?" >&2; exit 1; }
printf '{\n  "ps_off": "0x%s",\n  "zif_system": "0x%s"\n}\n' "${PS#0*}" "${ZS#0*}" > offsets.json
cat offsets.json
