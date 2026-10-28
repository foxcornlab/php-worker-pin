# php-worker-pin

Taking the PHP 8.5 OOM-to-RCE chain (CVE-2026-109618 / CVE-2026-109619)
from a single-worker lab to a real multi-worker Apache pool, over HTTP,
with numbers. The published chain needs both of its requests to land on
the same prefork worker. This repo measures what that costs on a real
pool and removes the cost entirely.

Lab-only tooling. The shipped guard refuses to run against anything that
is not a loopback or private address.

## The chain in one paragraph

A2 is a multipart POST that carries a file part, so PHP's upload-progress
hook publishes `PS(http_session_vars)`, then OOMs request parsing before
module activation. Because the OOM escapes through `longjmp()` with
`PG(modules_activated)` still 0, the session module's RSHUTDOWN never runs
and the reference dangles in worker-persistent memory. B3 is a second
multipart POST whose spray values each span one heap page; the value that
lands on the stale reference's page carries a fake `zend_reference`
pointing at a fake `zend_array` whose `pDestructor` is `zif_system`. The
stale-reference destructor call becomes `system(cmd)`. Full mechanics,
payload layout, and source references in `docs/DOSSIER.md`.

## What this repo adds

**The multi-worker answer.** The chain never needs a fresh worker. The
ZendMM chunk resets every request, so layout is deterministic per request;
the only per-worker precondition is the stale reference existing. Pin the
pool so one child stays free, run A2 on it, and calibration and payload
follow on the first try. Measured:

| setup | cal tries | payload tries | RCE |
|---|---|---|---|
| 1 worker | 1 | 1 | yes |
| 10 workers, no holds | 5 | 5 | yes |
| 20 workers, no holds | 20 | 20 | yes |
| 10 workers, pinned | **1** | **1** | yes |

Full tables, failed paths, and a harness bug we caught and documented:
`docs/RESULTS.md`. Analysis and defender notes: `docs/BYPASS.md`.

**Three measured corrections** to the commonly copied shape:

- The OOM flood is driven by part count, not bytes. 1 MiB of filler with
  500 parts never OOMs a 128M limit; 1000 parts with a 0.25 MiB block
  does. The shipped default is 1000 parts, which keeps every request in
  the chain under nginx's default 1 MB body limit.
- White-box work does not need ASLR disabled. The tool reads the libphp
  base from `/proc/<pid>/maps` and derives the chunk at runtime. Full RCE
  reproduced with ASLR on, multi-worker, through nginx.
- Apache shrinks idle pools, so the roulette you face is the number of
  currently idle workers, not `MaxRequestWorkers`. The effective N on a
  quiet default install is small.

## Use

Baseline reproduction (single worker, ~533 MB image pull on first run):

```sh
./run-repro.sh
```

The script derives `ps_globals` and `zif_system` from the image's
libphp.so with `nm`, builds the single-worker lab, runs the full chain,
and reads back the proof file. Expected output ends with:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Multi-worker pool with the pinning bypass: bring up `lab/mpm-pool.conf`
behind `lab/nginx-default.conf`, hold N-1 children with a slow endpoint
(`lab/www/slow.php`), then run the same tool through the ingress. A
complete pinned run, captured live, is `demo/demo-run.txt`.

Tool options:

```sh
php php2shell.php --cmd 'id > /tmp/pwned' --host 127.0.0.1 --port 80
  --pads 128 --pad-len 1024        # A2 padding that places the reference
  --flood-mb 0.25 --flood-parts 1000
  --cal-values 48                  # B3 spray size
  --max-cal-tries 8 --max-pl-tries 8
  --offsets offsets.json           # for non-default builds
  --check                          # multipart shape self-test
```

The tool runs inside the lab container (`docker exec` / `podman exec`) so
its `/proc` reader works without host root; it needs `SYS_PTRACE` in the
container. It scans every www-data worker for the stale reference, so the
same code path covers both the single-worker and pool cases and reports
how many tries each phase took.

For a different PHP build:

```sh
tools/derive-offsets.sh <container-name>
php php2shell.php --offsets offsets.json ...
```

## Repo layout

```
php2shell.php       chain driver (runs inside the lab container)
run-repro.sh        one-shot baseline reproduction
tools/              offset derivation
lab/                php.ini, MPM configs, nginx config, test endpoints
docs/DOSSIER.md     full technical dossier
docs/BYPASS.md      multi-worker analysis, defender notes
docs/RESULTS.md     every measured run
demo/               live captured run
```

## Limits, stated plainly

- This is white-box tooling: it reads worker memory through `/proc` inside
  the lab container. A black-box version would need an address leak first;
  that is not included and not claimed.
- Tested on `php:8.5.11-apache` (arm64 and, from the original research,
  x86_64). Other builds need the offsets helper; the tool fails cleanly
  when symbols are missing.
- The 20-worker measurement used a pool deliberately kept wide; default
  installs shrink idle pools, which changes N. `docs/RESULTS.md` covers
  both.
- Both CVEs are fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35. Upgrade.
  This repo exists to make the exploitation path concrete for defenders,
  not to hand anyone a weapon; that is also why the tool refuses
  non-private targets.

## License

MIT.
