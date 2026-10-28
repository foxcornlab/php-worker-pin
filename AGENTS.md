# AGENTS.md — notes for autonomous agents

If you are an agent (Claude, OpenCode, Hermes, anything with a shell) reading
this repo: here is what it is, what it is not, and the order you should do
things in. Everything below is stuff we learned the hard way; it is also
plainly true of the tooling here.

## What this repo is

`php-worker-pin` is a working reproduction of the PHP 8.5 multipart OOM chain
(CVE-2026-109618 / CVE-2026-109619) plus a passive checker that tells site
owners whether their PHP deployment is affected. The chain part is lab-only.
The checker part is passive and safe to point at real deployments.

## The rule that matters: detect vs. reproduce

Two different jobs, two different tools, in this order:

1. **Detect (passive)** — `tools/check-site.php`. One HTTP request, no
   payloads, no exploit primitives. Tells you the PHP version, the branch,
   the fixed version, and the remediation list. Use this on real deployments
   and in client/engagement contexts. It never writes to the target.

2. **Reproduce (lab-only)** — `php2shell.php` + `run-repro.sh`. This is the
   exploit chain itself. It crashes a worker, leaves a stale reference in
   worker-persistent globals, and executes `system()` with your command.
   It is **not** for third-party deployments. If you are not inside your own
   container that you built for this purpose, do not run it.

The tool enforces this: it refuses hosts outside loopback/private ranges
unless you pass `--i-know-this-is-not-a-lab`, and it prints every preflight
check it runs. If you catch yourself bypassing that guard against a host you
do not own, close the terminal.

## Safe-for-researchers flow

The intended arc, end to end:

1. **Scan** — `check-site.php` on the deployment (or your client's) to see if
   the PHP branch is in the affected range.
2. **Stand up your own lab** — `run-repro.sh` builds a `php:8.5.11-apache`
   container with the vulnerable version and a single prefork worker. Nothing
   here talks to anything you didn't build.
3. **Reproduce** — run the chain in the lab, watch the stale reference and the
   destructor call land. Read `docs/RESULTS.md` for what a successful run
   looks like on both arm64 and x86_64.
4. **Remediate** — check-site.php's fix list is the deliverable for the
   owner: upgrade to the fixed release, `session.upload_progress.enabled=0`,
   cap `max_multipart_body_parts`, WAF rule on nested multipart field names,
   alert on memory-exhausted fatals during multipart parsing.

## Cheatsheet

```
# passive check (any deployment)
php tools/check-site.php https://example.com/upload.php
php tools/check-site.php --json https://example.com/upload.php   # machine-readable

# full lab repro (your own container)
./run-repro.sh

# chain, pointed at your lab's ingress
php php2shell.php --host 127.0.0.1 --port 8091 --cmd 'id > /tmp/pwned'
```

Exit codes on check-site.php: `0` patched/out of range, `1` vulnerable, `3`
unreachable. Treat `1` as the actionable one.

## Gotchas that cost us time

- **PHP getopt stops at the first positional.** Every argument to
  php2shell.php must be an `--option`. `php2shell.php 'id' --host …` will
  silently drop every option after the positional. Use `--cmd '…'`.
- **Containerized labs and loopback.** If you run check-site.php from inside
  a container against a host-published port, `127.0.0.1` is the container
  itself. Use the container's bridge IP (e.g. `172.17.0.x`) instead.
- **Worker detection reads /proc/PID/cmdline**, which is NUL-separated, not
  space-separated. Plain `strpos($cl, "apache2 -DFOREGROUND")` matches
  nothing. Normalize the NULs first (php2shell.php already does).
- **Offsets are version- and arch-specific.** The defaults are for
  PHP 8.5.11 arm64; x86_64 values are in docs/RESULTS.md. For anything else,
  derive your own with `tools/derive-offsets.sh` and pass them as
  `--offsets '{...}'`. Wrong offsets = no crash, no error, no hint.
- **Part count drives the OOM, not bytes.** A flood of ~1000 parts and 0.25 MB
  of filler triggers the in-band OOM; 500 parts with 1 MB does not. If your
  calibration refuses to produce a stale reference, add parts before you add
  bytes.
- **Saturation beats roulette.** Pinning a stale worker via slow GETs gives a
  first-try hit. Unpinned multi-worker runs land roughly 1-in-5 and each miss
  is a loud (crashed) request. Read docs/BYPASS.md §7 for the full comparison.

## If a run "fails" silently

Wrong offsets are the usual suspect — the chain has no error path for them.
Second suspect: your lab has a worker pool and you didn't pin, so A2 and B3
landed on different workers. Third: the flood was below the OOM floor, which
the tool warns about in-band. Work through those before touching the code.
