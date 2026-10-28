# Measured results

Every run below was executed on this repo's tooling against a local lab
container. Nothing here is projected or assumed; each line is a real run.
Host: Raspberry Pi 5, aarch64, Debian, docker. Image: `php:8.5.11-apache`
(Apache 2.4.69, mod_php 8.5.11, prefork). Ingress: nginx 1.27 default
config unless noted.

"cal tries" is how many calibration B3 requests were needed before one
landed on the worker holding the stale reference. "payload tries" is the
same for the payload B3. Fewer is more deterministic.

## Baseline: single worker

| config | flood | cal tries | payload tries | RCE |
|---|---|---|---|---|
| mpm-single, ASLR off (setarch -R) | 1 MiB / 4000 parts | 1 | 1 | yes |
| mpm-single, ASLR ON | 1 MiB / 4000 parts | 1 | 1 | yes |
| mpm-single, ASLR ON | 0.25 MiB / 1000 parts | 1 | 1 | yes |

With one worker there is no roulette. The chain is deterministic in every
ASLR state. The stale reference landed at page offset 0x220 and the covering
spray index was 39 in all runs, matching the original x86_64 research.

## Multi-worker, no holds (worker roulette)

| pool | flood | cal tries | payload tries | RCE | wasted requests |
|---|---|---|---|---|---|
| 5 idle workers | 1 MiB / 4000 | 5 | 5 | yes | 8 |
| 5 idle workers (repeat, ASLR on) | 0.5 MiB / 2000 | 5 | 5 | yes | 8 |
| 20 idle workers (kept alive) | 1 MiB / 4000 | 20 | 20 | yes | 38 |

The 20-worker run is the clean measurement: 20 workers, hit at exactly try
20 in both phases. That is the 1-in-N geometric distribution doing what it
says on the tin. The stale reference persists in its worker for as long as
the worker lives, so brute force always eventually works; the cost is that
every miss is a full-size request on the ingress, visible in logs and
rate-limitable.

## Multi-worker with pool saturation (the fix)

Holds: 9 concurrent GETs to `slow.php` (sleep 25), pinning 9 of 10 children
so exactly one stays free. The chain then runs inside that window.

| pool | flood | cal tries | payload tries | RCE |
|---|---|---|---|---|
| 10 workers, ASLR off | 1 MiB / 4000 | 1 | 1 | yes |
| 10 workers, ASLR ON | 1 MiB / 4000 | 1 | 1 | yes |
| 10 workers, ASLR ON, shrunk B3 (48 values) | 0.25 MiB / 1000 | 1 | 1 | yes |

Three runs, three first-try hits. Saturation converts the multi-worker case
into the single-worker case.

## Flood size sweep (what actually triggers the OOM)

| parts | block size | filler to 1 MiB? | OOM |
|---|---|---|---|
| 4000 | 1 MiB | - | yes |
| 2000 | 0.5 MiB | - | yes |
| 1000 | 0.25 MiB | - | yes |
| 850 | 0.22 MiB | - | yes |
| 750 | 0.2 MiB | - | no |
| 500 | 1 MiB | yes | no |
| 500 | 0.125 MiB | - | no |
| 64, 32, 16, 8, 4, 2, 1 | 16 KB to 1 KB | - | no |

Two conclusions. The part count is the driver; 1 MiB of filler with only
500 parts never OOMs, while 1000 parts with a 0.25 MiB block does. And the
common 1 MiB / 4000-part shape is roughly 4x oversized for a 128M
`memory_limit`. We ship 1000 parts as the default: confirmed working with
margin, small enough to pass a stock nginx body limit.

The single sprayed part uses a 62-level nested field name
(`a[][a]` repeated); parsing multiplies array work per level, which is where
the memory goes.

## Pool size vs what Apache keeps alive

A container configured with `ServerLimit 20` but `MaxSpareServers 5` ran
with only 5 idle workers under light load. Apache kills spare children
down to the configured spare ceiling, so the roulette you face is the
number of *currently idle* workers, not the configured maximum. The
effective N on a quiet default install is small, which makes brute force
more practical than the config implies, and saturation easier to hold.

## Harness bugs found while measuring (kept for honesty)

- A first flood sweep reported "OOM with 1 nested part". That was a harness
  bug: PHP's `getopt()` stops at the first positional argument, so every
  flag after the positional command was silently ignored and every run had
  actually used the default 1 MiB / 4000-part flood. The tool now takes
  everything as long options (use `--cmd '...'`) and the sweep above was
  rerun with the flags verified. The correct floor is between 750 and 850
  parts.
- An early saturation test failed because the hold requests dribbled a body
  through nginx, which buffers request bodies by default: the Apache
  children stayed free and nothing was pinned. Holds must be requests the
  backend processes slowly (the `slow.php` endpoint, or any slow endpoint
  the target really has), not slow uploads.
- A kill-and-respawn variant (OOM the only free child, wait for Apache's
  replacement) works but is unnecessary: Apache only respawns under spawn
  pressure, and the per-request chunk reset already makes layout
  deterministic. Pinning the pool is simpler and was the shape that
  measured 1/1.

## Negative tests

- Unreachable ingress host: connection failure surfaced as
  `CONNFAIL:<reason>`, no crash.
- Malformed `--offsets` JSON: clear error, exit 2, no crash.
- Flood too small: in-band warning, clean exit 2, no crash.
- `--check` validates the multipart wire shape against the lab before any
  exploit traffic.
