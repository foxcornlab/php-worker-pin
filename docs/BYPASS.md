# Multi-worker pools and the php2shell chain

The published reproductions of CVE-2026-109618 / CVE-2026-109619 run against
a single prefork worker. That works because with `MaxRequestWorkers 1` both
requests are guaranteed to hit the same process, and the stale reference
lives in per-worker persistent memory. Real hosts run pools. This document
is the analysis and the measurements for the pool case.

## Why it looks blocked

The chain needs A2 and B3 on the same worker. With N workers and stock
nginx, every proxied request opens a fresh upstream connection, Apache
hands it to whichever child is free, and you cannot choose which one. Two
people testing this independently landed on the same wall and described it
the same way: worker roulette on a pool you cannot pin.

The tempting next step is OOM-killing children and racing the respawn. That
works but is the wrong shape. Apache's master only spawns replacements
under spawn pressure; with an idle pool it just shrinks. And you do not
need a fresh worker at all.

## The insight: freshness is not required

The main 2 MiB ZendMM chunk resets at every request boundary. The B3 spray
therefore carves a deterministic layout per request, on any worker, at any
worker age. The only per-worker precondition is that the stale reference
exists in that worker's `ps_globals`. So the real requirement is one
sentence:

> A2 and B3 must be served by the same worker. Which worker, and how old
> it is, does not matter.

## Pinning the pool without config access

MaxRequestWorkers 1 is just the degenerate case of "exactly one free
child". You can create that condition at runtime:

1. Send N-1 requests that keep N-1 children busy for a known duration.
   Any backend-slow endpoint works: a slow CGI, a report endpoint, or the
   chain's own heavy requests. Do not rely on slow request *bodies*; nginx
   buffers them by default and the children stay free. The hold has to be
   slow *processing*.
2. While the pool is saturated, A2 lands on the only free child. After A2
   returns, that child is free again and still the only one.
3. Calibration B3 and payload B3 follow, both landing on the same worker.

This was measured three times on a 10-worker pool through nginx: first-try
calibration and first-try payload every time, on two ASLR states. Without
the holds the same setup needed 5 tries per phase; on a 20-worker idle pool,
20 tries per phase. The 1-in-N law holds exactly.

## Honest failure modes

- If the pool has 2 free children, A2 can land on one and B3 on the other.
  Saturate properly, count your holds.
- The stale reference persists but not forever: any request that lands on
  the stale worker and reaches `php_session_track_init()` dtors the old
  reference before publishing a new one. Heavy retry traffic can churn the
  state you are trying to reuse. Pin, then move.
- Apache `MaxConnectionsPerChild` / `MaxRequestsPerChild` recycles workers
  and destroys the stale state. Check the target's defaults (Debian ships
  0, some distros ship 4000).
- A queueing target under your hold traffic may alert. Saturation traffic
  is N-1 slow requests; that is visible, and defenders should treat a
  pool-wide slow-request wave followed by two oversized multipart POSTs as
  exactly what it looks like.

## For defenders

The chain becomes multi-worker-viable with nothing but ordinary traffic
shapes: one wave of slow requests, then two large multipart POSTs. The
signals are the pairing: a slow-request wave immediately followed by
multipart bodies just under your body limit, repeated against the same
endpoint. Upgrade to the fixed PHP versions first; pinning detection second.
