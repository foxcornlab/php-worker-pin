<?php
/**
 * check-site.php — passive vulnerability check for the PHP OOM bug
 * (CVE-2026-109618 / CVE-2026-109619).
 *
 * Sends ONE GET request to the given URL, reads response headers and the
 * page's generator meta, and produces a verdict plus remediation steps.
 * It never sends multipart, oversized, or exploit-shaped traffic. It is
 * meant for a site owner, or an agent working for one, to learn whether
 * the site's PHP runtime is affected and what to upgrade to.
 *
 * usage: php check-site.php --url https://shop.example.com [--json] [--timeout 10]
 */
error_reporting(E_ALL & ~E_DEPRECATED);

$OPTS = getopt('', array('url:', 'json', 'timeout:', 'help'));
if (isset($OPTS['help']) || !isset($OPTS['url'])) {
  echo "usage: php check-site.php --url https://site.example [options]\n"
     . "  --url       site to check (GET request only, no exploit traffic)\n"
     . "  --json      machine-readable report\n"
     . "  --timeout N seconds (default 10)\n";
  exit(isset($OPTS['url']) ? 0 : 2);
}
$URL = (string)$OPTS['url'];
$TIMEOUT = isset($OPTS['timeout']) ? (int)$OPTS['timeout'] : 10;

if (!preg_match('#^https?://#i', $URL)) $URL = 'https://' . $URL;

/* the branch -> first fixed version table from the advisories */
$FIXED = array('8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12');
$GHSAS = array(
  'GHSA-w8hw-w9fx-j79w (CVE-2026-109618, OOM corruption)',
  'GHSA-6wmf-4rv5-p3rp (CVE-2026-109619, stale global state)',
);

function fetch($url, $timeout) {
  $ctx = stream_context_create(array('http' => array(
    'method' => 'GET',
    'timeout' => $timeout,
    'user_agent' => 'php-worker-pin-checker/1.0 (site owner vulnerability check)',
    'follow_location' => 1,
    'max_redirects' => 3,
    'ignore_errors' => true,
  )));
  $body = @file_get_contents($url, false, $ctx);
  $head = $http_response_header ?? array();
  return array($head, $body === false ? '' : $body);
}
function header_value(array $head, $name) {
  foreach ($head as $h) {
    if (stripos($h, $name . ':') === 0) return trim(substr($h, strlen($name) + 1));
  }
  return null;
}

list($head, $body) = fetch($URL, $TIMEOUT);
if (empty($head)) {
  $msg = "could not reach $URL";
  if (isset($OPTS['json'])) {
    echo json_encode(array('url' => $URL, 'error' => $msg), JSON_PRETTY_PRINT), "\n";
  } else {
    echo "[!] $msg\n";
  }
  exit(3);
}

$status = 0;
if (preg_match('#HTTP/\S+\s+(\d{3})#', $head[0], $m)) $status = (int)$m[1];
$xpb = header_value($head, 'X-Powered-By');
$server = header_value($head, 'Server');

$php_raw = null; $php_ver = null;
if ($xpb && preg_match('#PHP/(\d+\.\d+(?:\.\d+)?)#i', $xpb, $m)) {
  $php_raw = trim($xpb);
  $php_ver = $m[1];
}

/* generator meta (WordPress, and other CMSes, declare it) */
$wp = false; $wp_ver = null; $generator = null;
if (preg_match('#<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']#i', $body, $m)) {
  $generator = $m[1];
  if (stripos($generator, 'WordPress') !== false) {
    $wp = true;
    if (preg_match('#(\d+\.\d+(?:\.\d+)?)#', $generator, $v)) $wp_ver = $v[1];
  }
} elseif (stripos($body, 'wp-content') !== false) {
  $wp = true;
}

/* verdict */
$verdict = 'UNKNOWN'; $fixed_in = null; $branch = null;
$detail = '';
if ($php_ver) {
  if (preg_match('/^(\d+)\.(\d+)(?:\.(\d+))?/', $php_ver, $v)) {
    $branch = $v[1] . '.' . $v[2];
    $patch = isset($v[3]) ? $v[3] : '0';
    $full = $v[1] . '.' . $v[2] . '.' . $patch;
    if (isset($FIXED[$branch])) {
      $fixed_in = $FIXED[$branch];
      $verdict = version_compare($full, $fixed_in, '<') ? 'VULNERABLE' : 'PATCHED';
      $detail = "branch $branch, fixed in $fixed_in";
    } elseif (version_compare($branch, '8.2', '<')) {
      $verdict = 'END-OF-LIFE';
      $detail = "PHP $branch no longer receives security fixes; upgrade to a supported branch";
    } else {
      $verdict = 'UNKNOWN-BRANCH';
      $detail = "branch $branch is newer than this checker's table; verify against the advisories";
    }
  }
} else {
  $detail = "the PHP version is not visible in response headers (expose_php may be off). "
          . "verify on the server with: php -v";
}

$remediation = array();
if ($verdict === 'VULNERABLE' || $verdict === 'END-OF-LIFE') {
  $remediation[] = "Upgrade PHP to at least " . ($fixed_in ?: '8.3.36')
                 . " (the advisories are fixed in 8.5.12, 8.4.27, 8.3.36, 8.2.35).";
  $remediation[] = "If the upgrade must wait: set session.upload_progress.enabled=0 "
                 . "in php.ini — it removes the code path this bug needs.";
  $remediation[] = "Keep max_multipart_body_parts finite (e.g. 100) instead of unlimited.";
  $remediation[] = "At a WAF or reverse proxy, reject multipart bodies whose field names "
                 . "nest many array levels (repeated [] or [a] groups) — the OOM trigger "
                 . "is a few hundred nested parts, not raw size.";
  $remediation[] = "Alert on 'Allowed memory size ... exhausted' errors during multipart "
                 . "parsing; that is the in-band signature.";
}
if ($wp) {
  $remediation[] = "WordPress note: the PHP runtime comes from your hosting, not from "
                 . "WordPress core. Upgrade PHP in the hosting panel (or your server's "
                 . "packages), then confirm under Tools > Site Health > Server.";
}

$report = array(
  'url' => $URL,
  'http_status' => $status,
  'server' => $server,
  'php' => array(
    'raw_header' => $php_raw,
    'version' => $php_ver,
    'branch' => $branch,
    'verdict' => $verdict,
    'detail' => $detail,
    'fixed_in' => $fixed_in,
  ),
  'wordpress' => array(
    'detected' => $wp,
    'version' => $wp_ver,
    'generator' => $generator,
  ),
  'exploit_prerequisite' =>
    'the published RCE chain needs privileged access inside the target '
    . 'machine (worker memory access). Detection and remediation are the '
    . 'actions that make sense for a web-facing site.',
  'remediation' => $remediation,
  'references' => $GHSAS,
);

if (isset($OPTS['json'])) {
  echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
  exit($verdict === 'VULNERABLE' || $verdict === 'END-OF-LIFE' ? 1 : 0);
}

echo "url:     {$report['url']}\n";
echo "status:  $status\n";
echo "server:  " . ($server ?: '-') . "\n";
echo "php:     " . ($php_ver ?: 'not disclosed in headers') . "\n";
echo "verdict: $verdict" . ($detail ? " ($detail)" : '') . "\n";
if ($wp) echo "cms:     WordPress" . ($wp_ver ? " $wp_ver" : '') . "\n";
if ($remediation) {
  echo "\nrecommended fixes:\n";
  foreach ($remediation as $i => $r) echo '  ' . ($i + 1) . ". $r\n";
}
echo "\nreferences: " . implode('; ', $GHSAS) . "\n";
exit($verdict === 'VULNERABLE' || $verdict === 'END-OF-LIFE' ? 1 : 0);
