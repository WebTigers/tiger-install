<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * tiger-install.php — the one-file Tiger web installer.
 *
 * Drop this single file into a domain's document root (e.g. public_html/) and open it in a
 * browser. It:
 *   1. checks your host meets Tiger's requirements,
 *   2. downloads the latest Tiger release ZIP from GitHub (verified against its .sha256),
 *   3. extracts the app ABOVE the document root (so your secrets are never web-reachable),
 *   4. writes only a tiny shim + asset links into the document root,
 *   5. writes your DB settings + minted secrets into local.ini (above the docroot, chmod 600),
 *   6. builds the schema and creates your admin account,
 *   7. deletes itself.
 *
 * You create the empty MySQL database + user in cPanel first (a normal DB account can't create
 * one from PHP); the installer does everything else. It supports domain-namespaced multi-domain
 * cPanel accounts: each domain becomes its own self-contained install.
 *
 * This file is intentionally dependency-free, pre-bootstrap PHP — Tiger isn't installed yet. Once
 * the code is extracted it bootstraps Tiger and calls the platform's OWN installer (Tiger_Install)
 * so nothing here re-implements migrations, secrets, or admin creation.
 *
 * Repo: https://github.com/WebTigers/tiger-install  (evergreen — one file, resolves the latest release)
 */

error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);
@ini_set('display_errors', '1');
@set_time_limit(0);

const INSTALLER_VERSION = '1.0.0';
const RELEASE_REPO      = 'webtigers/tiger';   // the skeleton repo whose releases host the full-app bundle
const MIN_PHP           = '8.1.0';
const GH_API            = 'https://api.github.com';

@session_start();

/* ---------------------------------------------------------------------------
 * Tiny helpers
 * ------------------------------------------------------------------------- */

function h($s) { return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8'); }
function post($k, $d = '') { return isset($_POST[$k]) ? trim((string) $_POST[$k]) : $d; }
function req($k, $d = '') { return isset($_REQUEST[$k]) ? trim((string) $_REQUEST[$k]) : $d; }

/** A single-use-ish CSRF token bound to the session. */
function csrf_token() {
    if (empty($_SESSION['tiger_install_csrf'])) {
        $_SESSION['tiger_install_csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['tiger_install_csrf'];
}
function csrf_ok() {
    return isset($_SESSION['tiger_install_csrf'])
        && hash_equals($_SESSION['tiger_install_csrf'], (string) post('_csrf'));
}

/** Detect the cPanel account home reliably (POSIX first — correct even for addon docroots). */
function detect_home($docroot) {
    if (function_exists('posix_getpwuid') && function_exists('posix_getuid')) {
        $pw = @posix_getpwuid(@posix_getuid());
        if (!empty($pw['dir']) && is_dir($pw['dir'])) { return rtrim($pw['dir'], '/'); }
    }
    // Fallback: /home/<user> pattern walk.
    $p = rtrim((string) $docroot, '/');
    while ($p && $p !== '/' && dirname($p) !== '/home' && basename(dirname($p)) !== 'home') {
        $parent = dirname($p);
        if ($parent === $p) { break; }
        $p = $parent;
    }
    return ($p && dirname($p) !== '' && is_dir($p)) ? $p : dirname((string) $docroot);
}

/** The docroot this installer is serving from (it lives IN the docroot). */
function detect_docroot() {
    $dir = @realpath(__DIR__);
    return $dir ?: rtrim((string) ($_SERVER['DOCUMENT_ROOT'] ?? getcwd()), '/');
}

/** The domain being served, sanitized for use in a path. */
function detect_domain() {
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    $host = preg_replace('/:\d+$/', '', $host);                 // strip port
    $host = preg_replace('/[^a-z0-9.\-]/i', '', strtolower($host));
    return $host !== '' ? $host : 'site';
}

/** GET a URL as a string (cURL, else stream). Returns [body, httpCode] or [null, 0] on failure. */
function http_get($url, $accept = null) {
    $ua = 'tiger-install/' . INSTALLER_VERSION;
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $headers = ['User-Agent: ' . $ua];
        if ($accept) { $headers[] = 'Accept: ' . $accept; }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => 120,
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $body === false ? [null, 0] : [$body, $code];
    }
    if (ini_get('allow_url_fopen')) {
        $ctx = stream_context_create(['http' => ['header' => "User-Agent: {$ua}\r\n" . ($accept ? "Accept: {$accept}\r\n" : '')],
                                      'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $body = @file_get_contents($url, false, $ctx);
        return $body === false ? [null, 0] : [$body, 200];
    }
    return [null, 0];
}

/** Download a URL to a local file (streamed). Returns true on success. */
function http_download($url, $dest) {
    $ua = 'tiger-install/' . INSTALLER_VERSION;
    if (function_exists('curl_init')) {
        $fp = @fopen($dest, 'wb');
        if (!$fp) { return false; }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FILE => $fp, CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => ['User-Agent: ' . $ua], CURLOPT_TIMEOUT => 600,
        ]);
        $ok = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        fclose($fp);
        return $ok !== false && $code < 400 && filesize($dest) > 0;
    }
    if (ini_get('allow_url_fopen')) {
        $ctx = stream_context_create(['http' => ['header' => "User-Agent: {$ua}\r\n"],
                                      'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $data = @file_get_contents($url, false, $ctx);
        return $data !== false && @file_put_contents($dest, $data) !== false;
    }
    return false;
}

/** Recursively copy a directory tree. */
function rcopy($src, $dst) {
    $src = rtrim($src, '/'); $dst = rtrim($dst, '/');
    if (is_link($src)) { @symlink(readlink($src), $dst); return; }
    if (is_dir($src)) {
        @mkdir($dst, 0755, true);
        foreach (scandir($src) as $f) {
            if ($f === '.' || $f === '..') { continue; }
            rcopy("$src/$f", "$dst/$f");
        }
        return;
    }
    @copy($src, $dst);
}

/* ---------------------------------------------------------------------------
 * Preflight
 * ------------------------------------------------------------------------- */

function preflight($docroot, $home) {
    $checks = [];
    $add = function ($label, $ok, $hard, $detail, $fix = '') use (&$checks) {
        $checks[] = compact('label', 'ok', 'hard', 'detail', 'fix');
    };
    $add('PHP ' . MIN_PHP . '+', version_compare(PHP_VERSION, MIN_PHP, '>='), true,
        'You have PHP ' . PHP_VERSION, 'Set the PHP version in cPanel → MultiPHP Manager / Select PHP Version.');
    $add('pdo_mysql', extension_loaded('pdo_mysql'), true, 'MySQL database driver',
        'Enable pdo_mysql in cPanel → Select PHP Version → Extensions.');
    $add('zip (ZipArchive)', class_exists('ZipArchive'), true, 'To extract the download',
        'Enable the zip extension in cPanel → Select PHP Version → Extensions.');
    $add('curl or allow_url_fopen', function_exists('curl_init') || ini_get('allow_url_fopen'), false,
        'To download Tiger (manual upload offered if missing)', 'Enable curl, or upload the ZIP manually.');
    $add('mbstring', extension_loaded('mbstring'), true, 'UTF-8 text handling', 'Enable mbstring.');
    $add('openssl', extension_loaded('openssl'), true, 'HTTPS/TLS + secure tokens',
        'Enable openssl in cPanel → Select PHP Version → Extensions.');
    // sodium is OPTIONAL: tiger-core bundles paragonie/sodium_compat (a pure-PHP libsodium polyfill),
    // so Tiger_Crypto runs without the extension. Native ext-sodium is just faster when present.
    $add('sodium (libsodium)', extension_loaded('sodium') || function_exists('sodium_crypto_secretbox'), false,
        'Native-speed crypto (optional) — a pure-PHP polyfill is bundled, so Tiger runs without it',
        'Optional: enable sodium in Select PHP Version → Extensions for faster crypto.');
    $add('Home dir writable', is_writable($home), true, h($home) . ' — where the app is placed',
        'PHP must run as your cPanel user (it does on modern hosts).');
    $add('Docroot writable', is_writable($docroot), true, h($docroot) . ' — for the shim + assets',
        'Fix file ownership/permissions on the document root.');
    $add('symlink()', function_exists('symlink'), false, 'Asset links (a copy fallback is used otherwise)',
        'Optional — ask your host to allow symlink().');
    return $checks;
}

/* ---------------------------------------------------------------------------
 * Release resolution + download
 * ------------------------------------------------------------------------- */

/** Resolve the release + the full-app asset. Returns [tag, zipUrl, shaUrl, error]. */
function resolve_release($version = '') {
    if ($version !== '') {
        list($body, $code) = http_get(GH_API . '/repos/' . RELEASE_REPO . '/releases/tags/' . rawurlencode($version), 'application/vnd.github+json');
        if ($body === null || $code >= 400) {
            return [null, null, null, "Couldn't find release {$version} on GitHub (HTTP {$code}). Use manual upload below."];
        }
        $releases = [json_decode($body, true)];
    } else {
        // NOT /releases/latest — that endpoint SKIPS pre-releases, and a beta ships pre-releases.
        // List recent releases (newest first) and take the first that actually carries our bundle.
        list($body, $code) = http_get(GH_API . '/repos/' . RELEASE_REPO . '/releases?per_page=20', 'application/vnd.github+json');
        if ($body === null || $code >= 400) {
            return [null, null, null, "Couldn't reach GitHub to find a release (HTTP {$code}). Use manual upload below."];
        }
        $releases = json_decode($body, true);
        if (!is_array($releases)) { $releases = []; }
    }

    foreach ($releases as $rel) {
        if (!is_array($rel) || !empty($rel['draft']) || empty($rel['assets'])) { continue; }
        $tag = (string) ($rel['tag_name'] ?? '');
        $zipUrl = $shaUrl = null; $zipName = '';
        foreach ($rel['assets'] as $a) {
            $name = (string) ($a['name'] ?? '');
            // Full-app bundle: tiger-<version>.zip — NOT the vendor-only tiger-core-vendored-*.zip.
            if ($zipUrl === null && preg_match('/^tiger-\d[\w.\-]*\.zip$/', $name) && strpos($name, 'core-vendored') === false) {
                $zipUrl = (string) $a['browser_download_url']; $zipName = $name;
            }
        }
        if ($zipUrl === null) { continue; }
        foreach ($rel['assets'] as $a) {
            if ((string) ($a['name'] ?? '') === $zipName . '.sha256') { $shaUrl = (string) $a['browser_download_url']; }
        }
        return [$tag, $zipUrl, $shaUrl, null];
    }
    return [null, null, null, 'No installable full-app bundle (tiger-<version>.zip) found on a recent release yet. Use manual upload below.'];
}

/* ---------------------------------------------------------------------------
 * Rendering
 * ------------------------------------------------------------------------- */

function page($title, $body) {
    $csrf = csrf_token();
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width, initial-scale=1">'
       . '<title>' . h($title) . ' — Tiger Installer</title><style>'
       . ':root{--bg:#0f1216;--card:#171b21;--ink:#e8eaed;--mut:#9aa4b2;--line:#2a2f37;--brand:#f59e0b;--ok:#22c55e;--bad:#ef4444;--warn:#eab308}'
       . '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}'
       . '.wrap{max-width:760px;margin:0 auto;padding:32px 20px 64px}h1{font-size:1.5rem;margin:.2em 0}h2{font-size:1.1rem}'
       . '.brand{display:flex;align-items:center;gap:10px;color:var(--brand);font-weight:700;letter-spacing:.02em}'
       . '.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:18px 0}'
       . '.mut{color:var(--mut)}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:7px 6px;border-bottom:1px solid var(--line);vertical-align:top}'
       . '.pill{font-size:.72rem;font-weight:700;padding:2px 8px;border-radius:99px}.p-ok{background:rgba(34,197,94,.15);color:var(--ok)}'
       . '.p-bad{background:rgba(239,68,68,.15);color:var(--bad)}.p-warn{background:rgba(234,179,8,.15);color:var(--warn)}'
       . 'label{display:block;margin:12px 0 4px;font-weight:600}input[type=text],input[type=password],input[type=email]{width:100%;padding:10px 12px;'
       . 'background:#0d1014;border:1px solid var(--line);border-radius:8px;color:var(--ink);font:inherit}'
       . 'code{background:#0d1014;border:1px solid var(--line);border-radius:5px;padding:1px 6px;font-size:.85em}'
       . '.btn{display:inline-block;margin-top:18px;background:var(--brand);color:#1a1205;border:0;border-radius:8px;padding:11px 22px;font:inherit;font-weight:700;cursor:pointer}'
       . '.btn.sec{background:transparent;color:var(--ink);border:1px solid var(--line)}'
       . '.note{border-left:3px solid var(--brand);padding:8px 12px;background:rgba(245,158,11,.06);border-radius:0 8px 8px 0;margin:12px 0}'
       . '.bad{border-left-color:var(--bad);background:rgba(239,68,68,.07)}.ok{border-left-color:var(--ok);background:rgba(34,197,94,.07)}'
       . 'ol.steps{counter-reset:s;list-style:none;padding:0;display:flex;gap:8px;flex-wrap:wrap;margin:0 0 8px}ol.steps li{color:var(--mut);font-size:.8rem}'
       . 'ol.steps li.on{color:var(--brand);font-weight:700}'
       . '</style></head><body><div class="wrap">'
       . '<div class="brand"><span style="font-size:1.4rem">&#128062;</span> Tiger Installer <span class="mut" style="font-weight:400">v' . INSTALLER_VERSION . '</span></div>'
       . $body
       . '<p class="mut" style="margin-top:28px;font-size:.8rem">One file, nothing more. Downloads &amp; verifies the latest Tiger release, installs it above your document root, then deletes itself.</p>'
       . '</div></body></html>';
}

function steps_nav($active) {
    $steps = ['welcome' => 'Requirements', 'paths' => 'Location', 'files' => 'Download', 'db' => 'Database', 'admin' => 'Admin'];
    $out = '<ol class="steps">';
    foreach ($steps as $k => $v) { $out .= '<li class="' . ($k === $active ? 'on' : '') . '">' . h($v) . '</li>'; }
    return $out . '</ol>';
}

function hidden($fields) {
    $out = '<input type="hidden" name="_csrf" value="' . h(csrf_token()) . '">';
    foreach ($fields as $k => $v) { $out .= '<input type="hidden" name="' . h($k) . '" value="' . h($v) . '">'; }
    return $out;
}

/* ---------------------------------------------------------------------------
 * Controller
 * ------------------------------------------------------------------------- */

$docroot = detect_docroot();
$home    = detect_home($docroot);
$domain  = detect_domain();
$step    = req('step', 'welcome');

// CSRF gate for every POST that mutates.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !csrf_ok()) {
    page('Session expired', '<div class="card"><div class="note bad">Your session expired. <a href="?" style="color:var(--brand)">Start over</a>.</div></div>');
    exit;
}

switch ($step) {

/* --- 1) Welcome + preflight --------------------------------------------- */
case 'welcome':
default:
    $checks = preflight($docroot, $home);
    $blocked = false;
    $rows = '';
    foreach ($checks as $c) {
        $pill = $c['ok'] ? '<span class="pill p-ok">PASS</span>'
             : ($c['hard'] ? '<span class="pill p-bad">FAIL</span>' : '<span class="pill p-warn">WARN</span>');
        if (!$c['ok'] && $c['hard']) { $blocked = true; }
        $rows .= '<tr><td>' . $pill . '</td><td><strong>' . h($c['label']) . '</strong><br><span class="mut">'
              . $c['detail'] . '</span>' . ((!$c['ok']) ? '<br><span class="mut" style="font-size:.85em">&rarr; ' . h($c['fix']) . '</span>' : '')
              . '</td></tr>';
    }
    $body = steps_nav('welcome')
        . '<h1>Install Tiger</h1><p class="mut">This checks your hosting, then installs Tiger in a few clicks — '
        . 'the app and your secrets go <strong>above</strong> your web root, unlike the old <code>wp-config.php</code> way.</p>'
        . '<div class="card"><h2>Requirements</h2><table>' . $rows . '</table></div>';
    if ($blocked) {
        $body .= '<div class="note bad">Fix the <strong>FAIL</strong> items in cPanel, then reload this page.</div>';
    } else {
        $body .= '<form method="post">' . hidden(['step' => 'paths']) . '<button class="btn">Continue &rarr;</button></form>';
    }
    page('Requirements', $body);
    break;

/* --- 2) Choose install location ----------------------------------------- */
case 'paths':
    $defaultApp = $home . '/' . $domain . '/tiger-app';
    $body = steps_nav('paths')
        . '<h1>Where Tiger goes</h1>'
        . '<div class="card"><table>'
        . '<tr><td class="mut">Domain</td><td><strong>' . h($domain) . '</strong></td></tr>'
        . '<tr><td class="mut">Document root</td><td><code>' . h($docroot) . '</code><br><span class="mut" style="font-size:.85em">detected — the only web-reachable folder</span></td></tr>'
        . '<tr><td class="mut">Account home</td><td><code>' . h($home) . '</code></td></tr>'
        . '</table></div>'
        . '<form method="post">' . hidden(['step' => 'files', 'docroot' => $docroot])
        . '<div class="card"><h2>Application folder (above the web root)</h2>'
        . '<p class="mut">Your code + <code>local.ini</code> live here, safely out of the web root. The default is '
        . 'domain-namespaced so multiple domains never collide.</p>'
        . '<label for="app_dir">App folder</label><input id="app_dir" type="text" name="app_dir" value="' . h($defaultApp) . '">'
        . '<div class="note">Running several domains on this account? Each gets its own folder like '
        . '<code>' . h($home) . '/&lt;domain&gt;/tiger-app</code> and its own database — fully independent installs.</div>'
        . '</div><button class="btn">Download &amp; install files &rarr;</button></form>';
    page('Location', $body);
    break;

/* --- 3) Download + extract + wire the docroot --------------------------- */
case 'files':
    $appDir  = post('app_dir');
    $docroot = post('docroot', $docroot);
    $version = req('version', '');
    $err = '';

    if ($appDir === '' || $appDir[0] !== '/') {
        $err = 'Please provide an absolute app folder path.';
    } elseif (is_file($appDir . '/application/configs/local.ini')
              && preg_match('/tiger\.db\.dbname\s*=\s*"?\S/', (string) @file_get_contents($appDir . '/application/configs/local.ini'))) {
        $err = 'Tiger already appears to be installed at ' . h($appDir) . ' (a configured local.ini exists). Refusing to overwrite.';
    }

    if ($err === '') {
        @mkdir($appDir, 0755, true);
        $tmp = $home . '/.tiger-install-tmp';
        @mkdir($tmp, 0700, true);

        // Prefer a manually-uploaded ZIP; else resolve + download from GitHub.
        $zipPath = $tmp . '/tiger.zip';
        if (!empty($_FILES['bundle']['tmp_name']) && is_uploaded_file($_FILES['bundle']['tmp_name'])) {
            @move_uploaded_file($_FILES['bundle']['tmp_name'], $zipPath);
        } else {
            list($tag, $zipUrl, $shaUrl, $rerr) = resolve_release($version);
            if ($rerr) { $err = $rerr; }
            elseif (!http_download($zipUrl, $zipPath)) { $err = 'Download failed. Try the manual upload below.'; }
            elseif ($shaUrl) {
                list($shaBody,) = http_get($shaUrl);
                $expected = $shaBody ? strtolower(trim(preg_split('/\s+/', trim($shaBody))[0])) : '';
                $actual   = strtolower(hash_file('sha256', $zipPath));
                if ($expected && !hash_equals($expected, $actual)) {
                    $err = 'Checksum mismatch — the download may be corrupt or tampered. Aborting.';
                }
            }
        }
    }

    // Extract.
    if ($err === '' && is_file($zipPath)) {
        $ex = $tmp . '/extract';
        @mkdir($ex, 0755, true);
        $za = new ZipArchive();
        if ($za->open($zipPath) !== true) { $err = 'Could not open the downloaded ZIP.'; }
        else { $za->extractTo($ex); $za->close();
            // Flatten a single wrapper dir if present.
            $rootSrc = $ex;
            $entries = array_values(array_diff(scandir($ex), ['.', '..']));
            if (count($entries) === 1 && is_dir($ex . '/' . $entries[0]) && !is_dir($ex . '/application')) {
                $rootSrc = $ex . '/' . $entries[0];
            }
            if (!is_dir($rootSrc . '/application') || !is_dir($rootSrc . '/vendor')) {
                $err = 'The downloaded bundle is missing application/ or vendor/ — expected a vendored full-app ZIP.';
            } else {
                rcopy($rootSrc, $appDir);
            }
        }
    }

    // Wire the docroot: custom shim + .htaccess + asset links.
    if ($err === '') {
        $autoload = $appDir . '/vendor/autoload.php';
        if (!is_file($autoload)) { $err = 'Extraction incomplete (no vendor/autoload.php).'; }
        else {
            // Custom shim with an explicit APPLICATION_ROOT (Layout B — docroot stays put).
            $shim = "<?php\n"
                  . "// Generated by tiger-install.php — Tiger front controller shim.\n"
                  . "define('APPLICATION_ROOT', " . var_export($appDir, true) . ");\n"
                  . "require APPLICATION_ROOT . '/vendor/autoload.php';\n"
                  . "(new Tiger_Application(APPLICATION_ROOT))->run();\n";
            @file_put_contents($docroot . '/index.php', $shim);
            if (is_file($appDir . '/public/.htaccess')) { @copy($appDir . '/public/.htaccess', $docroot . '/.htaccess'); }

            require $autoload;
            define('APPLICATION_ROOT', $appDir);
            try {
                Tiger_Install::provisionStorage($appDir);
                Tiger_Install::linkPublicAssets($docroot, $appDir, 'puma');
                // Also expose the writable public dirs at the docroot (split layout).
                foreach (['_media', '_code', '_modules'] as $pub) {
                    $target = $appDir . '/public/' . $pub;
                    $link   = $docroot . '/' . $pub;
                    if (is_dir($target) && !file_exists($link) && function_exists('symlink')) { @symlink($target, $link); }
                }
            } catch (Throwable $e) {
                $err = 'Placed files, but wiring assets failed: ' . $e->getMessage();
            }
        }
    }

    if ($err !== '') {
        $body = steps_nav('files')
            . '<h1>Couldn\'t install the files</h1><div class="note bad">' . h($err) . '</div>'
            . '<div class="card"><h2>Manual upload</h2><p class="mut">Download the <code>tiger-&lt;version&gt;.zip</code> from the '
            . '<a style="color:var(--brand)" href="https://github.com/' . RELEASE_REPO . '/releases/latest" target="_blank" rel="noopener">latest release</a> '
            . 'on your computer, then upload it here.</p>'
            . '<form method="post" enctype="multipart/form-data">' . hidden(['step' => 'files', 'app_dir' => $appDir, 'docroot' => $docroot])
            . '<input type="file" name="bundle" accept=".zip"><button class="btn">Upload &amp; continue &rarr;</button></form></div>';
        page('Download', $body);
        break;
    }

    // Success → DB form.
    $body = steps_nav('db')
        . '<h1>Connect your database</h1>'
        . '<div class="note ok">Tiger\'s files are installed at <code>' . h($appDir) . '</code>.</div>'
        . '<div class="card"><h2>First, create a database in cPanel</h2><ol class="mut" style="margin:0;padding-left:18px">'
        . '<li>cPanel &rarr; <strong>MySQL&reg; Databases</strong>.</li>'
        . '<li>Create a <strong>New Database</strong> (e.g. <code>tiger</code>).</li>'
        . '<li>Create a <strong>User</strong> + password, then <strong>Add User to Database</strong> with <strong>ALL PRIVILEGES</strong>.</li>'
        . '<li>Paste the resulting names below (cPanel prefixes them, e.g. <code>acct_tiger</code>).</li></ol>'
        . '<p class="mut" style="font-size:.85em;margin-top:8px">Why you do this step: a normal cPanel MySQL account can\'t create a database from PHP — only you can, in cPanel. The installer does everything else.</p></div>'
        . '<form method="post">' . hidden(['step' => 'db', 'app_dir' => $appDir, 'docroot' => $docroot])
        . '<div class="card">'
        . '<label>Database host</label><input type="text" name="db_host" value="localhost">'
        . '<label>Database name</label><input type="text" name="db_name" placeholder="acct_tiger">'
        . '<label>Database user</label><input type="text" name="db_user" placeholder="acct_tiger">'
        . '<label>Database password</label><input type="password" name="db_pass">'
        . '</div><button class="btn">Test &amp; build the database &rarr;</button></form>';
    page('Database', $body);
    break;

/* --- 4) Test DB, write config, migrate ---------------------------------- */
case 'db':
    $appDir  = post('app_dir');
    $docroot = post('docroot');
    $dbHost  = post('db_host', 'localhost');
    $dbName  = post('db_name');
    $dbUser  = post('db_user');
    $dbPass  = post('db_pass');
    $err = '';

    if ($dbName === '' || $dbUser === '') { $err = 'Database name and user are required.'; }
    elseif (strpos($dbPass, '"') !== false) { $err = 'Please use a database password without double-quote (") characters.'; }
    else {
        try {
            $dsn = 'mysql:host=' . $dbHost . ';dbname=' . $dbName . ';charset=utf8mb4';
            new PDO($dsn, $dbUser, $dbPass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 8]);
        } catch (Throwable $e) {
            $err = 'Could not connect: ' . $e->getMessage();
        }
    }

    if ($err === '') {
        // Write the DB block, then let Tiger mint secrets + migrate.
        $ini = "[production]\n"
             . 'tiger.db.host = "' . $dbHost . "\"\n"
             . 'tiger.db.dbname = "' . $dbName . "\"\n"
             . 'tiger.db.username = "' . $dbUser . "\"\n"
             . 'tiger.db.password = "' . $dbPass . "\"\n"
             . 'tiger.db.charset = "utf8mb4"' . "\n";
        $iniPath = $appDir . '/application/configs/local.ini';
        @file_put_contents($iniPath, $ini);
        @chmod($iniPath, 0600);

        require $appDir . '/vendor/autoload.php';
        if (!defined('APPLICATION_ROOT')) { define('APPLICATION_ROOT', $appDir); }
        $log = [];
        try {
            Tiger_Install::provisionSecrets($iniPath);
            (new Tiger_Application($appDir))->boot();
            $paths = [TIGER_CORE_PATH . '/migrations', APPLICATION_PATH . '/migrations'];
            foreach (glob(MODULES_PATH . '/*/migrations') ?: [] as $m) { $paths[] = $m; }
            (new Tiger_Db_Migrator(Zend_Db_Table_Abstract::getDefaultAdapter(), $paths))
                ->migrate(function ($line) use (&$log) { $log[] = $line; });
        } catch (Throwable $e) {
            $err = 'Schema build failed: ' . $e->getMessage();
        }
    }

    if ($err !== '') {
        $body = steps_nav('db')
            . '<h1>Database</h1><div class="note bad">' . h($err) . '</div>'
            . '<form method="post">' . hidden(['step' => 'db', 'app_dir' => $appDir, 'docroot' => $docroot])
            . '<div class="card">'
            . '<label>Database host</label><input type="text" name="db_host" value="' . h($dbHost) . '">'
            . '<label>Database name</label><input type="text" name="db_name" value="' . h($dbName) . '">'
            . '<label>Database user</label><input type="text" name="db_user" value="' . h($dbUser) . '">'
            . '<label>Database password</label><input type="password" name="db_pass">'
            . '</div><button class="btn">Try again &rarr;</button></form>';
        page('Database', $body);
        break;
    }

    // Success → admin form.
    $body = steps_nav('admin')
        . '<h1>Create your admin account</h1><div class="note ok">Database ready — ' . count($log) . ' migration step(s) applied.</div>'
        . '<form method="post">' . hidden(['step' => 'admin', 'app_dir' => $appDir, 'docroot' => $docroot])
        . '<div class="card">'
        . '<label>Organization name</label><input type="text" name="org" placeholder="My Company">'
        . '<label>Admin email</label><input type="email" name="email">'
        . '<label>Username (optional)</label><input type="text" name="username">'
        . '<label>Password (min 8)</label><input type="password" name="password">'
        . '</div><button class="btn">Finish install &rarr;</button></form>';
    page('Admin', $body);
    break;

/* --- 5) Create admin, self-delete, done --------------------------------- */
case 'admin':
    $appDir  = post('app_dir');
    $docroot = post('docroot');
    $err = '';
    try {
        require $appDir . '/vendor/autoload.php';
        if (!defined('APPLICATION_ROOT')) { define('APPLICATION_ROOT', $appDir); }
        (new Tiger_Application($appDir))->boot();
        $username = post('username') !== '' ? post('username') : null;
        Tiger_Install::createOwner(post('email'), post('password'), post('org'), null, 'developer', $username);
    } catch (Throwable $e) {
        $err = $e->getMessage();
    }

    if ($err !== '') {
        $body = steps_nav('admin')
            . '<h1>Admin account</h1><div class="note bad">' . h($err) . '</div>'
            . '<form method="post">' . hidden(['step' => 'admin', 'app_dir' => $appDir, 'docroot' => $docroot])
            . '<div class="card">'
            . '<label>Organization name</label><input type="text" name="org" value="' . h(post('org')) . '">'
            . '<label>Admin email</label><input type="email" name="email" value="' . h(post('email')) . '">'
            . '<label>Username (optional)</label><input type="text" name="username" value="' . h(post('username')) . '">'
            . '<label>Password (min 8)</label><input type="password" name="password">'
            . '</div><button class="btn">Try again &rarr;</button></form>';
        page('Admin', $body);
        break;
    }

    // Clean up + self-destruct.
    @unlink($home . '/.tiger-install-tmp/tiger.zip');
    $deleted = @unlink(__FILE__);
    $scheme  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $base    = $scheme . '://' . $domain;
    $body = '<h1>&#127881; Tiger is installed</h1>'
        . '<div class="note ok">Your site is live. The app + your secrets are safely above the web root at <code>' . h($appDir) . '</code>.</div>'
        . '<div class="card"><table>'
        . '<tr><td class="mut">Your site</td><td><a style="color:var(--brand)" href="' . h($base) . '/">' . h($base) . '/</a></td></tr>'
        . '<tr><td class="mut">Sign in</td><td><a style="color:var(--brand)" href="' . h($base) . '/auth/login">' . h($base) . '/auth/login</a></td></tr>'
        . '<tr><td class="mut">Admin</td><td><a style="color:var(--brand)" href="' . h($base) . '/admin">' . h($base) . '/admin</a></td></tr>'
        . '</table></div>';
    $body .= $deleted
        ? '<div class="note ok">This installer has deleted itself. Nothing else to clean up.</div>'
        : '<div class="note bad"><strong>Delete this file now.</strong> The installer couldn\'t remove itself — delete <code>' . h(__FILE__) . '</code> via File Manager/FTP immediately.</div>';
    page('Done', $body);
    break;
}
