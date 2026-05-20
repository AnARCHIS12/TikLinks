<?php
// ============================================================
// index.php - TikTok Linktree free
// Stack: PHP 8+, SQLite WAL, file_get_contents (no cURL)
// ============================================================

define('DATA_DIR', getenv('TIKLINKS_DATA_DIR') ?: dirname(__DIR__) . '/tiklinks-data');
define('DB_PATH', getenv('TIKLINKS_DB_PATH') ?: DATA_DIR . '/linkdata.sqlite');
function normalizeSiteUrl(?string $url): string {
    $url = trim((string)$url);
    if ($url === '') $url = 'http://localhost:4242/index.php';
    if (!preg_match('#^https?://#i', $url)) $url = 'http://' . $url;
    return rtrim($url, '/');
}

define('SITE_URL', normalizeSiteUrl(getenv('TIKLINKS_SITE_URL') ?: 'http://localhost:4242/index.php'));

function e(?string $value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function requireDataDir(): void {
    $dir = dirname(DB_PATH);
    if (!is_dir($dir) && !mkdir($dir, 0700, true)) {
        throw new RuntimeException("Impossible de créer le dossier de données.");
    }
}

function isValidPublicUrl(string $url, array $schemes = ['http', 'https']): bool {
    $parts = parse_url($url);
    if (!$parts || empty($parts['scheme'])) return false;
    return in_array(strtolower($parts['scheme']), $schemes, true);
}

function csrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrfField(): string {
    return '<input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '">';
}

function verifyCsrf(?string $token): bool {
    return is_string($token) && hash_equals($_SESSION['csrf_token'] ?? '', $token);
}

function validTemplate(string $template): string {
    return in_array($template, ['cyberpunk', 'punk', 'artiste', 'vaporwave', 'minimaliste', 'custom'], true)
        ? $template
        : 'cyberpunk';
}

function validColor(?string $color, string $fallback): string {
    $color = trim((string)$color);
    return preg_match('/^#[0-9a-fA-F]{6}$/', $color) ? strtolower($color) : $fallback;
}

function cssUrl(?string $url): string {
    return str_replace(["\\", "\"", "\n", "\r"], ["\\\\", "\\\"", "", ""], (string)$url);
}

function validTab(string $tab): string {
    return in_array($tab, ['profile', 'links', 'videos', 'theme', 'account'], true) ? $tab : 'profile';
}

function normalizeIcon(?string $icon): string {
    $icon = trim((string)$icon);
    if (isValidPublicUrl($icon)) {
        return $icon;
    }
    if (preg_match('/^fa(?:-[a-z]+)? fa-[a-z0-9-]+(?: fa-[a-z0-9-]+)*$/', $icon)) {
        return $icon;
    }
    return 'fa-solid fa-link';
}

function renderIcon(?string $icon): string {
    $icon = normalizeIcon($icon);
    if (isValidPublicUrl($icon)) {
        return '<img src="' . e($icon) . '" alt="" loading="lazy" referrerpolicy="no-referrer">';
    }
    return '<i class="' . e($icon) . '" aria-hidden="true"></i>';
}

function base32Encode(string $bytes): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    $encoded = '';
    for ($i = 0, $len = strlen($bytes); $i < $len; $i++) {
        $bits .= str_pad(decbin(ord($bytes[$i])), 8, '0', STR_PAD_LEFT);
    }
    foreach (str_split($bits, 5) as $chunk) {
        $encoded .= $alphabet[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
    }
    return $encoded;
}

function base32Decode(string $base32): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $base32 = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $base32));
    $bits = '';
    foreach (str_split($base32) as $char) {
        $pos = strpos($alphabet, $char);
        if ($pos === false) continue;
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $bytes = '';
    foreach (str_split($bits, 8) as $chunk) {
        if (strlen($chunk) === 8) $bytes .= chr(bindec($chunk));
    }
    return $bytes;
}

function generateTotpSecret(): string {
    return base32Encode(random_bytes(20));
}

function hotp(string $secret, int $counter): string {
    $key = base32Decode($secret);
    $binaryCounter = pack('N2', 0, $counter);
    $hash = hash_hmac('sha1', $binaryCounter, $key, true);
    $offset = ord(substr($hash, -1)) & 0x0f;
    $value = ((ord($hash[$offset]) & 0x7f) << 24)
        | ((ord($hash[$offset + 1]) & 0xff) << 16)
        | ((ord($hash[$offset + 2]) & 0xff) << 8)
        | (ord($hash[$offset + 3]) & 0xff);
    return str_pad((string)($value % 1000000), 6, '0', STR_PAD_LEFT);
}

function verifyTotp(string $secret, string $code): bool {
    $code = preg_replace('/\D/', '', $code);
    if (strlen($code) !== 6 || $secret === '') return false;
    $counter = intdiv(time(), 30);
    for ($i = -1; $i <= 1; $i++) {
        if (hash_equals(hotp($secret, $counter + $i), $code)) return true;
    }
    return false;
}

function otpauthUri(array $member): string {
    $issuer = 'TikLinks';
    $label = $issuer . ':' . ($member['username'] ?? 'compte');
    return 'otpauth://totp/' . rawurlencode($label)
        . '?secret=' . rawurlencode((string)($member['totp_secret'] ?? ''))
        . '&issuer=' . rawurlencode($issuer)
        . '&algorithm=SHA1&digits=6&period=30';
}

function qrAppendBits(array &$bits, int $value, int $length): void {
    for ($i = $length - 1; $i >= 0; $i--) {
        $bits[] = ($value >> $i) & 1;
    }
}

function qrGfMul(int $x, int $y): int {
    $result = 0;
    while ($y > 0) {
        if ($y & 1) $result ^= $x;
        $x <<= 1;
        if ($x & 0x100) $x ^= 0x11D;
        $y >>= 1;
    }
    return $result & 0xFF;
}

function qrGfPow(int $x, int $power): int {
    $result = 1;
    for ($i = 0; $i < $power; $i++) {
        $result = qrGfMul($result, $x);
    }
    return $result;
}

function qrRsGenerator(int $degree): array {
    $gen = [1];
    for ($i = 0; $i < $degree; $i++) {
        $next = array_fill(0, count($gen) + 1, 0);
        $root = qrGfPow(2, $i);
        foreach ($gen as $j => $coef) {
            $next[$j] ^= qrGfMul($coef, 1);
            $next[$j + 1] ^= qrGfMul($coef, $root);
        }
        $gen = $next;
    }
    return $gen;
}

function qrRsRemainder(array $data, int $degree): array {
    $gen = qrRsGenerator($degree);
    $rem = array_fill(0, $degree, 0);
    foreach ($data as $byte) {
        $factor = $byte ^ $rem[0];
        array_shift($rem);
        $rem[] = 0;
        for ($i = 0; $i < $degree; $i++) {
            $rem[$i] ^= qrGfMul($gen[$i + 1], $factor);
        }
    }
    return $rem;
}

function qrTables(): array {
    return [
        1 => ['data' => 19, 'ec' => 7, 'blocks' => 1, 'total' => 26],
        2 => ['data' => 34, 'ec' => 10, 'blocks' => 1, 'total' => 44],
        3 => ['data' => 55, 'ec' => 15, 'blocks' => 1, 'total' => 70],
        4 => ['data' => 80, 'ec' => 20, 'blocks' => 1, 'total' => 100],
        5 => ['data' => 108, 'ec' => 26, 'blocks' => 1, 'total' => 134],
        6 => ['data' => 136, 'ec' => 18, 'blocks' => 2, 'total' => 172],
        7 => ['data' => 156, 'ec' => 20, 'blocks' => 2, 'total' => 196],
        8 => ['data' => 194, 'ec' => 24, 'blocks' => 2, 'total' => 242],
        9 => ['data' => 232, 'ec' => 30, 'blocks' => 2, 'total' => 292],
    ];
}

function qrDataCodewords(string $text): array {
    $bytes = array_values(unpack('C*', $text));
    $tables = qrTables();
    $version = 9;
    foreach ($tables as $v => $table) {
        if (4 + 8 + count($bytes) * 8 <= $table['data'] * 8) {
            $version = $v;
            break;
        }
    }

    $dataCapacity = $tables[$version]['data'];
    $bits = [];
    qrAppendBits($bits, 0b0100, 4);
    qrAppendBits($bits, count($bytes), 8);
    foreach ($bytes as $byte) {
        qrAppendBits($bits, $byte, 8);
    }
    $remaining = $dataCapacity * 8 - count($bits);
    qrAppendBits($bits, 0, min(4, max(0, $remaining)));
    while (count($bits) % 8 !== 0) $bits[] = 0;

    $data = [];
    foreach (array_chunk($bits, 8) as $chunk) {
        $value = 0;
        foreach ($chunk as $bit) $value = ($value << 1) | $bit;
        $data[] = $value;
    }
    for ($pad = 0; count($data) < $dataCapacity; $pad++) {
        $data[] = ($pad % 2 === 0) ? 0xEC : 0x11;
    }
    return [$version, $data];
}

function qrFinalCodewords(string $text): array {
    [$version, $data] = qrDataCodewords($text);
    $table = qrTables()[$version];
    $blockSize = intdiv($table['data'], $table['blocks']);
    $dataBlocks = array_chunk($data, $blockSize);
    $ecBlocks = array_map(fn($block) => qrRsRemainder($block, $table['ec']), $dataBlocks);
    $codewords = [];

    for ($i = 0; $i < $blockSize; $i++) {
        foreach ($dataBlocks as $block) $codewords[] = $block[$i];
    }
    for ($i = 0; $i < $table['ec']; $i++) {
        foreach ($ecBlocks as $block) $codewords[] = $block[$i];
    }
    return [$version, array_slice($codewords, 0, $table['total'])];
}

function qrSetModule(array &$matrix, array &$reserved, int $x, int $y, bool $dark, bool $isReserved = true): void {
    $size = count($matrix);
    if ($x < 0 || $y < 0 || $x >= $size || $y >= $size) return;
    $matrix[$y][$x] = $dark ? 1 : 0;
    if ($isReserved) $reserved[$y][$x] = true;
}

function qrDrawFinder(array &$matrix, array &$reserved, int $x, int $y): void {
    for ($dy = -1; $dy <= 7; $dy++) {
        for ($dx = -1; $dx <= 7; $dx++) {
            $xx = $x + $dx;
            $yy = $y + $dy;
            $dark = $dx >= 0 && $dx <= 6 && $dy >= 0 && $dy <= 6
                && ($dx === 0 || $dx === 6 || $dy === 0 || $dy === 6 || ($dx >= 2 && $dx <= 4 && $dy >= 2 && $dy <= 4));
            qrSetModule($matrix, $reserved, $xx, $yy, $dark);
        }
    }
}

function qrDrawAlignment(array &$matrix, array &$reserved, int $cx, int $cy): void {
    for ($dy = -2; $dy <= 2; $dy++) {
        for ($dx = -2; $dx <= 2; $dx++) {
            $dark = max(abs($dx), abs($dy)) === 2 || ($dx === 0 && $dy === 0);
            qrSetModule($matrix, $reserved, $cx + $dx, $cy + $dy, $dark);
        }
    }
}

function qrAlignmentCenters(int $version): array {
    return [
        1 => [], 2 => [6, 18], 3 => [6, 22], 4 => [6, 26], 5 => [6, 30],
        6 => [6, 34], 7 => [6, 22, 38], 8 => [6, 24, 42], 9 => [6, 26, 46],
    ][$version] ?? [];
}

function qrFormatBits(int $mask): int {
    $data = (1 << 3) | $mask;
    $rem = $data;
    for ($i = 0; $i < 10; $i++) {
        $rem = ($rem << 1) ^ ((($rem >> 9) & 1) ? 0x537 : 0);
    }
    return (($data << 10) | ($rem & 0x3FF)) ^ 0x5412;
}

function qrVersionBits(int $version): int {
    $rem = $version;
    for ($i = 0; $i < 12; $i++) {
        $rem = ($rem << 1) ^ ((($rem >> 11) & 1) ? 0x1F25 : 0);
    }
    return ($version << 12) | ($rem & 0xFFF);
}

function qrDrawFormat(array &$matrix, array &$reserved, int $mask): void {
    $size = count($matrix);
    $bits = qrFormatBits($mask);
    for ($i = 0; $i < 15; $i++) {
        $dark = (($bits >> $i) & 1) === 1;
        if ($i < 6) qrSetModule($matrix, $reserved, 8, $i, $dark);
        elseif ($i < 8) qrSetModule($matrix, $reserved, 8, $i + 1, $dark);
        else qrSetModule($matrix, $reserved, 8, $size - 15 + $i, $dark);

        if ($i < 8) qrSetModule($matrix, $reserved, $size - 1 - $i, 8, $dark);
        elseif ($i === 8) qrSetModule($matrix, $reserved, 7, 8, $dark);
        else qrSetModule($matrix, $reserved, 14 - $i, 8, $dark);
    }
    qrSetModule($matrix, $reserved, 8, $size - 8, true);
}

function qrDrawVersion(array &$matrix, array &$reserved, int $version): void {
    if ($version < 7) return;
    $size = count($matrix);
    $bits = qrVersionBits($version);
    for ($i = 0; $i < 18; $i++) {
        $dark = (($bits >> $i) & 1) === 1;
        $a = $size - 11 + ($i % 3);
        $b = intdiv($i, 3);
        qrSetModule($matrix, $reserved, $a, $b, $dark);
        qrSetModule($matrix, $reserved, $b, $a, $dark);
    }
}

function qrMaskBit(int $mask, int $x, int $y): bool {
    return match ($mask) {
        0 => (($x + $y) % 2) === 0,
        1 => ($y % 2) === 0,
        2 => ($x % 3) === 0,
        3 => (($x + $y) % 3) === 0,
        4 => ((intdiv($y, 2) + intdiv($x, 3)) % 2) === 0,
        5 => ((($x * $y) % 2) + (($x * $y) % 3)) === 0,
        6 => (((($x * $y) % 2) + (($x * $y) % 3)) % 2) === 0,
        default => (((($x + $y) % 2) + (($x * $y) % 3)) % 2) === 0,
    };
}

function qrPenalty(array $matrix): int {
    $size = count($matrix);
    $penalty = 0;
    for ($y = 0; $y < $size; $y++) {
        $runColor = $matrix[$y][0];
        $run = 1;
        for ($x = 1; $x < $size; $x++) {
            if ($matrix[$y][$x] === $runColor) $run++;
            else {
                if ($run >= 5) $penalty += 3 + ($run - 5);
                $runColor = $matrix[$y][$x];
                $run = 1;
            }
        }
        if ($run >= 5) $penalty += 3 + ($run - 5);
    }
    for ($x = 0; $x < $size; $x++) {
        $runColor = $matrix[0][$x];
        $run = 1;
        for ($y = 1; $y < $size; $y++) {
            if ($matrix[$y][$x] === $runColor) $run++;
            else {
                if ($run >= 5) $penalty += 3 + ($run - 5);
                $runColor = $matrix[$y][$x];
                $run = 1;
            }
        }
        if ($run >= 5) $penalty += 3 + ($run - 5);
    }
    for ($y = 0; $y < $size - 1; $y++) {
        for ($x = 0; $x < $size - 1; $x++) {
            $color = $matrix[$y][$x];
            if ($color === $matrix[$y][$x + 1] && $color === $matrix[$y + 1][$x] && $color === $matrix[$y + 1][$x + 1]) {
                $penalty += 3;
            }
        }
    }
    $dark = 0;
    foreach ($matrix as $row) $dark += array_sum($row);
    $total = $size * $size;
    return $penalty + intdiv(abs($dark * 20 - $total * 10), $total) * 10;
}

function qrMatrix(string $text): array {
    [$version, $codewords] = qrFinalCodewords($text);
    $size = 17 + 4 * $version;
    $matrix = array_fill(0, $size, array_fill(0, $size, 0));
    $reserved = array_fill(0, $size, array_fill(0, $size, false));

    qrDrawFinder($matrix, $reserved, 0, 0);
    qrDrawFinder($matrix, $reserved, $size - 7, 0);
    qrDrawFinder($matrix, $reserved, 0, $size - 7);
    foreach (qrAlignmentCenters($version) as $cx) {
        foreach (qrAlignmentCenters($version) as $cy) {
            if (($cx === 6 && $cy === 6) || ($cx === 6 && $cy === $size - 7) || ($cx === $size - 7 && $cy === 6)) continue;
            qrDrawAlignment($matrix, $reserved, $cx, $cy);
        }
    }
    for ($i = 8; $i < $size - 8; $i++) {
        $dark = ($i % 2) === 0;
        qrSetModule($matrix, $reserved, $i, 6, $dark);
        qrSetModule($matrix, $reserved, 6, $i, $dark);
    }
    qrDrawFormat($matrix, $reserved, 0);
    qrDrawVersion($matrix, $reserved, $version);

    $bits = [];
    foreach ($codewords as $byte) qrAppendBits($bits, $byte, 8);
    $bitIndex = 0;
    $direction = -1;
    for ($right = $size - 1; $right >= 1; $right -= 2) {
        if ($right === 6) $right--;
        for ($v = 0; $v < $size; $v++) {
            $y = $direction === 1 ? $v : $size - 1 - $v;
            for ($j = 0; $j < 2; $j++) {
                $x = $right - $j;
                if (!$reserved[$y][$x]) {
                    $matrix[$y][$x] = $bits[$bitIndex++] ?? 0;
                }
            }
        }
        $direction *= -1;
    }

    $best = null;
    $bestPenalty = PHP_INT_MAX;
    for ($mask = 0; $mask < 8; $mask++) {
        $candidate = $matrix;
        $candidateReserved = $reserved;
        for ($y = 0; $y < $size; $y++) {
            for ($x = 0; $x < $size; $x++) {
                if (!$reserved[$y][$x] && qrMaskBit($mask, $x, $y)) {
                    $candidate[$y][$x] ^= 1;
                }
            }
        }
        qrDrawFormat($candidate, $candidateReserved, $mask);
        $penalty = qrPenalty($candidate);
        if ($penalty < $bestPenalty) {
            $bestPenalty = $penalty;
            $best = $candidate;
        }
    }
    return $best ?? $matrix;
}

function qrSvg(string $text): string {
    $matrix = qrMatrix($text);
    $size = count($matrix);
    $quiet = 4;
    $view = $size + $quiet * 2;
    $rects = [];
    for ($y = 0; $y < $size; $y++) {
        for ($x = 0; $x < $size; $x++) {
            if ($matrix[$y][$x]) {
                $rects[] = '<rect x="' . ($x + $quiet) . '" y="' . ($y + $quiet) . '" width="1" height="1"/>';
            }
        }
    }
    return '<svg class="qr-svg" viewBox="0 0 ' . $view . ' ' . $view . '" role="img" aria-label="QR code 2FA" xmlns="http://www.w3.org/2000/svg">'
        . '<rect width="100%" height="100%" fill="#fff"/>'
        . '<g fill="#111">' . implode('', $rects) . '</g></svg>';
}

function isTikTokVideoUrl(string $url): bool {
    return (bool)preg_match('#^https://(?:www\.)?tiktok\.com/@[a-zA-Z0-9._-]+/video/\d+#', $url);
}

function tiktokThumbnailUrl(string $videoUrl): string {
    static $cache = [];
    if (isset($cache[$videoUrl])) return $cache[$videoUrl];
    if (!isTikTokVideoUrl($videoUrl) || !filter_var($videoUrl, FILTER_VALIDATE_URL)) {
        return $cache[$videoUrl] = '';
    }

    $context = stream_context_create([
        'http' => [
            'timeout' => 1.5,
            'header' => "User-Agent: TikLinks/1.0\r\nAccept: application/json\r\n",
        ],
    ]);
    $json = @file_get_contents('https://www.tiktok.com/oembed?url=' . rawurlencode($videoUrl), false, $context);
    if ($json === false) return $cache[$videoUrl] = '';

    $data = json_decode($json, true);
    $thumb = is_array($data) ? (string)($data['thumbnail_url'] ?? '') : '';
    return $cache[$videoUrl] = isValidPublicUrl($thumb) ? $thumb : '';
}

function safeRedirect(string $query = ''): void {
    header('Location: ' . SITE_URL . $query);
    exit;
}

function ensureColumn(PDO $db, string $table, string $column, string $definition): void {
    $columns = $db->query("PRAGMA table_info($table)")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($columns as $existing) {
        if (($existing['name'] ?? '') === $column) return;
    }
    $db->exec("ALTER TABLE $table ADD COLUMN $column $definition");
}

// ─── DB INIT ────────────────────────────────────────────────
function getDB(): PDO {
    requireDataDir();
    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("PRAGMA journal_mode=WAL");
    $db->exec("
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            tiktok_handle TEXT DEFAULT '',
            display_name TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            avatar_url TEXT DEFAULT '',
            template TEXT DEFAULT 'cyberpunk',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            icon TEXT DEFAULT 'fa-solid fa-link',
            sort_order INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            FOREIGN KEY(member_id) REFERENCES members(id)
        );
        CREATE TABLE IF NOT EXISTS tiktok_videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL,
            video_url TEXT NOT NULL,
            caption TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            FOREIGN KEY(member_id) REFERENCES members(id)
        );
    ");
    ensureColumn($db, 'members', 'custom_bg_color', "TEXT DEFAULT '#101018'");
    ensureColumn($db, 'members', 'custom_card_color', "TEXT DEFAULT '#ffffff'");
    ensureColumn($db, 'members', 'custom_border_color', "TEXT DEFAULT '#111111'");
    ensureColumn($db, 'members', 'custom_text_color', "TEXT DEFAULT '#ffffff'");
    ensureColumn($db, 'members', 'custom_sub_color', "TEXT DEFAULT '#d0d0d0'");
    ensureColumn($db, 'members', 'custom_button_color', "TEXT DEFAULT '#ffffff'");
    ensureColumn($db, 'members', 'custom_button_text_color', "TEXT DEFAULT '#111111'");
    ensureColumn($db, 'members', 'custom_bg_image', "TEXT DEFAULT ''");
    ensureColumn($db, 'members', 'totp_secret', "TEXT DEFAULT ''");
    ensureColumn($db, 'members', 'totp_enabled', "INTEGER DEFAULT 0");
    ensureColumn($db, 'members', 'admin_avatar_url', "TEXT DEFAULT ''");
    return $db;
}

// ─── SESSION + AUTH ─────────────────────────────────────────
session_set_cookie_params([
    'httponly' => true,
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'samesite' => 'Lax',
]);
session_start();
$db = getDB();
csrfToken();

function isLoggedIn(): bool { return isset($_SESSION['member_id']); }
function currentMember(): ?array {
    if (!isLoggedIn()) return null;
    global $db;
    $s = $db->prepare("SELECT * FROM members WHERE id=?");
    $s->execute([$_SESSION['member_id']]);
    return $s->fetch(PDO::FETCH_ASSOC) ?: null;
}

// ─── ROUTING ────────────────────────────────────────────────
$action = $_GET['action'] ?? '';
$slug   = $_GET['u'] ?? '';

// POST handlers
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $post_action = $_POST['action'] ?? '';

    if (!verifyCsrf($_POST['csrf_token'] ?? null)) {
        http_response_code(400);
        $error = "Session expirée, réessaie.";
    } elseif ($post_action === 'register') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $display  = trim($_POST['display_name'] ?? $username);
        if (preg_match('/^[a-zA-Z0-9_.-]{3,32}$/', $username) && strlen($password) >= 8) {
            try {
                $db->prepare("INSERT INTO members (username,password,display_name) VALUES (?,?,?)")
                   ->execute([$username, password_hash($password, PASSWORD_DEFAULT), $display]);
                session_regenerate_id(true);
                $_SESSION['member_id'] = $db->lastInsertId();
                safeRedirect('?action=admin');
            } catch (Exception $e) {
                $error = "Nom d'utilisateur déjà pris.";
            }
        } else {
            $error = "Pseudo 3-32 caractères (lettres, chiffres, . _ -), mot de passe 8+ caractères.";
        }
    } elseif ($post_action === 'login') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $s = $db->prepare("SELECT * FROM members WHERE username=?");
        $s->execute([$username]);
        $m = $s->fetch(PDO::FETCH_ASSOC);
        if ($m && password_verify($password, $m['password'])) {
            session_regenerate_id(true);
            if (!empty($m['totp_enabled'])) {
                $_SESSION['pending_totp_member_id'] = $m['id'];
                safeRedirect('?action=totp');
            }
            $_SESSION['member_id'] = $m['id'];
            safeRedirect('?action=admin');
        } else {
            $error = "Identifiants incorrects.";
        }
    } elseif ($post_action === 'verify_totp') {
        $pendingId = $_SESSION['pending_totp_member_id'] ?? null;
        if (!$pendingId) {
            $error = "Session 2FA expirée.";
        } else {
            $s = $db->prepare("SELECT * FROM members WHERE id=?");
            $s->execute([$pendingId]);
            $m = $s->fetch(PDO::FETCH_ASSOC);
            if ($m && !empty($m['totp_enabled']) && verifyTotp((string)$m['totp_secret'], $_POST['totp_code'] ?? '')) {
                unset($_SESSION['pending_totp_member_id']);
                session_regenerate_id(true);
                $_SESSION['member_id'] = $m['id'];
                safeRedirect('?action=admin');
            } else {
                $error = "Code 2FA invalide.";
            }
        }
    } elseif ($post_action === 'logout') {
        session_destroy();
        safeRedirect();
    } elseif ($post_action === 'change_password' && isLoggedIn()) {
        $m = currentMember();
        $current = $_POST['current_password'] ?? '';
        $new = $_POST['new_password'] ?? '';
        $confirm = $_POST['confirm_password'] ?? '';
        if (!$m || !password_verify($current, $m['password'])) {
            $error = "Mot de passe actuel incorrect.";
        } elseif (strlen($new) < 8) {
            $error = "Le nouveau mot de passe doit faire au moins 8 caractères.";
        } elseif (!hash_equals($new, $confirm)) {
            $error = "Les deux nouveaux mots de passe ne correspondent pas.";
        } else {
            $db->prepare("UPDATE members SET password=? WHERE id=?")
               ->execute([password_hash($new, PASSWORD_DEFAULT), $m['id']]);
            safeRedirect('?action=admin&tab=account&saved=1');
        }
    } elseif ($post_action === 'generate_totp' && isLoggedIn()) {
        $m = currentMember();
        if ($m) {
            $db->prepare("UPDATE members SET totp_secret=?, totp_enabled=0 WHERE id=?")
               ->execute([generateTotpSecret(), $m['id']]);
        }
        safeRedirect('?action=admin&tab=account&saved=1');
    } elseif ($post_action === 'enable_totp' && isLoggedIn()) {
        $m = currentMember();
        if (!$m || empty($m['totp_secret'])) {
            $error = "Génère d'abord une clé 2FA.";
        } elseif (!verifyTotp((string)$m['totp_secret'], $_POST['totp_code'] ?? '')) {
            $error = "Code 2FA invalide.";
        } else {
            $db->prepare("UPDATE members SET totp_enabled=1 WHERE id=?")->execute([$m['id']]);
            safeRedirect('?action=admin&tab=account&saved=1');
        }
    } elseif ($post_action === 'disable_totp' && isLoggedIn()) {
        $m = currentMember();
        $password = $_POST['password'] ?? '';
        if (!$m || !password_verify($password, $m['password'])) {
            $error = "Mot de passe incorrect.";
        } else {
            $db->prepare("UPDATE members SET totp_enabled=0, totp_secret='' WHERE id=?")->execute([$m['id']]);
            safeRedirect('?action=admin&tab=account&saved=1');
        }
    } elseif ($post_action === 'save_admin_photo' && isLoggedIn()) {
        $m = currentMember();
        $adminAvatarUrl = trim($_POST['admin_avatar_url'] ?? '');
        if ($adminAvatarUrl !== '' && !isValidPublicUrl($adminAvatarUrl)) {
            $error = "La photo admin doit être une URL http(s).";
        } else {
            $db->prepare("UPDATE members SET admin_avatar_url=? WHERE id=?")
               ->execute([$adminAvatarUrl, $m['id']]);
            safeRedirect('?action=admin&tab=account&saved=1');
        }
    } elseif ($post_action === 'save_profile' && isLoggedIn()) {
        $m = currentMember();
        $avatarUrl = trim($_POST['avatar_url'] ?? '');
        $customBgImage = trim($_POST['custom_bg_image'] ?? ($m['custom_bg_image'] ?? ''));
        if ($avatarUrl !== '' && !isValidPublicUrl($avatarUrl)) {
            $error = "L'avatar doit être une URL http(s).";
        } elseif ($customBgImage !== '' && !isValidPublicUrl($customBgImage)) {
            $error = "L'image de fond doit être une URL http(s).";
        } else {
        $db->prepare("UPDATE members SET display_name=?, bio=?, tiktok_handle=?, avatar_url=?, template=?, custom_bg_color=?, custom_card_color=?, custom_border_color=?, custom_text_color=?, custom_sub_color=?, custom_button_color=?, custom_button_text_color=?, custom_bg_image=? WHERE id=?")
           ->execute([
               trim($_POST['display_name'] ?? $m['display_name']),
               trim($_POST['bio'] ?? ''),
               preg_replace('/[^a-zA-Z0-9._]/', '', trim($_POST['tiktok_handle'] ?? '')),
               $avatarUrl,
               validTemplate($_POST['template'] ?? ($m['template'] ?? 'cyberpunk')),
               validColor($_POST['custom_bg_color'] ?? ($m['custom_bg_color'] ?? ''), '#101018'),
               validColor($_POST['custom_card_color'] ?? ($m['custom_card_color'] ?? ''), '#ffffff'),
               validColor($_POST['custom_border_color'] ?? ($m['custom_border_color'] ?? ''), '#111111'),
               validColor($_POST['custom_text_color'] ?? ($m['custom_text_color'] ?? ''), '#ffffff'),
               validColor($_POST['custom_sub_color'] ?? ($m['custom_sub_color'] ?? ''), '#d0d0d0'),
               validColor($_POST['custom_button_color'] ?? ($m['custom_button_color'] ?? ''), '#ffffff'),
               validColor($_POST['custom_button_text_color'] ?? ($m['custom_button_text_color'] ?? ''), '#111111'),
               $customBgImage,
               $m['id']
           ]);
        safeRedirect('?action=admin&tab=' . validTab($_POST['redirect_tab'] ?? 'profile') . '&saved=1');
        }
    } elseif ($post_action === 'add_link' && isLoggedIn()) {
        $m = currentMember();
        $url = trim($_POST['url'] ?? '');
        if (!isValidPublicUrl($url, ['http', 'https', 'mailto', 'tel'])) {
            $error = "URL invalide. Utilise http(s), mailto ou tel.";
        } else {
        $db->prepare("INSERT INTO links (member_id,title,url,icon,sort_order) VALUES (?,?,?,?,?)")
           ->execute([$m['id'], trim($_POST['title']), $url, normalizeIcon($_POST['icon'] ?? 'fa-solid fa-link'),
                      (int)$_POST['sort_order']]);
        safeRedirect('?action=admin&tab=links&saved=1');
        }
    } elseif ($post_action === 'delete_link' && isLoggedIn()) {
        $m = currentMember();
        $db->prepare("DELETE FROM links WHERE id=? AND member_id=?")->execute([(int)$_POST['link_id'], $m['id']]);
        safeRedirect('?action=admin&tab=links');
    } elseif ($post_action === 'toggle_link' && isLoggedIn()) {
        $m = currentMember();
        $db->prepare("UPDATE links SET active=1-active WHERE id=? AND member_id=?")->execute([(int)$_POST['link_id'], $m['id']]);
        safeRedirect('?action=admin&tab=links');
    } elseif ($post_action === 'add_video' && isLoggedIn()) {
        $m = currentMember();
        $videoUrl = trim($_POST['video_url'] ?? '');
        if (!isTikTokVideoUrl($videoUrl)) {
            $error = "URL TikTok invalide.";
        } else {
        $db->prepare("INSERT INTO tiktok_videos (member_id,video_url,caption,sort_order) VALUES (?,?,?,?)")
           ->execute([$m['id'], $videoUrl, trim($_POST['caption'] ?? ''), (int)$_POST['sort_order']]);
        safeRedirect('?action=admin&tab=videos&saved=1');
        }
    } elseif ($post_action === 'delete_video' && isLoggedIn()) {
        $m = currentMember();
        $db->prepare("DELETE FROM tiktok_videos WHERE id=? AND member_id=?")->execute([(int)$_POST['video_id'], $m['id']]);
        safeRedirect('?action=admin&tab=videos');
    }
}

// ─── TEMPLATES CONFIG ───────────────────────────────────────
$templates = [
    'cyberpunk' => [
        'name'  => 'CyberPunk',
        'icon' => 'fa-solid fa-wand-magic-sparkles',
        'bg'    => '#0a0a0f',
        'card'  => 'rgba(0,255,255,0.05)',
        'border'=> '#00ffff',
        'text'  => '#00ffff',
        'sub'   => '#ff00ff',
        'btn'   => 'linear-gradient(90deg,#00ffff,#ff00ff)',
        'btnTxt'=> '#000',
        'glow'  => '0 0 20px #00ffff55, 0 0 40px #ff00ff33',
        'font'  => "'Segoe UI', Arial, sans-serif",
        'bodyFont' => "'Segoe UI', Arial, sans-serif",
        'extra' => 'scanlines',
        'bgImage' => '',
    ],
    'punk' => [
        'name'  => 'Punk',
        'icon' => 'fa-solid fa-guitar',
        'bg'    => '#111',
        'card'  => 'rgba(255,20,20,0.08)',
        'border'=> '#ff1414',
        'text'  => '#fff',
        'sub'   => '#ff1414',
        'btn'   => 'linear-gradient(90deg,#ff1414,#ff6600)',
        'btnTxt'=> '#fff',
        'glow'  => '0 0 15px #ff141466',
        'font'  => "'Arial Black', Impact, sans-serif",
        'bodyFont' => "Arial, sans-serif",
        'extra' => 'noise',
        'bgImage' => '',
    ],
    'artiste' => [
        'name'  => 'Artiste',
        'icon' => 'fa-solid fa-palette',
        'bg'    => '#1a1008',
        'card'  => 'rgba(255,200,80,0.07)',
        'border'=> '#d4a017',
        'text'  => '#f0d080',
        'sub'   => '#c8860a',
        'btn'   => 'linear-gradient(135deg,#d4a017,#8b4513)',
        'btnTxt'=> '#fff',
        'glow'  => '0 0 20px #d4a01744',
        'font'  => "Georgia, 'Times New Roman', serif",
        'bodyFont' => "Georgia, 'Times New Roman', serif",
        'extra' => 'grain',
        'bgImage' => '',
    ],
    'vaporwave' => [
        'name'  => 'Vaporwave',
        'icon' => 'fa-solid fa-sun',
        'bg'    => '#1a0933',
        'card'  => 'rgba(255,120,220,0.08)',
        'border'=> '#ff78dc',
        'text'  => '#ffe4f7',
        'sub'   => '#b4a0ff',
        'btn'   => 'linear-gradient(90deg,#ff78dc,#b4a0ff)',
        'btnTxt'=> '#1a0933',
        'glow'  => '0 0 25px #ff78dc55, 0 0 50px #b4a0ff33',
        'font'  => "'Trebuchet MS', Arial, sans-serif",
        'bodyFont' => "'Trebuchet MS', Arial, sans-serif",
        'extra' => 'grid',
        'bgImage' => '',
    ],
    'minimaliste' => [
        'name'  => 'Minimaliste',
        'icon' => 'fa-solid fa-square',
        'bg'    => '#f5f5f0',
        'card'  => '#fff',
        'border'=> '#222',
        'text'  => '#111',
        'sub'   => '#555',
        'btn'   => 'linear-gradient(90deg,#111,#333)',
        'btnTxt'=> '#fff',
        'glow'  => '0 2px 20px rgba(0,0,0,0.12)',
        'font'  => "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        'bodyFont' => "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        'extra' => 'clean',
        'bgImage' => '',
    ],
    'custom' => [
        'name'  => 'Perso',
        'icon' => 'fa-solid fa-sliders',
        'bg'    => '#101018',
        'card'  => 'rgba(255,255,255,0.10)',
        'border'=> '#ffffff',
        'text'  => '#ffffff',
        'sub'   => '#d0d0d0',
        'btn'   => 'linear-gradient(90deg,#ffffff,#d0d0d0)',
        'btnTxt'=> '#111111',
        'glow'  => '0 0 20px rgba(255,255,255,.25)',
        'font'  => "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        'bodyFont' => "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        'extra' => 'custom',
        'bgImage' => '',
    ],
];

function resolveTemplate(array $member, array $tpls): array {
    $tpl = $tpls[$member['template']] ?? $tpls['cyberpunk'];
    if (($member['template'] ?? '') !== 'custom') return $tpl;

    $bg = validColor($member['custom_bg_color'] ?? '', '#101018');
    $card = validColor($member['custom_card_color'] ?? '', '#ffffff');
    $border = validColor($member['custom_border_color'] ?? '', '#ffffff');
    $text = validColor($member['custom_text_color'] ?? '', '#ffffff');
    $sub = validColor($member['custom_sub_color'] ?? '', '#d0d0d0');
    $button = validColor($member['custom_button_color'] ?? '', '#ffffff');
    $buttonText = validColor($member['custom_button_text_color'] ?? '', '#111111');
    $bgImage = trim((string)($member['custom_bg_image'] ?? ''));

    return [
        'name' => 'Perso',
        'icon' => 'fa-solid fa-sliders',
        'bg' => $bg,
        'card' => 'color-mix(in srgb, ' . $card . ' 20%, transparent)',
        'border' => $border,
        'text' => $text,
        'sub' => $sub,
        'btn' => 'linear-gradient(90deg,' . $button . ',' . $border . ')',
        'btnTxt' => $buttonText,
        'glow' => '0 0 20px color-mix(in srgb, ' . $border . ' 35%, transparent)',
        'font' => "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        'bodyFont' => "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        'extra' => 'custom',
        'bgImage' => isValidPublicUrl($bgImage) ? $bgImage : '',
    ];
}

// ─── RENDER PUBLIC PAGE ─────────────────────────────────────
function renderPublicPage(array $member, array $links, array $videos, array $tpl): void {
    $dn = htmlspecialchars($member['display_name'] ?: $member['username']);
    $bio = htmlspecialchars($member['bio'] ?? '');
    $handle = htmlspecialchars($member['tiktok_handle'] ?? '');
    $avatar = htmlspecialchars($member['avatar_url'] ?? '');
    ?><!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= $dn ?> | TikLinks</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:<?= $tpl['bg'] ?>;
  --card:<?= $tpl['card'] ?>;
  --border:<?= $tpl['border'] ?>;
  --text:<?= $tpl['text'] ?>;
  --sub:<?= $tpl['sub'] ?>;
  --btn:<?= $tpl['btn'] ?>;
  --btnTxt:<?= $tpl['btnTxt'] ?>;
  --glow:<?= $tpl['glow'] ?>;
  --font:<?= $tpl['font'] ?>;
  --bodyFont:<?= $tpl['bodyFont'] ?>;
}
body{
  background:var(--bg);
  color:var(--text);
  font-family:var(--bodyFont);
  min-height:100vh;
  overflow-x:hidden;
  <?php if(!empty($tpl['bgImage'])): ?>
  background-image:linear-gradient(rgba(0,0,0,.45),rgba(0,0,0,.45)),url("<?= cssUrl($tpl['bgImage']) ?>");
  background-size:cover;
  background-position:center;
  background-attachment:fixed;
  <?php endif; ?>
}
<?php if($tpl['extra']==='scanlines'): ?>
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,255,0.015) 2px,rgba(0,255,255,0.015) 4px);pointer-events:none;z-index:9999}
<?php elseif($tpl['extra']==='noise'): ?>
body::before{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");pointer-events:none;z-index:9999;opacity:.6}
<?php elseif($tpl['extra']==='grid'): ?>
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(180,160,255,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(180,160,255,.07) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
<?php elseif($tpl['extra']==='grain'): ?>
body::after{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='g'%3E%3CfeTurbulence type='turbulence' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23g)' opacity='0.06'/%3E%3C/svg%3E");pointer-events:none;z-index:9999}
<?php endif; ?>
.container{max-width:540px;margin:0 auto;padding:40px 20px 80px}
.avatar-wrap{display:flex;justify-content:center;margin-bottom:20px}
.avatar{
  width:96px;height:96px;border-radius:50%;
  border:3px solid var(--border);
  box-shadow:var(--glow);
  object-fit:cover;
  background:var(--card);
  display:flex;align-items:center;justify-content:center;
  font-size:40px;
  overflow:hidden;
}
.profile-name{font-family:var(--font);text-align:center;font-size:clamp(1.4rem,5vw,2rem);color:var(--text);text-shadow:var(--glow);margin-bottom:6px}
.tiktok-handle{text-align:center;color:var(--sub);font-size:.9rem;margin-bottom:12px;opacity:.9}
.bio{text-align:center;color:var(--text);opacity:.7;font-size:.92rem;margin-bottom:30px;line-height:1.5;max-width:380px;margin-left:auto;margin-right:auto}
.section-title{font-family:var(--font);color:var(--sub);font-size:.75rem;letter-spacing:3px;text-transform:uppercase;margin-bottom:14px;opacity:.7}
.link-btn{
  display:flex;align-items:center;gap:14px;
  width:100%;padding:15px 22px;
  background:var(--card);
  border:1.5px solid var(--border);
  border-radius:12px;
  color:var(--text);
  text-decoration:none;
  font-family:var(--bodyFont);font-size:1rem;font-weight:600;
  margin-bottom:12px;
  transition:all .25s;
  box-shadow:0 2px 10px rgba(0,0,0,.2);
  position:relative;overflow:hidden;
}
.link-btn::before{
  content:'';position:absolute;inset:0;
  background:var(--btn);opacity:0;
  transition:opacity .3s;
}
.link-btn:hover::before{opacity:.15}
.link-btn:hover{
  border-color:var(--sub);
  box-shadow:var(--glow);
  transform:translateY(-2px);
}
.link-icon{font-size:1.4rem;min-width:28px;text-align:center}
.link-icon img{width:24px;height:24px;object-fit:contain;display:block}
.link-arrow{margin-left:auto;opacity:.5;transition:all .3s}
.link-btn:hover .link-arrow{opacity:1;transform:translateX(4px)}
.videos-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(108px,1fr));gap:10px;margin-top:14px}
.video-card{
  border:1.5px solid var(--border);border-radius:10px;
  overflow:hidden;
  background:var(--card);
  transition:all .25s;
}
.video-card:hover{box-shadow:var(--glow);transform:scale(1.02)}
.video-link{display:block;color:inherit;text-decoration:none}
.video-cover{
  aspect-ratio:4/5;width:100%;
  background:var(--btn);
  color:var(--btnTxt);
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;
  font-family:var(--font);text-align:center;padding:12px;
  position:relative;isolation:isolate;
}
.video-thumb{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;z-index:-2}
.video-cover::after{content:'';position:absolute;inset:0;background:linear-gradient(180deg,rgba(0,0,0,.08),rgba(0,0,0,.5));z-index:-1}
.video-play{display:inline-flex;flex-direction:column;align-items:center;gap:6px;text-shadow:0 1px 8px rgba(0,0,0,.45)}
.video-play i{font-size:1.75rem}
.video-play span{font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.5px}
.video-cover.has-thumb .video-play{
  position:absolute;right:8px;bottom:8px;width:30px;height:30px;border-radius:50%;
  background:rgba(0,0,0,.55);color:#fff;display:flex;align-items:center;justify-content:center;
}
.video-cover.has-thumb .video-play i{font-size:.85rem}
.video-cover.has-thumb .video-play span{display:none}
.video-caption{padding:7px 8px;font-size:.72rem;color:var(--text);opacity:.85;line-height:1.25}
.tiktok-badge{
  display:inline-flex;align-items:center;gap:6px;
  padding:8px 18px;border-radius:50px;
  background:var(--btn);color:var(--btnTxt);
  font-family:var(--font);font-size:.8rem;font-weight:700;
  text-decoration:none;margin-top:8px;margin-bottom:26px;
  box-shadow:var(--glow);
  transition:all .25s;
}
.tiktok-badge:hover{transform:scale(1.05);filter:brightness(1.1)}
.powered{text-align:center;margin-top:50px;font-size:.72rem;opacity:.3;color:var(--text)}
.powered a{color:var(--sub);text-decoration:none}
.fade-in{animation:fadeIn .5s ease both}
@keyframes fadeIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
<?php if($tpl['extra']==='cyberpunk'||$tpl['extra']==='scanlines'): ?>
@keyframes flicker{0%,100%{opacity:1}92%{opacity:1}93%{opacity:.8}94%{opacity:1}97%{opacity:.9}98%{opacity:1}}
.profile-name{animation:flicker 4s infinite}
<?php endif; ?>
</style>
</head>
<body>
<div class="container">
  <div class="avatar-wrap fade-in" style="animation-delay:.05s">
    <div class="avatar">
      <?php if($avatar): ?><img src="<?= $avatar ?>" alt="<?= $dn ?>" style="width:100%;height:100%;object-fit:cover">
      <?php else: ?><i class="fa-solid fa-user" aria-hidden="true"></i><?php endif; ?>
    </div>
  </div>
  <div class="profile-name fade-in" style="animation-delay:.1s"><?= $dn ?></div>
  <?php if($handle): ?>
  <div class="tiktok-handle fade-in" style="animation-delay:.15s">
    <a href="https://tiktok.com/@<?= $handle ?>" target="_blank" class="tiktok-badge">
      <i class="fa-brands fa-tiktok" aria-hidden="true"></i>
      @<?= $handle ?>
    </a>
  </div>
  <?php endif; ?>
  <?php if($bio): ?><div class="bio fade-in" style="animation-delay:.2s"><?= nl2br($bio) ?></div><?php endif; ?>

  <?php if(!empty($links)): ?>
  <div class="fade-in" style="animation-delay:.25s">
    <div class="section-title">Mes liens</div>
    <?php foreach($links as $i=>$link): ?>
    <a href="<?= e($link['url']) ?>" target="_blank" rel="noopener noreferrer" class="link-btn" style="animation-delay:<?= .3+$i*.07 ?>s">
      <span class="link-icon"><?= renderIcon($link['icon']) ?></span>
      <span><?= htmlspecialchars($link['title']) ?></span>
      <span class="link-arrow">→</span>
    </a>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

  <?php if(!empty($videos)): ?>
  <div class="fade-in" style="animation-delay:.5s;margin-top:30px">
    <div class="section-title">Mes meilleures vidéos</div>
    <div class="videos-grid">
      <?php foreach($videos as $v): $thumb = tiktokThumbnailUrl($v['video_url']); ?>
      <div class="video-card">
        <a href="<?= e($v['video_url']) ?>" target="_blank" rel="noopener noreferrer" class="video-link">
          <div class="video-cover <?= $thumb ? 'has-thumb' : '' ?>">
            <?php if($thumb): ?><img src="<?= e($thumb) ?>" alt="" class="video-thumb" loading="lazy" referrerpolicy="no-referrer"><?php endif; ?>
            <div class="video-play">
              <i class="<?= $thumb ? 'fa-solid fa-play' : 'fa-brands fa-tiktok' ?>" aria-hidden="true"></i>
              <?php if(!$thumb): ?><span>Voir</span><?php endif; ?>
            </div>
          </div>
          <div class="video-caption"><?= htmlspecialchars($v['caption'] ?: 'Vidéo TikTok') ?></div>
        </a>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endif; ?>

  <div class="powered">Propulsé par <a href="<?= SITE_URL ?>">TikLinks</a> · Crée ta page <a href="<?= SITE_URL ?>?action=register">gratuitement</a></div>
</div>
</body>
</html><?php
}

// ─── ADMIN UI ───────────────────────────────────────────────
function renderAdmin(array $member, PDO $db, array $tpls): void {
    $tab = $_GET['tab'] ?? 'profile';
    $saved = isset($_GET['saved']);
    $error = $GLOBALS['error'] ?? null;
    $username = $member['username'];
    $adminAvatar = isValidPublicUrl((string)($member['admin_avatar_url'] ?? '')) ? (string)$member['admin_avatar_url'] : '';

    // Load links & videos
    $ls = $db->prepare("SELECT * FROM links WHERE member_id=? ORDER BY sort_order,id");
    $ls->execute([$member['id']]);
    $links = $ls->fetchAll(PDO::FETCH_ASSOC);

    $vs = $db->prepare("SELECT * FROM tiktok_videos WHERE member_id=? ORDER BY sort_order,id");
    $vs->execute([$member['id']]);
    $videos = $vs->fetchAll(PDO::FETCH_ASSOC);

    $currentTpl = resolveTemplate($member, $tpls);
    $pubUrl = SITE_URL . '?u=' . urlencode($username);
    ?><!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — TikLinks</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:<?= $currentTpl['bg'] ?>;
  --sidebar:<?= $currentTpl['bg'] ?>;
  --card:<?= $currentTpl['card'] ?>;
  --border:<?= $currentTpl['border'] ?>;
  --accent:<?= $currentTpl['border'] ?>;
  --accent2:<?= $currentTpl['sub'] ?>;
  --text:<?= $currentTpl['text'] ?>;
  --sub:<?= $currentTpl['sub'] ?>;
  --btn:<?= $currentTpl['btn'] ?>;
  --btnTxt:<?= $currentTpl['btnTxt'] ?>;
  --glow:<?= $currentTpl['glow'] ?>;
  --danger:#ff3355;--success:#00c978;
  --font:<?= $currentTpl['font'] ?>;
  --body:<?= $currentTpl['bodyFont'] ?>;
}
body{background:var(--bg);color:var(--text);font-family:var(--body);min-height:100vh;display:flex;flex-direction:column<?php if(!empty($currentTpl['bgImage'])): ?>;background-image:linear-gradient(rgba(0,0,0,.45),rgba(0,0,0,.45)),url("<?= cssUrl($currentTpl['bgImage']) ?>");background-size:cover;background-position:center;background-attachment:fixed<?php endif; ?>}
<?php if($currentTpl['extra']==='scanlines'): ?>
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,255,0.015) 2px,rgba(0,255,255,0.015) 4px);pointer-events:none;z-index:0}
<?php elseif($currentTpl['extra']==='noise'): ?>
body::before{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");pointer-events:none;z-index:0;opacity:.6}
<?php elseif($currentTpl['extra']==='grid'): ?>
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(180,160,255,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(180,160,255,.07) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
<?php elseif($currentTpl['extra']==='grain'): ?>
body::before{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='g'%3E%3CfeTurbulence type='turbulence' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23g)' opacity='0.06'/%3E%3C/svg%3E");pointer-events:none;z-index:0}
<?php endif; ?>
.topbar{
  background:var(--sidebar);border-bottom:1px solid var(--border);
  padding:14px 24px;display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:100;
}
.logo{font-family:var(--font);font-size:1.1rem;color:var(--accent);text-shadow:0 0 10px var(--accent);letter-spacing:2px}
.logo span{color:var(--accent2)}
.topbar-right{display:flex;align-items:center;gap:12px}
.user-chip{display:inline-flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--border);border-radius:999px;padding:5px 12px 5px 6px;font-size:.8rem;color:var(--text);min-width:0}
.user-avatar{width:26px;height:26px;border-radius:50%;border:1px solid var(--border);background:rgba(255,255,255,.08);display:inline-flex;align-items:center;justify-content:center;overflow:hidden;flex-shrink:0;color:var(--accent)}
.user-avatar img{width:100%;height:100%;object-fit:cover;display:block}
.user-name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:150px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:8px;border:none;cursor:pointer;font-family:var(--body);font-size:.85rem;font-weight:600;transition:all .2s;text-decoration:none}
.btn-primary{background:var(--btn);color:var(--btnTxt)}
.btn-primary:hover{filter:brightness(1.15);transform:translateY(-1px);box-shadow:var(--glow)}
.btn-danger{background:rgba(255,51,85,.15);border:1px solid var(--danger);color:var(--danger)}
.btn-danger:hover{background:rgba(255,51,85,.3)}
.btn-ghost{background:var(--card);border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn-sm{padding:5px 10px;font-size:.75rem}
.main{display:flex;flex:1;overflow:hidden}
.sidebar{width:220px;background:var(--sidebar);border-right:1px solid var(--border);padding:20px 0;display:flex;flex-direction:column}
.nav-item{display:flex;align-items:center;gap:10px;padding:12px 20px;color:var(--sub);font-size:.82rem;cursor:pointer;transition:all .2s;text-decoration:none;border-left:3px solid transparent}
.nav-item:hover{color:var(--text);background:var(--card)}
.nav-item.active{color:var(--accent);border-left-color:var(--accent);background:rgba(0,255,255,.05)}
.nav-icon{font-size:1.1rem;min-width:20px;text-align:center}
.preview-btn{margin:16px;padding:10px;background:var(--btn);color:var(--btnTxt);text-align:center;border-radius:8px;font-size:.78rem;font-weight:700;text-decoration:none;display:block;transition:all .2s}
.preview-btn:hover{filter:brightness(1.1);transform:scale(1.02)}
.content{flex:1;padding:28px;overflow-y:auto}
.page-title{font-family:var(--font);font-size:1.3rem;color:var(--text);margin-bottom:6px}
.page-sub{color:var(--sub);font-size:.82rem;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:22px;margin-bottom:18px}
.card-title{font-family:var(--font);font-size:.85rem;color:var(--accent);margin-bottom:16px;letter-spacing:1px}
.form-group{margin-bottom:16px}
label{display:block;font-size:.78rem;color:var(--sub);margin-bottom:6px;letter-spacing:.5px}
input,textarea,select{
  width:100%;padding:10px 14px;
  background:rgba(255,255,255,.04);
  border:1px solid var(--border);
  border-radius:8px;
  color:var(--text);
  font-family:var(--body);font-size:.9rem;
  transition:border-color .2s;
  outline:none;
}
input:focus,textarea:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,255,255,.1)}
textarea{resize:vertical;min-height:80px}
select option{background:#1a1a2e;color:var(--text)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.template-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px}
.tpl-card{
  border:2px solid transparent;border-radius:10px;padding:14px;
  cursor:pointer;transition:all .2s;text-align:center;
  background:var(--card);
}
.tpl-card:hover{transform:scale(1.03)}
.tpl-card.selected{border-color:var(--accent);box-shadow:var(--glow)}
.tpl-card input[type=radio]{display:none}
.tpl-icon{font-size:1.8rem;margin-bottom:6px}
.tpl-name{font-family:var(--font);font-size:.72rem;letter-spacing:1px}
.custom-theme-panel[hidden]{display:none}
.links-list{list-style:none}
.link-row{
  display:flex;align-items:center;gap:10px;
  padding:12px 16px;background:var(--card);
  border:1px solid var(--border);border-radius:8px;
  margin-bottom:8px;transition:all .2s;
}
.link-row:hover{border-color:var(--accent)}
.link-row-icon{font-size:1.2rem;min-width:28px;text-align:center}
.link-row-icon img{width:22px;height:22px;object-fit:contain;display:block;margin:auto}
.link-row-info{flex:1;min-width:0}
.link-row-title{font-size:.9rem;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.link-row-url{font-size:.72rem;color:var(--sub);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.link-row-actions{display:flex;gap:6px;flex-shrink:0}
.badge{display:inline-flex;padding:3px 8px;border-radius:4px;font-size:.68rem;font-weight:700}
.badge-on{background:rgba(0,255,136,.15);color:var(--success);border:1px solid rgba(0,255,136,.3)}
.badge-off{background:rgba(255,51,85,.1);color:var(--danger);border:1px solid rgba(255,51,85,.2)}
.alert-success{background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.3);color:var(--success);padding:10px 16px;border-radius:8px;margin-bottom:16px;font-size:.85rem}
.url-display{background:rgba(0,255,255,.05);border:1px solid rgba(0,255,255,.2);border-radius:8px;padding:10px 16px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;gap:10px}
.url-text{font-size:.85rem;color:var(--accent);word-break:break-all}
.copy-status{font-size:.72rem;color:var(--success);min-height:1em;margin-bottom:16px}
.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}
.stat-num{font-family:var(--font);font-size:1.8rem;color:var(--accent);text-shadow:0 0 10px rgba(0,255,255,.4)}
.stat-label{font-size:.72rem;color:var(--sub);margin-top:4px}
.empty-state{text-align:center;padding:40px;color:var(--sub);font-size:.88rem;border:1px dashed var(--border);border-radius:10px}
.icon-picker{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.icon-btn{width:36px;height:36px;border:1px solid var(--border);border-radius:6px;background:var(--card);cursor:pointer;font-size:1.1rem;transition:all .15s;display:flex;align-items:center;justify-content:center;color:var(--text);position:relative}
.icon-btn img{width:20px;height:20px;object-fit:contain}
.icon-btn:hover,.icon-btn.active{border-color:var(--accent);background:var(--btn);color:var(--btnTxt);box-shadow:var(--glow);transform:translateY(-1px)}
.icon-btn.active::after{content:'';position:absolute;right:3px;bottom:3px;width:7px;height:7px;border-radius:50%;background:var(--btnTxt);box-shadow:0 0 0 1px var(--accent)}
.totp-setup{display:grid;grid-template-columns:180px minmax(0,1fr);gap:18px;align-items:start;margin-bottom:18px}
.totp-qr{background:#fff;border-radius:10px;padding:10px;width:180px;box-shadow:0 10px 28px rgba(0,0,0,.22)}
.totp-qr svg{display:block;width:100%;height:auto}
.totp-details{min-width:0}
.totp-help{color:var(--sub);font-size:.82rem;line-height:1.5;margin-bottom:12px}
.admin-photo-form{display:grid;grid-template-columns:88px minmax(0,1fr);gap:18px;align-items:center}
.admin-photo-preview{width:88px;height:88px;border-radius:50%;border:2px solid var(--border);background:rgba(255,255,255,.08);display:flex;align-items:center;justify-content:center;overflow:hidden;color:var(--accent);font-size:2rem;box-shadow:var(--glow)}
.admin-photo-preview img{width:100%;height:100%;object-fit:cover;display:block}
.admin-photo-note{font-size:.78rem;color:var(--sub);line-height:1.45;margin-top:-6px;margin-bottom:14px}
@media(max-width:768px){
  html{height:100%;overflow:hidden}
  body{height:100dvh;min-height:100dvh;overflow:hidden;padding-bottom:0}
  .topbar{padding:10px 12px;gap:10px}
  .logo{font-size:.92rem;letter-spacing:1px}
  .topbar-right{gap:8px;min-width:0}
  .user-chip{padding:4px 8px 4px 4px}
  .user-name{max-width:86px}
  .topbar .btn{padding:7px 9px;font-size:0}
  .topbar .btn i{font-size:.9rem}
  .main{flex:1;min-height:0;flex-direction:column;overflow:hidden}
  .sidebar{
    position:fixed!important;left:10px;right:10px;bottom:calc(10px + env(safe-area-inset-bottom,0px));z-index:1000;
    width:auto;height:58px;flex-direction:row;align-items:center;justify-content:space-around;
    overflow:visible;padding:5px;
    background:color-mix(in srgb,var(--sidebar) 88%,#000 12%);
    border:1px solid var(--border);border-radius:14px;
    box-shadow:0 12px 34px rgba(0,0,0,.36);
    backdrop-filter:blur(14px);
    transform:translateZ(0);
  }
  .nav-item{
    flex:1;min-width:0;height:48px;justify-content:center;flex-direction:column;gap:3px;
    padding:5px 3px;border-left:none;border-bottom:none;border-radius:10px;
    white-space:nowrap;font-size:.64rem;line-height:1;color:var(--sub);
  }
  .nav-item.active{border-left-color:transparent;background:var(--btn);color:var(--btnTxt)}
  .nav-icon{font-size:1rem;min-width:0}
  .preview-btn{display:none}
  .content{flex:1;min-height:0;padding:18px 14px calc(92px + env(safe-area-inset-bottom,0px));overflow-y:auto;-webkit-overflow-scrolling:touch}
  .url-display{align-items:flex-start;flex-direction:column}
  .url-display .btn{align-self:flex-start}
  .form-row{grid-template-columns:1fr}
  .stats-row{grid-template-columns:1fr 1fr}
  .totp-setup{grid-template-columns:1fr}
  .admin-photo-form{grid-template-columns:1fr}
  .admin-photo-preview{width:76px;height:76px}
}
</style>
</head>
<body>
<div class="topbar">
  <div class="logo">Tik<span>Links</span></div>
  <div class="topbar-right">
    <span class="user-chip">
      <span class="user-avatar">
        <?php if($adminAvatar): ?><img src="<?= e($adminAvatar) ?>" alt="" loading="lazy" referrerpolicy="no-referrer"><?php else: ?><i class="fa-solid fa-user" aria-hidden="true"></i><?php endif; ?>
      </span>
      <span class="user-name">@<?= htmlspecialchars($username) ?></span>
    </span>
    <form method="POST" style="display:inline"><?= csrfField() ?><input type="hidden" name="action" value="logout"><button type="submit" class="btn btn-ghost btn-sm"><i class="fa-solid fa-right-from-bracket" aria-hidden="true"></i> Déconnexion</button></form>
  </div>
</div>
<div class="main">
  <div class="sidebar">
    <a href="?action=admin&tab=profile" class="nav-item <?= $tab==='profile'?'active':'' ?>"><span class="nav-icon"><i class="fa-solid fa-user" aria-hidden="true"></i></span> Profil</a>
    <a href="?action=admin&tab=links" class="nav-item <?= $tab==='links'?'active':'' ?>"><span class="nav-icon"><i class="fa-solid fa-link" aria-hidden="true"></i></span> Liens</a>
    <a href="?action=admin&tab=videos" class="nav-item <?= $tab==='videos'?'active':'' ?>"><span class="nav-icon"><i class="fa-solid fa-music" aria-hidden="true"></i></span> Vidéos</a>
    <a href="?action=admin&tab=theme" class="nav-item <?= $tab==='theme'?'active':'' ?>"><span class="nav-icon"><i class="fa-solid fa-palette" aria-hidden="true"></i></span> Thème</a>
    <a href="?action=admin&tab=account" class="nav-item <?= $tab==='account'?'active':'' ?>"><span class="nav-icon"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i></span> Compte</a>
    <a href="<?= htmlspecialchars($pubUrl) ?>" target="_blank" class="preview-btn" style="margin-top:auto"><i class="fa-solid fa-eye" aria-hidden="true"></i> Voir ma page</a>
  </div>
  <div class="content">
    <?php if($saved): ?><div class="alert-success"><i class="fa-solid fa-check" aria-hidden="true"></i> Modifications sauvegardées !</div><?php endif; ?>
    <?php if($error): ?><div class="error" style="margin-bottom:16px"><?= e($error) ?></div><?php endif; ?>

    <div class="url-display">
      <span class="url-text"><?= htmlspecialchars($pubUrl) ?></span>
      <button type="button" class="btn btn-ghost btn-sm" data-copy-value="<?= e($pubUrl) ?>" data-copy-target="copy-status"><i class="fa-regular fa-copy" aria-hidden="true"></i> Copier</button>
    </div>
    <div class="copy-status" id="copy-status" aria-live="polite"></div>

    <?php if($tab==='profile'): ?>
    <div class="page-title">Mon Profil</div>
    <div class="page-sub">Personnalise les infos de ta page publique</div>
    <form method="POST">
      <?= csrfField() ?>
      <input type="hidden" name="action" value="save_profile">
      <input type="hidden" name="redirect_tab" value="profile">
      <div class="card">
        <div class="card-title">INFORMATIONS</div>
        <div class="form-row">
          <div class="form-group">
            <label>Nom affiché</label>
            <input type="text" name="display_name" value="<?= htmlspecialchars($member['display_name']) ?>" placeholder="Ton nom ou pseudo">
          </div>
          <div class="form-group">
            <label>@ TikTok</label>
            <input type="text" name="tiktok_handle" value="<?= htmlspecialchars($member['tiktok_handle']) ?>" placeholder="tonpseudo (sans @)">
          </div>
        </div>
        <div class="form-group">
          <label>Bio</label>
          <textarea name="bio" placeholder="Décris-toi en quelques mots..."><?= htmlspecialchars($member['bio']) ?></textarea>
        </div>
        <div class="form-group">
          <label>URL Photo de profil</label>
          <input type="url" name="avatar_url" value="<?= htmlspecialchars($member['avatar_url']) ?>" placeholder="https://...">
        </div>
      </div>
      <button type="submit" class="btn btn-primary"><i class="fa-solid fa-floppy-disk" aria-hidden="true"></i> Sauvegarder le profil</button>
    </form>

    <?php elseif($tab==='links'): ?>
    <div class="page-title">Mes Liens</div>
    <div class="page-sub">Ajoute et gère tes liens personnalisés</div>

    <div class="stats-row">
      <div class="stat-card"><div class="stat-num"><?= count($links) ?></div><div class="stat-label">Liens totaux</div></div>
      <div class="stat-card"><div class="stat-num"><?= count(array_filter($links,fn($l)=>$l['active'])) ?></div><div class="stat-label">Actifs</div></div>
      <div class="stat-card"><div class="stat-num"><?= count(array_filter($links,fn($l)=>!$l['active'])) ?></div><div class="stat-label">Masqués</div></div>
    </div>

    <div class="card">
      <div class="card-title">AJOUTER UN LIEN</div>
      <form method="POST">
        <?= csrfField() ?>
        <input type="hidden" name="action" value="add_link">
        <input type="hidden" name="sort_order" value="<?= count($links) ?>">
        <div class="form-row">
          <div class="form-group">
            <label>Titre</label>
            <input type="text" name="title" placeholder="Mon Instagram" required>
          </div>
          <div class="form-group">
            <label>URL</label>
            <input type="url" name="url" placeholder="https://instagram.com/..." required>
          </div>
        </div>
        <div class="form-group">
          <label>Icône</label>
          <input type="hidden" name="icon" id="icon-input" value="fa-solid fa-link">
          <div class="icon-picker">
            <?php foreach(['fa-solid fa-link','https://militant.revlibertaire.com/assets/favicon.svg','fa-solid fa-mobile-screen','fa-solid fa-music','fa-solid fa-camera','fa-solid fa-film','fa-solid fa-comment','fa-solid fa-globe','fa-solid fa-bag-shopping','fa-solid fa-gamepad','fa-solid fa-envelope','fa-solid fa-microphone','fa-solid fa-tv','fa-solid fa-star','fa-solid fa-lightbulb','fa-solid fa-headphones','fa-solid fa-palette','fa-solid fa-dollar-sign','fa-brands fa-tiktok','fa-brands fa-instagram','fa-brands fa-youtube'] as $ic): ?>
            <button type="button" class="icon-btn <?= $ic === 'fa-solid fa-link' ? 'active' : '' ?>" title="<?= isValidPublicUrl($ic) ? 'Militant' : e($ic) ?>" onclick="document.getElementById('icon-input').value=<?= e(json_encode($ic)) ?>;document.querySelectorAll('.icon-btn').forEach(b=>b.classList.remove('active'));this.classList.add('active')"><?= renderIcon($ic) ?></button>
            <?php endforeach; ?>
          </div>
        </div>
        <button type="submit" class="btn btn-primary">+ Ajouter le lien</button>
      </form>
    </div>

    <?php if(!empty($links)): ?>
    <div class="card">
      <div class="card-title">MES LIENS (<?= count($links) ?>)</div>
      <ul class="links-list">
        <?php foreach($links as $link): ?>
        <li class="link-row">
          <span class="link-row-icon"><?= renderIcon($link['icon']) ?></span>
          <div class="link-row-info">
            <div class="link-row-title"><?= htmlspecialchars($link['title']) ?></div>
            <div class="link-row-url"><?= htmlspecialchars($link['url']) ?></div>
          </div>
          <span class="badge <?= $link['active']?'badge-on':'badge-off' ?>"><?= $link['active']?'ON':'OFF' ?></span>
          <div class="link-row-actions">
            <form method="POST" style="display:inline">
              <?= csrfField() ?>
              <input type="hidden" name="action" value="toggle_link">
              <input type="hidden" name="link_id" value="<?= $link['id'] ?>">
              <button type="submit" class="btn btn-ghost btn-sm"><i class="fa-solid <?= $link['active']?'fa-eye-slash':'fa-eye' ?>" aria-hidden="true"></i></button>
            </form>
            <form method="POST" style="display:inline" onsubmit="return confirm('Supprimer ce lien ?')">
              <?= csrfField() ?>
              <input type="hidden" name="action" value="delete_link">
              <input type="hidden" name="link_id" value="<?= $link['id'] ?>">
              <button type="submit" class="btn btn-danger btn-sm"><i class="fa-solid fa-trash" aria-hidden="true"></i></button>
            </form>
          </div>
        </li>
        <?php endforeach; ?>
      </ul>
    </div>
    <?php else: ?>
    <div class="empty-state"><i class="fa-solid fa-link" aria-hidden="true"></i> Aucun lien pour l'instant. Ajoute ton premier lien ci-dessus !</div>
    <?php endif; ?>

    <?php elseif($tab==='videos'): ?>
    <div class="page-title">Vidéos TikTok</div>
    <div class="page-sub">Mets en avant tes meilleures vidéos</div>

    <div class="card">
      <div class="card-title">AJOUTER UNE VIDÉO</div>
      <form method="POST">
        <?= csrfField() ?>
        <input type="hidden" name="action" value="add_video">
        <input type="hidden" name="sort_order" value="<?= count($videos) ?>">
        <div class="form-group">
          <label>URL de la vidéo TikTok</label>
          <input type="url" name="video_url" placeholder="https://www.tiktok.com/@pseudo/video/1234567890" required>
        </div>
        <div class="form-group">
          <label>Légende (optionnel)</label>
          <input type="text" name="caption" placeholder="Ma meilleure vidéo">
        </div>
        <button type="submit" class="btn btn-primary">+ Ajouter la vidéo</button>
      </form>
    </div>

    <?php if(!empty($videos)): ?>
    <div class="card">
      <div class="card-title">MES VIDÉOS (<?= count($videos) ?>)</div>
      <ul class="links-list">
        <?php foreach($videos as $v): ?>
        <li class="link-row">
          <span class="link-row-icon"><i class="fa-solid fa-music" aria-hidden="true"></i></span>
          <div class="link-row-info">
            <div class="link-row-title"><?= htmlspecialchars($v['caption'] ?: 'Vidéo TikTok') ?></div>
            <div class="link-row-url"><?= htmlspecialchars($v['video_url']) ?></div>
          </div>
          <div class="link-row-actions">
            <form method="POST" style="display:inline" onsubmit="return confirm('Supprimer cette vidéo ?')">
              <?= csrfField() ?>
              <input type="hidden" name="action" value="delete_video">
              <input type="hidden" name="video_id" value="<?= $v['id'] ?>">
              <button type="submit" class="btn btn-danger btn-sm"><i class="fa-solid fa-trash" aria-hidden="true"></i></button>
            </form>
          </div>
        </li>
        <?php endforeach; ?>
      </ul>
    </div>
    <?php else: ?>
    <div class="empty-state"><i class="fa-solid fa-music" aria-hidden="true"></i> Aucune vidéo ajoutée. Colle l'URL d'une vidéo TikTok !</div>
    <?php endif; ?>

    <?php elseif($tab==='theme'): ?>
    <div class="page-title">Thème de ma page et de l'admin</div>
    <div class="page-sub">Choisis le style visuel appliqué partout</div>
    <form method="POST">
      <?= csrfField() ?>
      <input type="hidden" name="action" value="save_profile">
      <input type="hidden" name="redirect_tab" value="theme">
      <input type="hidden" name="display_name" value="<?= htmlspecialchars($member['display_name']) ?>">
      <input type="hidden" name="bio" value="<?= htmlspecialchars($member['bio']) ?>">
      <input type="hidden" name="tiktok_handle" value="<?= htmlspecialchars($member['tiktok_handle']) ?>">
      <input type="hidden" name="avatar_url" value="<?= htmlspecialchars($member['avatar_url']) ?>">
      <div class="card">
        <div class="card-title">CHOISIR UN TEMPLATE</div>
        <div class="template-grid">
          <?php foreach($tpls as $key=>$tpl): ?>
          <label class="tpl-card <?= $member['template']===$key?'selected':'' ?>" style="background:<?= $tpl['bg'] ?>;border-color:<?= $member['template']===$key?$tpl['border']:'transparent' ?>">
            <input type="radio" name="template" value="<?= $key ?>" <?= $member['template']===$key?'checked':'' ?> onchange="document.querySelectorAll('.tpl-card').forEach(c=>c.classList.remove('selected'));this.closest('.tpl-card').classList.add('selected');document.getElementById('custom-theme-panel').hidden=this.value!=='custom'">
            <div class="tpl-icon"><i class="<?= e($tpl['icon']) ?>" aria-hidden="true"></i></div>
            <div class="tpl-name" style="color:<?= $tpl['text'] ?>;font-family:<?= $tpl['font'] ?>"><?= $tpl['name'] ?></div>
            <div style="margin-top:8px;height:4px;border-radius:2px;background:<?= $tpl['btn'] ?>"></div>
          </label>
          <?php endforeach; ?>
        </div>
      </div>
      <div class="card custom-theme-panel" id="custom-theme-panel" <?= $member['template']==='custom'?'':'hidden' ?>>
        <div class="card-title">TEMPLATE PERSO</div>
        <div class="form-row">
          <div class="form-group">
            <label>Fond</label>
            <input type="color" name="custom_bg_color" value="<?= e(validColor($member['custom_bg_color'] ?? '', '#101018')) ?>">
          </div>
          <div class="form-group">
            <label>Cartes</label>
            <input type="color" name="custom_card_color" value="<?= e(validColor($member['custom_card_color'] ?? '', '#ffffff')) ?>">
          </div>
          <div class="form-group">
            <label>Bordures</label>
            <input type="color" name="custom_border_color" value="<?= e(validColor($member['custom_border_color'] ?? '', '#ffffff')) ?>">
          </div>
          <div class="form-group">
            <label>Texte</label>
            <input type="color" name="custom_text_color" value="<?= e(validColor($member['custom_text_color'] ?? '', '#ffffff')) ?>">
          </div>
          <div class="form-group">
            <label>Texte secondaire</label>
            <input type="color" name="custom_sub_color" value="<?= e(validColor($member['custom_sub_color'] ?? '', '#d0d0d0')) ?>">
          </div>
          <div class="form-group">
            <label>Boutons</label>
            <input type="color" name="custom_button_color" value="<?= e(validColor($member['custom_button_color'] ?? '', '#ffffff')) ?>">
          </div>
          <div class="form-group">
            <label>Texte boutons</label>
            <input type="color" name="custom_button_text_color" value="<?= e(validColor($member['custom_button_text_color'] ?? '', '#111111')) ?>">
          </div>
        </div>
        <div class="form-group">
          <label>Image de fond</label>
          <input type="url" name="custom_bg_image" value="<?= e($member['custom_bg_image'] ?? '') ?>" placeholder="https://exemple.com/fond.jpg">
        </div>
      </div>
      <button type="submit" class="btn btn-primary"><i class="fa-solid fa-palette" aria-hidden="true"></i> Appliquer le thème</button>
    </form>
    <?php elseif($tab==='account'): ?>
    <div class="page-title">Mon compte</div>
    <div class="page-sub">Mot de passe et double authentification</div>

    <div class="card">
      <div class="card-title">PHOTO DU PANEL ADMIN</div>
      <form method="POST" class="admin-photo-form">
        <?= csrfField() ?>
        <input type="hidden" name="action" value="save_admin_photo">
        <div class="admin-photo-preview">
          <?php if($adminAvatar): ?><img src="<?= e($adminAvatar) ?>" alt="" loading="lazy" referrerpolicy="no-referrer"><?php else: ?><i class="fa-solid fa-user-shield" aria-hidden="true"></i><?php endif; ?>
        </div>
        <div>
          <div class="admin-photo-note">Cette photo sert seulement dans le panel admin. Elle ne remplace pas la photo publique de ta page.</div>
          <div class="form-group">
            <label>URL de la photo admin</label>
            <input type="url" name="admin_avatar_url" value="<?= e($member['admin_avatar_url'] ?? '') ?>" placeholder="https://exemple.com/photo.jpg">
          </div>
          <button type="submit" class="btn btn-primary"><i class="fa-solid fa-floppy-disk" aria-hidden="true"></i> Enregistrer la photo</button>
        </div>
      </form>
    </div>

    <div class="card">
      <div class="card-title">CHANGER LE MOT DE PASSE</div>
      <form method="POST">
        <?= csrfField() ?>
        <input type="hidden" name="action" value="change_password">
        <div class="form-row">
          <div class="form-group">
            <label>Mot de passe actuel</label>
            <input type="password" name="current_password" required autocomplete="current-password">
          </div>
          <div class="form-group">
            <label>Nouveau mot de passe</label>
            <input type="password" name="new_password" required minlength="8" autocomplete="new-password">
          </div>
        </div>
        <div class="form-group">
          <label>Confirmer le nouveau mot de passe</label>
          <input type="password" name="confirm_password" required minlength="8" autocomplete="new-password">
        </div>
        <button type="submit" class="btn btn-primary"><i class="fa-solid fa-key" aria-hidden="true"></i> Mettre à jour</button>
      </form>
    </div>

    <div class="card">
      <div class="card-title">DOUBLE AUTHENTIFICATION TOTP</div>
      <?php if(!empty($member['totp_enabled'])): ?>
        <div class="alert-success"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i> La double authentification est active.</div>
        <form method="POST" onsubmit="return confirm('Désactiver la double authentification ?')">
          <?= csrfField() ?>
          <input type="hidden" name="action" value="disable_totp">
          <div class="form-group">
            <label>Mot de passe pour désactiver</label>
            <input type="password" name="password" required autocomplete="current-password">
          </div>
          <button type="submit" class="btn btn-danger"><i class="fa-solid fa-lock-open" aria-hidden="true"></i> Désactiver la 2FA</button>
        </form>
      <?php else: ?>
        <?php if(empty($member['totp_secret'])): ?>
          <form method="POST">
            <?= csrfField() ?>
            <input type="hidden" name="action" value="generate_totp">
            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i> Générer une clé 2FA</button>
          </form>
        <?php else: ?>
          <div class="totp-setup">
            <div class="totp-qr"><?= qrSvg(otpauthUri($member)) ?></div>
            <div class="totp-details">
              <div class="totp-help">Scanne ce QR code avec Google Authenticator, Aegis, 1Password, Bitwarden ou une autre application TOTP.</div>
              <div class="url-display">
                <span class="url-text"><?= e(chunk_split($member['totp_secret'], 4, ' ')) ?></span>
                <button type="button" class="btn btn-ghost btn-sm" data-copy-value="<?= e(otpauthUri($member)) ?>" data-copy-target="copy-totp-status"><i class="fa-regular fa-copy" aria-hidden="true"></i> Copier</button>
              </div>
              <div class="copy-status" id="copy-totp-status" aria-live="polite"></div>
            </div>
          </div>
          <form method="POST">
            <?= csrfField() ?>
            <input type="hidden" name="action" value="enable_totp">
            <div class="form-group">
              <label>Code 6 chiffres de l'application</label>
              <input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code">
            </div>
            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-check" aria-hidden="true"></i> Activer la 2FA</button>
          </form>
          <form method="POST" style="margin-top:12px">
            <?= csrfField() ?>
            <input type="hidden" name="action" value="generate_totp">
            <button type="submit" class="btn btn-ghost"><i class="fa-solid fa-rotate" aria-hidden="true"></i> Regénérer une clé</button>
          </form>
        <?php endif; ?>
      <?php endif; ?>
    </div>
    <?php endif; ?>

  </div>
</div>
<script>
document.querySelectorAll('[data-copy-value]').forEach((copyButton) => {
  const copyStatus = document.getElementById(copyButton.dataset.copyTarget || 'copy-status');
  const defaultLabel = copyButton.innerHTML;
  copyButton.addEventListener('click', async () => {
    const value = copyButton.dataset.copyValue || '';
    let copied = false;
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(value);
        copied = true;
      } catch (error) {
        copied = false;
      }
    }
    if (!copied) {
      const input = document.createElement('input');
      input.value = value;
      input.style.position = 'fixed';
      input.style.opacity = '0';
      document.body.appendChild(input);
      input.select();
      copied = document.execCommand('copy');
      input.remove();
    }
    copyButton.innerHTML = copied
      ? '<i class="fa-solid fa-check" aria-hidden="true"></i> Copié'
      : defaultLabel;
    if (copyStatus) {
      copyStatus.textContent = copied ? 'Copié dans le presse-papiers.' : 'Copie impossible, sélectionne le texte manuellement.';
    }
    window.clearTimeout(copyButton._resetTimer);
    copyButton._resetTimer = window.setTimeout(() => {
      copyButton.innerHTML = defaultLabel;
      if (copyStatus) copyStatus.textContent = '';
    }, 1800);
  });
});
</script>
</body>
</html><?php
}

// ─── AUTH PAGES ─────────────────────────────────────────────
function renderAuthPage(string $mode, ?string $error = null): void { ?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TikLinks — <?= $mode==='register'?'Créer un compte':'Connexion' ?></title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{
  background:#0a0a0f;color:#e0e8ff;font-family:'Segoe UI',Arial,sans-serif;
  min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;
  background-image:radial-gradient(ellipse at 30% 30%,rgba(0,255,255,.06),transparent 60%),radial-gradient(ellipse at 70% 70%,rgba(255,0,255,.06),transparent 60%);
}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,255,.01) 2px,rgba(0,255,255,.01) 4px);pointer-events:none}
.box{width:100%;max-width:400px;padding:20px}
.logo{font-family:'Segoe UI',Arial,sans-serif;font-size:2rem;color:#00ffff;text-shadow:0 0 20px #00ffff,0 0 40px rgba(0,255,255,.3);text-align:center;margin-bottom:8px}
.logo span{color:#ff00ff}
.tagline{text-align:center;color:#7080a0;font-size:.78rem;margin-bottom:32px;letter-spacing:1px}
.card{background:rgba(255,255,255,.04);border:1px solid rgba(0,255,255,.2);border-radius:14px;padding:28px}
.card-title{font-family:'Segoe UI',Arial,sans-serif;font-size:.9rem;color:#00ffff;margin-bottom:20px;text-align:center;letter-spacing:2px}
.form-group{margin-bottom:16px}
label{display:block;font-size:.75rem;color:#7080a0;margin-bottom:6px}
input{width:100%;padding:11px 14px;background:rgba(255,255,255,.04);border:1px solid rgba(0,255,255,.2);border-radius:8px;color:#e0e8ff;font-family:'Segoe UI',Arial,sans-serif;font-size:.9rem;outline:none;transition:all .2s}
input:focus{border-color:#00ffff;box-shadow:0 0 0 2px rgba(0,255,255,.1)}
.btn{width:100%;padding:12px;border:none;border-radius:8px;background:linear-gradient(90deg,#00ffff,#ff00ff);color:#000;font-family:'Segoe UI',Arial,sans-serif;font-size:.95rem;font-weight:700;cursor:pointer;transition:all .25s;margin-top:6px}
.btn:hover{filter:brightness(1.1);transform:translateY(-1px);box-shadow:0 4px 20px rgba(0,255,255,.3)}
.error{background:rgba(255,51,85,.1);border:1px solid rgba(255,51,85,.3);color:#ff3355;padding:10px 14px;border-radius:8px;font-size:.8rem;margin-bottom:14px}
.switch{text-align:center;margin-top:16px;font-size:.8rem;color:#7080a0}
.switch a{color:#00ffff;text-decoration:none}
.switch a:hover{text-shadow:0 0 8px #00ffff}
</style>
</head>
<body>
<div class="box">
  <div class="logo">Tik<span>Links</span></div>
  <div class="tagline">// crée ta page de liens TikTok //</div>
  <div class="card">
    <div class="card-title"><?= $mode==='register'?'CRÉER UN COMPTE':'CONNEXION' ?></div>
    <?php if($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <form method="POST">
      <?= csrfField() ?>
      <input type="hidden" name="action" value="<?= $mode ?>">
      <div class="form-group">
        <label>Nom d'utilisateur</label>
        <input type="text" name="username" placeholder="tonpseudo" required autocomplete="username">
      </div>
      <?php if($mode==='register'): ?>
      <div class="form-group">
        <label>Nom affiché</label>
        <input type="text" name="display_name" placeholder="Ton vrai nom ou pseudo">
      </div>
      <?php endif; ?>
      <div class="form-group">
        <label>Mot de passe</label>
        <input type="password" name="password" placeholder="••••••••" required autocomplete="<?= $mode==='register'?'new-password':'current-password' ?>">
      </div>
      <button type="submit" class="btn"><i class="fa-solid <?= $mode==='register'?'fa-user-plus':'fa-right-to-bracket' ?>" aria-hidden="true"></i> <?= $mode==='register'?'Créer ma page':'Se connecter' ?></button>
    </form>
    <div class="switch">
      <?php if($mode==='register'): ?>
        Déjà un compte ? <a href="?action=login">Connexion</a>
      <?php else: ?>
        Pas encore de compte ? <a href="?action=register">Créer ma page</a>
      <?php endif; ?>
    </div>
  </div>
</div>
</body>
</html><?php
}

function renderTotpPage(?string $error = null): void { ?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TikLinks — Vérification 2FA</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#e0e8ff;font-family:'Segoe UI',Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.box{width:100%;max-width:400px}
.logo{font-size:2rem;color:#00ffff;text-shadow:0 0 20px #00ffff;text-align:center;margin-bottom:8px;font-weight:800}
.logo span{color:#ff00ff}
.tagline{text-align:center;color:#7080a0;font-size:.78rem;margin-bottom:32px;letter-spacing:1px}
.card{background:rgba(255,255,255,.04);border:1px solid rgba(0,255,255,.2);border-radius:14px;padding:28px}
.card-title{font-size:.9rem;color:#00ffff;margin-bottom:20px;text-align:center;letter-spacing:2px;font-weight:800}
.form-group{margin-bottom:16px}
label{display:block;font-size:.75rem;color:#7080a0;margin-bottom:6px}
input{width:100%;padding:11px 14px;background:rgba(255,255,255,.04);border:1px solid rgba(0,255,255,.2);border-radius:8px;color:#e0e8ff;font-family:'Segoe UI',Arial,sans-serif;font-size:1.1rem;text-align:center;letter-spacing:4px;outline:none}
.btn{width:100%;padding:12px;border:none;border-radius:8px;background:linear-gradient(90deg,#00ffff,#ff00ff);color:#000;font-size:.95rem;font-weight:700;cursor:pointer}
.error{background:rgba(255,51,85,.1);border:1px solid rgba(255,51,85,.3);color:#ff3355;padding:10px 14px;border-radius:8px;font-size:.8rem;margin-bottom:14px}
</style>
</head>
<body>
<div class="box">
  <div class="logo">Tik<span>Links</span></div>
  <div class="tagline">// double authentification //</div>
  <div class="card">
    <div class="card-title">CODE 2FA</div>
    <?php if($error): ?><div class="error"><?= e($error) ?></div><?php endif; ?>
    <form method="POST">
      <?= csrfField() ?>
      <input type="hidden" name="action" value="verify_totp">
      <div class="form-group">
        <label>Code 6 chiffres</label>
        <input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code" autofocus>
      </div>
      <button type="submit" class="btn"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i> Vérifier</button>
    </form>
  </div>
</div>
</body>
</html><?php
}

// ─── HOME PAGE ──────────────────────────────────────────────
function renderHome(): void { ?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TikLinks — Crée ta page de liens TikTok</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#e0e8ff;font-family:'Segoe UI',Arial,sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:24px;background-image:radial-gradient(ellipse at 20% 20%,rgba(0,255,255,.08),transparent 60%),radial-gradient(ellipse at 80% 80%,rgba(255,0,255,.08),transparent 60%)}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,255,.012) 2px,rgba(0,255,255,.012) 4px);pointer-events:none}
.logo{font-family:'Segoe UI',Arial,sans-serif;font-size:clamp(2.5rem,8vw,4rem);color:#00ffff;text-shadow:0 0 30px #00ffff,0 0 60px rgba(0,255,255,.4);animation:pulse 3s ease-in-out infinite}
.logo span{color:#ff00ff;text-shadow:0 0 30px #ff00ff}
@keyframes pulse{0%,100%{text-shadow:0 0 30px #00ffff,0 0 60px rgba(0,255,255,.4)}50%{text-shadow:0 0 50px #00ffff,0 0 100px rgba(0,255,255,.6)}}
.tagline{font-size:clamp(.9rem,2.5vw,1.1rem);color:#7080a0;margin:14px 0 40px;line-height:1.6;max-width:480px}
.ctas{display:flex;gap:14px;justify-content:center;flex-wrap:wrap}
.btn{padding:13px 28px;border-radius:10px;font-family:'Segoe UI',Arial,sans-serif;font-size:.95rem;font-weight:700;cursor:pointer;transition:all .25s;text-decoration:none;border:none}
.btn-primary{background:linear-gradient(90deg,#00ffff,#ff00ff);color:#000}
.btn-primary:hover{filter:brightness(1.1);transform:translateY(-2px);box-shadow:0 6px 25px rgba(0,255,255,.4)}
.btn-ghost{background:transparent;border:2px solid rgba(0,255,255,.3);color:#00ffff}
.btn-ghost:hover{border-color:#00ffff;box-shadow:0 0 15px rgba(0,255,255,.2);transform:translateY(-2px)}
.repo-link{display:inline-flex;align-items:center;gap:10px;margin-top:22px;padding:10px 16px;border:1px solid rgba(255,255,255,.14);border-radius:999px;background:rgba(255,255,255,.045);color:#e0e8ff;text-decoration:none;font-size:.82rem;font-weight:700;box-shadow:0 0 24px rgba(0,255,255,.08);transition:all .25s}
.repo-link i{font-size:1.1rem;color:#00ffff}
.repo-link span{color:#ff00ff}
.repo-link:hover{border-color:#00ffff;transform:translateY(-2px);box-shadow:0 8px 28px rgba(0,255,255,.2)}
.features{display:flex;gap:18px;margin-top:50px;flex-wrap:wrap;justify-content:center;max-width:600px}
.feat{background:rgba(255,255,255,.03);border:1px solid rgba(0,255,255,.15);border-radius:12px;padding:18px 20px;flex:1;min-width:160px;text-align:left}
.feat-icon{font-size:1.5rem;margin-bottom:8px}
.feat-title{font-family:'Segoe UI',Arial,sans-serif;font-size:.7rem;color:#00ffff;margin-bottom:4px;letter-spacing:1px}
.feat-desc{font-size:.72rem;color:#7080a0;line-height:1.4}
</style>
</head>
<body>
  <div class="logo">Tik<span>Links</span></div>
  <p class="tagline">Crée gratuitement ta page de liens personnalisée pour TikTok.<br>Six thèmes. Vidéos intégrées. Admin complet.</p>
  <div class="ctas">
    <a href="?action=register" class="btn btn-primary"><i class="fa-solid fa-user-plus" aria-hidden="true"></i> Créer ma page</a>
    <a href="?action=login" class="btn btn-ghost"><i class="fa-solid fa-right-to-bracket" aria-hidden="true"></i> Connexion</a>
  </div>
  <a href="https://github.com/AnARCHIS12/TikLinks" target="_blank" rel="noopener noreferrer" class="repo-link">
    <i class="fa-brands fa-github" aria-hidden="true"></i>
    Dépôt du projet <span>TikLinks</span>
  </a>
  <div class="features">
    <div class="feat"><div class="feat-icon"><i class="fa-solid fa-palette" aria-hidden="true"></i></div><div class="feat-title">6 THÈMES</div><div class="feat-desc">CyberPunk, Punk, Artiste, Vaporwave, Minimaliste, Perso</div></div>
    <div class="feat"><div class="feat-icon"><i class="fa-solid fa-link" aria-hidden="true"></i></div><div class="feat-title">LIENS ILLIMITÉS</div><div class="feat-desc">Ajoute tous tes réseaux avec icônes</div></div>
    <div class="feat"><div class="feat-icon"><i class="fa-solid fa-music" aria-hidden="true"></i></div><div class="feat-title">VIDÉOS TIKTOK</div><div class="feat-desc">Intègre tes meilleures vidéos directement</div></div>
    <div class="feat"><div class="feat-icon"><i class="fa-solid fa-gauge-high" aria-hidden="true"></i></div><div class="feat-title">PAGE RAPIDE</div><div class="feat-desc">PHP + SQLite, aucune dépendance lourde</div></div>
  </div>
</body>
</html><?php
}

// ─── MAIN DISPATCH ───────────────────────────────────────────
if (!empty($slug)) {
    // Public profile page
    $s = $db->prepare("SELECT * FROM members WHERE username=?");
    $s->execute([$slug]);
    $member = $s->fetch(PDO::FETCH_ASSOC);
    if (!$member) { http_response_code(404); die('<h1>Page introuvable</h1>'); }

    $ls = $db->prepare("SELECT * FROM links WHERE member_id=? AND active=1 ORDER BY sort_order,id");
    $ls->execute([$member['id']]);
    $links = $ls->fetchAll(PDO::FETCH_ASSOC);

    $vs = $db->prepare("SELECT * FROM tiktok_videos WHERE member_id=? ORDER BY sort_order,id");
    $vs->execute([$member['id']]);
    $videos = $vs->fetchAll(PDO::FETCH_ASSOC);

    $tpl = resolveTemplate($member, $templates);
    renderPublicPage($member, $links, $videos, $tpl);

} elseif ($action === 'admin') {
    if (!isLoggedIn()) { header('Location: ' . SITE_URL . '?action=login'); exit; }
    $member = currentMember();
    if (!$member) { session_destroy(); header('Location: ' . SITE_URL . '?action=login'); exit; }
    renderAdmin($member, $db, $templates);

} elseif ($action === 'register') {
    if (isLoggedIn()) { header('Location: ' . SITE_URL . '?action=admin'); exit; }
    renderAuthPage('register', $error ?? null);

} elseif ($action === 'login') {
    if (isLoggedIn()) { header('Location: ' . SITE_URL . '?action=admin'); exit; }
    renderAuthPage('login', $error ?? null);

} elseif ($action === 'totp') {
    if (isLoggedIn()) { header('Location: ' . SITE_URL . '?action=admin'); exit; }
    if (empty($_SESSION['pending_totp_member_id'])) { header('Location: ' . SITE_URL . '?action=login'); exit; }
    renderTotpPage($error ?? null);

} else {
    renderHome();
}
