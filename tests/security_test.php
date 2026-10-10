<?php
declare(strict_types=1);

// Security Unit Tests for TikLinks

require_once __DIR__ . '/../index.php';

echo "Running TikLinks Security Verification Suite...\n\n";

$passed = 0;
$failed = 0;

function assertTest(string $name, bool $condition): void {
    global $passed, $failed;
    if ($condition) {
        echo " [PASS] " . $name . "\n";
        $passed++;
    } else {
        echo " [FAIL] " . $name . "\n";
        $failed++;
    }
}

// 1. Test safeCssUrl against XSS payloads
$xssPayloads = [
    'https://evil.com/bg.png</style><script>alert(1)</script>' => '',
    'javascript:alert(1)' => '',
    'data:text/html,<script>alert(1)</script>' => '',
    'https://evil.com/bg.png" onmouseover="alert(1)' => '',
    'https://evil.com/bg.png\' onmouseover=\'alert(1)' => '',
    'https://evil.com/bg.png; color:red' => '',
    'https://evil.com/bg.png\\)' => '',
];

foreach ($xssPayloads as $payload => $expected) {
    assertTest("safeCssUrl rejects XSS: " . substr($payload, 0, 40), safeCssUrl($payload) === $expected);
}

// Test safe URL
assertTest("safeCssUrl accepts safe HTTPS url", safeCssUrl("https://example.com/assets/bg.jpg") === "https://example.com/assets/bg.jpg");

// 2. Test Rate Limiting
$testDb = new PDO('sqlite::memory:');
$testDb->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$testDb->exec("
    CREATE TABLE rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        action TEXT NOT NULL,
        attempted_at INTEGER NOT NULL
    );
    CREATE INDEX idx_rate_limits_lookup ON rate_limits (key, action, attempted_at);
");

$testKey = 'test_ip_127.0.0.1';
assertTest("Rate limit initial check passes", checkRateLimit($testDb, $testKey, 'login', 5, 900) === true);

for ($i = 0; $i < 4; $i++) {
    recordRateLimitAttempt($testDb, $testKey, 'login');
}
assertTest("Rate limit allows 4 attempts", checkRateLimit($testDb, $testKey, 'login', 5, 900) === true);

recordRateLimitAttempt($testDb, $testKey, 'login'); // 5th attempt
assertTest("Rate limit triggers on 5th attempt", checkRateLimit($testDb, $testKey, 'login', 5, 900) === false);

clearRateLimit($testDb, $testKey, 'login');
assertTest("Rate limit cleared successfully", checkRateLimit($testDb, $testKey, 'login', 5, 900) === true);

// 3. Test assetUrl
assertTest("assetUrl returns local relative path", str_contains(assetUrl('fontawesome/css/all.min.css'), 'assets/fontawesome/css/all.min.css'));

// 4. Test Local Icon Support
assertTest("normalizeIcon maps local militant icon", normalizeIcon('assets/icons/militant.svg') === 'assets/icons/militant.svg');
assertTest("renderIcon renders local militant svg without cdn", str_contains(renderIcon('assets/icons/militant.svg'), 'icons/militant.svg'));

// 5. Test TOTP functions
$secret = generateTotpSecret();
assertTest("generateTotpSecret returns 32-char Base32", strlen($secret) === 32);
$currentTotp = hotp($secret, intdiv(time(), 30));
assertTest("verifyTotp validates current code", verifyTotp($secret, $currentTotp) === true);
assertTest("verifyTotp rejects bad code", verifyTotp($secret, '000000') === false || $currentTotp === '000000');

echo "\nSummary: {$passed} passed, {$failed} failed.\n";
if ($failed > 0) {
    exit(1);
}
