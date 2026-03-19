<?php
// ═══════════════════════════════════════════════════════════════
// TEST FILE: vuln_php.php
// EXPECTED: 7 findings (all True Positives)
// ═══════════════════════════════════════════════════════════════


// ── VULN 1: SQL Injection (CWE-89) ──────────────────────────
// EXPECTED: Critical — user input concatenated into query
function getUser($conn) {
    $id = $_GET['id'];
    $result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    return mysqli_fetch_assoc($result);
}


// ── VULN 2: Command Injection (CWE-78) ──────────────────────
// EXPECTED: Critical — user input passed to system()
function pingHost() {
    $host = $_GET['host'];
    system("ping -c 4 " . $host);
}


// ── VULN 3: XSS (CWE-79) ───────────────────────────────────
// EXPECTED: High — unescaped user input echoed to page
function searchResults() {
    $query = $_GET['q'];
    echo "<h1>Results for: " . $query . "</h1>";
    echo "<p>No results found for " . $_REQUEST['q'] . "</p>";
}


// ── VULN 4: File Inclusion (CWE-98) ────────────────────────
// EXPECTED: High — user input in include()
function loadPage() {
    $page = $_GET['page'];
    include($page . ".php");
}


// ── VULN 5: Insecure Deserialization (CWE-502) ─────────────
// EXPECTED: Critical — unserialize on user data
function loadSession() {
    $data = $_COOKIE['session_data'];
    $session = unserialize($data);
    return $session;
}


// ── VULN 6: Hardcoded Credentials (CWE-798) ────────────────
// EXPECTED: High — database credentials in source
$db_password = "mysql_prod_password_2024";
$api_secret = "sk-live-php-abcdef123456789";

function connectDB() {
    $conn = mysqli_connect("localhost", "root", "mysql_prod_password_2024", "production_db");
    return $conn;
}


// ── VULN 7: Weak Hash (CWE-328) ────────────────────────────
// EXPECTED: Medium — MD5 for password hashing
function hashPassword($password) {
    return md5($password);
}

function verifyPassword($password, $hash) {
    return md5($password) === $hash;
}
?>
