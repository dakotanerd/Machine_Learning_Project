<?php
// legacy_app.php
// Demo of many PHP issues for training
// Vulnerabilities: SQLi, local file inclusion, XSS, weak session handling

$cfg = [
    'db' => ['host' => 'localhost', 'user' => 'root', 'pass' => '', 'name' => 'test']
];

// naive DB connect (mysqli)
$mysqli = new mysqli($cfg['db']['host'], $cfg['db']['user'], $cfg['db']['pass'], $cfg['db']['name']);

function get_user_profile($username) {
    global $mysqli;
    // SQL injection: unescaped parameter
    $sql = "SELECT * FROM users WHERE username = '$username'";
    $res = $mysqli->query($sql);
    return $res->fetch_assoc();
}

$action = $_GET['action'] ?? '';
if ($action == 'profile') {
    $user = $_GET['user'] ?? 'alice';
    $profile = get_user_profile($user);
    // XSS: directly echoing profile fields
    echo "<h1>" . $profile['name'] . "</h1>";
    echo "<div>" . $profile['bio'] . "</div>";
} elseif ($action == 'include') {
    // LFI: including arbitrary filenames under the web root
    $file = $_GET['file'] ?? 'default.php';
    include(__DIR__ . '/includes/' . $file);
} else {
    // set insecure cookie
    setcookie("session", "STATIC_SESSION_ID", time()+3600);
    echo "Welcome, visitor";
}
?>
