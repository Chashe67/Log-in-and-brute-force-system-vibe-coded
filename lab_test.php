<?php
/* ============================================================
   CYBER LAB · Authentication Tester
   - Accepts target URL, identifier type (username/email),
     and identifier value from the UI form.
   - Attempts a candidate password list against the login
     endpoint and reports whether the credentials are traceable.
   - Detects HTTP 429 (lockout active) → NOT traceable.
   - Localhost only.
   ============================================================ */

/* Defaults (used only if the form leaves fields blank) */
$default_target      = "http://localhost/System/login.php";
$default_login_type  = "username";
$default_login_value = "admin12";
$password_field      = "password";

$common_passwords = [
    "1234",
    "12345",
    "123456",
    "12345678",
    "password",
    "password123",
    "admin",
    "admin123",
    "admin1234",
    "qwerty",
    "welcome",
    "student",
    "student123"
];

$numeric_passwords = [];
for ($i = 0; $i <= 5000; $i++) {
    $numeric_passwords[] = str_pad($i, 6, "0", STR_PAD_LEFT);
}

$password_list = array_merge($common_passwords, $numeric_passwords);
$password_list = array_values(array_unique($password_list));

/* ---- Read values from the UI form (query string) ---- */
$target      = trim($_GET["target"]   ?? $default_target);
$login_type  = trim($_GET["type"]     ?? $default_login_type);
$login_value = trim($_GET["username"] ?? $default_login_value);

/* ---- Validate host ---- */
$parsed_url = parse_url($target);
$host = $parsed_url["host"] ?? "";
$allowed_hosts = ["localhost", "127.0.0.1", "::1"];

if (!in_array($host, $allowed_hosts, true)) {
    http_response_code(403);
    die("ACCESS DENIED");
}

/* ---- Validate identifier type ---- */
if (!in_array($login_type, ["username", "email"], true)) {
    $login_type = "username";
}

/* ============================================================
   Login tester
   ============================================================ */
function test_login($url, $login_type, $login_value, $password_field, $password) {
    $post_data = [];

    if ($login_type === "username") {
        $post_data["username"] = $login_value;
    } elseif ($login_type === "email") {
        $post_data["email"] = $login_value;
    } else {
        return ["success" => false, "blocked" => false, "http_code" => 0, "error" => "Invalid login type."];
    }

    $post_data[$password_field] = $password;

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post_data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_USERAGENT, "Cyber-Lab-Localhost-Tester/1.1");

    $response = curl_exec($ch);

    if ($response === false) {
        $error = curl_error($ch);
        curl_close($ch);
        return ["success" => false, "blocked" => false, "http_code" => 0, "error" => $error];
    }

    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $redirect  = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
    curl_close($ch);

    $success = ($http_code >= 300 && $http_code < 400);
    $blocked = ($http_code === 429);

    return [
        "success"   => $success,
        "blocked"   => $blocked,
        "http_code" => $http_code,
        "redirect"  => $redirect,
        "error"     => ""
    ];
}

/* ============================================================
   Streaming test
   ============================================================ */
if (isset($_GET["start"])) {
    @ini_set("output_buffering", "off");
    @ini_set("zlib.output_compression", "0");
    @ini_set("implicit_flush", "1");

    while (ob_get_level() > 0) { @ob_end_flush(); }
    ob_implicit_flush(true);

    header("Content-Type: text/plain; charset=UTF-8");
    header("Cache-Control: no-cache, no-store, must-revalidate");
    header("Pragma: no-cache");
    header("Expires: 0");
    header("X-Accel-Buffering: no");

    $start_time = microtime(true);

    echo "╔════════════════════════════════════════════╗\n";
    echo "║        CYBER AUTHENTICATION LAB            ║\n";
    echo "║        LOCALHOST TESTING TERMINAL          ║\n";
    echo "╚════════════════════════════════════════════╝\n\n";

    echo "[+] Initializing laboratory test...\n";
    echo "[+] Target      : $target\n";
    echo "[+] Identifier  : $login_type\n";
    echo "[+] Login Value : $login_value\n";
    echo "[+] Password    : $password_field\n";
    echo "[+] Candidates  : " . count($password_list) . "\n";
    echo "[+] Environment : LOCALHOST\n";
    echo "\n";
    echo "──────────────────────────────────────────────\n\n";

    @ob_flush(); @flush();

    $attempt      = 0;
    $blockedSeen  = false;
    $foundPassword = null;
    $lastHttp     = 0;

    foreach ($password_list as $password) {
        $attempt++;

        $result    = test_login($target, $login_type, $login_value, $password_field, $password);
        $http_code = $result["http_code"];
        $lastHttp  = $http_code;

        if (!empty($result["error"])) {
            echo "[ERROR] " . $result["error"] . "\n";
            break;
        }

        /* Lockout detected → credentials are NOT traceable */
        if ($result["blocked"]) {
            $blockedSeen = true;
            echo sprintf("[%04d] %-18s [HTTP %d]  ", $attempt, $password, $http_code);
            echo ">>> BLOCKED (lockout active) <<<\n\n";
            @ob_flush(); @flush();
            break;
        }

        /* Password found → credentials ARE traceable */
        if ($result["success"]) {
            $foundPassword = $password;
            echo sprintf("[%04d] %-18s [HTTP %d]  ", $attempt, $password, $http_code);
            echo ">>> SUCCESS <<<\n\n";
            @ob_flush(); @flush();
            break;
        }

        echo sprintf("[%04d] %-18s [HTTP %d]  FAILED\n", $attempt, $password, $http_code);
        @ob_flush(); @flush();
        usleep(50000);
    }

    $elapsed = microtime(true) - $start_time;

    echo "\n";
    echo "──────────────────────────────────────────────\n\n";

    /* ============================================================
       Verdict
       ============================================================ */
    echo "╔════════════════════════════════════════════╗\n";
    echo "║                VERDICT                     ║\n";
    echo "╚════════════════════════════════════════════╝\n\n";

    echo "[+] Login Identifier : " . $login_value . "\n";
    echo "[+] Identifier Type  : " . $login_type . "\n";

    if ($foundPassword !== null) {
        echo "[+] Credential       : TRACEABLE\n";
        echo "[+] Recovered        : " . $foundPassword . "\n";
        echo "[+] Attempts         : " . $attempt . "\n";
        echo "[+] HTTP Status      : " . $lastHttp . "\n";
        echo "\n";
        echo "[!] RESULT: PASSWORD TRACEABLE\n";
        echo "[!] The account has no effective rate limiting.\n";
        echo "[!] An attacker can recover the password by brute force.\n";
    } elseif ($blockedSeen) {
        echo "[+] Credential       : NOT TRACEABLE\n";
        echo "[+] Reason           : server returned HTTP 429 (rate limited).\n";
        echo "[+] Attempts before block : " . $attempt . "\n";
        echo "\n";
        echo "[✓] RESULT: PASSWORD NOT TRACEABLE\n";
        echo "[✓] The account is protected by a lockout / rate limit.\n";
        echo "[✓] Brute-force recovery is not feasible.\n";
    } elseif ($attempt >= count($password_list)) {
        echo "[+] Credential       : NOT TRACEABLE\n";
        echo "[+] Reason           : none of the " . count($password_list) . " candidates matched.\n";
        echo "[+] Attempts         : " . $attempt . "\n";
        echo "\n";
        echo "[?] RESULT: PASSWORD NOT IN TEST LIST\n";
        echo "[?] The password is strong (or uncommon). But note that the\n";
        echo "[?] server never returned HTTP 429 — meaning there is no\n";
        echo "[?] lockout. A larger attack would still eventually succeed.\n";
    } else {
        echo "[+] Credential       : UNKNOWN\n";
        echo "[+] Reason           : test did not complete.\n";
    }

    echo "\n";
    echo "[+] Elapsed Time     : " . number_format($elapsed, 2) . " seconds\n";
    echo "[+] TEST COMPLETE.\n";
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CYBER LAB // Authentication Tester</title>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; width: 100%; min-height: 100%; font-family: "Courier New", Consolas, monospace; background: #020604; color: #00ff88; }
body { overflow-x: hidden; background: radial-gradient(circle at 50% 0%, rgba(0,255,120,0.08), transparent 40%), radial-gradient(circle at 0% 100%, rgba(0,180,255,0.06), transparent 35%), #020604; }
body::before { content: ""; position: fixed; inset: 0; pointer-events: none; opacity: 0.08; background-image: linear-gradient(rgba(0,255,120,0.15) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,120,0.15) 1px, transparent 1px); background-size: 40px 40px; animation: gridMove 12s linear infinite; }
@keyframes gridMove { from { background-position: 0 0, 0 0; } to { background-position: 0 40px, 40px 0; } }
.wrapper { position: relative; z-index: 1; width: min(1400px, 94%); margin: 30px auto 50px; }
.header { display: flex; justify-content: space-between; align-items: center; padding: 18px 22px; border: 1px solid rgba(0,255,120,0.35); background: rgba(0,10,6,0.88); box-shadow: 0 0 30px rgba(0,255,120,0.08); border-radius: 8px 8px 0 0; }
.logo { display: flex; align-items: center; gap: 14px; }
.logo-icon { width: 42px; height: 42px; display: flex; align-items: center; justify-content: center; border: 1px solid #00ff88; color: #00ff88; font-size: 20px; box-shadow: 0 0 15px rgba(0,255,120,0.4); }
.logo-title { font-size: 18px; font-weight: bold; letter-spacing: 2px; color: #00ff88; }
.logo-sub { color: #4f9f78; font-size: 11px; margin-top: 3px; letter-spacing: 1px; }
.local-status { display: flex; align-items: center; gap: 9px; padding: 8px 13px; border: 1px solid rgba(0,255,120,0.35); color: #00ff88; font-size: 11px; letter-spacing: 1px; background: rgba(0,255,120,0.04); }
.status-dot { width: 9px; height: 9px; border-radius: 50%; background: #00ff88; box-shadow: 0 0 12px #00ff88; animation: pulse 1.4s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
.content { display: grid; grid-template-columns: 380px 1fr; gap: 18px; margin-top: 18px; }
@media(max-width:900px) { .content { grid-template-columns: 1fr; } }
.panel { border: 1px solid rgba(0,255,120,0.25); background: rgba(1,12,8,0.90); box-shadow: 0 0 25px rgba(0,255,120,0.04); border-radius: 6px; overflow: hidden; }
.panel-header { display: flex; justify-content: space-between; padding: 12px 15px; border-bottom: 1px solid rgba(0,255,120,0.18); background: rgba(0,255,120,0.035); font-size: 11px; letter-spacing: 1.5px; }
.panel-header span:first-child { color: #00ff88; }
.panel-header span:last-child { color: #276b4c; }
.config { padding: 18px; }
.field { margin-bottom: 17px; }
.field label { display: block; margin-bottom: 7px; color: #52b88a; font-size: 10px; letter-spacing: 1px; }
input, select { width: 100%; padding: 12px 13px; border: 1px solid rgba(0,255,120,0.25); outline: none; background: #020805; color: #00ff88; font-family: inherit; font-size: 12px; border-radius: 3px; transition: .2s; }
input:focus, select:focus { border-color: #00ff88; box-shadow: 0 0 12px rgba(0,255,120,0.18); }
select option { background: #020805; color: #00ff88; }
.buttons { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 20px; }
button { padding: 13px; border: 1px solid #00ff88; background: rgba(0,255,120,0.07); color: #00ff88; font-family: inherit; font-weight: bold; font-size: 11px; letter-spacing: 1px; cursor: pointer; border-radius: 3px; transition: .2s; }
button:hover { background: rgba(0,255,120,0.18); box-shadow: 0 0 18px rgba(0,255,120,0.25); }
#stopBtn { border-color: #ff3355; color: #ff3355; background: rgba(255,30,70,0.05); }
#stopBtn:hover { background: rgba(255,30,70,0.12); box-shadow: 0 0 18px rgba(255,30,70,0.2); }
.stats { display: grid; grid-template-columns: repeat(4,1fr); gap: 10px; padding: 15px; }
.stat { border: 1px solid rgba(0,255,120,0.16); background: rgba(0,0,0,0.25); padding: 13px; text-align: center; }
.stat-label { color: #347858; font-size: 9px; letter-spacing: 1px; margin-bottom: 7px; }
.stat-value { color: #00ff88; font-size: 18px; font-weight: bold; }
.terminal-panel { min-height: 650px; }
.terminal { margin: 0; height: 560px; overflow-y: auto; padding: 18px; background: #010302; color: #00ff88; font-size: 12px; line-height: 1.7; white-space: pre-wrap; text-shadow: 0 0 5px rgba(0,255,120,0.45); scrollbar-width: thin; scrollbar-color: #0c603b #010302; }
.terminal::before { content: "root@localhost:~$ "; color: #00bfff; }
.falling-code { position: fixed; top: 0; bottom: 0; width: 170px; overflow: hidden; pointer-events: none; z-index: 0; opacity: 0.42; font-family: "Courier New", Consolas, monospace; color: #00ff88; text-shadow: 0 0 7px rgba(0,255,120,0.55); }
.falling-code.left { left: 0; } .falling-code.right { right: 0; }
.falling-column { position: absolute; top: -220px; white-space: pre; font-size: 12px; line-height: 1.55; animation: codeFall linear infinite; }
@keyframes codeFall { from { transform: translateY(-260px); } to { transform: translateY(calc(100vh + 300px)); } }
@media(max-width:1100px) { .falling-code { width: 95px; opacity: 0.25; } }
@media(max-width:900px) { .falling-code { display: none; } }
.terminal .failed-line { color: #ff4d6d !important; font-weight: 700; text-shadow: 0 0 6px rgba(255, 77, 109, 0.45); }
.terminal .success-line { color: #00ffff !important; font-weight: 800; text-shadow: 0 0 8px rgba(0, 255, 255, 0.65); }
.terminal .blocked-line { color: #ffb347 !important; font-weight: 800; text-shadow: 0 0 8px rgba(255, 179, 71, 0.65); }
.terminal .attempt-line { font-weight: 700; }
.terminal-bar { display: flex; align-items: center; gap: 7px; padding: 9px 12px; border-bottom: 1px solid rgba(0,255,120,0.15); background: #050807; }
.terminal-circle { width: 9px; height: 9px; border-radius: 50%; background: #244c37; }
.terminal-title { margin-left: 8px; color: #3d805f; font-size: 10px; }
.footer { margin-top: 18px; padding: 14px; text-align: center; border: 1px solid rgba(0,255,120,0.15); color: #286044; font-size: 10px; letter-spacing: 1px; background: rgba(0,10,6,0.7); }
.warning { margin: 0 18px 18px; padding: 11px; border: 1px solid rgba(255,190,0,0.3); background: rgba(255,180,0,0.04); color: #c9a84b; font-size: 10px; line-height: 1.6; }
</style>
</head>
<body>
<div class="falling-code left" id="fallingLeft"></div>
<div class="falling-code right" id="fallingRight"></div>
<div class="wrapper">
    <div class="header">
        <div class="logo">
            <div class="logo-icon">&gt;_</div>
            <div>
                <div class="logo-title">CYBER LAB</div>
                <div class="logo-sub">AUTHENTICATION SECURITY TESTER</div>
            </div>
        </div>
        <div class="local-status"><span class="status-dot"></span>LOCALHOST ONLY</div>
    </div>
    <div class="content">
        <div>
            <div class="panel">
                <div class="panel-header"><span>TARGET CONFIGURATION</span><span>[CONFIG]</span></div>
                <div class="config">
                    <div class="field">
                        <label>TARGET LOGIN URL</label>
                        <input type="text" id="target" value="<?php echo htmlspecialchars($target); ?>">
                    </div>
                    <div class="field">
                        <label>LOGIN IDENTIFIER</label>
                        <select id="loginType">
                            <option value="username" <?php if ($login_type === "username") echo "selected"; ?>>USERNAME</option>
                            <option value="email" <?php if ($login_type === "email") echo "selected"; ?>>EMAIL</option>
                        </select>
                    </div>
                    <div class="field">
                        <label>LOGIN VALUE</label>
                        <input type="text" id="loginValue" value="<?php echo htmlspecialchars($login_value); ?>">
                    </div>
                    <div class="warning">⚠ AUTHORIZED LAB USE ONLY<br>This tester is restricted to localhost environments.</div>
                    <div class="buttons">
                        <button id="startBtn">▶ START TEST</button>
                        <button id="stopBtn">■ STOP</button>
                    </div>
                </div>
            </div>
            <div class="panel" style="margin-top:18px;">
                <div class="panel-header"><span>SYSTEM STATUS</span><span>[ONLINE]</span></div>
                <div class="stats">
                    <div class="stat"><div class="stat-label">CANDIDATES</div><div class="stat-value"><?php echo count($password_list); ?></div></div>
                    <div class="stat"><div class="stat-label">ATTEMPTS</div><div class="stat-value" id="attemptStat">0</div></div>
                    <div class="stat"><div class="stat-label">FAILED</div><div class="stat-value" id="failedStat">0</div></div>
                    <div class="stat"><div class="stat-label">STATUS</div><div class="stat-value" id="statusStat">IDLE</div></div>
                </div>
            </div>
        </div>
        <div class="panel terminal-panel">
            <div class="terminal-bar">
                <span class="terminal-circle"></span><span class="terminal-circle"></span><span class="terminal-circle"></span>
                <span class="terminal-title">CYBER-LAB TERMINAL // localhost</span>
            </div>
            <div class="terminal" id="output">
╔════════════════════════════════════════════╗
║        CYBER AUTHENTICATION LAB            ║
║        LOCALHOST TESTING TERMINAL          ║
╚════════════════════════════════════════════╝

root@localhost:~$ system-check

[+] Environment : LOCALHOST
[+] Security    : LOCAL TARGET ONLY
[+] Status      : READY

root@localhost:~$ waiting for test...
            </div>
        </div>
    </div>
    <div class="footer">CYBERSECURITY LABORATORY // AUTHENTICATION SECURITY ANALYSIS // LOCAL ENVIRONMENT</div>
</div>
<script>
let running = false;
let controller = null;
document.getElementById("startBtn").addEventListener("click", async function () {
    if (running) return;
    running = true;
    const output = document.getElementById("output");
    const status = document.getElementById("statusStat");
    const attempts = document.getElementById("attemptStat");
    const failedStat = document.getElementById("failedStat");

    output.textContent = "root@localhost:~$ ./auth-test\n\n";
    attempts.textContent = "0";
    if (failedStat) failedStat.textContent = "0";
    status.textContent = "RUNNING";
    status.style.color = "#00bfff";

    const target = document.getElementById("target").value;
    const loginType = document.getElementById("loginType").value;
    const loginValue = document.getElementById("loginValue").value;

    output.textContent += "[*] Initializing test...\n";
    output.textContent += "[*] Target      : " + target + "\n";
    output.textContent += "[*] Identifier  : " + loginType + "\n";
    output.textContent += "[*] Login Value : " + loginValue + "\n";
    output.textContent += "[*] Environment : LOCALHOST\n";
    output.textContent += "---------------------------------------------\n";
    output.scrollTop = output.scrollHeight;

    try {
        controller = new AbortController();
        const params = new URLSearchParams({
            start:    "1",
            target:   target,
            type:     loginType,
            username: loginValue,
            _:        Date.now()
        });
        const response = await fetch("lab_test.php?" + params.toString(), {
            method: "GET", cache: "no-store", signal: controller.signal
        });
        if (!response.ok) throw new Error("HTTP " + response.status);
        if (!response.body) throw new Error("Streaming response is not available.");

        const reader = response.body.getReader();
        const decoder = new TextDecoder("utf-8");

        while (true) {
            const result = await reader.read();
            if (result.done) break;
            const chunk = decoder.decode(result.value, { stream: true });
            if (!chunk) continue;

            const lines = chunk.split("\n");
            lines.forEach(function (lineText, index) {
                if (index === lines.length - 1 && lineText === "") return;
                const line = document.createElement("div");
                line.textContent = lineText;
                if (lineText.indexOf(">>> SUCCESS <<<") !== -1) line.className = "success-line";
                else if (lineText.indexOf(">>> BLOCKED") !== -1) line.className = "blocked-line";
                else if (lineText.indexOf("FAILED") !== -1) line.className = "failed-line";
                else if (lineText.match(/^\[\d+\]/)) line.className = "attempt-line";
                output.appendChild(line);
            });

            const attemptMatches = chunk.match(/\[(\d+)\]/g);
            if (attemptMatches && attemptMatches.length) {
                const last = attemptMatches[attemptMatches.length - 1];
                attempts.textContent = parseInt(last.replace(/\D/g, ""), 10);
            }
            if (failedStat) {
                const failedMatches = chunk.match(/FAILED/g);
                if (failedMatches) failedStat.textContent = parseInt(failedStat.textContent || "0", 10) + failedMatches.length;
            }
            if (chunk.indexOf(">>> SUCCESS <<<") !== -1) {
                status.textContent = "TRACEABLE";
                status.style.color = "#ff3355";
            }
            if (chunk.indexOf(">>> BLOCKED") !== -1) {
                status.textContent = "PROTECTED";
                status.style.color = "#00ff88";
            }
            output.scrollTop = output.scrollHeight;
            requestAnimationFrame(function () {
                output.scrollTo({ top: output.scrollHeight, left: 0, behavior: "auto" });
            });
        }
    } catch (error) {
        if (error.name === "AbortError") {
            output.textContent += "\n\n[!] PROCESS STOPPED BY USER.\n";
            status.textContent = "STOPPED";
            status.style.color = "#ff3355";
        } else {
            output.textContent += "\n\n[ERROR] " + error.message + "\n";
            status.textContent = "ERROR";
            status.style.color = "#ff3355";
        }
        output.scrollTop = output.scrollHeight;
    }
    running = false;
    controller = null;
    if (status.textContent === "RUNNING") {
        status.textContent = "DONE";
        status.style.color = "#00ff88";
    }
});
document.getElementById("stopBtn").addEventListener("click", function () {
    if (controller && running) controller.abort();
    running = false;
});
document.getElementById("loginType").addEventListener("change", function () {
    const loginValue = document.getElementById("loginValue");
    if (this.value === "email") loginValue.placeholder = "example@gmail.com";
    else loginValue.placeholder = "Enter username";
});
setInterval(function () {
    if (running) {
        const output = document.getElementById("output");
        if (output) output.scrollTop = output.scrollHeight;
    }
}, 100);
(function () {
    const characters = "01ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz<>[]{}#$%&@";
    function randomCode(length) {
        let result = "";
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * characters.length));
            if (i % 3 === 2) result += "\n";
        }
        return result;
    }
    function createColumns(containerId, count) {
        const container = document.getElementById(containerId);
        if (!container) return;
        for (let i = 0; i < count; i++) {
            const column = document.createElement("div");
            column.className = "falling-column";
            column.textContent = randomCode(95 + Math.floor(Math.random() * 55));
            column.style.left = (5 + Math.random() * 88) + "%";
            column.style.animationDuration = (7 + Math.random() * 10) + "s";
            column.style.animationDelay = (-Math.random() * 12) + "s";
            column.style.opacity = (0.25 + Math.random() * 0.65).toFixed(2);
            column.style.fontSize = (9 + Math.random() * 5) + "px";
            container.appendChild(column);
        }
    }
    createColumns("fallingLeft", 7);
    createColumns("fallingRight", 7);
})();
</script>
</body>
</html>