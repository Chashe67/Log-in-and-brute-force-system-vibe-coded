<?php
session_start();

$host = "localhost";
$port = "3306";
$database = "glamhub_db";
$dbUsername = "root";
$dbPassword = "";

try {
    $pdo = new PDO(
        "mysql:host=$host;port=$port;dbname=$database;charset=utf8mb4",
        $dbUsername,
        $dbPassword,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]
    );
} catch (PDOException $e) {
    http_response_code(500);
    die("Database connection failed.");
}

/* ============================================================
   MODE TOGGLE
   ?mode=protected   -> lockout ENABLED
   ?mode=unprotected -> lockout DISABLED
   ============================================================ */
$mode        = $_GET["mode"] ?? "protected";
$isProtected = ($mode === "protected");

$maxAttempts   = 5;
$lockoutWindow = 30 * 60; // 30 minutes

$message          = "";
$messageType      = "error";
$lockoutRemaining = 0;

if (isset($_GET["registered"])) {
    $message     = "Account created! You can now log in.";
    $messageType = "success";
}

$ip = $_SERVER["REMOTE_ADDR"] ?? "0.0.0.0";

/* ============================================================
   Helper: get active lockout for a username + IP
   ============================================================ */
function getActiveLockout($pdo, $username, $ip, $maxAttempts, $lockoutWindow) {
    $stmt = $pdo->prepare(
        "SELECT attempts, last_attempt
         FROM login_attempts
         WHERE username = :username AND ip_address = :ip"
    );
    $stmt->execute([":username" => $username, ":ip" => $ip]);
    $record = $stmt->fetch();

    if (!$record) return 0;

    $attempts = (int)$record["attempts"];
    $lastTime = strtotime($record["last_attempt"]);
    $elapsed  = time() - $lastTime;

    if ($attempts >= $maxAttempts && $elapsed < $lockoutWindow) {
        return $lockoutWindow - $elapsed; // seconds remaining
    }

    return 0;
}

/* ============================================================
   Handle POST
   ============================================================ */
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";

    if ($username === "" || $password === "") {
        $message = "Please enter both username and password.";
    } else {

        $remaining = $isProtected
            ? getActiveLockout($pdo, $username, $ip, $maxAttempts, $lockoutWindow)
            : 0;

        if ($remaining > 0) {
            /* Already locked out */
            http_response_code(429);
            $message          = "Account temporarily locked.";
            $lockoutRemaining = $remaining;
            $_SESSION["lockout_username"] = $username;   // remember for GET
        } else {

            /* Look up the user */
            $stmt = $pdo->prepare(
                "SELECT id, username, password FROM users WHERE username = :username"
            );
            $stmt->execute([":username" => $username]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user["password"])) {

                /* ---- SUCCESS ---- */
                if ($isProtected) {
                    $pdo->prepare(
                        "DELETE FROM login_attempts
                         WHERE username = :username AND ip_address = :ip"
                    )->execute([":username" => $username, ":ip" => $ip]);
                }

                /* Clear any session-side lockout flag */
                unset($_SESSION["lockout_username"]);

                session_regenerate_id(true);
                $_SESSION["user_id"]  = $user["id"];
                $_SESSION["username"] = $user["username"];

                header("Location: dashboard.php");
                exit;

            } else {

                /* ---- FAILED LOGIN ---- */
                if ($isProtected) {

                    /* Increment attempts */
                    $stmt = $pdo->prepare(
                        "SELECT attempts FROM login_attempts
                         WHERE username = :username AND ip_address = :ip"
                    );
                    $stmt->execute([":username" => $username, ":ip" => $ip]);
                    $row = $stmt->fetch();

                    if ($row) {
                        $pdo->prepare(
                            "UPDATE login_attempts
                             SET attempts = attempts + 1, last_attempt = NOW()
                             WHERE username = :username AND ip_address = :ip"
                        )->execute([":username" => $username, ":ip" => $ip]);
                    } else {
                        $pdo->prepare(
                            "INSERT INTO login_attempts
                             (username, ip_address, attempts, last_attempt)
                             VALUES (:username, :ip, 1, NOW())"
                        )->execute([":username" => $username, ":ip" => $ip]);
                    }

                    /* Check whether that failure triggered the lockout */
                    $remaining = getActiveLockout($pdo, $username, $ip, $maxAttempts, $lockoutWindow);

                    if ($remaining > 0) {
                        http_response_code(429);
                        $message          = "Account temporarily locked.";
                        $messageType      = "error";
                        $lockoutRemaining = $remaining;
                        $_SESSION["lockout_username"] = $username;   // remember for GET
                    } else {
                        /* How many tries are left? */
                        $left = $maxAttempts - ((int)($row["attempts"] ?? 0) + 1);
                        if ($left < 0) $left = 0;
                        http_response_code(401);
                        $message = "Invalid username or password. $left attempt" .
                                   ($left === 1 ? "" : "s") . " remaining.";
                    }

                } else {
                    http_response_code(401);
                    $message = "Invalid username or password.";
                }
            }
        }
    }
}

/* ============================================================
   On GET: show countdown ONLY if this session remembers the
   locked-out username AND that lockout is still active in DB.
   This lets you log back in normally after logout, since the
   session (and its lockout flag) is wiped by logout.php.
   ============================================================ */
if ($_SERVER["REQUEST_METHOD"] === "GET" && $isProtected && $lockoutRemaining === 0) {

    if (!empty($_SESSION["lockout_username"])) {
        $lockUser  = $_SESSION["lockout_username"];
        $remaining = getActiveLockout($pdo, $lockUser, $ip, $maxAttempts, $lockoutWindow);

        if ($remaining > 0) {
            $lockoutRemaining = $remaining;
            $message          = "Account temporarily locked.";
        } else {
            /* Lockout expired — clear the session flag */
            unset($_SESSION["lockout_username"]);
        }
    }
}

/* Housekeeping: drop expired rows older than 2x the lockout window */
$pdo->prepare(
    "DELETE FROM login_attempts WHERE last_attempt < (NOW() - INTERVAL :sec SECOND)"
)->execute([":sec" => $lockoutWindow * 2]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GlamHub | Login</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <main class="page-shell">
    <section class="brand-panel">
      <div class="brand-badge">GH</div>
      <p class="eyebrow">Cosmetics Inventory System</p>
      <h1>Welcome back to <em>GlamHub</em></h1>
      <p class="brand-copy">
        Sign in to access your dashboard, manage inventory, and continue where you left off.
      </p>
      <div class="security-note">
        <span class="security-icon">🛡️</span>
        <div>
          <strong>Account Protection</strong>
          <?php if ($isProtected): ?>
            <p>Accounts are temporarily locked for 30 minutes after 5 failed login attempts.</p>
          <?php else: ?>
            <p>Login attempts are monitored for security purposes.</p>
          <?php endif; ?>
        </div>
      </div>
    </section>

    <section class="form-panel">
      <div class="form-card">
        <div class="form-heading">
          <p class="eyebrow">Sign In</p>
          <h2>Login</h2>
          <p>Enter your credentials below.</p>
          <p style="font-size:11px;color:#888;">
            Mode: <strong><?php echo $isProtected ? "PROTECTED" : "UNPROTECTED"; ?></strong>
          </p>
        </div>

        <form method="POST" action="login.php?mode=<?php echo htmlspecialchars($mode); ?>" id="loginForm">
          <div class="field-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" placeholder="Enter username" required
                   autocomplete="username"
                   <?php if ($lockoutRemaining > 0) echo 'disabled'; ?>>
          </div>

          <div class="field-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Enter password" required
                   autocomplete="current-password"
                   <?php if ($lockoutRemaining > 0) echo 'disabled'; ?>>
            <label class="show-pw">
              <input type="checkbox" onclick="togglePw('password')"
                     <?php if ($lockoutRemaining > 0) echo 'disabled'; ?>> Show Password
            </label>
          </div>

          <button type="submit" class="primary-btn"
                  <?php if ($lockoutRemaining > 0) echo 'disabled'; ?>>
            Login
          </button>

          <?php if ($message !== "" && $lockoutRemaining === 0): ?>
            <p class="form-message <?php echo $messageType === 'success' ? 'form-message-success' : ''; ?>">
              <?php echo htmlspecialchars($message, ENT_QUOTES, "UTF-8"); ?>
            </p>
          <?php endif; ?>

          <?php if ($lockoutRemaining > 0): ?>
            <div class="countdown-box">
              <div class="countdown-label">Access Temporarily Suspended</div>
              <div class="countdown-timer" id="countdownTimer">--:--</div>
              <div class="countdown-bar">
                <div class="countdown-bar-fill" id="countdownFill"></div>
              </div>

              <div class="countdown-details">
                <p class="countdown-heading">Why am I locked out?</p>
                <ul>
                  <li>You entered an incorrect password <strong>5 times</strong> in a row.</li>
                  <li>To protect your account, login is suspended for <strong>30 minutes</strong>.</li>
                  <li>You may try again once the timer reaches <strong>00:00</strong>.</li>
                </ul>
              </div>
            </div>
          <?php endif; ?>

          <p class="switch-text">
            Don't have an account? <a href="register.php">Register here</a>
          </p>
        </form>
      </div>
    </section>
  </main>

  <script>
  function togglePw(inputId) {
      const input = document.getElementById(inputId);
      input.type = (input.type === "password") ? "text" : "password";
  }

  <?php if ($lockoutRemaining > 0): ?>
  (function () {
      let remaining = <?php echo (int)$lockoutRemaining; ?>;
      const total   = remaining;
      const timerEl = document.getElementById("countdownTimer");
      const fillEl  = document.getElementById("countdownFill");

      function pad(n) { return n < 10 ? "0" + n : "" + n; }

      function render() {
          const m = Math.floor(remaining / 60);
          const s = remaining % 60;
          timerEl.textContent = pad(m) + ":" + pad(s);

          const pct = total > 0 ? (remaining / total) * 100 : 0;
          fillEl.style.width = pct + "%";

          /* Urgent state in the final 60 seconds */
          if (remaining <= 60 && remaining > 0) {
              timerEl.classList.add("urgent");
              fillEl.classList.add("urgent");
          } else {
              timerEl.classList.remove("urgent");
              fillEl.classList.remove("urgent");
          }

          if (remaining <= 0) {
              timerEl.textContent = "00:00";
              timerEl.classList.remove("urgent");
              fillEl.classList.remove("urgent");
              setTimeout(() => {
                  window.location.href = "login.php?mode=<?php echo htmlspecialchars($mode); ?>";
              }, 800);
              return;
          }

          remaining--;
          setTimeout(render, 1000);
      }
      render();
  })();
  <?php endif; ?>
  </script>
</body>
</html>