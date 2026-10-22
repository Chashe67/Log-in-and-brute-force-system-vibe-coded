<?php
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

$message = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";

    if ($username === "" || $password === "") {
        $message = "Please fill in all fields.";
    } elseif (strlen($password) < 8) {
        $message = "Password must be at least 8 characters.";
    } else {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);

        if ($stmt->fetch()) {
            $message = "That username is already taken.";
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
            $stmt->execute([$username, $hash]);

            header("Location: login.php?registered=1");
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GlamHub · Register</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <main class="page-shell">
    <section class="brand-panel">
      <div class="brand-badge">GH</div>
      <p class="eyebrow">Get Started</p>
      <h1>Create your <em>GlamHub</em> account.</h1>
      <p class="brand-copy">
        Join the platform to manage inventory, monitor stock levels, and keep your catalog in sync.
      </p>
      <div class="security-note">
        <span class="security-icon">🔐</span>
        <div>
          <strong>Secure by Default</strong>
          <p>Passwords are hashed and protected against brute-force attempts.</p>
        </div>
      </div>
    </section>

    <section class="form-panel">
      <div class="form-card">
        <div class="form-heading">
          <p class="eyebrow">Sign Up</p>
          <h2>Create Account</h2>
          <p>Just a username and password to get started.</p>
        </div>

        <form method="POST" action="register.php">
          <div class="field-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" placeholder="Choose a username" required autocomplete="username">
          </div>

          <div class="field-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="At least 8 characters" required autocomplete="new-password">
            <label class="show-pw">
              <input type="checkbox" onclick="togglePw('password')"> Show password
            </label>
          </div>

          <button type="submit" class="primary-btn">Create Account</button>

          <?php if ($message !== ""): ?>
            <p class="form-message"><?php echo htmlspecialchars($message, ENT_QUOTES, "UTF-8"); ?></p>
          <?php endif; ?>

          <p class="switch-text">
            Already have an account? <a href="login.php">Sign in</a>
          </p>
        </form>
      </div>
    </section>
  </main>

  <script>
  function togglePw(id) {
      const input = document.getElementById(id);
      input.type = (input.type === "password") ? "text" : "password";
  }
  </script>
</body>
</html>