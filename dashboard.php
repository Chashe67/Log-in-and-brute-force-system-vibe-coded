<?php
session_start();
if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GlamHub · Dashboard</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="dash-shell">
    <nav class="dash-nav">
      <div class="logo">
        <div class="logo-badge">GH</div>
        GlamHub
      </div>
      <a href="logout.php" class="logout-btn">↪ Logout</a>
    </nav>

    <main class="dash-main">
      <div class="dash-container">
        <div class="welcome-card">
          <h1>Welcome, <?php echo htmlspecialchars($_SESSION["username"]); ?> 👋</h1>
          <p>You're signed in. Here's a quick overview of your account.</p>

          <div class="dash-stats">
            <div class="dash-stat">
              <div class="label">Status</div>
              <div class="value green">● Active</div>
            </div>
            <div class="dash-stat">
              <div class="label">Session</div>
              <div class="value">Secure</div>
            </div>
            <div class="dash-stat">
              <div class="label">Role</div>
              <div class="value">User</div>
            </div>
          </div>

          <a href="lab_test.php" class="btn btn-secondary" style="text-decoration:none;display:inline-flex;">
            🧪 Open Security Verification Tool
          </a>
        </div>
      </div>
    </main>
  </div>
</body>
</html>