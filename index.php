<?php
// هر بار صفحه بارگذاری شود، یک توکن جدید تولید می‌شود
$user_token = bin2hex(random_bytes(5));
$domain = "tst.bstways.ir";

// Get the base URL for assets
$base_url = rtrim(dirname($_SERVER['PHP_SELF']), '/');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Tester</title>
    <!-- Material Icons -->
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <!-- Roboto Font -->
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <!-- Custom CSS -->
    <link href="<?php echo $base_url; ?>/styles.css" rel="stylesheet">
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
        <i class="material-icons">dark_mode</i>
    </button>

    <div class="container">
        <div class="content-wrapper">
            <h1>📩 Email Tester</h1>
            
            <div class="card">
                <p>Send an email to the following address:</p>
                
                <div class="email-input-container">
                    <input type="text" 
                           id="userEmail" 
                           class="input-field" 
                           value="user-<?php echo $user_token; ?>@<?php echo $domain; ?>"
                           onchange="validateEmail(this)">
                    <button class="copy-button" onclick="copyEmail()" title="Copy to clipboard">
                        <i class="material-icons">content_copy</i>
                    </button>
                </div>

                <p class="info">You can edit the token or paste a previous one to check older emails</p>
                
                <button class="check-button" onclick="checkEmail()">
                    <i class="material-icons">search</i>
                    Check Email
                </button>
            </div>

            <div class="loading-container" id="loading">
                <div class="loading-spinner"></div>
                <p class="loading-text">Checking email...</p>
                <p class="loading-timer" id="timer">Waiting for email... (0:00)</p>
            </div>

            <div class="timeout-message" id="timeout-message">
                <i class="material-icons" style="vertical-align: middle;">timer_off</i>
                Email not received yet. You can:
                <br>
                <button class="check-button" style="margin-top: 10px;" onclick="checkEmail()">
                    <i class="material-icons">refresh</i>
                    Check Again
                </button>
            </div>

            <div class="result" id="result"></div>
        </div>
    </div>

    <!-- Pass PHP variables to JavaScript -->
    <script>
        const userToken = "<?php echo $user_token; ?>";
        const domainName = "<?php echo $domain; ?>";
        const baseUrl = "<?php echo $base_url; ?>";
    </script>
    
    <!-- Custom JavaScript -->
    <script src="<?php echo $base_url; ?>/script.js"></script>
</body>
</html>