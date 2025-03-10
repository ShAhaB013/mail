// Global variables
let checkTimeout;
let timerInterval;

// Email validation
function validateEmail(input) {
    const email = input.value.trim();
    const regex = /^user-[a-zA-Z0-9]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!regex.test(email)) {
        input.value = `user-${userToken}@${domainName}`;
        alert("Please only modify the token part. The email format should be: user-TOKEN@domain.com");
    }
}

// Timer functions
function updateTimer(startTime) {
    const now = new Date().getTime();
    const elapsed = Math.floor((now - startTime) / 1000);
    const minutes = Math.floor(elapsed / 60);
    const seconds = elapsed % 60;
    document.getElementById("timer").textContent = 
        `Waiting for email... (${minutes}:${seconds.toString().padStart(2, '0')})`;
}

// Theme toggle
function toggleTheme() {
    const body = document.body;
    const isDark = body.getAttribute('data-theme') === 'dark';
    body.setAttribute('data-theme', isDark ? 'light' : 'dark');
    localStorage.setItem('theme', isDark ? 'light' : 'dark');
    
    const themeIcon = document.querySelector('.theme-toggle i');
    themeIcon.textContent = isDark ? 'dark_mode' : 'light_mode';
}

// Copy email function
function copyEmail() {
    const emailInput = document.getElementById('userEmail');
    emailInput.select();
    document.execCommand('copy');
    
    const copyButton = document.querySelector('.copy-button i');
    const originalTitle = copyButton.parentElement.title;
    copyButton.textContent = 'check';
    copyButton.parentElement.title = 'Copied!';
    
    setTimeout(() => {
        copyButton.textContent = 'content_copy';
        copyButton.parentElement.title = originalTitle;
    }, 2000);
}

// Accordion functionality
function toggleAccordion(element) {
    const header = element;
    const content = element.nextElementSibling;
    
    header.classList.toggle('active');
    content.classList.toggle('active');
    
    if (content.classList.contains('active')) {
        content.style.maxHeight = content.scrollHeight + "px";
    } else {
        content.style.maxHeight = null;
    }
}

// Status class helper
function getStatusClass(value) {
    if (value.includes('✅')) return 'status-success';
    if (value.includes('ℹ️')) return 'status-warning';
    return 'status-error';
}

// Helper function to create accordion sections
function createAccordionSection(headerText, contentHTML) {
    return `
        <div class="accordion-section">
            <div class="accordion-header" onclick="toggleAccordion(this)">
                <div class="status-indicator">
                    <div class="status-icon ${getStatusClass(contentHTML)}"></div>
                    <span>${headerText}</span>
                </div>
                <i class="material-icons toggle-icon">expand_more</i>
            </div>
            <div class="accordion-content">
                <div class="accordion-inner">
                    ${contentHTML}
                </div>
            </div>
        </div>`;
}

function updateResultDisplay(data) {
    let scoreColor = data.final_score >= 7 ? "#4caf50" : (data.final_score >= 4 ? "#ff9800" : "#f44336");
    let resultHTML = `
        <div class="card" style="text-align: center;">
            <h3>Final Score</h3>
            <p style="font-size: 36px; color: ${scoreColor}; margin: 20px 0;">
                ${data.final_score} / 10
            </p>
        </div>`;

    // Email Details and Email Content (combined)
    resultHTML += createAccordionSection("Email Details & Content", `
        <p><strong>From:</strong> ${data.from}</p>
        <p><strong>From Email:</strong> ${data.from_email}</p>
        <p><strong>Subject:</strong> ${data.subject}</p>
        <hr>
        <pre>${data.message}</pre>
    `);

    // SPF Authentication
    resultHTML += createAccordionSection("SPF Authentication", `
        <p><strong>Status:</strong> ${data.spf}</p>
        <p><strong>Record:</strong> ${data.spf_dns}</p>
        <p><strong>Details:</strong> ${data.spf_details}</p>
    `, data.spf);

    // DKIM Authentication
    resultHTML += createAccordionSection("DKIM Authentication", `
        <p><strong>Status:</strong> ${data.dkim}</p>
        <p><strong>Details:</strong> ${data.dkim_details}</p>
        <pre>${data.dkim_dns}</pre>
    `, data.dkim);

    // DMARC Authentication
    resultHTML += createAccordionSection("DMARC Authentication", `
        <p><strong>Status:</strong> ${data.dmarc}</p>
        <p><strong>Details:</strong> ${data.dmarc_details}</p>
        ${data.dmarc.includes('Invalid') ? `
        <div class="recommendation">
            <h4>💡 DMARC Recommendation</h4>
            <p>To improve your email authentication, add this DMARC record to your DNS:</p>
            <pre>Name: _dmarc.${data.from_email.split('@')[1]}
Record Type: TXT
Value: v=DMARC1; p=none; rua=mailto:dmarc@${data.from_email.split('@')[1]}; ruf=mailto:dmarc@${data.from_email.split('@')[1]}; pct=100</pre>
            <p><strong>What this record does:</strong></p>
            <ul style="list-style-type: none; padding-left: 0;">
                <li>✓ <strong>v=DMARC1</strong> - Specifies DMARC version</li>
                <li>✓ <strong>p=none</strong> - Monitor mode (no action taken)</li>
                <li>✓ <strong>rua=mailto:...</strong> - Where to send aggregate reports</li>
                <li>✓ <strong>ruf=mailto:...</strong> - Where to send forensic reports</li>
                <li>✓ <strong>pct=100</strong> - Apply to 100% of emails</li>
            </ul>
            <p><strong>Recommended Implementation Steps:</strong></p>
            <ol style="padding-left: 20px;">
                <li>Start with <code>p=none</code> to monitor without affecting delivery</li>
                <li>After 2-4 weeks, review reports for any issues</li>
                <li>If no problems, consider changing to <code>p=quarantine</code></li>
                <li>Finally, move to <code>p=reject</code> for maximum security</li>
            </ol>
            <p><em>Note: Replace dmarc@domain.com with your actual email address for receiving reports.</em></p>
        </div>
        ` : ''}
    `, data.dmarc);

    // Server Information (including Spam Score and PTR Record)
    resultHTML += createAccordionSection("Server Information", `
        <p><strong>Sender IP:</strong> ${data.sender_ip}</p>
        <p><strong>PTR Record:</strong> ${data.ptr}</p>
        <p><strong>Spam Score:</strong> ${data.spam_score}</p>
    `);

    // Reverse DNS Check (rDNS)
    resultHTML += createAccordionSection("Reverse DNS Check", `
        <p>Your server ${data.sender_ip} is successfully associated with ${data.ptr}.</p>
        <p>Reverse DNS lookup or reverse DNS resolution (rDNS) is the determination of a domain name that is associated with a given IP address.</p>
        <p>Some companies such as AOL will reject any message sent from a server without rDNS, so you must ensure that you have one.</p>
        <p>You cannot associate more than one domain name with a single IP address.</p>
        <p>Here are the tested values for this check:</p>
        <ul>
            <li><strong>IP:</strong> ${data.sender_ip}</li>
            <li><strong>HELO:</strong> ${data.helo}</li>
            <li><strong>rDNS:</strong> ${data.ptr}</li>
        </ul>
    `);

    // Update the result container
    document.getElementById("result").innerHTML = resultHTML;
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Email check function
function checkEmail() {
    if (checkTimeout) clearTimeout(checkTimeout);
    if (timerInterval) clearInterval(timerInterval);
    
    document.getElementById("timeout-message").style.display = "none";
    document.getElementById("result").innerHTML = "";
    document.getElementById("loading").style.display = "block";
    
    const startTime = new Date().getTime();
    timerInterval = setInterval(() => updateTimer(startTime), 1000);

    let userEmail = document.getElementById("userEmail").value.trim();
    
    if (!userEmail.includes("user-") || !userEmail.includes("@")) {
        clearInterval(timerInterval);
        document.getElementById("loading").style.display = "none";
        document.getElementById("result").innerHTML = `
            <div class="card error">
                <i class="material-icons">error</i> Invalid email format.
            </div>`;
        return;
    }

    let userToken = userEmail.split("@")[0].replace("user-", "");
    
    checkTimeout = setTimeout(() => {
        clearInterval(timerInterval);
        document.getElementById("loading").style.display = "none";
        document.getElementById("timeout-message").style.display = "block";
    }, 120000); // 2 minutes timeout

    // Add debug logging
    console.log('Fetching email data for token:', userToken);
    
    fetch("fetch_emails.php?token=" + encodeURIComponent(userToken))
        .then(response => {
            console.log('Response status:', response.status);
            return response.json();
        })
        .then(data => {
            console.log('Received data:', data);
            clearTimeout(checkTimeout);
            clearInterval(timerInterval);
            document.getElementById("loading").style.display = "none";
            document.getElementById("timeout-message").style.display = "none";
            
            if (data.error) {
                document.getElementById("result").innerHTML = `
                    <div class="card error">
                        <i class="material-icons">error</i> ${data.error}
                    </div>`;
            } else {
                updateResultDisplay(data);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            clearTimeout(checkTimeout);
            clearInterval(timerInterval);
            document.getElementById("loading").style.display = "none";
            document.getElementById("timeout-message").style.display = "none";
            document.getElementById("result").innerHTML = `
                <div class="card error">
                    <i class="material-icons">error</i> 
                    Error fetching email data. Please try again.
                </div>`;
        });
}

// Initialize theme on page load
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.body.setAttribute('data-theme', savedTheme);
    const themeIcon = document.querySelector('.theme-toggle i');
    themeIcon.textContent = savedTheme === 'dark' ? 'light_mode' : 'dark_mode';
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (checkTimeout) clearTimeout(checkTimeout);
    if (timerInterval) clearInterval(timerInterval);
});