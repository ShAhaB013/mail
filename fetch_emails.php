<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: application/json');

function getSPFStatus($headers, $domain) {
    // بررسی وجود SPF_PASS در هدر
    $status = (stripos($headers, 'SPF_PASS') !== false) ? "Valid ✅" : "Invalid ❌";
    
    // دریافت رکورد SPF از DNS دامنه
    $spfRecord = "Not Found";
    $txtRecords = dns_get_record($domain, DNS_TXT);
    if ($txtRecords) {
        foreach ($txtRecords as $record) {
            if (isset($record['txt']) && stripos($record['txt'], 'v=spf1') === 0) {
                $spfRecord = $record['txt'];
                break;
            }
        }
    }
    
    $details = ($status === "Valid ✅") ? "SPF record is correctly configured." : "Ensure your domain's DNS has a valid SPF record that includes the sending server.";
    return ["status" => $status, "details" => $details, "dns_spf" => $spfRecord];
}

function getDKIMStatus($headers) {
    $result = [];
    
    // استخراج دامنه فرستنده
    if (!preg_match('/From:.*?@([^\s>]+)/i', $headers, $from_matches)) {
        $result["status"] = "Invalid ❌";
        $result["details"] = "Could not determine sender domain";
        $result["dns_dkim"] = "No domain found to check DKIM";
        return $result;
    }
    
    $sender_domain = trim($from_matches[1]);
    $has_dkim_records = false;
    $found_records = [];
    $dkim_settings = [];
    
    // تشخیص سرویس‌های خاص
    $is_gmail = (stripos($sender_domain, 'gmail.com') !== false);
    $is_google_domain = (
        stripos($sender_domain, 'google.com') !== false || 
        stripos($sender_domain, 'googlemail.com') !== false
    );
    
    // استخراج اطلاعات DKIM-Signature از هدر
    if (preg_match_all('/DKIM-Signature:\s*((?:.|\n)*?)(?=\n[^\s])/i', $headers, $dkim_matches)) {
        foreach ($dkim_matches[1] as $dkimHeader) {
            $sig_info = [];
            
            // استخراج پارامترهای مهم
            if (preg_match('/s=([^;]+)/i', $dkimHeader, $s_match)) {
                $sig_info['selector'] = trim($s_match[1]);
            }
            if (preg_match('/d=([^;]+)/i', $dkimHeader, $d_match)) {
                $sig_info['domain'] = trim($d_match[1]);
            }
            if (preg_match('/a=([^;]+)/i', $dkimHeader, $a_match)) {
                $sig_info['algorithm'] = trim($a_match[1]);
            }
            
            if (!empty($sig_info)) {
                $dkim_settings[] = $sig_info;
            }
        }
    }
    
    // سلکتورهای مخصوص برای سرویس‌های مختلف
    $common_selectors = ['default', 'mail', 'dkim', 'key1', 'selector1', 'google', 'k1', 'mxvault'];
    if ($is_gmail || $is_google_domain) {
        $common_selectors = array_merge($common_selectors, ['20120113', '20150623', '20161025', '20161101', '20170112', '20200309', '20201103', '20210112']);
    }
    
    // بررسی رکوردهای DKIM دامنه
    foreach ($common_selectors as $selector) {
        $dnsName = $selector . "._domainkey." . $sender_domain;
        $txtRecords = dns_get_record($dnsName, DNS_TXT);
        
        if ($txtRecords) {
            foreach ($txtRecords as $record) {
                if (isset($record['txt']) && stripos($record['txt'], 'v=DKIM1') !== false) {
                    $has_dkim_records = true;
                    
                    // تحلیل تنظیمات DKIM از رکورد DNS
                    $record_info = [
                        'selector' => $selector,
                        'record' => $record['txt']
                    ];
                    
                    // استخراج پارامترهای مهم از رکورد
                    if (preg_match('/k=([^;\s]+)/', $record['txt'], $k_match)) {
                        $record_info['key_type'] = $k_match[1];
                    }
                    if (preg_match('/t=([^;\s]+)/', $record['txt'], $t_match)) {
                        $record_info['flags'] = $t_match[1];
                    }
                    
                    $found_records[] = $record_info;
                }
            }
        }
    }
    
    // بررسی وضعیت DKIM در هدر
    $has_dkim_header = (
        stripos($headers, 'DKIM-Signature') !== false ||
        preg_match('/X-Google-DKIM-Signature/i', $headers)
    );
    
    $is_dkim_valid = (
        stripos($headers, 'DKIM_VALID') !== false ||
        stripos($headers, 'DKIM=pass') !== false ||
        stripos($headers, 'dkim=success') !== false ||
        stripos($headers, 'dkim=accept') !== false ||
        stripos($headers, 'dkim=yes') !== false ||
        stripos($headers, 'dkim=ok') !== false ||
        preg_match('/authentication-results:.*dkim=pass/i', $headers) ||
        preg_match('/authentication-results:.*dkim=ok/i', $headers) ||
        preg_match('/dkim=pass/i', $headers) ||
        preg_match('/ARC-Authentication-Results:.*dkim=(pass|yes|ok)/i', $headers) ||
        preg_match('/Authentication-Results:.*dkim=(pass|yes|ok)/i', $headers) ||
        preg_match('/X-DKIM:.*pass/i', $headers) ||
        preg_match('/X-Google-DKIM-Signature.*pass/i', $headers) ||
        preg_match('/X-Gm-Message-State:/i', $headers) ||
        preg_match('/X-Google-Smtp-Source:/i', $headers)
    );
    
    // تشخیص شکست صریح DKIM
    $is_dkim_fail = (
        stripos($headers, 'dkim=fail') !== false ||
        stripos($headers, 'dkim=invalid') !== false ||
        stripos($headers, 'DKIM_INVALID') !== false ||
        preg_match('/authentication-results:.*dkim=fail/i', $headers) ||
        preg_match('/Authentication-Results:.*dkim=hardfail/i', $headers)
    );
    
    // تصمیم‌گیری درباره وضعیت DKIM
    if ($has_dkim_records || $has_dkim_header) {
        if ($has_dkim_header) {
            if ($is_dkim_valid || ($is_gmail && !$is_dkim_fail)) {
                $result["status"] = "Valid ✅";
                $result["details"] = "DKIM is properly configured and email is signed.";
            } elseif ($is_dkim_fail) {
                $result["status"] = "Invalid ❌";
                $result["details"] = "DKIM signature is invalid.";
            } else {
                $result["status"] = "Valid ✅";
                $result["details"] = "DKIM appears to be valid.";
            }
        } else {
            $result["status"] = "Configured ℹ️";
            $result["details"] = "DKIM is configured but this email was not signed.";
        }
    } else {
        $result["status"] = "Invalid ❌";
        $result["details"] = "No DKIM configuration found for domain.";
    }
    
    // اضافه کردن اطلاعات DNS و تنظیمات
    $output_sections = [];
    
    // نمایش تنظیمات DKIM از هدر ایمیل
    if (!empty($dkim_settings)) {
        $output_sections[] = "=== DKIM Signature Settings ===";
        foreach ($dkim_settings as $setting) {
            $setting_info = [];
            foreach ($setting as $key => $value) {
                $setting_info[] = ucfirst($key) . ": " . $value;
            }
            $output_sections[] = implode("\n", $setting_info);
        }
    }
    
    // نمایش رکوردهای DNS
    if (!empty($found_records)) {
        $output_sections[] = "=== DKIM DNS Records ===";
        foreach ($found_records as $record) {
            $record_info = ["Selector: " . $record['selector']];
            
            // نمایش پارامترهای اضافی اگر موجود باشند
            if (isset($record['key_type'])) {
                $record_info[] = "Key Type: " . $record['key_type'];
            }
            if (isset($record['flags'])) {
                $record_info[] = "Flags: " . $record['flags'];
            }
            
            $record_info[] = "Record: " . $record['record'];
            $output_sections[] = implode("\n", $record_info);
        }
    }
    
    $result["dns_dkim"] = !empty($output_sections) ? 
        implode("\n\n", $output_sections) : 
        "No DKIM records or settings found";
    
    return $result;
}

function getOrganizationalDomain($domain) {
    // Special TLDs that require special handling
    $specialTlds = [
        'co.uk', 'co.ir', 'co.jp', 'com.br', 'com.au', 'co.nz',
        'ac.ir', 'gov.ir', 'org.ir', 'sch.ir', 'ac.uk', 'gov.uk',
        'net.ir', 'id.ir', 'ac.ir', 'co.in', 'net.uk', 'org.uk'
    ];
    
    // Remove _dmarc prefix if present
    $cleanDomain = str_replace('_dmarc.', '', $domain);
    $parts = explode('.', $cleanDomain);
    
    if (count($parts) <= 2) {
        return $cleanDomain;
    }
    
    // Check for special TLDs
    $lastTwo = $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];
    if (in_array($lastTwo, $specialTlds)) {
        if (count($parts) >= 3) {
            return $parts[count($parts) - 3] . '.' . $lastTwo;
        }
        return $lastTwo;
    }
    
    // For normal domains, return last two parts
    return $lastTwo;
}

function getDMARCStatus($headers) {
    $result = [];

    // Extract sender domain
    if (!preg_match('/From:.*?@([^\s>]+)/i', $headers, $from_matches)) {
        return [
            "status" => "Invalid ❌",
            "details" => "Could not determine sender domain",
            "dns_dmarc" => "No domain found to check DMARC"
        ];
    }

    $sender_domain = trim($from_matches[1]);
    
    // Get organizational domain for DMARC checking
    $org_domain = getOrganizationalDomain($sender_domain);
    $dmarc_domain = "_dmarc." . $org_domain;
    
    // Enhanced DMARC validation patterns
    $dmarc_patterns = [
        '/dmarc=pass\s*\(/i',
        '/Authentication-Results:.*?dmarc=pass/i',
        '/Authentication-Results:.*?compauth=pass/i',  // For Outlook/Microsoft
        '/X-Microsoft-Antispam.*?compauth=pass/i',    // For Outlook/Microsoft
        '/ARC-Authentication-Results:.*?dmarc=pass/i', // For Google Workspace
        '/X-Google-DMARC-Status:\s*PASS/i'           // For some Gmail configurations
    ];
    
    $has_dmarc_pass = false;
    foreach ($dmarc_patterns as $pattern) {
        if (preg_match($pattern, $headers)) {
            $has_dmarc_pass = true;
            break;
        }
    }

    // Enhanced DKIM validation patterns
    $dkim_patterns = [
        '/dkim=pass\s+/i',
        '/Authentication-Results:.*?dkim=pass/i',
        '/DKIM-Signature/i',
        '/X-Google-DKIM-Signature/i',
        '/X-Microsoft-DKIM/i'
    ];
    
    $has_dkim_pass = false;
    foreach ($dkim_patterns as $pattern) {
        if (preg_match($pattern, $headers)) {
            $has_dkim_pass = true;
            break;
        }
    }

    // Try multiple DNS queries with error handling
    $dmarc_record = null;
    $dns_errors = [];
    
    // First try direct DMARC lookup
    $txtRecords = @dns_get_record($dmarc_domain, DNS_TXT);
    
    if ($txtRecords) {
        foreach ($txtRecords as $record) {
            if (isset($record['txt']) && stripos($record['txt'], 'v=DMARC1') !== false) {
                $dmarc_record = $record['txt'];
                break;
            }
        }
    }

    // Parse DMARC record components
    $components = [];
    if ($dmarc_record) {
        // Extract all DMARC tags
        $tags = [
            'p' => 'Policy',
            'sp' => 'Subdomain Policy',
            'pct' => 'Percentage',
            'rua' => 'Aggregate Reports',
            'ruf' => 'Forensic Reports',
            'adkim' => 'DKIM Alignment',
            'aspf' => 'SPF Alignment',
            'fo' => 'Failure Options',
            'rf' => 'Report Format',
            'ri' => 'Report Interval'
        ];
        
        foreach ($tags as $tag => $label) {
            if (preg_match("/$tag=([^;\s]+)/", $dmarc_record, $match)) {
                $components[] = "$label: " . strtoupper($match[1]);
            }
        }
        
        // Get main policy
        preg_match('/p=([^;\s]+)/', $dmarc_record, $p_match);
        $policy = isset($p_match[1]) ? strtolower($p_match[1]) : "";
    }

    // Enhanced decision logic
    if ($dmarc_record) {
        if ($has_dmarc_pass) {
            $result["status"] = "Valid ✅";
            $result["details"] = "DMARC passed validation. " . ($policy ? "Policy: $policy" : "");
        } elseif ($has_dkim_pass && ($policy === "none" || $policy === "")) {
            $result["status"] = "Valid ✅";
            $result["details"] = "DMARC is properly configured with monitoring policy and DKIM passed";
        } else {
            $result["status"] = "Configured ℹ️";
            $result["details"] = "DMARC is configured but validation incomplete. " . ($policy ? "Policy: $policy" : "");
        }
    } else {
        $result["status"] = "Invalid ❌";
        $result["details"] = "No DMARC record found. Configure DMARC for better email security.";
    }

    // Build comprehensive DNS analysis
    $dns_sections = ["=== DMARC Configuration ==="];
    if ($dmarc_record) {
        $dns_sections[] = "Domain Checked: " . $org_domain;
        $dns_sections[] = "Record: " . $dmarc_record;
        
        if (!empty($components)) {
            $dns_sections[] = "
=== Analysis ===";
            $dns_sections = array_merge($dns_sections, $components);
        }
    } else {
        $dns_sections[] = "No DMARC record found for " . $org_domain;
        if (!empty($dns_errors)) {
            $dns_sections[] = "
=== DNS Lookup Details ===";
            $dns_sections = array_merge($dns_sections, $dns_errors);
        }
    }

    $result["dns_dmarc"] = implode("
", $dns_sections);
    return $result;
}

function getSpamScore($headers) {
    $score = null;
    if (preg_match('/X-Spam-Score:\s*([\d\.\-]+)/i', $headers, $matches)) {
        $score = floatval($matches[1]);
    } elseif (preg_match('/X-Spam-Status:.*score=([\d\.\-]+)/i', $headers, $matches)) {
        $score = floatval($matches[1]);
    } elseif (preg_match('/X-Spam-Level:\s*(\*+)/i', $headers, $matches)) {
        $score = strlen($matches[1]);
    }
    if ($score === null) {
        return ["score" => "Unknown ❓", "points" => 0, "details" => "Spam score could not be determined. Ensure spam filters are properly configured."];
    } else {
        // در SpamAssassin، امتیازهای منفی یعنی ایمیل کمتر اسپمی است.
        if ($score < 0) {
            $points = 2; 
            $display = "Excellent (score: $score)";
        } else {
            if ($score <= 3) {
                $points = 2;
            } elseif ($score <= 6) {
                $points = 1;
            } else {
                $points = 0;
            }
            $display = $score . " / 10";
        }
        return ["score" => $display, "points" => $points, "details" => ""];
    }
}

/* اصلی */
if (!isset($_GET['token'])) {
    echo json_encode(["error" => "Invalid request."]);
    exit;
}

$user_token = $_GET['token'];

// Add delay to simulate email processing (optional)
sleep(2); // اختیاری: برای شبیه‌سازی پردازش ایمیل

// تنظیمات IMAP
$hostname = '{mail.tst.bstways.ir:993/imap/ssl}INBOX';
$username = 'catchall@tst.bstways.ir';
$password = 'Gmu16IhSrZoQ';

// Set timeout for IMAP connection
$timeout = 30; // تنظیم تایم‌اوت به 30 ثانیه
imap_timeout(IMAP_OPENTIMEOUT, $timeout);
imap_timeout(IMAP_READTIMEOUT, $timeout);
imap_timeout(IMAP_WRITETIMEOUT, $timeout);
imap_timeout(IMAP_CLOSETIMEOUT, $timeout);

$inbox = imap_open($hostname, $username, $password) or die(json_encode(["error" => imap_last_error()]));
if (!$inbox) {
    echo json_encode(["error" => "Cannot connect to mailbox."]);
    exit;
}
$emails = imap_search($inbox, 'ALL');
if (!$emails) {
    echo json_encode(["error" => "No emails found."]);
    imap_close($inbox);
    exit;
}
rsort($emails);

foreach ($emails as $email_number) {
    $overview = imap_fetch_overview($inbox, $email_number, 0);
    $message = imap_fetchbody($inbox, $email_number, 1);
    $headers = imap_fetchheader($inbox, $email_number);
    $to = $overview[0]->to ?? '';
    
    $from = $overview[0]->from;

// استخراج آدرس ایمیل از "From"
preg_match('/<([^>]+)>/', $from, $email_match);
$from_email = $email_match[1] ?? $from; // اگر ایمیل داخل <> بود، آن را بگیریم، در غیر این صورت خود مقدار $from را استفاده کنیم

    
    $subject = $overview[0]->subject;

    // بررسی اینکه آیا توکن ورودی در آدرس دریافت (To) به صورت "user-<token>@tst.bstways.ir" موجود است.
    if (preg_match("/user-" . preg_quote($user_token, "/") . "@tst\.bstways\.ir/i", $to)) {
        // استخراج دامنه از آدرس فرستنده
        if (preg_match('/@([^>]+)>?/', $from, $matches)) {
            $domain = trim($matches[1]);
        } else {
            $domain = "tst.bstways.ir";
        }
        
        $spf = getSPFStatus($headers, $domain);
        $dkim = getDKIMStatus($headers);
        $dmarc = getDMARCStatus($headers);
        $spam = getSpamScore($headers);

        // امتیازدهی: SPF (3), DKIM (3), DMARC (2) + Spam Score (0-2)
        $final_score = (($spf['status'] === "Valid ✅") ? 3 : 0) +
                       (($dkim['status'] === "Valid ✅") ? 3 : 0) +
                       (($dmarc['status'] === "Valid ✅") ? 2 : 0) +
                       $spam['points'];
        if ($final_score > 10) $final_score = 10;


// استخراج آدرس IP فرستنده از هدر Received
$sender_ip = "Not available";
if (preg_match('/Received:.*\[(\d{1,3}(?:\.\d{1,3}){3})\]/i', $headers, $ip_matches)) {
    $sender_ip = $ip_matches[1];
    $ptr_record = gethostbyaddr($sender_ip); // دریافت PTR Record (نام دامنه)
} else {
    $ptr_record = "PTR lookup failed";
}

$helo = "Not available";
// تابع برای استخراج آدرس IP فرستنده از هدرهای Received
function extractSenderIP($headers) {
    $receivedHeaders = explode("\n", $headers);
    $sender_ip = "Not available";

    // بررسی تمام هدرهای Received
    foreach ($receivedHeaders as $header) {
        if (strpos($header, 'Received:') === 0) {
            // استخراج آدرس IP از هدر Received
            if (preg_match('/\[(\d{1,3}(?:\.\d{1,3}){3})\]/', $header, $matches)) {
                $ip = $matches[1];
                // اگر آدرس IP لوکال نباشد، آن را ذخیره کنید
                if ($ip !== '127.0.0.1') {
                    $sender_ip = $ip;
                }
            }
        }
    }

    return $sender_ip;
}

echo json_encode([
    "from"         => $from,
    "from_email"   => $from_email,
    "subject"      => $subject,
    "spf"          => $spf['status'],
    "spf_details"  => $spf['details'],
    "spf_dns"      => $spf['dns_spf'],
    "dkim"         => $dkim['status'],
    "dkim_details" => $dkim['details'],
    "dkim_dns"     => $dkim['dns_dkim'],
    "dmarc"        => $dmarc['status'],
    "dmarc_details"=> $dmarc['details'],
    "spam_score"   => $spam['score'],
    "spam_details" => $spam['details'],
    "sender_ip"    => $sender_ip,
    "ptr"          => $ptr_record,
    "helo"         => $helo, // اضافه کردن HELO
    "message"      => strip_tags($message),
    "final_score"  => $final_score
]);
        imap_close($inbox);
        exit;
    }
}

echo json_encode(["error" => "No emails found for your token."]);
imap_close($inbox);
?>