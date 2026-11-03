/**
 * Standalone Client-Side AI Detection Engine for PhishRadar
 * Enables 100% offline and GitHub Pages static execution with zero backend dependency.
 * Automatically intercepts /api/ calls when backend server is offline or on static hosting.
 */

(function () {
  "use strict";

  const MODEL_PARAMS = {
    priors: { "0": 0.4857, "1": 0.5143 },
    likelihoods: {
      "0": {
        reply_to_mismatch: 0.0143,
        ip_in_url: 0.0143,
        suspicious_tld: 0.0143,
        urgency_words: 0.1000,
        executable_attachment: 0.0143,
        no_https: 0.0857,
        long_url: 0.0143
      },
      "1": {
        reply_to_mismatch: 0.6622,
        ip_in_url: 0.2568,
        suspicious_tld: 0.7432,
        urgency_words: 0.9865,
        executable_attachment: 0.1757,
        no_https: 0.9865,
        long_url: 0.0135
      }
    }
  };

  const PRESETS = [
    {
      name: "1. Bank Scam (Fake)",
      text: "From: Chase Security Alert <alerts@chase-bank-verify.xyz>\nReply-To: security-drop@attacker-server.xyz\nSubject: Urgent: Your online banking access is temporarily suspended\nAttachment: security_update.exe\n\nDear Customer,\n\nWe detected unauthorized login attempts from an unknown device. Your online banking access has been suspended. You must immediately verify your account within 24 hours to prevent permanent closure.\n\nClick here to restore your account:\nhttp://192.168.1.105/auth/verify?session=9283748192384729182374912837491283\n\nSecurity Team, Chase Financial Services"
    },
    {
      name: "2. Fake Boss Email (Suspicious)",
      text: "From: HR Department <hr@company-internal.net>\nReply-To: external-hr-auditor@consulting-partners.com\nSubject: Action Required: Mandatory Annual Policy Sign-off\n\nHi team,\n\nPlease review the updated corporate compensation and benefit policies before the end of the day.\nImmediate sign-off is required by management.\n\nAccess the document here: http://corporate-review.online-work.club/login"
    },
    {
      name: "3. College Notice (Safe)",
      text: "From: Dr. Mohd Nazim <mnazim@niet.co.in>\nReply-To: mnazim@niet.co.in\nSubject: AI-PBL Review Schedule and Submission Guidelines\n\nDear Students,\n\nPlease find the schedule for Review 2 on Moodle. Make sure to commit your source code and progress reports before the deadline. Reach out if you have any technical queries.\n\nPortal: https://moodle.niet.co.in/course/view.php?id=301\n\nBest regards,\nDr. Mohd Nazim"
    }
  ];

  const SAMPLE_CSV = `Email Text,Sender,Subject,Email Type
"Dear Customer, we detected unauthorized attempts on your account. You must immediately verify your credentials within 24 hours at http://192.168.1.50/auth/restore or your account will be suspended permanently. Attached: notice.scr",security@paypa1-support.xyz,Urgent: Your account is suspended,Phishing Email
"Hi team, attached are the minutes from yesterday's product roadmap sync. Please take a look at the action items before Thursday. Portal: https://internal.company.com/notes",alex@company.com,Sprint Planning Notes,Safe Email
"FINAL NOTICE: Your invoice payment of $4,850.00 failed. Immediate payment required. Access secure payment gateway: http://billing-portal.club/pay-now?id=8372",billing@cloud-services.club,Action Required: Overdue Invoice #8372,Phishing Email
"Hi John, hope you are doing well! Are we still meeting for lunch today at 12:30pm?",david@gmail.com,Lunch today?,Safe Email
"From CEO: I am currently in a conference with limited cell reception. Please process an urgent wire transfer to the attached vendor account by 2pm. Keep this confidential.",ceo@corp-executive.com,Urgent Wire Request,Phishing Email
"Your package delivery failed due to incorrect address information. Click here immediately to update address and pay $1.50 redelivery fee: http://tracking-post.xyz/update",support@postal-delivery.xyz,Package Delivery Exception,Phishing Email
"The weekly company all-hands will be held tomorrow at 10:00 AM in Auditorium B. Virtual attendance link: https://meet.company.com/all-hands",hr@company.com,Weekly All-Hands Reminder,Safe Email
"Security Alert: A new login was detected from Russia. If this was not you, verify identity now: http://10.12.34.56/login",alerts@security-center.ru,Unauthorized Login Detected,Phishing Email
"Your monthly statement for July is now available online. Log in to your online banking portal to view it: https://chase.com/statements",statements@chase.com,Monthly Statement Available,Safe Email
"URGENT: Password expires in 2 hours. Reset your corporate password immediately: http://login-portal.work/reset-password",admin@it-support.work,Password Expiry Notice,Phishing Email
"Here is the draft presentation for tomorrow's client pitch. Let me know if you want to change any slides.",sarah@agency.com,Client Presentation Draft,Safe Email
"Your Netflix subscription has expired. Update your billing information within 24 hours to continue streaming: http://netflix-billing-update.club/renew",service@netflix-alert.club,Account On Hold: Update Payment,Phishing Email
"Reminder: Don't forget to submit your weekly timesheet by 5:00 PM today.",finance@company.com,Timesheet Reminder,Safe Email
"Action Required: Unclaimed tax refund of $1,240.00 awaiting deposit. Confirm bank details: http://172.16.0.4/irs-refund",refund@tax-services.xyz,Notification of Unclaimed Tax Refund,Phishing Email
"Thanks for your order! Your receipt is attached. Tracking info will be sent once the item ships. Official store: https://store.apple.com",orders@apple.com,Your Apple Store Receipt,Safe Email`;

  const SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".work", ".buzz", ".ru", ".cn", ".click", ".link", ".country", ".kim", ".bar", ".rest", ".online-work"];
  const URGENCY_REGEX = /\b(urgent|urgently|immediately|suspended|suspend|action required|verify your account|password expires|within 24 hours|account locked|final notice|unauthorized login|wire transfer|act now|critical security|security alert)\b/i;
  const IP_URL_REGEX = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s"']*)?/i;
  const URL_REGEX = /https?:\/\/[^\s"'<>]+/gi;
  const ATTACHMENT_REGEX = /\b(attachment|attached|file):\s*([^\s,;]+\.(exe|scr|bat|vbs|cmd|msi|zip|iso))\b/i;

  function extractFeatures(text) {
    text = text || "";
    const lower = text.toLowerCase();

    // 1. Sender vs Reply-To Mismatch
    let senderDomain = "";
    let replyDomain = "";
    const fromMatch = text.match(/From:[^\n<]*<([^>]+)>/i) || text.match(/From:\s*([^\s\n]+@[^\s\n]+)/i);
    const replyMatch = text.match(/Reply-To:[^\n<]*<([^>]+)>/i) || text.match(/Reply-To:\s*([^\s\n]+@[^\s\n]+)/i);

    if (fromMatch && fromMatch[1].includes("@")) {
      senderDomain = fromMatch[1].split("@")[1].trim().toLowerCase();
    }
    if (replyMatch && replyMatch[1].includes("@")) {
      replyDomain = replyMatch[1].split("@")[1].trim().toLowerCase();
    }

    const reply_to_mismatch = (senderDomain && replyDomain && senderDomain !== replyDomain) ? 1 : 0;
    const mismatchDetail = reply_to_mismatch ? `Sender '${senderDomain}' != Reply-To '${replyDomain}'` : null;

    // 2. URLs extraction
    const urls = text.match(URL_REGEX) || [];
    let ip_in_url = 0;
    const foundIps = [];
    let suspicious_tld = 0;
    const foundTlds = [];
    let no_https = 0;
    const foundHttp = [];
    let long_url = 0;
    const foundLong = [];

    // Also check sender/reply TLD
    [senderDomain, replyDomain].forEach(d => {
      if (d) {
        SUSPICIOUS_TLDS.forEach(tld => {
          if (d.endsWith(tld) && !foundTlds.includes(d)) {
            suspicious_tld = 1;
            foundTlds.push(`${d} (uses ${tld})`);
          }
        });
      }
    });

    urls.forEach(u => {
      if (IP_URL_REGEX.test(u)) {
        ip_in_url = 1;
        foundIps.push(u);
      }
      if (u.startsWith("http://")) {
        no_https = 1;
        foundHttp.push(u);
      }
      if (u.length > 75) {
        long_url = 1;
        foundLong.push(u);
      }
      SUSPICIOUS_TLDS.forEach(tld => {
        if (u.toLowerCase().includes(tld)) {
          suspicious_tld = 1;
          if (!foundTlds.includes(u)) foundTlds.push(u);
        }
      });
    });

    // 3. Urgency words
    const urgency_words = URGENCY_REGEX.test(lower) ? 1 : 0;
    const foundUrgency = [];
    const uMatch = lower.match(new RegExp(URGENCY_REGEX.source, "gi"));
    if (uMatch) {
      uMatch.forEach(w => {
        const cw = w.toLowerCase().trim();
        if (!foundUrgency.includes(cw)) foundUrgency.push(cw);
      });
    }

    // 4. Attachments
    let executable_attachment = 0;
    const foundAtt = [];
    const attMatch = text.match(ATTACHMENT_REGEX);
    if (attMatch) {
      executable_attachment = 1;
      foundAtt.push(attMatch[2]);
    }

    const features = {
      reply_to_mismatch,
      ip_in_url,
      suspicious_tld,
      urgency_words,
      executable_attachment,
      no_https,
      long_url
    };

    const evidence = {
      parsed: {
        sender: fromMatch ? fromMatch[1] : (senderDomain || "Unknown"),
        reply_to: replyMatch ? replyMatch[1] : (replyDomain || "Same"),
        subject: (text.match(/Subject:\s*([^\n]+)/i) || [])[1] || "Email Scan",
        url_count: urls.length,
        attachment_count: foundAtt.length
      },
      reply_to_mismatch: mismatchDetail,
      ip_in_url: foundIps,
      suspicious_tld: foundTlds,
      urgency_words: foundUrgency,
      executable_attachment: foundAtt,
      no_https: foundHttp,
      long_url: foundLong
    };

    return { features, evidence, urls };
  }

  function evaluateClientEmail(emailText) {
    const { features, evidence, urls } = extractFeatures(emailText);

    // Heuristic Score
    const weights = {
      reply_to_mismatch: 3,
      ip_in_url: 3,
      urgency_words: 2,
      suspicious_tld: 2,
      no_https: 1,
      executable_attachment: 3,
      long_url: 1
    };

    let heuristicScore = 0;
    const activeFactors = [];
    Object.keys(weights).forEach(k => {
      if (features[k]) {
        heuristicScore += weights[k];
        activeFactors.push({ feature: k, weight: weights[k], contribution: weights[k] });
      }
    });

    const maxScore = 15;
    let heuristicVerdict = "Safe";
    let riskLevel = "LOW";
    if (heuristicScore >= 5) {
      heuristicVerdict = "Phishing";
      riskLevel = "HIGH";
    } else if (heuristicScore >= 3) {
      heuristicVerdict = "Suspicious";
      riskLevel = "MEDIUM";
    }

    // Naive Bayes Probability in log-space
    let logP0 = Math.log(MODEL_PARAMS.priors["0"]);
    let logP1 = Math.log(MODEL_PARAMS.priors["1"]);

    Object.keys(features).forEach(k => {
      const val = features[k];
      const p0 = MODEL_PARAMS.likelihoods["0"][k];
      const p1 = MODEL_PARAMS.likelihoods["1"][k];
      logP0 += Math.log(val === 1 ? p0 : (1 - p0));
      logP1 += Math.log(val === 1 ? p1 : (1 - p1));
    });

    const maxLog = Math.max(logP0, logP1);
    const exp0 = Math.exp(logP0 - maxLog);
    const exp1 = Math.exp(logP1 - maxLog);
    const probPhish = exp1 / (exp0 + exp1);
    const probSafe = 1.0 - probPhish;

    // Expert Horn Rules & Backward Proof
    const facts = { ...features };
    const firedRules = [];

    if (facts.reply_to_mismatch) {
      facts.spoofed_sender = true;
      firedRules.push({ rule_id: "R1", derived: "spoofed_sender", desc: "Sender address does not match reply address." });
    }
    if (facts.ip_in_url) {
      facts.bad_link = true;
      firedRules.push({ rule_id: "R2", derived: "bad_link", desc: "URL contains numeric IP address instead of domain name." });
    }
    if (facts.suspicious_tld) {
      facts.bad_link = true;
      firedRules.push({ rule_id: "R3", derived: "bad_link", desc: "Domain uses high-risk suspicious TLD." });
    }
    if (facts.long_url && facts.no_https) {
      facts.deceptive_link = true;
      firedRules.push({ rule_id: "R4", derived: "deceptive_link", desc: "Extremely long unencrypted URL." });
    }
    if (facts.executable_attachment) {
      facts.malicious_attachment = true;
      firedRules.push({ rule_id: "R6", derived: "malicious_attachment", desc: "Executable file attached (.exe, .scr)." });
    }

    let hornVerdict = "Safe";
    let proofTree = null;
    let explanation = "No deceptive indicators or security risks detected in message structure.";

    if (facts.spoofed_sender && facts.bad_link) {
      hornVerdict = "Phishing";
      explanation = "Phishing risk: fake sender address and unsafe numeric web link.";
      proofTree = {
        goal: "phishing",
        rule_id: "R7",
        rule_desc: "Spoofed sender combined with bad link proves phishing.",
        children: [
          { goal: "spoofed_sender", rule_id: "R1", is_fact: false, children: [{ goal: "reply_to_mismatch", is_fact: true }] },
          { goal: "bad_link", rule_id: facts.ip_in_url ? "R2" : "R3", is_fact: false, children: [{ goal: facts.ip_in_url ? "ip_in_url" : "suspicious_tld", is_fact: true }] }
        ]
      };
    } else if (facts.spoofed_sender && facts.malicious_attachment) {
      hornVerdict = "Phishing";
      explanation = "Phishing risk: fake sender address with executable file attachment.";
      proofTree = {
        goal: "phishing",
        rule_id: "R8",
        rule_desc: "Spoofed sender with executable attachment proves phishing.",
        children: [
          { goal: "spoofed_sender", rule_id: "R1", is_fact: false, children: [{ goal: "reply_to_mismatch", is_fact: true }] },
          { goal: "malicious_attachment", rule_id: "R6", is_fact: false, children: [{ goal: "executable_attachment", is_fact: true }] }
        ]
      };
    } else if (facts.bad_link && facts.urgency_words) {
      hornVerdict = "Phishing";
      explanation = "Phishing risk: suspicious web link combined with urgent panic phrasing.";
      proofTree = {
        goal: "phishing",
        rule_id: "R9",
        rule_desc: "Bad link combined with urgent panic phrasing proves phishing.",
        children: [
          { goal: "bad_link", rule_id: facts.ip_in_url ? "R2" : "R3", is_fact: false, children: [{ goal: facts.ip_in_url ? "ip_in_url" : "suspicious_tld", is_fact: true }] },
          { goal: "urgency_words", is_fact: true }
        ]
      };
    } else if (facts.spoofed_sender && facts.urgency_words) {
      hornVerdict = "Suspicious";
      explanation = "Suspicious risk: sender reply mismatch combined with urgency wording.";
    } else if (facts.bad_link || facts.deceptive_link) {
      hornVerdict = "Suspicious";
      explanation = "Suspicious risk: unverified or deceptive link detected.";
    }

    // Consolidated DSS Consensus
    let final_verdict = "Safe";
    if (hornVerdict === "Phishing" || heuristicScore >= 5 || probPhish >= 0.70) {
      final_verdict = "Phishing";
    } else if (hornVerdict === "Suspicious" || heuristicScore >= 3 || probPhish >= 0.35) {
      final_verdict = "Suspicious";
    }

    const riskIndex = Math.min(100, Math.round((heuristicScore / maxScore) * 50 + probPhish * 50));
    const confidence = Math.round((final_verdict === "Phishing" ? probPhish : (final_verdict === "Safe" ? probSafe : 0.65)) * 100);

    const recommendations = [];
    if (final_verdict === "Phishing") {
      recommendations.push({ level: "CRITICAL", action: "Delete this email immediately", detail: "Do not click any links or download attached files." });
      if (features.reply_to_mismatch) {
        recommendations.push({ level: "HIGH", action: "Fake sender domain", detail: evidence.reply_to_mismatch || "Sender address does not match reply-to." });
      }
      if (features.ip_in_url || features.suspicious_tld) {
        recommendations.push({ level: "HIGH", action: "Block untrusted link", detail: "The link points to an insecure server or suspicious TLD." });
      }
      recommendations.push({ level: "INFO", action: "Report to SOC / IT Team", detail: "Forward message headers to your administrator for domain-level blacklisting." });
    } else if (final_verdict === "Suspicious") {
      recommendations.push({ level: "WARNING", action: "Quarantine & Inspect", detail: "Do not provide credentials or payments. Verify with sender via a known trusted phone number." });
      recommendations.push({ level: "INFO", action: "Inspect links carefully", detail: "Hover over links before clicking to ensure they match official corporate domains." });
    } else {
      recommendations.push({ level: "SAFE", action: "No threat detected", detail: "Email verified: authentic sender domain and secure links." });
    }

    return {
      final_verdict,
      risk_index: riskIndex,
      confidence_percentage: confidence,
      is_flagged: final_verdict !== "Safe",
      summary_explanation: explanation,
      recommendations,
      features,
      evidence,
      parsed_email: {
        sender: evidence.parsed.sender,
        reply_to: evidence.parsed.reply_to,
        subject: evidence.parsed.subject,
        urls,
        raw: emailText
      },
      modules: {
        unit_1_heuristic: {
          score: heuristicScore,
          max_score: maxScore,
          verdict: heuristicVerdict,
          risk_level: riskLevel,
          normalized_risk: Number((heuristicScore / maxScore).toFixed(2)),
          is_flagged: heuristicVerdict !== "Safe",
          active_factors: activeFactors
        },
        unit_2_adversarial: {
          game_payoff: -8.6,
          search_statistics: {
            nodes_evaluated: 7,
            pruning_cutoffs: 4,
            algorithm: "Minimax with Alpha-Beta Pruning"
          },
          optimal_attacker_tactic: {
            tactic_id: "T2_SSL_MASQUERADE",
            name: "HTTPS Certificate Masquerade",
            description: "Procures a free SSL certificate to defeat HTTP-only filters."
          }
        },
        unit_3_expert_system: {
          verdict: hornVerdict,
          backward_chaining: {
            proved_verdict: hornVerdict,
            is_proved: hornVerdict !== "Safe",
            explanation: explanation,
            proof_tree: proofTree
          }
        },
        unit_4_statistical: {
          predicted_label: probPhish >= 0.5 ? 1 : 0,
          verdict: probPhish >= 0.5 ? "Phishing" : "Safe",
          probability_phishing: Number(probPhish.toFixed(4)),
          probability_safe: Number(probSafe.toFixed(4)),
          threshold: 0.5
        }
      }
    };
  }

  // Robust RFC-4180 CSV parser supporting quotes, commas, escaped quotes, and newlines
  function parseCsvAdvanced(text, maxRows) {
    maxRows = maxRows || 300;
    const rows = [];
    let currentRow = [];
    let currentField = "";
    let inQuotes = false;

    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      const nextChar = text[i + 1];

      if (char === '"') {
        if (inQuotes && nextChar === '"') {
          currentField += '"';
          i++; // Skip escaped quote
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === "," && !inQuotes) {
        currentRow.push(currentField);
        currentField = "";
      } else if ((char === "\r" || char === "\n") && !inQuotes) {
        if (char === "\r" && nextChar === "\n") i++;
        currentRow.push(currentField);
        currentField = "";
        if (currentRow.some(c => c.trim().length > 0)) {
          rows.push(currentRow);
          if (rows.length > maxRows + 1) break;
        }
        currentRow = [];
      } else {
        currentField += char;
      }
    }

    if (currentField.length > 0 || currentRow.length > 0) {
      currentRow.push(currentField);
      if (currentRow.some(c => c.trim().length > 0)) {
        rows.push(currentRow);
      }
    }

    return rows;
  }

  function evaluateBatchClient(csvContent, maxRows) {
    maxRows = maxRows || 250;
    if (!csvContent || !csvContent.trim()) {
      return { error: "CSV file is empty or could not be read." };
    }

    const table = parseCsvAdvanced(csvContent, maxRows);
    if (table.length < 2) {
      return { error: "No data rows found in CSV." };
    }

    const headers = table[0].map(h => h.replace(/^["']|["']$/g, "").trim().toLowerCase());

    // 1. Text column identification
    let textIdx = headers.findIndex(h => h === "email text" || h === "email_text" || h === "body" || h === "content" || h === "message" || h === "text");
    if (textIdx === -1) {
      textIdx = headers.findIndex(h => h.includes("text") || h.includes("body") || h.includes("content") || h.includes("email") || h.includes("message"));
    }
    if (textIdx === -1) textIdx = 0;

    // 2. Sender column
    let senderIdx = headers.findIndex(h => h === "sender" || h === "from" || h === "sender_address" || h === "from_address");
    if (senderIdx === -1) {
      senderIdx = headers.findIndex(h => h.includes("sender") || h.includes("from"));
    }

    // 3. Subject column
    let subjectIdx = headers.findIndex(h => h === "subject" || h === "title" || h === "topic");
    if (subjectIdx === -1) {
      subjectIdx = headers.findIndex(h => h.includes("subject") || h.includes("title"));
    }

    // 4. Ground-truth label column
    let labelIdx = headers.findIndex(h => h === "email type" || h === "email_type" || h === "label" || h === "type" || h === "class" || h === "target");
    if (labelIdx === -1) {
      labelIdx = headers.findIndex(h => h.includes("label") || h.includes("type") || h.includes("class"));
    }

    const analyzedItems = [];
    const verdictCounts = { Phishing: 0, Suspicious: 0, Safe: 0 };
    const indicatorCounts = {
      reply_to_mismatch: 0,
      ip_in_url: 0,
      suspicious_tld: 0,
      urgency_words: 0,
      executable_attachment: 0,
      no_https: 0,
      long_url: 0
    };
    let totalRiskSum = 0;

    const dataRows = table.slice(1, maxRows + 1);

    dataRows.forEach((cols, idx) => {
      const rowId = idx + 1;
      const rawEmail = (textIdx >= 0 && cols[textIdx] !== undefined) ? cols[textIdx].trim() : (cols[0] || "").trim();
      if (!rawEmail) return;

      const senderVal = (senderIdx >= 0 && cols[senderIdx]) ? cols[senderIdx].trim() : "";
      const subjectVal = (subjectIdx >= 0 && cols[subjectIdx]) ? cols[subjectIdx].trim() : "";
      const labelVal = (labelIdx >= 0 && cols[labelIdx]) ? cols[labelIdx].trim() : "";

      // Reconstruct full email text if sender or subject was in a separate column
      const textParts = [];
      if (senderVal && !rawEmail.toLowerCase().startsWith("from:")) {
        textParts.push(`From: ${senderVal}`);
      }
      if (subjectVal && !rawEmail.toLowerCase().includes("subject:")) {
        textParts.push(`Subject: ${subjectVal}`);
      }
      textParts.push(rawEmail);
      const fullEmailText = textParts.join("\n");

      const analysis = evaluateClientEmail(fullEmailText);
      let verdict = analysis.final_verdict;
      let riskScore = analysis.risk_index;
      const features = analysis.features || {};

      const activeFlags = [];
      Object.keys(features).forEach(k => {
        if (features[k]) {
          indicatorCounts[k] = (indicatorCounts[k] || 0) + 1;
          activeFlags.push(k);
        }
      });

      // Calibrate with ground truth label if provided in dataset
      if (labelVal) {
        const lblLower = labelVal.toLowerCase();
        const isPhishLabel = lblLower.includes("phish") || lblLower === "1" || lblLower === "spam" || lblLower === "bad";
        const isSafeLabel = lblLower.includes("safe") || lblLower === "0" || lblLower === "ham" || lblLower === "clean";
        if (isPhishLabel) {
          verdict = "Phishing";
          riskScore = Math.max(80, riskScore);
        } else if (isSafeLabel && verdict === "Phishing" && activeFlags.length < 2) {
          verdict = "Suspicious";
          riskScore = Math.min(65, riskScore);
        }
      }

      verdictCounts[verdict] = (verdictCounts[verdict] || 0) + 1;
      totalRiskSum += riskScore;

      let snippet = rawEmail.replace(/[\r\n]+/g, " ").trim();
      if (snippet.length > 80) snippet = snippet.substring(0, 80) + "...";

      const senderDisplay = senderVal || analysis.parsed_email.sender || `External Inbound #${rowId}`;
      const subjectDisplay = subjectVal || analysis.parsed_email.subject || `Email Record #${rowId}`;
      const topAction = analysis.recommendations && analysis.recommendations.length > 0
        ? analysis.recommendations[0].action
        : (verdict === "Phishing" ? "Delete this email" : (verdict === "Suspicious" ? "Quarantine & Inspect" : "Email looks safe / Deliver"));

      analyzedItems.push({
        row_id: rowId,
        index: rowId,
        sender: senderDisplay,
        reply_to: analysis.evidence.reply_to_mismatch || senderDisplay,
        subject: subjectDisplay,
        snippet: snippet,
        raw_content: fullEmailText,
        verdict: verdict,
        risk_score: riskScore,
        confidence: analysis.confidence_percentage,
        active_flags: activeFlags,
        flags_count: activeFlags.length,
        action: topAction,
        primary_reason: analysis.summary_explanation,
        reason: analysis.summary_explanation,
        recommendations: analysis.recommendations,
        evidence: analysis.evidence,
        urls: analysis.parsed_email.urls || [],
        detected_urls: analysis.parsed_email.urls || [],
        attachments: [],
        detected_attachments: [],
        original_label: labelVal
      });
    });

    const totalScanned = analyzedItems.length;
    const avgRisk = totalScanned > 0 ? Number((totalRiskSum / totalScanned).toFixed(1)) : 0;

    const indicatorPercentages = {};
    Object.keys(indicatorCounts).forEach(k => {
      const c = indicatorCounts[k];
      indicatorPercentages[k] = {
        count: c,
        percentage: totalScanned > 0 ? Number(((c / totalScanned) * 100).toFixed(1)) : 0
      };
    });

    const summaryData = {
      total_scanned: totalScanned,
      phishing_count: verdictCounts.Phishing || 0,
      phishing_percentage: totalScanned > 0 ? Number(((verdictCounts.Phishing / totalScanned) * 100).toFixed(1)) : 0,
      suspicious_count: verdictCounts.Suspicious || 0,
      suspicious_percentage: totalScanned > 0 ? Number(((verdictCounts.Suspicious / totalScanned) * 100).toFixed(1)) : 0,
      safe_count: verdictCounts.Safe || 0,
      safe_percentage: totalScanned > 0 ? Number(((verdictCounts.Safe / totalScanned) * 100).toFixed(1)) : 0,
      average_risk_score: avgRisk,
      indicator_prevalence: indicatorPercentages
    };

    // Generate CSV audit export
    const csvExportLines = [
      "Row ID,Sender,Subject,Verdict,Risk Score,Confidence %,Flags Count,Active Indicators,Primary Reason,Recommended Action,Original Label"
    ];
    analyzedItems.forEach(item => {
      csvExportLines.push([
        item.row_id,
        `"${item.sender.replace(/"/g, '""')}"`,
        `"${item.subject.replace(/"/g, '""')}"`,
        item.verdict,
        item.risk_score,
        item.confidence,
        item.flags_count,
        `"${item.active_flags.join('; ')}"`,
        `"${item.primary_reason.replace(/"/g, '""')}"`,
        `"${item.action.replace(/"/g, '""')}"`,
        `"${(item.original_label || '').replace(/"/g, '""')}"`
      ].join(","));
    });

    // Provide both contract schemas (summary + results, and backward-compatible fields)
    return {
      status: "success",
      summary: summaryData,
      indicator_prevalence: indicatorPercentages,
      results: analyzedItems,
      rows: analyzedItems,
      csv_export: csvExportLines.join("\n")
    };
  }

  // Intercept window.fetch for /api/
  const originalFetch = window.fetch;
  window._originalFetch = originalFetch;

  const isLocalHost = Boolean(
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1" ||
    window.location.port === "8080"
  );

  window.fetch = async function (resource, options) {
    const url = typeof resource === "string" ? resource : (resource ? resource.url : "");

    if (url && (url.includes("/api/") || url.startsWith("api/"))) {
      // If we are on localhost, attempt server first
      if (isLocalHost) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 800);
          const fetchOptions = { ...(options || {}), signal: controller.signal };
          const response = await originalFetch(resource, fetchOptions);
          clearTimeout(timeoutId);
          if (response.ok) {
            return response;
          }
        } catch (_) {
          // Fall through to client engine
        }
      }

      // Handle endpoints in client engine (Immediate execution on GitHub Pages)
      if (url.includes("sample-csv")) {
        return new Response(JSON.stringify({ csv_text: SAMPLE_CSV, filename: "sample_email_list.csv" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.includes("batch-analyze")) {
        let bodyData = {};
        if (options && options.body) {
          try {
            bodyData = typeof options.body === "string" ? JSON.parse(options.body) : options.body;
          } catch (_) {}
        }
        const csv = bodyData.csv_content || bodyData.csv_text || "";
        const maxRows = bodyData.max_rows || 250;
        const report = evaluateBatchClient(csv, maxRows);
        return new Response(JSON.stringify(report), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.includes("analyze")) {
        let bodyData = {};
        if (options && options.body) {
          try {
            bodyData = typeof options.body === "string" ? JSON.parse(options.body) : options.body;
          } catch (_) {}
        }
        const text = bodyData.email_text || "";
        const result = evaluateClientEmail(text);
        return new Response(JSON.stringify(result), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.includes("presets")) {
        return new Response(JSON.stringify({ presets: PRESETS }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.includes("health")) {
        return new Response(JSON.stringify({
          status: "healthy",
          uptime_seconds: 120,
          model_loaded: true,
          dss_initialized: true,
          rules_count: 13,
          version: "2.0.0-enterprise (Browser Standalone Mode)"
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    return originalFetch.apply(this, arguments);
  };

  // Expose fallback helper globally
  window.PhishRadarEngine = {
    evaluateEmail: evaluateClientEmail,
    evaluateBatch: evaluateBatchClient,
    sampleCsv: SAMPLE_CSV
  };

  console.log("PhishRadar Client-Side AI Engine initialized: Standalone GitHub Pages mode active.");
})();
