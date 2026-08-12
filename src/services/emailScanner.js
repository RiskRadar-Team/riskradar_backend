import ApiError from "../utils/ApiError.js";

import EmailScanModel from "../models/emailScanModel.js";
import ScanFindingModel from "../models/scanFindingModel.js";
import PhishingKeywordModel from "../models/phishingKeywordModel.js";

import RiskScoreService from "./riskScoreService.js";
import AIScanner from "./aiScanner.js";

class EmailScanner {
  /**
   * Main email scanning function.
   *
   * Current implementation:
   * - Rule-based email analysis
   * - Phishing keyword detection
   * - Link analysis
   * - Urgency detection
   * - Credential request detection
   * - Reply-To analysis
   * - Return-Path analysis
   * - SPF/DKIM/DMARC analysis
   * - Risk scoring
   *
   * AI detection will be integrated later.
   */
  static async scan(scanId, emailData) {
    if (!scanId) {
      throw new ApiError(400, "Scan id is required.");
    }

    if (!emailData || typeof emailData !== "object") {
      throw new ApiError(400, "Email data is required.");
    }

    const {
      sender_email,
      reply_to = null,
      return_path = null,
      subject = "",
      body = "",
      attachment_found = false,

      /*
       * These should eventually come from
       * actual email header analysis.
       */
      spf_result = null,
      dkim_result = null,
      dmarc_result = null,
    } = emailData;

    /*
     * Validate sender email.
     */
    if (!sender_email || typeof sender_email !== "string") {
      throw new ApiError(400, "Sender email is required.");
    }

    /*
     * Validate optional email fields.
     */
    if (reply_to !== null && typeof reply_to !== "string") {
      throw new ApiError(400, "Reply-to must be a string.");
    }

    if (return_path !== null && typeof return_path !== "string") {
      throw new ApiError(400, "Return path must be a string.");
    }

    if (typeof subject !== "string") {
      throw new ApiError(400, "Subject must be a string.");
    }

    if (typeof body !== "string") {
      throw new ApiError(400, "Email body must be a string.");
    }

    /*
     * Normalize values.
     */
    const normalizedSender = sender_email.trim().toLowerCase();

    const normalizedReplyTo = reply_to ? reply_to.trim().toLowerCase() : null;

    const normalizedReturnPath = return_path
      ? return_path.trim().toLowerCase()
      : null;

    const normalizedSubject = subject.trim();

    const normalizedBody = body.trim();

    /*
     * Extract sender domain.
     */
    const senderDomain = this.extractEmailDomain(normalizedSender);

    /*
     * Extract Reply-To domain.
     */
    const replyToDomain = normalizedReplyTo
      ? this.extractEmailDomain(normalizedReplyTo)
      : null;

    /*
     * Extract Return-Path domain.
     */
    const returnPathDomain = normalizedReturnPath
      ? this.extractEmailDomain(normalizedReturnPath)
      : null;

    /*
     * Combine subject and body for
     * content analysis.
     */
    const emailContent = `${normalizedSubject} ${normalizedBody}`;

    /*
     * Extract links.
     */
    const suspiciousLinks = this.extractLinks(emailContent);

    /*
     * Detect phishing keywords.
     */
    const keywordMatches = await this.detectPhishingKeywords(emailContent);

    /*
     * Detect urgency.
     */
    const urgencyDetected = this.detectUrgency(
      normalizedSubject,
      normalizedBody,
    );

    /*
     * Detect credential requests.
     */
    const credentialRequest = this.detectCredentialRequest(
      normalizedSubject,
      normalizedBody,
    );

    /*
     * Detect sender/reply-to/return-path
     * inconsistencies.
     */
    const emailAddressMismatch = this.detectEmailAddressMismatch({
      senderDomain,
      replyToDomain,
      returnPathDomain,
    });

    /*
     * Detect possible spoofing.
     */
    const spoofDetected = this.detectSpoofing({
      senderEmail: normalizedSender,

      senderDomain,

      replyTo: normalizedReplyTo,

      returnPath: normalizedReturnPath,

      subject: normalizedSubject,

      body: normalizedBody,

      emailAddressMismatch,

      spfResult: spf_result,

      dkimResult: dkim_result,

      dmarcResult: dmarc_result,
    });
    const findings = [];
    const aiInput = {
      sender_email,
      senderDomain,
      reply_to,
      return_path,
      subject,
      body,
      suspiciousLinks,
      attachment_found,
      urgencyDetected,
      credentialRequest,
      spoofDetected,
      spf_result,
      dkim_result,
      dmarc_result,
    };
    //AI with timeout handling
    let aiResult = null;
    try {
      const aiPromise = AIScanner.analyseEmail(aiInput);
      const timeout = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("AI scanning timed out")), 15000),
      );
      aiResult = await Promise.race([aiPromise, timeout]);
      const aiFindings = await AIScanner.generateFindings(aiResult);
      // if (aiFindings) {
      // }
      findings.push(...aiFindings);
    } catch (error) {
      console.error("AI scanning failed:", error);
    }
    // const aiResult = await AIScanner.analyseEmail(aiInput);
    // const aiFindings = await AIScanner.generateFindings(aiResult);
    /*
     * Generate findings.
     */

    // findings.push(...aiFindings);
    /*
     * Sender/domain findings.
     */
    this.generateSenderFindings(normalizedSender, senderDomain, findings);

    /*
     * Reply-To / Return-Path findings.
     */
    this.generateEmailAddressFindings(
      {
        senderEmail: normalizedSender,

        senderDomain,

        replyTo: normalizedReplyTo,

        replyToDomain,

        returnPath: normalizedReturnPath,

        returnPathDomain,
      },
      findings,
    );

    /*
     * SPF/DKIM/DMARC findings.
     */
    this.generateAuthenticationFindings(
      {
        spfResult: spf_result,

        dkimResult: dkim_result,

        dmarcResult: dmarc_result,
      },
      findings,
    );

    /*
     * Link findings.
     */
    this.generateLinkFindings(suspiciousLinks, findings);

    /*
     * Keyword findings.
     */
    this.generateKeywordFindings(keywordMatches, findings);

    /*
     * Urgency finding.
     */
    if (urgencyDetected) {
      findings.push({
        finding_type: "OTHER",

        finding_value: "URGENT_LANGUAGE",

        severity: 3,

        score: 15,

        description:
          "The email contains language commonly used to create urgency or pressure the recipient.",

        source: "EMAIL_RULE_ENGINE",

        evidence: {
          subject: normalizedSubject,
        },
      });
    }

    /*
     * Credential request finding.
     */
    if (credentialRequest) {
      findings.push({
        finding_type: "OTHER",

        finding_value: "CREDENTIAL_REQUEST",

        severity: 5,

        score: 30,

        description:
          "The email appears to request sensitive credentials or authentication information.",

        source: "EMAIL_RULE_ENGINE",

        evidence: {
          subject: normalizedSubject,
        },
      });
    }

    /*
     * Spoofing finding.
     */
    if (spoofDetected) {
      findings.push({
        finding_type: "HEADER",

        finding_value: "POSSIBLE_SPOOFING",

        severity: 5,

        score: 35,

        description:
          "The email contains indicators of possible sender spoofing or authentication failure.",

        source: "EMAIL_RULE_ENGINE",

        evidence: {
          sender: normalizedSender,

          senderDomain,

          replyTo: normalizedReplyTo,

          returnPath: normalizedReturnPath,

          spfResult: spf_result,

          dkimResult: dkim_result,

          dmarcResult: dmarc_result,
        },
      });
    }

    /*
     * Attachment finding.
     */
    if (attachment_found === true) {
      findings.push({
        finding_type: "OTHER",

        finding_value: "ATTACHMENT_PRESENT",

        severity: 2,

        score: 5,

        description:
          "The email contains an attachment. Attachments may require additional security analysis.",

        source: "EMAIL_RULE_ENGINE",

        evidence: {
          attachmentFound: true,
        },
      });
    }

    /*
     * Calculate final risk score.
     */
    const riskResult = await RiskScoreService.calculate(findings);

    /*
     * Store email scan result.
     */
    const emailScan = await EmailScanModel.create({
      scan_id: scanId,

      sender_email: normalizedSender,

      sender_domain: senderDomain,

      reply_to: normalizedReplyTo,

      return_path: normalizedReturnPath,

      subject: normalizedSubject,

      body: normalizedBody,

      suspicious_links: suspiciousLinks,

      suspicious_keywords: keywordMatches.map((item) => item.keyword),

      attachment_found: attachment_found,
      // attachment_found: attachment_found === true,

      urgency_detected: urgencyDetected,

      credential_request: credentialRequest,

      spoof_detected: spoofDetected,

      spf_result: spf_result,

      dkim_result: dkim_result,

      dmarc_result: dmarc_result,

      ai_summary: aiResult?.summary ?? null,

      api_response: {
        ai: aiResult ?? null,
      },
    });

    /*
     * Store findings.
     */
    const createdFindings = [];

    for (const finding of findings) {
      const created = await ScanFindingModel.create({
        scan_id: scanId,

        finding_type: finding.finding_type,

        finding_value: finding.finding_value,

        severity: finding.severity,

        score: finding.score,

        description: finding.description,

        source: finding.source,

        evidence: finding.evidence,
      });

      createdFindings.push(created);
    }

    /*
     * Return complete scan result.
     */
    return {
      emailScan,

      findings: createdFindings,

      riskScore: riskResult.riskScore,

      riskLevel: riskResult.riskLevel,

      isPhishing: riskResult.isPhishing,

      recommendation: riskResult.recommendation,

      statistics: riskResult.statistics,
      ai: aiResult
        ? {
            confidence: aiResult.confidence,
            summary: aiResult.summary,
            category: aiResult.category,
          }
        : null,
    };
  }

  /**
   * Extract domain from an email address.
   */
  static extractEmailDomain(email) {
    const parts = email.split("@");

    if (parts.length !== 2) {
      throw new ApiError(400, `Invalid email address: ${email}`);
    }

    const domain = parts[1].trim().toLowerCase();

    if (!domain) {
      throw new ApiError(400, `Invalid email domain: ${email}`);
    }

    return domain;
  }

  /**
   * Extract links from email content.
   */
  static extractLinks(text) {
    if (!text) {
      return [];
    }

    const urlRegex = /https?:\/\/[^\s<>"']+/gi;

    const matches = text.match(urlRegex) || [];

    return [...new Set(matches.map((url) => url.replace(/[),.;!?]+$/, "")))];
  }

  /**
   * Detect urgency-related language.
   */
  static detectUrgency(subject, body) {
    const text = `${subject} ${body}`.toLowerCase();

    const urgencyPatterns = [
      "urgent",
      "immediately",
      "act now",
      "action required",
      "account will be closed",
      "account will be suspended",
      "verify now",
      "respond immediately",
      "final warning",
      "last warning",
      "within 24 hours",
      "within 48 hours",
      "limited time",
      "expires today",
      "expires soon",
    ];

    return urgencyPatterns.some((pattern) => text.includes(pattern));
  }

  /**
   * Detect credential requests.
   */
  static detectCredentialRequest(subject, body) {
    const text = `${subject} ${body}`.toLowerCase();

    const credentialPatterns = [
      "password",
      "login",
      "username",
      "user name",
      "sign in",
      "signin",
      "verify your account",
      "verify your identity",
      "confirm your identity",
      "security code",
      "verification code",
      "otp",
      "one time password",
      "credit card",
      "card number",
      "cvv",
      "bank account",
      "account number",
      "pin",
    ];

    return credentialPatterns.some((pattern) => text.includes(pattern));
  }

  /**
   * Detect mismatches between:
   *
   * From
   * Reply-To
   * Return-Path
   */
  static detectEmailAddressMismatch({
    senderDomain,
    replyToDomain,
    returnPathDomain,
  }) {
    const mismatches = [];

    if (replyToDomain && replyToDomain !== senderDomain) {
      mismatches.push("REPLY_TO_DOMAIN_MISMATCH");
    }

    if (returnPathDomain && returnPathDomain !== senderDomain) {
      mismatches.push("RETURN_PATH_DOMAIN_MISMATCH");
    }

    return mismatches;
  }

  /**
   * Generate Reply-To / Return-Path
   * findings.
   */
  static generateEmailAddressFindings(
    {
      senderEmail,
      senderDomain,
      replyTo,
      replyToDomain,
      returnPath,
      returnPathDomain,
    },
    findings,
  ) {
    /*
     * Reply-To mismatch.
     */
    if (replyToDomain && replyToDomain !== senderDomain) {
      findings.push({
        finding_type: "HEADER",

        finding_value: "REPLY_TO_DOMAIN_MISMATCH",

        severity: 4,

        score: 20,

        description: "The Reply-To domain differs from the sender domain.",

        source: "EMAIL_HEADER_ANALYSIS",

        evidence: {
          senderEmail,
          senderDomain,
          replyTo,
          replyToDomain,
        },
      });
    }

    /*
     * Return-Path mismatch.
     */
    if (returnPathDomain && returnPathDomain !== senderDomain) {
      findings.push({
        finding_type: "HEADER",

        finding_value: "RETURN_PATH_DOMAIN_MISMATCH",

        severity: 3,

        score: 10,

        description: "The Return-Path domain differs from the sender domain.",

        source: "EMAIL_HEADER_ANALYSIS",

        evidence: {
          senderEmail,
          senderDomain,
          returnPath,
          returnPathDomain,
        },
      });
    }
  }

  /**
   * Generate SPF, DKIM and DMARC findings.
   *
   * Accepted results:
   *
   * PASS
   * FAIL
   * SOFTFAIL
   * NEUTRAL
   * NONE
   * TEMPERROR
   * PERMERROR
   */
  static generateAuthenticationFindings(
    { spfResult, dkimResult, dmarcResult },
    findings,
  ) {
    const normalize = (value) => (value ? value.trim().toUpperCase() : null);

    const spf = normalize(spfResult);

    const dkim = normalize(dkimResult);

    const dmarc = normalize(dmarcResult);

    /*
     * SPF.
     */
    if (spf === "FAIL" || spf === "SOFTFAIL") {
      findings.push({
        finding_type: "HEADER",

        finding_value: `SPF_${spf}`,

        severity: spf === "FAIL" ? 4 : 3,

        score: spf === "FAIL" ? 20 : 10,

        description: `SPF authentication returned ${spf}.`,

        source: "SPF",

        evidence: {
          result: spf,
        },
      });
    }

    /*
     * DKIM.
     */
    if (dkim === "FAIL") {
      findings.push({
        finding_type: "HEADER",

        finding_value: "DKIM_FAIL",

        severity: 4,

        score: 20,

        description: "DKIM authentication failed.",

        source: "DKIM",

        evidence: {
          result: dkim,
        },
      });
    }

    /*
     * DMARC.
     */
    if (dmarc === "FAIL") {
      findings.push({
        finding_type: "HEADER",

        finding_value: "DMARC_FAIL",

        severity: 5,

        score: 30,

        description: "DMARC authentication failed.",

        source: "DMARC",

        evidence: {
          result: dmarc,
        },
      });
    }
  }

  /**
   * Detect possible spoofing.
   *
   * This is still rule-based.
   * Real spoofing analysis should use
   * actual email authentication headers.
   */
  static detectSpoofing({
    senderEmail,
    senderDomain,
    replyTo,
    returnPath,
    subject,
    body,
    emailAddressMismatch,
    spfResult,
    dkimResult,
    dmarcResult,
  }) {
    const spf = spfResult?.trim().toUpperCase();

    const dkim = dkimResult?.trim().toUpperCase();

    const dmarc = dmarcResult?.trim().toUpperCase();

    /*
     * Authentication failure.
     */
    if (spf === "FAIL" || dkim === "FAIL" || dmarc === "FAIL") {
      return true;
    }

    /*
     * Header mismatch.
     */
    if (emailAddressMismatch.length > 0) {
      return true;
    }

    /*
     * Brand impersonation using
     * generic email providers.
     */
    const text = `${subject} ${body}`.toLowerCase();

    const trustedBrands = [
      "paypal",
      "microsoft",
      "google",
      "apple",
      "amazon",
      "facebook",
      "instagram",
      "netflix",
      "linkedin",
      "bank",
    ];

    const genericProviders = [
      "gmail.com",
      "yahoo.com",
      "hotmail.com",
      "outlook.com",
      "proton.me",
    ];

    const claimsTrustedBrand = trustedBrands.some((brand) =>
      text.includes(brand),
    );

    if (claimsTrustedBrand && genericProviders.includes(senderDomain)) {
      return true;
    }

    return false;
  }

  /**
   * Generate sender/domain findings.
   */
  static generateSenderFindings(senderEmail, senderDomain, findings) {
    const freeEmailProviders = [
      "gmail.com",
      "yahoo.com",
      "hotmail.com",
      "outlook.com",
      "proton.me",
    ];

    if (freeEmailProviders.includes(senderDomain)) {
      findings.push({
        finding_type: "DOMAIN",

        finding_value: "FREE_EMAIL_PROVIDER",

        severity: 1,

        score: 2,

        description: "The sender uses a public/free email provider.",

        source: "EMAIL_RULE_ENGINE",

        evidence: {
          sender: senderEmail,

          domain: senderDomain,
        },
      });
    }

    /*
     * Long sender domain.
     */
    if (senderDomain.length > 50) {
      findings.push({
        finding_type: "DOMAIN",

        finding_value: "LONG_SENDER_DOMAIN",

        severity: 2,

        score: 5,

        description: "The sender domain is unusually long.",

        source: "EMAIL_RULE_ENGINE",

        evidence: {
          domain: senderDomain,

          length: senderDomain.length,
        },
      });
    }
  }

  /**
   * Generate link findings.
   */
  static generateLinkFindings(links, findings) {
    if (!links || links.length === 0) {
      return;
    }

    for (const link of links) {
      try {
        const parsed = new URL(link);

        const hostname = parsed.hostname;

        /*
         * HTTP instead of HTTPS.
         */
        if (parsed.protocol === "http:") {
          findings.push({
            finding_type: "LINK",

            finding_value: "INSECURE_HTTP_LINK",

            severity: 3,

            score: 10,

            description: "The email contains a link that does not use HTTPS.",

            source: "EMAIL_RULE_ENGINE",

            evidence: {
              url: link,
              hostname,
            },
          });
        }

        /*
         * IP address as hostname.
         */
        if (this.isIpAddress(hostname)) {
          findings.push({
            finding_type: "LINK",

            finding_value: "IP_ADDRESS_LINK",

            severity: 4,

            score: 20,

            description:
              "The email contains a link using an IP address instead of a domain name.",

            source: "EMAIL_RULE_ENGINE",

            evidence: {
              url: link,
              hostname,
            },
          });
        }

        /*
         * @ symbol.
         */
        if (link.includes("@")) {
          findings.push({
            finding_type: "LINK",

            finding_value: "AT_SYMBOL_LINK",

            severity: 4,

            score: 20,

            description:
              "The email contains a URL with an @ symbol, which can obscure the actual destination.",

            source: "EMAIL_RULE_ENGINE",

            evidence: {
              url: link,
            },
          });
        }

        /*
         * Very long URL.
         */
        if (link.length > 150) {
          findings.push({
            finding_type: "LINK",

            finding_value: "LONG_URL",

            severity: 2,

            score: 5,

            description: "The email contains an unusually long URL.",

            source: "EMAIL_RULE_ENGINE",

            evidence: {
              url: link,
              length: link.length,
            },
          });
        }
      } catch {
        /*
         * Invalid URL is ignored here.
         * Full URL analysis can later be
         * delegated to UrlScanner.
         */
      }
    }
  }

  /**
   * Generate phishing keyword findings.
   */
  static generateKeywordFindings(keywordMatches, findings) {
    for (const keyword of keywordMatches) {
      findings.push({
        finding_type: "KEYWORD",

        finding_value: keyword.keyword,

        severity: keyword.severity ?? 3,

        score: keyword.score ?? 10,

        description:
          keyword.description ||
          `Suspicious phishing keyword detected: ${keyword.keyword}`,

        source: "PHISHING_KEYWORD_DATABASE",

        evidence: {
          keyword: keyword.keyword,

          category: keyword.category,

          match_type: keyword.match_type,
        },
      });
    }
  }

  /**
   * Detect phishing keywords from database.
   */
  static async detectPhishingKeywords(text) {
    if (!text) {
      return [];
    }

    const keywords = await PhishingKeywordModel.getActiveKeywords();

    if (!keywords || keywords.length === 0) {
      return [];
    }

    const matches = [];

    for (const keyword of keywords) {
      if (!keyword.keyword) {
        continue;
      }

      const searchText = keyword.is_case_sensitive ? text : text.toLowerCase();

      const searchKeyword = keyword.is_case_sensitive
        ? keyword.keyword
        : keyword.keyword.toLowerCase();

      let matched = false;

      switch (keyword.match_type) {
        case "EXACT":
          matched = searchText.split(/\s+/).includes(searchKeyword);
          break;

        case "CONTAINS":
          matched = searchText.includes(searchKeyword);
          break;

        case "REGEX":
          try {
            const flags = keyword.is_case_sensitive ? "" : "i";

            const regex = new RegExp(keyword.keyword, flags);

            matched = regex.test(text);
          } catch {
            matched = false;
          }
          break;

        default:
          matched = false;
      }

      if (matched) {
        matches.push(keyword);
      }
    }

    return matches;
  }

  /**
   * Check whether hostname is IPv4.
   */
  static isIpAddress(hostname) {
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  }
}

export default EmailScanner;
