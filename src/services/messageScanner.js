import ApiError from "../utils/ApiError.js";

import Url from "url-parse";

import MessageScanModel from "../models/messageScanModel.js";
import ScanFindingModel from "../models/scanFindingModel.js";
import UrlModel from "../models/urlModel.js";
import DomainModel from "../models/domainModel.js";
import PhishingKeywordModel from "../models/phishingKeywordModel.js";

import UrlScanner from "./urlScanner.js";
import UrlReputationService from "./urlReputationService.js";
import RiskScoreService from "./riskScoreService.js";
import AIScanner from "./aiScanner.js";

class MessageScanner {
  static async scan(scanId, messageData) {
    if (!scanId) {
      throw new ApiError(400, "Scan id is required.");
    }

    if (!messageData) {
      throw new ApiError(400, "Message data is required.");
    }

    const {
      platform = "OTHER",
      sender = null,
      sender_id = null,
      language = null,
      message,
    } = messageData;

    if (!message || typeof message !== "string") {
      throw new ApiError(400, "Message is required.");
    }
    const urls = this.extractUrls(message);

    const emails = this.extractEmails(message);

    const phoneNumbers = this.extractPhoneNumbers(message);

    const keywordMatches = await this.detectPhishingKeywords(message);

    const urgencyDetected = this.detectUrgency(message);

    const credentialRequest = this.detectCredentialRequest(message);

    const financialRequest = this.detectFinancialRequest(message);

    const impersonationDetected = this.detectImpersonation(message);

    const shortenedUrlDetected = this.detectShortenedUrls(urls);

    const detectedLanguage = language ?? this.detectLanguage(message);

    const scamType = this.detectScamType(message);
    //Input for AI
    const aiInput = {
      urls,
      emails,
      phoneNumbers,
      keywordMatches,
      urgencyDetected,
      credentialRequest,
      financialRequest,
      impersonationDetected,
      shortenedUrlDetected,
      detectedLanguage,
    };
    const findings = [];
    //ai
    const aiPromise = AIScanner.analyseMessage(aiInput);
    //wait for ai max 15 sec
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("AI timeout")), 15000),
    );
    let aiResult = null;
    try {
      // aiResult = await AIScanner.analyseMessage(aiInput);
      aiResult = await Promise.race([aiPromise, timeoutPromise]);
      const aiFindings = await AIScanner.generateFindings(aiResult);
      // if (aiFindings) {
      // }
      findings.push(...aiFindings);
    } catch (error) {
      console.error("AI message analysis failed:", error.message);
    }

    // findings.push(...aiResult.findings);

    const scannedUrls = [];

    for (const url of urls) {
      try {
        const normalized = UrlScanner.normaliseUrl(url);

        const parsed = UrlScanner.parseUrl(normalized);

        const features = UrlScanner.analyseUrl(parsed, normalized);

        scannedUrls.push({
          original: url,
          normalized,
          features,
        });
      } catch (error) {
        findings.push({
          finding_type: "URL",
          finding_value: "INVALID_URL",
          severity: 2,
          score: 10,
          description: "Invalid URL detected.",
          source: "MESSAGE_ANALYZER",
          evidence: {
            url,
          },
        });
      }
    }
    /*
     * Analyse every extracted URL.
     */
    for (const scannedUrl of scannedUrls) {
      const urlRecord = await UrlModel.findByUrl(scannedUrl.normalized);

      const urlBlacklisted = Boolean(
        urlRecord && urlRecord.list_type === "BLACKLIST" && urlRecord.is_active,
      );

      const urlWhitelisted = Boolean(
        urlRecord && urlRecord.list_type === "WHITELIST" && urlRecord.is_active,
      );

      const domainRecord = await DomainModel.findByDomainName(
        scannedUrl.features.hostname,
      );

      const domainBlacklisted = Boolean(
        domainRecord &&
        domainRecord.list_type === "BLACKLIST" &&
        domainRecord.is_active,
      );

      const domainWhitelisted = Boolean(
        domainRecord &&
        domainRecord.list_type === "WHITELIST" &&
        domainRecord.is_active,
      );

      /*
       * External reputation.
       */
      const reputation = await UrlReputationService.checkUrl(
        scannedUrl.normalized,
      );

      /*
       * Generate URL findings.
       */
      this.generateUrlFindings(scannedUrl.features, findings);

      /*
       * Generate blacklist findings.
       */
      this.generateReputationFindings(
        {
          urlBlacklisted,
          urlWhitelisted,
          domainBlacklisted,
          domainWhitelisted,
          urlRecord,
          domainRecord,
          reputation,
        },
        findings,
      );
    }
    /*
     * Keyword findings.
     */
    this.generateKeywordFindings(keywordMatches, findings);
    /*
     * Urgency detection.
     */
    if (urgencyDetected) {
      findings.push({
        finding_type: "OTHER",
        finding_value: "URGENT_LANGUAGE",
        severity: 3,
        score: 15,
        description: "Urgent language detected.",
        source: "MESSAGE_RULE_ENGINE",
        evidence: {
          message,
        },
      });
    }

    /*
     * Credential request.
     */
    if (credentialRequest) {
      findings.push({
        finding_type: "OTHER",
        finding_value: "CREDENTIAL_REQUEST",
        severity: 5,
        score: 30,
        description: "Credential request detected.",
        source: "MESSAGE_RULE_ENGINE",
        evidence: {
          message,
        },
      });
    }

    /*
     * Financial request.
     */
    if (financialRequest) {
      findings.push({
        finding_type: "OTHER",
        finding_value: "FINANCIAL_REQUEST",
        severity: 5,
        score: 25,
        description: "Financial request detected.",
        source: "MESSAGE_RULE_ENGINE",
        evidence: {
          message,
        },
      });
    }

    /*
     * Impersonation.
     */
    if (impersonationDetected) {
      findings.push({
        finding_type: "OTHER",
        finding_value: "IMPERSONATION",
        severity: 5,
        score: 30,
        description: "Possible impersonation detected.",
        source: "MESSAGE_RULE_ENGINE",
        evidence: {
          message,
        },
      });
    }

    /*
     * Shortened URLs.
     */
    if (shortenedUrlDetected) {
      findings.push({
        finding_type: "URL",
        finding_value: "SHORTENED_URL",
        severity: 3,
        score: 15,
        description: "Shortened URL detected.",
        source: "MESSAGE_RULE_ENGINE",
        evidence: {
          urls,
        },
      });
    }

    /*
     * Phone numbers.
     */
    if (phoneNumbers.length > 0) {
      findings.push({
        finding_type: "OTHER",
        finding_value: "PHONE_NUMBER",
        severity: 1,
        score: 2,
        description: "Phone number detected.",
        source: "MESSAGE_RULE_ENGINE",
        evidence: {
          phoneNumbers,
        },
      });
    }

    /*
     * Email addresses.
     */
    if (emails.length > 0) {
      findings.push({
        finding_type: "OTHER",
        finding_value: "EMAIL_ADDRESS",
        severity: 1,
        score: 2,
        description: "Email address detected.",
        source: "MESSAGE_RULE_ENGINE",
        evidence: {
          emails,
        },
      });
    }
    /*
     * Calculate final risk.
     */
    const riskResult = await RiskScoreService.calculate(findings);
    /*
     * Save message scan.
     */
    const messageScan = await MessageScanModel.create({
      scan_id: scanId,

      platform,

      sender,

      sender_id,

      message,

      language: detectedLanguage,

      suspicious_links: urls,

      suspicious_keywords: keywordMatches.map((item) => item.keyword),

      urgency_detected: urgencyDetected,

      credential_request: credentialRequest,

      financial_request: financialRequest,

      impersonation_detected: impersonationDetected,

      shortened_url_detected: shortenedUrlDetected,

      phone_number_detected: phoneNumbers.length > 0,

      email_detected: emails.length > 0,

      scam_type: scamType,

      ai_summary: aiResult?.summary ?? null,

      // api_response: {
      //   scannedUrls,
      // },
      api_response: {
        ai: aiResult,
        scannedUrls,
      },
    });
    /*
     * Save findings.
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
    return {
      messageScan,

      findings: createdFindings,

      riskScore: riskResult.riskScore,

      riskLevel: riskResult.riskLevel,

      recommendation: riskResult.recommendation,

      isPhishing: riskResult.isPhishing,

      statistics: riskResult.statistics,

      extracted: {
        urls,

        emails,

        phoneNumbers,
      },
      ai: {
        confidence: aiResult.confidence,

        category: aiResult.category,

        summary: aiResult.summary,
      },
    };
  }
  /**
   * Extract URLs from a message.
   */
  static extractUrls(message) {
    if (!message) {
      return [];
    }

    const regex =
      /https?:\/\/[^\s]+|www\.[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s]*)?/gi;

    return [...new Set(message.match(regex) || [])];
  }
  /**
   * Extract email addresses.
   */
  static extractEmails(message) {
    if (!message) {
      return [];
    }

    const regex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

    return [...new Set(message.match(regex) || [])];
  }
  /**
   * Extract phone numbers.
   */
  static extractPhoneNumbers(message) {
    if (!message) {
      return [];
    }

    const regex = /(\+?\d[\d\s-]{8,}\d)/g;

    return [...new Set(message.match(regex) || [])];
  } /**
   * Detect urgency language.
   */
  static detectUrgency(message) {
    const words = [
      "urgent",
      "immediately",
      "verify now",
      "act now",
      "limited time",
      "today",
      "expire",
      "expires",
      "suspended",
      "blocked",
      "warning",
      "alert",
    ];

    const text = message.toLowerCase();

    return words.some((word) => text.includes(word));
  } /**
   * Detect credential requests.
   */
  static detectCredentialRequest(message) {
    const patterns = [
      "password",
      "login",
      "otp",
      "pin",
      "cvv",
      "verification code",
      "security code",
      "username",
    ];

    const text = message.toLowerCase();

    return patterns.some((word) => text.includes(word));
  }
  /**
   * Detect financial requests.
   */
  static detectFinancialRequest(message) {
    const patterns = [
      "bank",
      "payment",
      "upi",
      "wallet",
      "transfer",
      "credit card",
      "debit card",
      "refund",
      "invoice",
      "transaction",
      "pay now",
    ];

    const text = message.toLowerCase();

    return patterns.some((word) => text.includes(word));
  }
  /**
   * Detect impersonation.
   */
  static detectImpersonation(message) {
    const brands = [
      "paypal",
      "google",
      "amazon",
      "apple",
      "microsoft",
      "facebook",
      "instagram",
      "netflix",
      "bank",
      "sbi",
      "hdfc",
      "icici",
      "axis",
      "paytm",
    ];

    const text = message.toLowerCase();

    return brands.some((brand) => text.includes(brand));
  }
  /**
   * Detect shortened URLs.
   */
  static detectShortenedUrls(urls) {
    const services = [
      "bit.ly",
      "tinyurl.com",
      "goo.gl",
      "t.co",
      "is.gd",
      "ow.ly",
      "buff.ly",
      "rebrand.ly",
    ];

    return urls.some((url) =>
      services.some((service) => url.includes(service)),
    );
  }
  /**
   * Very basic language detection.
   */
  static detectLanguage(message) {
    if (/[\u0900-\u097F]/.test(message)) {
      return "hi";
    }

    return "en";
  }
  /**
   * Detect scam type.
   */
  static detectScamType(message) {
    const text = message.toLowerCase();

    if (text.includes("otp") || text.includes("password")) {
      return "Credential Theft";
    }

    if (text.includes("bank") || text.includes("payment")) {
      return "Financial Fraud";
    }

    if (text.includes("gift") || text.includes("lottery")) {
      return "Lottery Scam";
    }

    if (text.includes("refund")) {
      return "Refund Scam";
    }

    return "Unknown";
  }
  /**
   * Detect phishing keywords in a message.
   */
  static async detectPhishingKeywords(message) {
    if (!message) {
      return [];
    }

    const keywords = await PhishingKeywordModel.getActiveKeywords();

    const matches = [];

    for (const keyword of keywords) {
      const text = keyword.is_case_sensitive ? message : message.toLowerCase();

      const value = keyword.is_case_sensitive
        ? keyword.keyword
        : keyword.keyword.toLowerCase();

      let matched = false;

      switch (keyword.match_type) {
        case "EXACT":
          matched = text === value;

          break;

        case "CONTAINS":
          matched = text.includes(value);

          break;

        case "REGEX":
          try {
            const regex = new RegExp(
              keyword.keyword,
              keyword.is_case_sensitive ? "g" : "gi",
            );

            matched = regex.test(message);
          } catch (error) {
            console.error(`Invalid regex keyword: ${keyword.keyword}`);
          }

          break;

        default:
          break;
      }

      if (matched) {
        matches.push({
          keyword: keyword.keyword,

          category: keyword.category,

          severity: keyword.severity,

          score: keyword.score,

          description: keyword.description,

          example: keyword.example,

          match_type: keyword.match_type,
        });
      }
    }

    return matches;
  }

  /**
   * Generate findings from phishing keyword matches.
   */
  static generateKeywordFindings(keywordMatches, findings) {
    if (!keywordMatches?.length) {
      return;
    }

    for (const keyword of keywordMatches) {
      findings.push({
        finding_type: "KEYWORD",

        finding_value: keyword.keyword,

        severity: keyword.severity,

        score: keyword.score,

        description:
          keyword.description ??
          `Matched phishing keyword "${keyword.keyword}".`,

        source: "KEYWORD_DATABASE",

        evidence: {
          category: keyword.category,
          match_type: keyword.match_type,
          example: keyword.example,
        },
      });
    }
  }
  /**
   * Generate findings based on blacklist, whitelist,
   * and external reputation.
   */
  static generateReputationFindings(reputationData, findings) {
    const {
      urlBlacklisted,
      urlWhitelisted,

      domainBlacklisted,
      domainWhitelisted,

      urlRecord,
      domainRecord,

      reputation,
    } = reputationData;

    /*
     * URL blacklist.
     */
    if (urlBlacklisted) {
      findings.push({
        finding_type: "URL",

        finding_value: "BLACKLISTED_URL",

        severity: 5,

        score: 50,

        description: "The URL exists in the RiskRadar blacklist.",

        source: "URL_DATABASE",

        evidence: {
          url: urlRecord?.url,
          reason: urlRecord?.reason,
          source: urlRecord?.source,
          confidence_score: urlRecord?.confidence_score,
        },
      });
    }

    /*
     * Domain blacklist.
     */
    if (domainBlacklisted) {
      findings.push({
        finding_type: "DOMAIN",

        finding_value: "BLACKLISTED_DOMAIN",

        severity: 5,

        score: 50,

        description: "The domain exists in the RiskRadar blacklist.",

        source: "DOMAIN_DATABASE",

        evidence: {
          domain: domainRecord?.domain_name,
          reason: domainRecord?.reason,
          source: domainRecord?.source,
          confidence_score: domainRecord?.confidence_score,
        },
      });
    }

    /*
     * URL whitelist.
     */
    if (urlWhitelisted) {
      findings.push({
        finding_type: "URL",

        finding_value: "WHITELISTED_URL",

        severity: 1,

        score: -30,

        description: "The URL exists in the whitelist.",

        source: "URL_DATABASE",

        evidence: {
          url: urlRecord?.url,
        },
      });
    }

    /*
     * Domain whitelist.
     */
    if (domainWhitelisted) {
      findings.push({
        finding_type: "DOMAIN",

        finding_value: "WHITELISTED_DOMAIN",

        severity: 1,

        score: -30,

        description: "The domain exists in the whitelist.",

        source: "DOMAIN_DATABASE",

        evidence: {
          domain: domainRecord?.domain_name,
        },
      });
    }

    // /*
    //  * Google Safe Browsing.
    //  */
    // if (reputation?.google?.safe === false) {
    //   findings.push({
    //     finding_type: "URL",

    //     finding_value: "GOOGLE_UNSAFE",

    //     severity: 5,

    //     score: 40,

    //     description: "Google Safe Browsing flagged this URL.",

    //     source: "GOOGLE_SAFE_BROWSING",

    //     evidence: reputation.google.response,
    //   });
    // }

    // /*
    //  * VirusTotal.
    //  */
    // if (reputation?.virustotal?.malicious) {
    //   findings.push({
    //     finding_type: "URL",

    //     finding_value: "VIRUSTOTAL_MALICIOUS",

    //     severity: 5,

    //     score: 40,

    //     description: "VirusTotal marked this URL as malicious.",

    //     source: "VIRUSTOTAL",

    //     evidence: reputation.virustotal.response,
    //   });
    // }
  }
  /**
   * Generate findings from URL features.
   */
  static generateUrlFindings(features, findings) {
    if (features.containsIp) {
      findings.push({
        finding_type: "URL",

        finding_value: "IP_ADDRESS",

        severity: 3,

        score: 10,

        description: "URL contains an IP address.",

        source: "URL_ANALYZER",

        evidence: features,
      });
    }

    if (features.containsAtSymbol) {
      findings.push({
        finding_type: "URL",

        finding_value: "AT_SYMBOL",

        severity: 3,

        score: 10,

        description: "URL contains '@' symbol.",

        source: "URL_ANALYZER",

        evidence: features,
      });
    }

    if (features.containsHexEncoding) {
      findings.push({
        finding_type: "URL",

        finding_value: "HEX_ENCODING",

        severity: 4,

        score: 20,

        description: "URL contains hexadecimal encoding.",

        source: "URL_ANALYZER",

        evidence: features,
      });
    }

    if (features.containsPunycode) {
      findings.push({
        finding_type: "URL",

        finding_value: "PUNYCODE",

        severity: 4,

        score: 20,

        description: "Internationalized domain (Punycode) detected.",

        source: "URL_ANALYZER",

        evidence: features,
      });
    }

    if (features.containsSuspiciousTld) {
      findings.push({
        finding_type: "URL",

        finding_value: "SUSPICIOUS_TLD",

        severity: 3,

        score: 15,

        description: "Suspicious top-level domain detected.",

        source: "URL_ANALYZER",

        evidence: features,
      });
    }

    if (features.hasNonStandardPort) {
      findings.push({
        finding_type: "URL",

        finding_value: "NON_STANDARD_PORT",

        severity: 2,

        score: 8,

        description: "URL uses a non-standard port.",

        source: "URL_ANALYZER",

        evidence: features,
      });
    }
  }
}
export default MessageScanner;
