import dns from "node:dns/promises";
import net from "node:net";
import ApiError from "../utils/ApiError.js";
import PhishingKeywordModel from "../models/phishingKeywordModel.js";
import UrlModel from "../models/urlModel.js";
import DomainModel from "../models/domainModel.js";
import UrlScanModel from "../models/urlScanModel.js";
import ScanFindingModel from "../models/scanFindingModel.js";
import RiskScoreService from "./riskScoreService.js";
import UrlReputationService from "./urlReputationService.js";
import AIScanner from "./aiScanner.js";
/**
 * Common URL shortener domains.
 *
 * note:This list can be expanded later or moved to the database.
 */
const URL_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "buff.ly",
  "cutt.ly",
  "shorturl.at",
  "rebrand.ly",
  "tiny.cc",
  "lnkd.in",
  "rb.gy",
  "s.id",
]);

/**
 * Suspicious / commonly abused TLDs-top-level-domain example .com,.in etc.
 *
 * This is only a heuristic.
 * It should NOT be treated as proof that a domain is malicious.
 */
const SUSPICIOUS_TLDS = new Set([
  "zip",
  "mov",
  "click",
  "country",
  "gq",
  "tk",
  "ml",
  "ga",
  "cf",
  "top",
  "xyz",
  "work",
  "party",
  "download",
  "stream",
  "loan",
  "win",
  "review",
  "trade",
  "science",
  "racing",
  "date",
  "faith",
  "men",
  "live",
]);

class UrlScanner {
  /**
   * main scanning function
   * this method will do the following:
   * 1. Validates URL
   * 2. Normalizes URL
   * 3. Extracts URL features
   * 4. Checks URL blacklist
   * 5. Checks domain blacklist / whitelist
   * 6. Checks phishing keywords
   * 7. Creates scan_findings
   * 8. Stores complete url_scans record
   */
  static async scan(scanId, inputUrl) {
    if (!scanId) {
      throw new ApiError(400, "Scan id is required.");
    }
    if (!inputUrl || typeof inputUrl !== "string") {
      throw new ApiError(400, "URL is required.");
    }
    const normalisedUrl = this.normaliseUrl(inputUrl);
    const url = this.parseUrl(normalisedUrl);
    const features = this.analyseUrl(url, normalisedUrl);
    /**
     * check wheather the exact url exists in
     * the URL database
     */
    const urlRecord = await UrlModel.findByUrl(normalisedUrl);
    const urlBlacklisted = Boolean(
      urlRecord && urlRecord.list_type === "BLACKLIST" && urlRecord.is_active,
    );
    /**
     * Now check the domain
     */
    const domainRecord = await DomainModel.findByDomainName(url.hostname);
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
    /**
     * check for phishing keywords.
     */
    const keywordMatches = await this.detectPhishingKeywords(
      normalisedUrl,
      url,
    );

    const findings = [];
    /**
     * calculate intital rule-based score.
     
     */
    this.generateUrlFindings(features, findings);
    this.generateReputationFindings(
      {
        urlBlacklisted,
        domainBlacklisted,
        domainWhitelisted,
        domainRecord,
        urlRecord,
      },
      findings,
    );
    /**check for reputation providers */
    const reputationResult = await UrlReputationService.checkUrl(normalisedUrl);
    if (reputationResult.google.malicious) {
      findings.push({
        finding_type: "REPUTATION",
        finding_value: "GOOGLE_SAFE_BROWSING",
        severity: 5,
        score: 60,
        description: "Google Safe Browsing identified this URL as unsafe.",
        source: "GOOGLE_SAFE_BROWSING",
        evidence: {
          response: reputationResult.google.response,
        },
      });
    }

    if (reputationResult.virustotal.malicious) {
      const analysis = reputationResult.virustotal.analysis;

      findings.push({
        finding_type: "REPUTATION",
        finding_value: "VIRUSTOTAL_MALICIOUS",
        severity: 5,
        score: Math.min(60, 20 + Number(analysis?.malicious || 0) * 5),
        description:
          "VirusTotal detected malicious security engines for this URL.",
        source: "VIRUSTOTAL",
        evidence: {
          malicious: analysis?.malicious || 0,

          suspicious: analysis?.suspicious || 0,

          harmless: analysis?.harmless || 0,

          undetected: analysis?.undetected || 0,
        },
      });
    }
    if (
      !reputationResult.virustotal.malicious &&
      reputationResult.virustotal.suspicious
    ) {
      findings.push({
        finding_type: "REPUTATION",
        finding_value: "VIRUSTOTAL_SUSPICIOUS",
        severity: 3,
        score: 20,
        description: "VirusTotal identified suspicious signals for this URL.",
        source: "VIRUSTOTAL",
        evidence: {
          malicious: reputationResult.virustotal.analysis?.malicious || 0,

          suspicious: reputationResult.virustotal.analysis?.suspicious || 0,
        },
      });
    }
    this.generateKeywordFindings(keywordMatches, findings);
    /*
     * Calculate score from findings.
     */
    // const riskScore = this.calculateRiskScore(findings);
    const riskResult = await RiskScoreService.calculate(findings);
    //ai
    const aiInput = {
      inputUrl,
      normalizedUrl: normalisedUrl,
      hostname: url.hostname,
      protocol: url.protocol.replace(":", ""),
      googleSafe: reputationResult.google.safe,
      virustotalSafe: reputationResult.virustotal.safe,
      domainBlacklisted,
      domainWhitelisted,
      urlBlacklisted,
      keywordMatches,
      features,
      recommendation: riskResult.recommendation,
      riskScore: riskResult.riskScore,
    };
    let aiResult = null;
    try {
      const aiPromise = AIScanner.analyseUrl(aiInput);
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error("AI analysis timeout")), 15000);
      });
      aiResult = await Promise.race([aiPromise, timeoutPromise]);

      const aiFindings = AIScanner.generateFindings(aiResult);

      findings.push(...aiFindings);
    } catch (error) {
      console.error("AI URL analysis skipped:", error.message);
    }

    /**store url scan result */
    const urlScan = await UrlScanModel.create({
      scan_id: scanId,
      input_url: inputUrl,
      normalized_url: normalisedUrl,
      final_url: null,
      domain_name: url.hostname,
      protocol: url.protocol.replace(":", ""),
      uses_https: features.usesHttps,
      url_length: normalisedUrl.length,
      hostname_length: features.hostnameLength,
      path_length: features.pathLength,
      query_length: features.queryLength,
      subdomain_count: features.subdomainCount,
      contains_ip: features.containsIp,
      contains_shortener: features.containsShortener,
      contains_at_symbol: features.containsAtSymbol,
      contains_hex_encoding: features.containsHexEncoding,
      contains_punycode: features.containsPunycode,
      contains_suspicious_tld: features.containsSuspiciousTld,
      has_non_standard_port: features.hasNonStandardPort,
      domain_blacklisted: domainBlacklisted,
      url_blacklisted: urlBlacklisted,
      // reputation_score: this.calculateReputationScore({
      //   urlBlacklisted,
      //   domainBlacklisted,
      //   domainWhitelisted,
      //   domainRecord,
      //   urlRecord,
      // }),
      reputation_score: reputationResult.reputationScore,
      google_safe: reputationResult.google.safe,

      virustotal_safe: reputationResult.virustotal.safe,
      // recommendation: this.getRecommendation({
      //   riskScore,
      //   urlBlacklisted,
      //   domainBlacklisted,
      //   domainWhitelisted,
      // }),
      recommendation: riskResult.recommendation,
      risk_score: riskResult.riskScore,
      risk_level: riskResult.riskLevel,
      is_phishing: riskResult.isPhishing,
      statistics: riskResult.statistics,
      api_response: {
        reputation: reputationResult,
        ai: aiResult,
      },
    });

    // const aiResult = await AIScanner.analyseUrl(aiInput);

    // const aiFindings = AIScanner.generateFindings(aiResult);

    // findings.push(...aiFindings);
    /*
     * Insert findings into scan_findings.
     *
     * We intentionally do this after url_scans
     * succeeds so that we have a valid scan result.
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
      urlScan,
      findings: createdFindings,
      riskScore: riskResult.riskScore,
      recommendation: riskResult.recommendation,
      riskLevel: riskResult.riskLevel,
      isPhishing: riskResult.isPhishing,
      statistics: riskResult.statistics,
      features,
      ai: aiResult
        ? {
            confidence: aiResult.confidence,
            category: aiResult.category,
            summary: aiResult.summary,
          }
        : null,
    };
  }
  /** Normailise URL
   * Example: example.com to https://example.com
   */
  static normaliseUrl(inputUrl) {
    let value = inputUrl.trim();
    if (!value) {
      throw new ApiError(400, "URL is required.");
    }
    /**
     * Add https if protocol is missing i.e http or https
     */
    if (!/^https?:\/\//i.test(value)) {
      value = `https://${value}`;
    }
    /**
     * Converts the string into a proper URL object.
      This validates the structure (host, protocol, path, etc.).
      If invalid, it throws an error.
      */
    try {
      const url = new URL(value);
      /**
       * 
       * Strips out any embedded username/password.
        Example: https://user:pass@example.com → https://example.com/
        This is a security measure: credentials shouldn’t be sent in normalized URLs.

       * However, @ in the original URL is still
       * detected separately before normalization
       * in the analysis flow where applicable.
       */
      url.username = "";
      url.password = "";
      return url.toString();
    } catch (error) {
      throw new ApiError(400, "Invalid URL.");
    }
  }
  /**
   * parse URL safely.
   */
  static parseUrl(normalisedUrl) {
    try {
      const url = new URL(normalisedUrl);
      if (!["http:", "https:"].includes(url.protocol)) {
        throw new ApiError(400, "Only HTTP and HTTPS URLs are supported.");
      }
      /**
       * Checks that the URL has a valid hostname (like example.com).
        Prevents malformed URLs such as https:///path (missing domain
       */
      if (!url.hostname) {
        throw new ApiError(400, "URL hostname is missing.");
      }
      return url;
    } catch (error) {
      /**
       * Check the type of error
      error instanceof ApiError means: “Is this error already one of my custom ApiError objects?”
      If yes, it simply rethrows the same error.
      This preserves the original message and status code you set earlier 
      (like "Only HTTP and HTTPS URLs are supported.").
       */
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError(400, "Invalid URL.");
    }
  }
  /**
   * Detect URL shorteners by checking the hostname against a predefined list of known URL shortener domains.
   *
   */
  static isUrlShortener(hostname) {
    const host = hostname.toLowerCase();
    if (URL_SHORTENERS.has(host)) {
      return true;
    }
    /**
     * Also support subdomains.
     */
    for (const shortener of URL_SHORTENERS) {
      if (host.endsWith(`.${shortener}`)) {
        return true;
      }
    }
    return false;
  }
  /**
   * Analyse URL structure.
   */
  static analyseUrl(url, normalisedUrl) {
    const hostname = url.hostname.toLowerCase();
    const protocol = url.protocol.replace(":", "");
    const containsIP = net.isIP(hostname) !== 0;
    const containsShortener = this.isUrlShortener(hostname);

    /**
     * Detect @ from the original URL representation.
     * URL.username /URL.password can be used
     * https://user@example.com
     */
    const containsAtSymbol =
      url.username.length > 0 ||
      url.password.length > 0 ||
      normalisedUrl.includes("@");

    const containsHexEncoding = /%[0-9a-f]{2}/i.test(normalisedUrl);
    // const containsPunycode = hostname
    //   .split(".")
    //   .some((part) => part.startsWith("xn--"));
    const containsPunycode = hostname
      .split(".")
      .some(
        (part) =>
          typeof part === "string" && part.toLowerCase().startsWith("xn--"),
      );
    const tld = this.getTld(hostname);
    const containsSuspiciousTld = Boolean(
      tld && SUSPICIOUS_TLDS.has(tld.toLowerCase()),
    );
    const hasNonStandardPort = this.hasNonStandardPort(url);
    const subdomainCount = this.getSubdomainCount(hostname);
    return {
      hostname,
      protocol,
      usesHttps: protocol === "https",
      hostnameLength: hostname.length,
      pathLength: url.pathname.length,
      queryLength: url.search.length,
      subdomainCount,
      containsIP,
      containsShortener,
      containsAtSymbol,
      containsHexEncoding,
      containsPunycode,
      containsSuspiciousTld,
      hasNonStandardPort,
      tld,
      urlLength: normalisedUrl.length,
    };
  }
  /**
   * Check whether port is non-standard.
   *
   * HTTP  -> 80
   * HTTPS -> 443
   */
  static hasNonStandardPort(url) {
    if (!url.port) {
      return false;
    }
    const port = Number(url.port);
    if (url.protocol === "http:" && port === 80) {
      return false;
    }
    if (url.protocol === "https:" && port === 443) {
      return false;
    }
    return true;
  }
  /**
   * Extract TLD.
   *
   * This is a basic implementation.
   *
   * Later we can use the Public Suffix List
   * for more accurate handling.
   */
  static getTld(hostname) {
    const parts = hostname.split(".");

    if (parts.length < 2) {
      return null;
    }

    return parts[parts.length - 1];
  }
  /**
   * Count subdomains.
   *
   * example.com
   * => 0
   *
   * www.example.com
   * => 1
   *
   * login.secure.example.com
   * => 2
   */
  static getSubdomainCount(hostname) {
    if (net.isIP(hostname)) {
      return 0;
    }

    const parts = hostname.split(".");

    if (parts.length <= 2) {
      return 0;
    }

    return parts.length - 2;
  }
  /**
   * Detect phishing keywords.
   * We use phishing_keyword table data.
   */
  static async detectPhishingKeywords(normailsedUrl, url) {
    // const { hostname, pathname, search } = url;
    const keywords = await PhishingKeywordModel.getActiveKeywords();
    if (!keywords?.length) {
      return [];
    }
    const searchableText =
      `${url.hostname}${url.pathname}${url.search}`.toLowerCase();
    const matches = [];
    for (const keyword of keywords) {
      if (!keyword.keyword) {
        continue;
      }
      const keywordValue = keyword.keyword.trim();
      if (!keywordValue) {
        continue;
      }
      const text = keyword.is_case_sensitive
        ? keywordValue
        : keywordValue.toLowerCase();
      const searchKeyword = keyword.is_case_sensitive
        ? keywordValue
        : keywordValue.toLowerCase();

      let matched = false;
      switch (keyword.match_type) {
        case "EXACT":
          matched = text === searchKeyword;
          break;
        case "REGEX":
          try {
            const regex = new RegExp(
              keywordValue,
              keyword.is_case_sensitive ? "" : "i",
            );
            matched = regex.test(text);
          } catch (error) {
            /*
             * Invalid regex in database should not
             * break the entire URL scan.
             */
            matched = false;
          }

          break;

        default:
          matched = false;
      }
      if (matched) {
        matches.push(keyword);
      }
    } //end of for loop
    return matches;
  }
  /**
   * Generate findings from URL structure.
   */
  static generateUrlFindings(features, findings) {
    if (features.containsIP) {
      findings.push({
        finding_type: "URL",
        finding_value: "IP_ADDRESS_HOST",
        severity: 4,
        score: 20,
        description: "The URL users and IP address instead of a domain name.",
        source: "URL_ANALYZER",
        evidence: {
          hostname: features.hostname,
        },
      });
    }
    if (features.containsShortener) {
      findings.push({
        finding_type: "URL",
        finding_value: "URL_SHORTENER",
        severity: 3,
        score: 15,
        description: "The URL uses a known URL shortening service.",
        source: "URL_ANALYZER",
        evidence: {
          hostname: features.hostname,
        },
      });
    }
    if (features.containsAtSymbol) {
      findings.push({
        finding_type: "URL",
        finding_value: "AT_SYMBOL",
        severity: 4,
        score: 20,
        description:
          "The URL contains an @ symbol, which can be used to obscure the actual destination.",
        source: "URL_ANALYZER",
        evidence: {
          hostname: features.hostname,
        },
      });
    }
    if (features.containsHexEncoding) {
      findings.push({
        finding_type: "URL",
        finding_value: "HEX_ENCODING",
        severity: 3,
        score: 10,
        description: "The URL contains percent-encoded characters.",
        source: "URL_ANALYZER",
        evidence: {
          hostname: features.hostname,
        },
      });
    }
    if (features.containsPunycode) {
      findings.push({
        finding_type: "URL",
        finding_vaue: "PUNYCODE",
        severity: 4,
        score: 20,
        description:
          "The hostname contains punycode, which can be associated with IDN homograhp attacks.",
        source: "URL_ANALYZER",
        evidence: {
          hostname: features.hostname,
        },
      });
    }
    if (features.containsSuspiciousTld) {
      findings.push({
        finding_type: "DOMAIN",
        finding_value: `SUSPICIOUS_TLD .${features.tld}`,
        severity: 3,
        score: 15,
        description:
          "The domain uses a TLD that is commonly associated with abusive or suspicious domians..",
        source: "URL_ANALYZER",
        evidence: {
          tld: features.tld,
        },
      });
    }
    if (features.hasNonStandardPort) {
      findings.push({
        finding_type: "URL",
        finding_value: "NON_STANDARD_PORT",
        severity: 3,
        score: 10,
        description: "The URL uses a non-standard HTTP/HTTPS port.",
        source: "URL_ANALYZER",
        evidence: {
          protocol: features.protocol,
        },
      });
    }
    if (!features.usesHttps) {
      findings.push({
        finding_type: "URL",
        finding_value: "NO_HTTPS",
        severity: 2,
        score: 5,
        description: "The URL does not use HTTPS.",
        source: "URL_ANALYZER",
        evidence: {
          protocol: features.protocol,
        },
      });
    }
    if (features.subdomainCount >= 3) {
      findings.push({
        finding_type: "DOMAIN",
        finding_value: "EXCESSIVE_SUBDOMAINS",
        severity: 3,
        score: 10,
        description:
          "The hostname contains on unusually high number of subdomains.",
        source: "URL_ANALYZER",
        evidence: {
          hostname: features.hostname,
          subdomain_count: features.subdomainCount,
        },
      });
    }
    if (features.urlLength >= 200) {
      findings.push({
        finding_type: "URL",
        finding_value: "LONG_URL",
        severity: 2,
        score: 5,
        description: "The URL is unusually long.",
        source: "URL_ANALYZER",
        evidence: {
          url_length: features.urlLength,
        },
      });
    }
  }
  /**
   * generate findings from URL/domain reputatons.
   */
  static generateReputationFindings(reputation, findings) {
    const {
      urlBlacklisted,
      domainBlacklisted,
      domainWhitelisted,
      domainRecord,
      urlRecord,
    } = reputation;
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
          threat_type: domainRecord?.threat_type,
          reason: domainRecord?.reason,
          source: domainRecord?.source,
          confidence_score: domainRecord?.confidence_score,
        },
      });
    }
    if (urlBlacklisted) {
      findings.push({
        finding_type: "URL",
        finding_value: "BLACKLISTED_URL",
        severity: 5,
        score: 60,
        description: "The exact URL exists in the RiskRadar blacklist.",
        source: "URL_DATABASE",
        evidence: {
          url: urlRecord?.url,
          threat_type: urlRecord?.threat_type,
          reason: urlRecord?.reason,
          source: urlRecord?.source,
        },
      });
    }
    if (domainWhitelisted) {
      findings.push({
        finding_type: "DOMAIN",
        finding_value: "WHITELISTED_DOMAIN",
        severity: 1,
        score: 0,
        description: "The domain exists in the RiskRadar whitelist.",
        source: "DOMAIN_DATABASE",
        evidence: {
          domain: domainRecord?.domain_name,
        },
      });
    }
  }
  /**
   * generate findings from phishing keywords.
   *
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
          "A suspicious phishing keyword was detected in the URL.",
        source: "PHISHING_KEYWORD",
        evidence: {
          keyword: keyword.keyword,
          category: keyword.category,
          match_type: keyword.match_type,
          is_case_sensitive: keyword.is_case_sensitive,
        },
      });
    }
  }
  /**
   * Calculate initial risk score.
   *
   * Maximum score = 100.
   */
  static calculateRiskScore(findings) {
    const total = findings.reduce(
      (sum, finding) => sum + Number(finding.score || 0),
      0,
    );

    return Math.min(total, 100);
  }
  /**
   * Calculate a basic reputation score.
   *
   * This is NOT the final risk score.
   *
   * Later this will incorporate:
   *
   * - Google Safe Browsing
   * - VirusTotal
   * - Domain reputation
   * - AI confidence
   */
  static calculateReputationScore(reputation) {
    const {
      urlBlacklisted,
      domainBlacklisted,
      domainWhitelisted,
      domainRecord,
      urlRecord,
    } = reputation;

    if (urlBlacklisted) {
      return 0;
    }

    if (domainBlacklisted) {
      return 0;
    }

    if (domainWhitelisted) {
      return 100;
    }

    if (urlRecord?.confidence_score != null) {
      return Number(urlRecord.confidence_score);
    }

    if (domainRecord?.confidence_score != null) {
      return Number(domainRecord.confidence_score);
    }

    return 50;
  }
  /**
   * Generate recommendation.
   */
  static getRecommendation({
    riskScore,
    urlBlacklisted,
    domainBlacklisted,
    domainWhitelisted,
  }) {
    if (urlBlacklisted) {
      return "BLOCK";
    }

    if (domainBlacklisted) {
      return "BLOCK";
    }

    if (domainWhitelisted && riskScore < 20) {
      return "ALLOW";
    }

    if (riskScore >= 70) {
      return "BLOCK";
    }

    if (riskScore >= 40) {
      return "WARN";
    }

    return "ALLOW";
  }
  /**
   * Optional DNS check.
   *
   * This is kept separate because DNS lookup may be slow
   * and should not be required for every basic scan.
   *
   * We can use it later to detect:
   *
   * - DNS resolution
   * - suspicious IPs
   * - hosting reputation
   */
  static async resolveHostname(hostname) {
    try {
      const addresses = await dns.lookup(hostname, {
        all: true,
      });

      return addresses;
    } catch {
      return [];
    }
  }
}
export default UrlScanner;
