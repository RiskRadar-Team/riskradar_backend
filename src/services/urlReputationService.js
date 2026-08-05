import ApiError from "../utils/ApiError.js";

class UrlReputationService {
  /**
   * Scan a URL using all configured reputation providers
   *
   * Currently supported:
   * 1.Google safe browsing
   * 2.Virus total
   *
   * The service does not throw an error when an external provider is unavailable.
   * A reputation provider failing should not make the complete RiskRadar scan fail.
   *
   */
  static async checkUrl(url) {
    if (!url || typeof url !== "string" || !url.trim()) {
      throw new ApiError(400, "URL is required for reputation check.");
    }
    const normalisedUrl = url.trim();
    const results = {
      google: {
        enabled: false,
        safe: null,
        malicious: false,
        suspicious: false,
        response: null,
        error: null,
      },
      virustotal: {
        enabled: false,
        safe: null,
        malicious: false,
        suspicious: false,
        response: null,
        error: null,
      },

      reputationScore: null,
    };
    /*
     * Run reputation providers independently.
     *
     * Promise.allSettled() ensures that failure of one
     * provider does not prevent the other provider from
     * returning its result.
     */
    const providerResults = await Promise.allSettled([
      this.checkGoogleSafeBrowsing(normalisedUrl),

      this.checkVirusTotal(normalisedUrl),
    ]);
    /*
     * Google Safe Browsing
     */
    if (providerResults[0].status === "fulfilled") {
      results.google = providerResults[0].value;
    } else {
      results.google.error =
        providerResults[0].reason?.message ||
        "Google Safe Browsing check failed.";
    }
    /*
     * VirusTotal
     */
    if (providerResults[1].status === "fulfilled") {
      results.virustotal = providerResults[1].value;
    } else {
      results.virustotal.error =
        providerResults[1].reason?.message || "VirusTotal check failed.";
    }
    /*
     * Calculate combined reputation score.
     */
    results.reputationScore = this.calculateReputationScore(results);

    return results;
  }
  /**
   * Google Safe Browsing API.
   *
   * TODO:
   * Add the actual Google Safe Browsing API
   * implementation when the API key is configured.
   */
  static async checkGoogleSafeBrowsing(url) {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    /*
     * API not configured.
     *
     * Return a neutral result instead of failing
     * the entire URL scan.
     */
    if (!apiKey) {
      return {
        enabled: false,
        safe: null,
        malicious: false,
        suspicious: false,
        response: null,
        error: "Google Safe Browsing API key is not configured.",
      };
    }

    /*
     * Google Safe Browsing endpoint.
     */
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    const requestBody = {
      client: {
        clientId: "riskradar",
        clientVersion: "1.0.0",
      },

      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION",
        ],

        platformTypes: ["ANY_PLATFORM"],

        threatEntryTypes: ["URL"],

        threatEntries: [
          {
            url,
          },
        ],
      },
    };

    try {
      const response = await fetch(endpoint, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        const errorText = await response.text();

        throw new Error(
          `Google Safe Browsing API returned ${response.status}: ${errorText}`,
        );
      }

      const data = await response.json();

      const threats = data.matches || [];

      return {
        enabled: true,

        safe: threats.length === 0,

        malicious: threats.length > 0,

        suspicious: threats.length > 0,

        response: data,

        error: null,
      };
    } catch (error) {
      throw new Error(`Google Safe Browsing check failed: ${error.message}`);
    }
  }

  /**
   * VirusTotal URL reputation check.
   *
   * VirusTotal requires:
   * 1. URL encoded using Base64 URL-safe encoding
   * 2. GET request against the URL analysis endpoint
   */
  static async checkVirusTotal(url) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
      return {
        enabled: false,
        safe: null,
        malicious: false,
        suspicious: false,
        response: null,
        error: "VirusTotal API key is not configured.",
      };
    }

    /*
     * VirusTotal uses URL-safe Base64
     * without trailing "=" characters.
     */
    const urlId = Buffer.from(url)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;

    try {
      const response = await fetch(endpoint, {
        method: "GET",

        headers: {
          "x-apikey": apiKey,
          Accept: "application/json",
        },
      });

      if (response.status === 404) {
        /*
         * URL has not been analyzed by
         * VirusTotal yet.
         */
        return {
          enabled: true,
          safe: null,
          malicious: false,
          suspicious: false,
          response: null,
          error: "URL has not been analyzed by VirusTotal.",
        };
      }

      if (!response.ok) {
        const errorText = await response.text();

        throw new Error(
          `VirusTotal API returned ${response.status}: ${errorText}`,
        );
      }

      const data = await response.json();

      const stats = data?.data?.attributes?.last_analysis_stats || {};

      const malicious = Number(stats.malicious || 0);

      const suspicious = Number(stats.suspicious || 0);

      const harmless = Number(stats.harmless || 0);

      const undetected = Number(stats.undetected || 0);

      const totalEngines = malicious + suspicious + harmless + undetected;

      return {
        enabled: true,

        safe: malicious === 0 && suspicious === 0,

        malicious: malicious > 0,

        suspicious: suspicious > 0,

        response: data,

        analysis: {
          malicious,
          suspicious,
          harmless,
          undetected,
          total: totalEngines,
        },

        error: null,
      };
    } catch (error) {
      throw new Error(`VirusTotal check failed: ${error.message}`);
    }
  }

  /**
   * Calculate a combined reputation score.
   *
   * 100 = completely safe
   * 0   = highly malicious
   *
   * null = no reputation provider available
   */
  static calculateReputationScore(results) {
    const scores = [];

    /*
     * Google Safe Browsing
     */
    if (results.google.enabled && typeof results.google.safe === "boolean") {
      scores.push(results.google.safe ? 100 : 0);
    }

    /*
     * VirusTotal
     */
    if (results.virustotal.enabled && results.virustotal.analysis) {
      const {
        malicious = 0,
        suspicious = 0,
        total = 0,
      } = results.virustotal.analysis;

      if (total > 0) {
        /*
         * Malicious engines have a stronger
         * impact than suspicious engines.
         */
        const maliciousWeight = malicious * 1;

        const suspiciousWeight = suspicious * 0.5;

        const threatRatio = (maliciousWeight + suspiciousWeight) / total;

        const score = Math.max(0, Math.round(100 - threatRatio * 100));

        scores.push(score);
      }
    }

    /*
     * No external reputation data.
     */
    if (scores.length === 0) {
      return null;
    }

    /*
     * Average all available providers.
     */
    const totalScore = scores.reduce((sum, score) => sum + score, 0);

    return Math.round(totalScore / scores.length);
  }
}
export default UrlReputationService;
