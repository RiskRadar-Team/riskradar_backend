import RiskLevelModel from "../models/riskLevelModel.js";
import ApiError from "../utils/ApiError.js";
class RiskScoreService {
  /**
   * Calculate the final risk result from scan findings.
   *
   * Expected finding format:
   *
   * {
   *   finding_type: "DOMAIN",
   *   finding_value: "BLACKLISTED_DOMAIN",
   *   severity: 5,
   *   score: 50,
   *   description: "...",
   *   source: "DOMAIN_DATABASE"
   * }
   */
  static async calculate(findings = []) {
    if (!Array.isArray(findings)) {
      findings = [];
    }
    /**
     * calculate total score.
     * Each finding contributes its own score
     */
    const totalScore = findings.reduce((total, finding) => {
      const score = Number(finding.score);
      if (Number.isNaN(score) || score < 0) {
        return total;
      }
      return total + score;
    }, 0);
    /**Risk score is always between 0 to 100. */
    const riskScore = Math.min(Math.max(totalScore, 0), 100);

    /**
     * Determine risk level.
     */
    // const riskLevel = this.getRiskLevel(riskScore);
    const riskLevel = await RiskLevelModel.getByScore(riskScore);
    if (!riskLevel) {
      throw new ApiError(
        500,
        `No risk level configured for score ${riskScore}.`,
      );
    }

    /**
     * now determine whether the scan should be considered phishing.
     */
    const isPhishing = this.isPhishing(riskScore, findings);
    /**
     * Determine recommended action
     *
     */
    const recommendation = this.getRecommendation(riskScore, findings);
    /**
     * calculate statistics that can be useful to the frontend and later with AI layer
     */
    const statistics = this.getStatistics(findings);
    return {
      riskScore,
      riskLevel,
      isPhishing,
      recommendation,
      statistics,
    };
  }
  /**
   * Convert numerical risk score into
   * a human-readable risk level.
   *
   * 0 - 19   SAFE
   * 20 - 39  LOW
   * 40 - 59  MEDIUM
   * 60 - 79  HIGH
   * 80 - 100 CRITICAL
   */
  static getRiskLevel(riskScore) {
    if (riskScore < 20) {
      return "SAFE";
    }

    if (riskScore < 40) {
      return "LOW";
    }

    if (riskScore < 60) {
      return "MEDIUM";
    }

    if (riskScore < 80) {
      return "HIGH";
    }

    return "CRITICAL";
  }
  /**
   * Determine whether the URL/message/email
   * should be classified as phishing.
   *
   * A score of 60+ is considered phishing.
   *
   * However, a strong blacklist finding can
   * immediately classify the scan as phishing.
   */
  static isPhishing(riskScore, findings) {
    /*
     * Critical intelligence findings should
     * immediately indicate phishing.
     */
    const hasCriticalFinding = findings.some(
      (finding) =>
        Number(finding.severity) === 5 &&
        ["BLACKLISTED_DOMAIN", "BLACKLISTED_URL"].includes(
          finding.finding_value,
        ),
    );

    if (hasCriticalFinding) {
      return true;
    }

    /*
     * Otherwise use the risk threshold.
     */
    return riskScore >= 60;
  }
  /**
   * Determine recommended action.
   */
  static getRecommendation(riskScore, findings) {
    /*
     * Explicit blacklist always wins.
     */
    const blacklisted = findings.some((finding) =>
      ["BLACKLISTED_DOMAIN", "BLACKLISTED_URL"].includes(finding.finding_value),
    );

    if (blacklisted) {
      return "BLOCK";
    }

    if (riskScore >= 80) {
      return "BLOCK";
    }

    if (riskScore >= 40) {
      return "WARN";
    }

    return "ALLOW";
  }

  /**
   * Generate useful finding statistics.
   */
  static getStatistics(findings) {
    const statistics = {
      totalFindings: findings.length,

      criticalFindings: 0,
      highFindings: 0,
      mediumFindings: 0,
      lowFindings: 0,

      domainFindings: 0,
      urlFindings: 0,
      keywordFindings: 0,
      reputationFindings: 0,
      aiFindings: 0,
      otherFindings: 0,

      totalFindingScore: 0,
    };

    for (const finding of findings) {
      const severity = Number(finding.severity) || 0;

      const score = Number(finding.score) || 0;

      statistics.totalFindingScore += score;

      /*
       * Severity statistics.
       */
      if (severity === 5) {
        statistics.criticalFindings++;
      } else if (severity === 4) {
        statistics.highFindings++;
      } else if (severity === 3) {
        statistics.mediumFindings++;
      } else if (severity === 1 || severity === 2) {
        statistics.lowFindings++;
      }

      /*
       * Finding type statistics.
       */
      switch (finding.finding_type) {
        case "DOMAIN":
          statistics.domainFindings++;
          break;

        case "URL":
          statistics.urlFindings++;
          break;

        case "KEYWORD":
          statistics.keywordFindings++;
          break;

        case "REPUTATION":
          statistics.reputationFindings++;
          break;

        case "AI":
          statistics.aiFindings++;
          break;

        default:
          statistics.otherFindings++;
          break;
      }
    }

    return statistics;
  }

  /**
   * Convenience method for calculating
   * a result from only one finding.
   */
  static calculateFromFinding(finding) {
    return this.calculate(finding ? [finding] : []);
  }
}
export default RiskScoreService;
