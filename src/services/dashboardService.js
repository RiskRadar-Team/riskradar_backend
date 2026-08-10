import ApiError from "../utils/ApiError.js";
import DashboardModel from "../models/dashboardModel.js";

class DashboardService {
  /**
   * Get complete dashboard analysis.
   *
   * @param {string} userId
   * @param {string} period
   */
  static async getDashboard(userId, period = "30d") {
    if (!userId) {
      throw new ApiError(400, "User id is required.");
    }

    /*
     * Calculate start date based on
     * requested dashboard period.
     */
    const startDate = this.getStartDate(period);

    /*
     * Fetch dashboard data.
     *
     * These queries are independent, so run
     * them in one go.
     */
    const [
      summary,
      riskDistribution,
      scanTypes,
      threatCategories,
      threatTrend,
      recentScans,
      recentThreats,
    ] = await Promise.all([
      DashboardModel.getSummary(userId, startDate),

      DashboardModel.getRiskDistribution(userId, startDate),

      DashboardModel.getScanTypeDistribution(userId, startDate),

      DashboardModel.getThreatCategories(userId, startDate),

      DashboardModel.getThreatTrend(userId, startDate),

      DashboardModel.getRecentScans(userId, 10),

      DashboardModel.getRecentThreats(userId, 10),
    ]);

    /*
     * Calculate overall security score.
     */
    const securityScore = this.calculateSecurityScore(summary);

    return {
      period,

      summary: {
        totalScans: Number(summary.total_scans || 0),

        safeScans: Number(summary.safe_scans || 0),

        threatsDetected: Number(summary.threats_detected || 0),

        highCriticalThreats: Number(summary.high_critical_threats || 0),

        averageRiskScore: Number(summary.average_risk_score || 0),

        securityScore,
      },

      riskDistribution: riskDistribution.map((item) => ({
        code: item.code,
        displayName: item.display_name,
        color: item.color,
        count: Number(item.count || 0),
      })),

      scanTypes: scanTypes.map((item) => ({
        type: item.scan_type,
        count: Number(item.count || 0),
      })),

      threatCategories: threatCategories.map((item) => ({
        type: item.finding_type,
        count: Number(item.count || 0),
      })),

      threatTrend: threatTrend.map((item) => ({
        date: item.date,
        totalScans: Number(item.total_scans || 0),
        threatsDetected: Number(item.threats_detected || 0),
        safeScans: Number(item.safe_scans || 0),
      })),

      recentScans: recentScans.map((scan) => this.formatScan(scan)),

      recentThreats: recentThreats.map((scan) => this.formatThreat(scan)),
    };
  }

  /**
   * Calculate dashboard period start date.
   *
   * Returns null for "all".
   */
  static getStartDate(period) {
    const now = new Date();

    switch (period) {
      case "7d": {
        const date = new Date(now);
        date.setDate(date.getDate() - 7);
        return date;
      }

      case "30d": {
        const date = new Date(now);
        date.setDate(date.getDate() - 30);
        return date;
      }

      case "90d": {
        const date = new Date(now);
        date.setDate(date.getDate() - 90);
        return date;
      }

      case "all":
        return null;

      default:
        throw new ApiError(
          400,
          "Invalid dashboard period. Use 7d, 30d, 90d, or all.",
        );
    }
  }

  /**
   * Calculate an overall security score.
   *
   * 100 = best security posture.
   *
   * The score is based primarily on
   * the user's detected threat percentage
   * and average risk score.
   */
  static calculateSecurityScore(summary) {
    const totalScans = Number(summary.total_scans || 0);

    if (totalScans === 0) {
      return 100;
    }

    const averageRiskScore = Number(summary.average_risk_score || 0);

    /*
     * Percentage of scans detected
     * as phishing.
     */
    const threatRate =
      (Number(summary.threats_detected || 0) / totalScans) * 100;

    /*
     * Risk component.
     *
     * Higher average risk means
     * lower security score.
     */
    const riskComponent = Math.max(0, 100 - averageRiskScore);

    /*
     * Threat component.
     *
     * Higher threat rate means
     * lower security score.
     */
    const threatComponent = Math.max(0, 100 - threatRate);

    /*
     * Weighted security score.
     *
     * Average risk is given more weight
     * than simple threat frequency.
     */
    const score = riskComponent * 0.7 + threatComponent * 0.3;

    return Math.round(Math.max(0, Math.min(100, score)));
  }

  /**
   * Format recent scan.
   */
  static formatScan(scan) {
    return {
      id: scan.id,

      type: scan.scan_type,

      status: scan.status,

      input: scan.input,

      riskScore: scan.risk_score !== null ? Number(scan.risk_score) : null,

      isPhishing: scan.is_phishing,

      riskLevel: scan.risk_level
        ? {
            code: scan.risk_level,
            displayName: scan.risk_level_name,
            color: scan.risk_level_color,
          }
        : null,

      scanDurationMs:
        scan.scan_duration_ms !== null ? Number(scan.scan_duration_ms) : null,

      createdAt: scan.created_at,

      completedAt: scan.completed_at,
    };
  }

  /**
   * Format recent threat.
   */
  static formatThreat(scan) {
    return {
      id: scan.id,

      type: scan.scan_type,

      input: scan.input,

      riskScore: scan.risk_score !== null ? Number(scan.risk_score) : null,

      isPhishing: scan.is_phishing,

      riskLevel: scan.risk_level
        ? {
            code: scan.risk_level,
            displayName: scan.risk_level_name,
            color: scan.risk_level_color,
          }
        : null,

      createdAt: scan.created_at,

      completedAt: scan.completed_at,
    };
  }
}

export default DashboardService;
