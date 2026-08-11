import ApiError from "../utils/ApiError.js";
import AdminDashboardModel from "../models/adminDashboardModel.js";

class AdminDashboardService {
  /**
   * Get complete admin dashboard.
   *
   * @param {string} period
   */
  static async getDashboard(period = "30d") {
    /*
     * Convert dashboard period into
     * a database start date.
     */
    const startDate = this.getStartDate(period);

    /*
     * All dashboard queries are independent,
     * so execute them concurrently.
     */
    const [
      summary,
      riskDistribution,
      scanTypes,
      threatCategories,
      threatTrend,
      topUsers,
      recentUsers,
      recentThreats,
      aiStatistics,
    ] = await Promise.all([
      AdminDashboardModel.getSummary(startDate),

      AdminDashboardModel.getRiskDistribution(startDate),

      AdminDashboardModel.getScanTypeDistribution(startDate),

      AdminDashboardModel.getThreatCategories(startDate),

      AdminDashboardModel.getThreatTrend(startDate),

      AdminDashboardModel.getTopUsers(startDate, 10),

      AdminDashboardModel.getRecentUsers(10),

      AdminDashboardModel.getRecentThreats(startDate, 10),

      AdminDashboardModel.getAiStatistics(startDate),
    ]);

    /*
     * Calculate derived platform metrics.
     */
    const totalScans = Number(summary.total_scans || 0);

    const threatsDetected = Number(summary.threats_detected || 0);

    const threatRate =
      totalScans > 0
        ? Number(((threatsDetected / totalScans) * 100).toFixed(2))
        : 0;

    /*
     * Format the final response.
     */
    return {
      period,

      summary: {
        totalUsers: Number(summary.total_users || 0),

        activeUsers: Number(summary.active_users || 0),

        inactiveUsers: Number(summary.inactive_users || 0),

        totalScans,

        scansToday: Number(summary.scans_today || 0),

        threatsDetected,

        safeScans: Number(summary.safe_scans || 0),

        highCriticalScans: Number(summary.high_critical_scans || 0),

        threatRate,

        averageRiskScore: Number(summary.average_risk_score || 0),
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

        totalScore: Number(item.total_score || 0),
      })),

      threatTrend: threatTrend.map((item) => ({
        date: item.date,

        totalScans: Number(item.total_scans || 0),

        threatsDetected: Number(item.threats_detected || 0),

        safeScans: Number(item.safe_scans || 0),

        averageRiskScore: Number(item.average_risk_score || 0),
      })),

      topUsers: topUsers.map((user) => ({
        id: user.id,

        fullName: user.full_name,

        email: user.email,

        totalScans: Number(user.total_scans || 0),

        threatsDetected: Number(user.threats_detected || 0),

        averageRiskScore: Number(user.average_risk_score || 0),

        lastScanAt: user.last_scan_at,
      })),

      recentUsers: recentUsers.map((user) => ({
        id: user.id,

        fullName: user.full_name,

        email: user.email,

        role: user.role,

        isActive: user.is_active,

        emailVerified: user.email_verified,

        lastLogin: user.last_login,

        createdAt: user.created_at,
      })),

      recentThreats: recentThreats.map((threat) => ({
        id: threat.id,

        userId: threat.user_id,

        user: threat.full_name
          ? {
              fullName: threat.full_name,

              email: threat.email,
            }
          : null,

        scanType: threat.scan_type,

        status: threat.status,

        input: threat.input,

        riskScore:
          threat.risk_score !== null ? Number(threat.risk_score) : null,

        isPhishing: threat.is_phishing,

        riskLevel: threat.risk_level
          ? {
              code: threat.risk_level,

              displayName: threat.risk_level_name,

              color: threat.risk_level_color,
            }
          : null,

        createdAt: threat.created_at,

        completedAt: threat.completed_at,
      })),

      aiAnalysis: {
        analyzedScans: Number(aiStatistics.ai_analyzed_scans || 0),

        findings: Number(aiStatistics.ai_findings || 0),

        highRiskFindings: Number(aiStatistics.high_risk_ai_findings || 0),

        averageScore: Number(aiStatistics.average_ai_score || 0),
      },
    };
  }

  /**
   * Convert dashboard period into
   * a database start date.
   *
   * Supported:
   * 7d
   * 30d
   * 90d
   * all
   */
  static getStartDate(period) {
    switch (period) {
      case "7d": {
        const date = new Date();

        date.setDate(date.getDate() - 7);

        return date;
      }

      case "30d": {
        const date = new Date();

        date.setDate(date.getDate() - 30);

        return date;
      }

      case "90d": {
        const date = new Date();

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
}

export default AdminDashboardService;
