import { dbPool } from "../config/db.js";

class AdminDashboardModel {
  /**
   * Get overall platform summary.
   *
   * @param {Date|null} startDate
   */
  static async getSummary(startDate = null) {
    try {
      const query = `
      SELECT
        COUNT(DISTINCT users.id)::INTEGER
          AS total_users,

        COUNT(DISTINCT users.id) FILTER (
          WHERE users.is_active = TRUE
        )::INTEGER
          AS active_users,

        COUNT(DISTINCT users.id) FILTER (
          WHERE users.is_active = FALSE
        )::INTEGER
          AS inactive_users,

        COUNT(scans.id)::INTEGER
          AS total_scans,

        COUNT(scans.id) FILTER (
          WHERE scans.created_at >= CURRENT_DATE
        )::INTEGER
          AS scans_today,

        COUNT(scans.id) FILTER (
          WHERE scans.is_phishing = TRUE
        )::INTEGER
          AS threats_detected,

        COUNT(scans.id) FILTER (
          WHERE scans.is_phishing = FALSE
        )::INTEGER
          AS safe_scans,

        COUNT(scans.id) FILTER (
          WHERE scans.risk_level_id IN (
            SELECT id
            FROM risk_levels
            WHERE code IN ('HIGH', 'CRITICAL')
          )
        )::INTEGER
          AS high_critical_scans,

        COALESCE(
          ROUND(AVG(scans.risk_score), 2),
          0
        ) AS average_risk_score

      FROM users 

      FULL OUTER JOIN scans
        ON scans.user_id = users.id

      WHERE
        $1::TIMESTAMP IS NULL
        OR scans.created_at >= $1;
    `;

      const { rows } = await dbPool.query(query, [startDate]);

      return rows[0] || {};
    } catch (error) {
      console.log("Error getting summary for admin dashboard:", error);
      throw error;
    }
  }

  /**
   * Get risk-level distribution.
   *
   * SAFE / LOW / MEDIUM / HIGH / CRITICAL
   */
  static async getRiskDistribution(startDate = null) {
    try {
      const query = `
      SELECT
        risk_levels.code,
        risk_levels.display_name,
        risk_levels.color,

        COUNT(scans.id)::INTEGER AS count

      FROM risk_levels

      LEFT JOIN scans 
        ON scans.risk_level_id = risk_levels.id
        AND (
          $1::TIMESTAMP IS NULL
          OR scans.created_at >= $1
        )

      GROUP BY
        risk_levels.id,
        risk_levels.code,
        risk_levels.display_name,
        risk_levels.color,
        risk_levels.min_score

      ORDER BY
        risk_levels.min_score ASC;
    `;

      const { rows } = await dbPool.query(query, [startDate]);

      return rows || [];
    } catch (error) {
      console.log(
        "Error getting risk distribution for admin dashboard:",
        error,
      );
      throw error;
    }
  }

  /**
   * Get scan type distribution.
   *
   * URL / EMAIL / MESSAGE
   */
  static async getScanTypeDistribution(startDate = null) {
    try {
      const query = `
      SELECT
        scan_type,
        COUNT(*)::INTEGER AS count

      FROM scans

      WHERE
        $1::TIMESTAMP IS NULL
        OR created_at >= $1

      GROUP BY scan_type

      ORDER BY count DESC;
    `;

      const { rows } = await dbPool.query(query, [startDate]);

      return rows || [];
    } catch (error) {
      console.log(
        "Error getting scan type distrbution for admin dashboard:",
        error,
      );
      throw error;
    }
  }

  /**
   * Get threat-category distribution.
   *
   * Based on scan_findings.finding_type.
   */
  static async getThreatCategories(startDate = null) {
    try {
      const query = `
      SELECT
        scan_findings.finding_type,
        COUNT(*)::INTEGER AS count,
        COALESCE(
          SUM(scan_findings.score),
          0
        )::INTEGER AS total_score

      FROM scan_findings

      INNER JOIN scans
        ON scans.id = scan_findings.scan_id

      WHERE
        $1::TIMESTAMP IS NULL
        OR scans.created_at >= $1

      GROUP BY scan_findings.finding_type

      ORDER BY count DESC;
    `;

      const { rows } = await dbPool.query(query, [startDate]);

      return rows || [];
    } catch (error) {
      console.log(
        "Error getting threat categories for  admin dashboard:",
        error,
      );
      throw error;
    }
  }

  /**
   * Get daily scan/threat trend.
   */
  static async getThreatTrend(startDate = null) {
    try {
      const query = `
      SELECT
        DATE(scans.created_at) AS date,

        COUNT(*)::INTEGER
          AS total_scans,

        COUNT(*) FILTER (
          WHERE scans.is_phishing = TRUE
        )::INTEGER
          AS threats_detected,

        COUNT(*) FILTER (
          WHERE scans.is_phishing = FALSE
        )::INTEGER
          AS safe_scans,

        COALESCE(
          ROUND(AVG(scans.risk_score), 2),
          0
        ) AS average_risk_score

      FROM scans 

      WHERE
        $1::TIMESTAMP IS NULL
        OR scans.created_at >= $1

      GROUP BY DATE(scans.created_at)

      ORDER BY DATE(scans.created_at) ASC;
    `;

      const { rows } = await dbPool.query(query, [startDate]);

      return rows || [];
    } catch (error) {
      console.log("Error getting threat trends:", error);
      throw error;
      sers;
    }
  }

  /**
   * Get most active users.
   */
  static async getTopUsers(startDate = null, limit = 10) {
    try {
      const query = `
      SELECT
        users.id,
        users.full_name,
        users.email,

        COUNT(scans.id)::INTEGER
          AS total_scans,

        COUNT(scans.id) FILTER (
          WHERE scans.is_phishing = TRUE
        )::INTEGER
          AS threats_detected,

        COALESCE(
          ROUND(AVG(scans.risk_score), 2),
          0
        ) AS average_risk_score,

        MAX(scans.created_at)
          AS last_scan_at

      FROM users 

      INNER JOIN scans 
        ON scans.user_id = users.id

      WHERE
        $1::TIMESTAMP IS NULL
        OR scans.created_at >= $1

      GROUP BY
        users.id,
        users.full_name,
        users.email

      ORDER BY
        total_scans DESC

      LIMIT $2;
    `;

      const { rows } = await dbPool.query(query, [startDate, limit]);

      return rows || [];
    } catch (error) {
      console.log("Error getting top active users for admin dashboard:", error);
      throw error;
    }
  }

  /**
   * Get recently registered users.
   */
  static async getRecentUsers(limit = 10) {
    try {
      const query = `
      SELECT
        id,
        full_name,
        email,
        role,
        is_active,
        email_verified,
        last_login,
        created_at

      FROM users

      ORDER BY created_at DESC

      LIMIT $1;
    `;

      const { rows } = await dbPool.query(query, [limit]);

      return rows || [];
    } catch (error) {
      console.log(
        "Error getting recently registered users for admin dashboard:",
        error,
      );
      throw error;
      cans;
    }
  }

  /**
   * Get recent threats.
   *
   * We intentionally do not return email bodies
   * or message contents.
   */
  static async getRecentThreats(startDate = null, limit = 10) {
    try {
      const query = `
      SELECT
        scans.id,
        scans.user_id,
        users.full_name,
        users.email,

        scans.scan_type,
        scans.status,
        scans.risk_score,
        scans.is_phishing,

        risk_levels.code
          AS risk_level,

        risk_levels.display_name
          AS risk_level_name,

        risk_levels.color
          AS risk_level_color,

        CASE

          WHEN scans.scan_type = 'URL'
            THEN url_scans.input_url

          WHEN scans.scan_type = 'EMAIL'
            THEN email_scans.subject

          WHEN scans.scan_type = 'MESSAGE'
            THEN LEFT(message_scans.message, 100)

          ELSE NULL

        END AS input,

        scans.created_at,
        scans.completed_at

      FROM scans

      LEFT JOIN users
        ON users.id = scans.user_id

      LEFT JOIN risk_levels 
        ON risk_levels.id = scans.risk_level_id

      LEFT JOIN url_scans
        ON url_scans.scan_id = scans.id

      LEFT JOIN email_scans
        ON email_scans.scan_id = scans.id

      LEFT JOIN message_scans
        ON message_scans.scan_id = scans.id

      WHERE
        scans.is_phishing = TRUE

        AND (
          $1::TIMESTAMP IS NULL
          OR scans.created_at >= $1
        )

      ORDER BY scans.created_at DESC

      LIMIT $2;
    `;

      const { rows } = await dbPool.query(query, [startDate, limit]);

      return rows || [];
    } catch (error) {
      console.log("Error getting recent threats for admin dashboard:", error);
      throw error;
    }
  }

  /**
   * Get AI analysis statistics.
   *
   * AI findings are stored in scan_findings
   * using finding_type = 'AI'.
   */
  static async getAiStatistics(startDate = null) {
    try {
      const query = `
      SELECT

        COUNT(DISTINCT scan_findings.scan_id)::INTEGER
          AS ai_analyzed_scans,

        COUNT(scan_findings.id)::INTEGER
          AS ai_findings,

        COUNT(scan_findings.id) FILTER (
          WHERE scan_findings.severity >= 4
        )::INTEGER
          AS high_risk_ai_findings,

        COALESCE(
          ROUND(AVG(scan_findings.score), 2),
          0
        ) AS average_ai_score

      FROM scan_findings 

      INNER JOIN scans
        ON scans.id = scan_findings.scan_id

      WHERE
        scan_findings.finding_type = 'AI'

        AND (
          $1::TIMESTAMP IS NULL
          OR scans.created_at >= $1
        );
    `;

      const { rows } = await dbPool.query(query, [startDate]);

      return rows[0] || {};
    } catch (error) {
      console.log(
        "Error getting the ai statistics for admin dashboard:",
        error,
      );
      throw error;
    }
  }
}

export default AdminDashboardModel;
