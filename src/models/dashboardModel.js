import { dbPool } from "../config/db.js";

class DashboardModel {
  /**
   * Get dashboard summary
   */
  static async getSummary(userId, startDate = null) {
    try {
      const query = `
        SELECT 
        COUNT(*)::INTEGER AS total_scans,
        COUNT(*) FILTER (WHERE is_phishing= FALSE)::INTEGER AS safe_scans,
        COUNT(*) FILTER (WHERE is_phishing = TRUE)::INTEGER AS threats_detected,
        COUNT(*) FILTER (WHERE risk_score >= 70)::INTEGER AS high_critical_threats,
        COALESCE(ROUND(AVG(risk_score),2),0) AS average_risk_score
        FROM scans
        WHERE user_id = $1 
        AND status ='COMPLETED'
        AND ($2::TIMESTAMP IS NULL
        OR created_at >=$2
        );
      `;
      const { rows } = await dbPool.query(query, [userId, startDate]);
      return (
        rows[0] || {
          total_scans: 0,
          safe_scans: 0,
          threats_detected: 0,
          high_critical_threats: 0,
          average_risk_score: 0,
        }
      );
    } catch (error) {
      console.log("Error getting dashboard summary.", error);
      throw error;
    }
  }
  /**
   * Get risk-level distribution
   */
  static async getRiskDistribution(userId, startDate = null) {
    try {
      const query = `
        SELECT risk_levels.code, risk_levels.display_name,
        risk_levels.color,
        COUNT(scans.id)::INTEGER AS count
        FROM risk_levels
        LEFT JOIN scans
          ON scans.risk_level_id =  risk_levels.id
          AND scans.user_id = $1 
          AND scans.status = 'COMPLETED'
          AND (
            $2::TIMESTAMP IS NULL
            OR scans.created_at >=$2
          )
        GROUP BY risk_levels.id,risk_levels.code,
        risk_levels.display_name,risk_levels.color,
        risk_levels.min_score
        ORDER BY risk_levels.min_score ASC;
      `;
      const { rows } = await dbPool.query(query, [userId, startDate]);
      return rows || [];
    } catch (error) {
      console.log("Error getting risk distributon:", error);
      throw error;
    }
  }
  /**
   * Get scan distribution by type
   */
  static async getScanTypeDistribution(userId, startDate = null) {
    try {
      const query = `
        SELECT scan_type,COUNT(*)::INTEGER AS count
        FROM scans
        WHERE user_id = $1 AND status = 'COMPLETED'
        AND ($2::TIMESTAMP IS NULL OR created_at  >= $2)
        GROUP BY scan_type
        ORDER BY 
        CASE scan_type
          WHEN 'URL' THEN 1
          WHEN 'EMAIL' THEN 2
          WHEN 'MESSAGE' THEN 3
          ELSE 4
        END;
      `;
      const { rows } = await dbPool.query(query, [userId, startDate]);
      return rows || [];
    } catch (error) {
      console.log("DB error while getting scan type distribution:", error);
      throw error;
    }
  }
  /**Get threat findings */
  static async getThreatCategories(userId, startDate = null) {
    try {
      const query = `
        SELECT
          scan_findings.finding_type,
          COUNT(scan_findings.id)::INTEGER AS count
  
        FROM scan_findings 
  
        INNER JOIN scans 
          ON scans.id = scan_findings.scan_id
  
        WHERE scans.user_id = $1
          AND scans.status = 'COMPLETED'
          AND scans.is_phishing = TRUE
          AND (
            $2::TIMESTAMP IS NULL
            OR scans.created_at >= $2
          )
  
        GROUP BY scan_findings.finding_type
  
        ORDER BY count DESC;
      `;

      const { rows } = await dbPool.query(query, [userId, startDate]);

      return rows || [];
    } catch (error) {
      throw error;
    }
  }
  /**Get daily scan/threat trends */
  static async getThreatTrend(userId, startDate = null) {
    try {
      const query = `
        SELECT
          DATE_TRUNC('day', created_at)::DATE AS date,

          COUNT(*)::INTEGER AS total_scans,

          COUNT(*) FILTER (
            WHERE is_phishing = TRUE
          )::INTEGER AS threats_detected,

          COUNT(*) FILTER (
            WHERE is_phishing = FALSE
          )::INTEGER AS safe_scans

        FROM scans

        WHERE user_id = $1
          AND status = 'COMPLETED'
          AND (
            $2::TIMESTAMP IS NULL
            OR created_at >= $2
          )

        GROUP BY DATE_TRUNC('day', created_at)

        ORDER BY date ASC;
      `;

      const { rows } = await dbPool.query(query, [userId, startDate]);

      return rows || [];
    } catch (error) {
      throw error;
    }
  }
  /** Get recent scans */
  static async getRecentScans(userId, limit = 10) {
    try {
      const query = `
        SELECT
          scans.id,
          scans.scan_type,
          scans.status,
          scans.risk_score,
          scans.is_phishing,
          scans.risk_level_id,
          risk_levels.code AS risk_level,
          risk_levels.display_name AS risk_level_name,
          risk_levels.color AS risk_level_color,
          scans.scan_duration_ms,
          scans.created_at,
          scans.completed_at,
  
          CASE
            WHEN scans.scan_type = 'URL'
              THEN url_scans.input_url
  
            WHEN scans.scan_type = 'EMAIL'
              THEN email_scans.subject
  
            WHEN scans.scan_type = 'MESSAGE'
              THEN message_scans.message
  
            ELSE NULL
          END AS input
  
        FROM scans 
  
        LEFT JOIN risk_levels
          ON risk_levels.id = scans.risk_level_id
  
        LEFT JOIN url_scans
          ON url_scans.scan_id = scans.id
  
        LEFT JOIN email_scans
          ON email_scans.scan_id = scans.id
  
        LEFT JOIN message_scans
          ON message_scans.scan_id = scans.id
  
        WHERE scans.user_id = $1
  
        ORDER BY scans.created_at DESC
  
        LIMIT $2;
      `;

      const { rows } = await dbPool.query(query, [userId, limit]);

      return rows || [];
    } catch (error) {
      throw error;
    }
  }
  /** get recent threats */
  static async getRecentThreats(userId, limit = 10) {
    try {
      const query = `
        SELECT
          scans.id,
          scans.scan_type,
          scans.risk_score,
          scans.is_phishing,
  
          risk_levels.code AS risk_level,
          risk_levels.display_name AS risk_level_name,
          risk_levels.color AS risk_level_color,
  
          scans.created_at,
          scans.completed_at,
  
          CASE
            WHEN scans.scan_type = 'URL'
              THEN url_scans.input_url
  
            WHEN scans.scan_type = 'EMAIL'
              THEN email_scans.subject
  
            WHEN scans.scan_type = 'MESSAGE'
              THEN message_scans.message
  
            ELSE NULL
          END AS input
  
        FROM scans
  
        LEFT JOIN risk_levels
          ON risk_levels.id = scans.risk_level_id
  
        LEFT JOIN url_scans
          ON url_scans.scan_id = scans.id
  
        LEFT JOIN email_scans
          ON email_scans.scan_id = scans.id
  
        LEFT JOIN message_scans 
          ON message_scans.scan_id = scans.id
  
        WHERE scans.user_id = $1
          AND scans.status = 'COMPLETED'
          AND scans.is_phishing = TRUE
  
        ORDER BY
          scans.created_at DESC
  
        LIMIT $2;
      `;

      const { rows } = await dbPool.query(query, [userId, limit]);

      return rows || [];
    } catch (error) {}
  }
}
export default DashboardModel;
