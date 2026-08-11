import { dbPool } from "../config/db.js";

class HistoryModel {
  /**
   * Get paginated scan history for a user.
   *
   * Supported filters:
   * - scanType: URL | EMAIL | MESSAGE
   * - riskLevel: SAFE | LOW | MEDIUM | HIGH | CRITICAL
   * - isPhishing: true | false
   * - from: date
   * - to: date
   */
  static async getHistory({
    userId,
    page = 1,
    limit = 20,
    scanType = null,
    riskLevel = null,
    isPhishing = null,
    from = null,
    to = null,
  }) {
    const offset = (page - 1) * limit;
    try {
      const query = `
      SELECT
        scans.id,
        scans.scan_type,
        scans.status,
        scans.risk_score,
        scans.is_phishing,
        scans.scan_duration_ms,
        scans.started_at,
        scans.completed_at,
        scans.created_at,

        risk_levels.code AS risk_level,
        risk_levels.display_name AS risk_level_name,
        risk_levels.color AS risk_level_color,

        CASE

          WHEN scans.scan_type = 'URL'
            THEN url_scans.input_url

          WHEN scans.scan_type = 'EMAIL'
            THEN email_scans.subject

          WHEN scans.scan_type = 'MESSAGE'
            THEN LEFT(message_scans.message, 100)

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

      WHERE
        scans.user_id = $1

        AND (
          $2::VARCHAR IS NULL
          OR scans.scan_type = $2
        )

        AND (
          $3::VARCHAR IS NULL
          OR risk_levels.code = $3
        )

        AND (
          $4::BOOLEAN IS NULL
          OR scans.is_phishing = $4
        )

        AND (
          $5::TIMESTAMP IS NULL
          OR scans.created_at >= $5
        )

        AND (
          $6::TIMESTAMP IS NULL
          OR scans.created_at < ($6::DATE + INTERVAL '1 day')
        )

      ORDER BY scans.created_at DESC

      LIMIT $7
      OFFSET $8;
    `;

      const { rows } = await dbPool.query(query, [
        userId,
        scanType,
        riskLevel,
        isPhishing,
        from,
        to,
        limit,
        offset,
      ]);

      return rows || [];
    } catch (error) {
      console.log("Error getting search able history for user:", error);
      throw error;
    }
  }

  /**
   * Get total number of scans matching
   * the supplied filters.
   */
  static async getHistoryCount({
    userId,
    scanType = null,
    riskLevel = null,
    isPhishing = null,
    from = null,
    to = null,
  }) {
    try {
      const query = `
      SELECT COUNT(*)::INTEGER AS total

      FROM scans 

      LEFT JOIN risk_levels
        ON risk_levels.id = scans.risk_level_id

      WHERE
        scans.user_id = $1

        AND (
          $2::VARCHAR IS NULL
          OR scans.scan_type = $2
        )

        AND (
          $3::VARCHAR IS NULL
          OR risk_levels.code = $3
        )

        AND (
          $4::BOOLEAN IS NULL
          OR scans.is_phishing = $4
        )

        AND (
          $5::TIMESTAMP IS NULL
          OR scans.created_at >= $5
        )

        AND (
          $6::TIMESTAMP IS NULL
          OR scans.created_at < ($6::DATE + INTERVAL '1 day')
        );
    `;

      const { rows } = await dbPool.query(query, [
        userId,
        scanType,
        riskLevel,
        isPhishing,
        from,
        to,
      ]);

      return Number(rows[0]?.total || 0);
    } catch (error) {
      console.log("Error getting history count for user:", error);
      throw error;
    }
  }

  /**
   * Get one complete historical scan.
   *
   * The scan must belong to the
   * authenticated user.
   */
  static async getScanById(userId, scanId) {
    try {
      const scanQuery = `
      SELECT
        scans.id,
        scans.user_id,
        scans.scan_type,
        scans.status,
        scans.risk_score,
        scans.is_phishing,
        scans.scan_duration_ms,
        scans.engine_version,
        scans.started_at,
        scans.completed_at,
        scans.created_at,
        scans.updated_at,

        risk_levels.id AS risk_level_id,
        risk_levels.code AS risk_level,
        risk_levels.display_name AS risk_level_name,
        risk_levels.min_score AS risk_min_score,
        risk_levels.max_score AS risk_max_score,
        risk_levels.color AS risk_level_color

      FROM scans 

      LEFT JOIN risk_levels
        ON risk_levels.id = scans.risk_level_id

      WHERE
        scans.id = $1
        AND scans.user_id = $2

      LIMIT 1;
    `;

      const { rows: scanRows } = await dbPool.query(scanQuery, [
        scanId,
        userId,
      ]);

      if (!scanRows.length) {
        return null;
      }

      const scan = scanRows[0];

      /*
       * Get findings belonging to this scan.
       */
      const findingsQuery = `
      SELECT
        id,
        finding_type,
        finding_value,
        severity,
        score,
        description,
        source,
        evidence,
        created_at

      FROM scan_findings

      WHERE scan_id = $1

      ORDER BY
        severity DESC,
        score DESC,
        created_at ASC;
    `;

      const { rows: findings } = await dbPool.query(findingsQuery, [scanId]);

      /*
       * Get URL-specific information.
       */
      let urlScan = null;

      if (scan.scan_type === "URL") {
        const query = `
        SELECT *
        FROM url_scans
        WHERE scan_id = $1
        LIMIT 1;
      `;

        const { rows } = await dbPool.query(query, [scanId]);

        urlScan = rows[0] || null;
      }

      /*
       * Get EMAIL-specific information.
       */
      let emailScan = null;

      if (scan.scan_type === "EMAIL") {
        const query = `
        SELECT *
        FROM email_scans
        WHERE scan_id = $1
        LIMIT 1;
      `;

        const { rows } = await dbPool.query(query, [scanId]);

        emailScan = rows[0] || null;
      }

      /*
       * Get MESSAGE-specific information.
       */
      let messageScan = null;

      if (scan.scan_type === "MESSAGE") {
        const query = `
        SELECT *
        FROM message_scans
        WHERE scan_id = $1
        LIMIT 1;
      `;

        const { rows } = await dbPool.query(query, [scanId]);

        messageScan = rows[0] || null;
      }

      return {
        scan,
        findings,
        urlScan,
        emailScan,
        messageScan,
      };
    } catch (error) {
      console.log(
        "Error gettting complete scan history by scanid and userid:",
        error,
      );
      throw error;
    }
  }
}

export default HistoryModel;
