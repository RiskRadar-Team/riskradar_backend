import { dbPool } from "../config/db.js";

class AdminScanModel {
  /**
   * Get paginated scans for admin.
   *
   * Supported filters:
   * - userId
   * - scanType
   * - riskLevel
   * - isPhishing
   * - status
   * - from
   * - to
   */
  static async getScans({
    page = 1,
    limit = 20,
    userId = null,
    scanType = null,
    riskLevel = null,
    isPhishing = null,
    status = null,
    from = null,
    to = null,
  }) {
    const offset = (page - 1) * limit;
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

        scans.scan_duration_ms,

        scans.started_at,
        scans.completed_at,
        scans.created_at,

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

        END AS input

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

        (
          $1::UUID IS NULL
          OR scans.user_id = $1
        )

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
          $5::VARCHAR IS NULL
          OR scans.status = $5
        )

        AND (
          $6::TIMESTAMP IS NULL
          OR scans.created_at >= $6
        )

        AND (
          $7::TIMESTAMP IS NULL
          OR scans.created_at < (
            $7::DATE + INTERVAL '1 day'
          )
        )

      ORDER BY
        scans.created_at DESC

      LIMIT $8
      OFFSET $9;
    `;

      const { rows } = await dbPool.query(query, [
        userId,
        scanType,
        riskLevel,
        isPhishing,
        status,
        from,
        to,
        limit,
        offset,
      ]);

      return rows || [];
    } catch (error) {
      console.log("Error getting the scans for admin:", error);
      throw error;
    }
  }

  /**
   * Get total number of scans
   * matching admin filters.
   */
  static async getScansCount({
    userId = null,
    scanType = null,
    riskLevel = null,
    isPhishing = null,
    status = null,
    from = null,
    to = null,
  }) {
    try {
      const query = `
      SELECT
        COUNT(*)::INTEGER AS total

      FROM scans

      LEFT JOIN risk_levels
        ON risk_levels.id = scans.risk_level_id

      WHERE

        (
          $1::UUID IS NULL
          OR scans.user_id = $1
        )

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
          $5::VARCHAR IS NULL
          OR scans.status = $5
        )

        AND (
          $6::TIMESTAMP IS NULL
          OR scans.created_at >= $6
        )

        AND (
          $7::TIMESTAMP IS NULL
          OR scans.created_at < (
            $7::DATE + INTERVAL '1 day'
          )
        );
    `;

      const { rows } = await dbPool.query(query, [
        userId,
        scanType,
        riskLevel,
        isPhishing,
        status,
        from,
        to,
      ]);

      return Number(rows[0]?.total || 0);
    } catch (error) {
      console.log("Error getting scan count for admin:", error);
      throw error;
    }
  }

  /**
   * Get complete scan details.
   *
   * Admin can inspect any scan.
   */
  static async getScanById(scanId) {
    /*
     * Parent scan.
     */
    try {
      const scanQuery = `
      SELECT
        scans.id,
        scans.user_id,

        users.full_name,
        users.email,

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

        risk_levels.id
          AS risk_level_id,

        risk_levels.code
          AS risk_level,

        risk_levels.display_name
          AS risk_level_name,

        risk_levels.min_score
          AS risk_min_score,

        risk_levels.max_score
          AS risk_max_score,

        risk_levels.color
          AS risk_level_color

      FROM scans 

      LEFT JOIN users 
        ON users.id = scans.user_id

      LEFT JOIN risk_levels
        ON risk_levels.id = scans.risk_level_id

      WHERE
        scans.id = $1

      LIMIT 1;
    `;

      const { rows: scanRows } = await dbPool.query(scanQuery, [scanId]);

      if (!scanRows.length) {
        return null;
      }

      const scan = scanRows[0];

      /*
       * Scan findings.
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
       * URL scan details.
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
       * Email scan details.
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
       * Message scan details.
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
      console.log("Error getting complete scan details for admin:", error);
      throw error;
    }
  }
}

export default AdminScanModel;
