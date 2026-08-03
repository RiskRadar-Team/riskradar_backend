import { dbPool } from "../config/db.js";

class ScanFindingModel {
  /**create a scan finding */
  static async create(data) {
    try {
      const query = `
        INSERT INTO scan_findings(
          scan_id,
          finding_type,
          finding_value,
          severity,
          score,
          description,
          source,
          evidence
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *;
      `;
      const values = [
        data.scan_id,
        data.finding_type,
        data.finding_value,
        data.severity ?? 3,
        data.score ?? 0,
        data.description ?? null,
        data.source ?? null,
        data.evidence ?? null,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      console.log("Error creating scan findings.", error);
      throw error;
    }
  }
  /**find scan findings by ID */
  static async findById(id) {
    try {
      const query = `
        SELECT * FROM scan_findings WHERE id = $1;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0];
    } catch (error) {
      console.log("Error finding scan findings.", error);
      throw error;
    }
  }
  /** get all findings for a scan */
  static async findByScanId(scanId) {
    try {
      const query = `
        SELECT * FROM scan_findings
        WHERE scan_id = $1
        ORDER BY created_at ASC;
      `;
      const { rows } = await dbPool.query(query, [scanId]);
      return rows;
    } catch (error) {
      console.log("Error fetching scan_findings by scanId.", error);
      throw error;
    }
  }
  /**Get findings by finding_type and scan Id */
  static async findByScanIdAndFindingType(scanId, findingType) {
    try {
      const query = `
          SELECT * FROM scan_findings
          WHERE scan_id = $1 AND finding_type = $2
          ORDER BY created_at ASC;
        `;
      const { rows } = await dbPool.query(query, [scanId, findingType]);
      return rows;
    } catch (error) {
      console.log(
        "Error fetching scan_findings by scanId and findingType.",
        error,
      );
      throw error;
    }
  }
  /** get findings by severity */
  static async findBySeverity(severity) {
    try {
      const query = `
        SELECT * FROM scan_findings
        WHERE severity = $1
        ORDER BY created_at ASC;
      `;
      const { rows } = await dbPool.query(query, [severity]);
      return rows;
    } catch (error) {
      console.log("Error fetching scan_findings by severity.", error);
      throw error;
    }
  }
  /**
   * GET high risk findings for a scan
   * Example
   * SEVERITY 4 = HIGH
   * SEVERITY 5 = CRITICAL
   */
  static async findHighRiskByScanId(scanId) {
    try {
      const query = `
        SELECT * FROM scan_findings 
        WHERE scan_id = $1 
        AND severity >= 4
        ORDER BY severity DESC,
        score DESC,
        created_at ASC;
      `;
      const { rows } = await dbPool.query(query, [scanId]);
      return rows;
    } catch (error) {
      console.log(
        "Error fetching scan findings with condition risk and scan_id.",
      );
      throw error;
    }
  }
  /** GET  findings ordered by score */
  static async findByScanIdOrderByScore(scanId, order = "DESC") {
    try {
      const safeOrder = order.toUpperCase() === "ASC" ? "ASC" : "DESC";
      const query = `
        SELECT * FROM scan_findings
        WHERE scan_id = $1
        ORDER BY score ${safeOrder}, created_at ASC;
      `;
      const { rows } = await dbPool.query(query, [scanId]);
      return rows;
    } catch (error) {
      console.log(
        "Error fetching scan findings by scanId and order by Score.",
        error,
      );
      throw error;
    }
  }
  /** Count findings for a particular scan id */
  static async countByScanId(scanId) {
    try {
      const query = `
        SELECT COUNT(*) AS total
        FROM scan_findings
        WHERE scan_id = $1;
      `;
      const {
        rows: [{ total }],
      } = await dbPool.query(query, [scanId]);
      return Number(total);
    } catch (error) {
      console.log("Error counting scan findings by scan id");
      throw error;
    }
  }
  /**
   * Calculate total finding score
   * used later by the risk scoring engine.
   */
  static async getTotalScore(scanId) {
    try {
      const query = `
        SELECT COALESCE(SUM(score),0) AS total_score
        FROM scan_findings
        WHERE scan_id = $1;
      `;
      const {
        rows: [{ total_score }],
      } = await dbPool.query(query, [scanId]);
      return Number(total_score);
    } catch (error) {
      console.log("Error getting total score.", error);
      throw error;
    }
  }
  /**
   * Get finding summary
   * Returns total findings and score grouped by finding type
   */
  static async getSummaryByScanId(scanId) {
    try {
      const query = `
        SELECT finding_type,
        COUNT(*) AS finding_count,
        COALESCE(SUM(score),0) AS total_score,
        MAX(severity) AS highest_severity
        FROM scan_findings
        WHERE scan_id = $1
        GROUP BY finding_type 
        ORDER BY total_score DESC;
      `;
      const { rows } = await dbPool.query(query, [scanId]);
      return rows.map((row) => ({
        finding_type: row.finding_type,
        finding_count: Number(row.finding_count),
        total_score: Number(row.total_score),
        highest_severity: Number(row.highest_severity),
      }));
    } catch (error) {
      console.log("Error getting the summary.", error);
      throw error;
    }
  }
  /**update a finding */
  static async update(id, data) {
    try {
      const query = `
        UPDATE scan_findings
        SET 
        finding_type = COALESCE($2, finding_type),
        finding_value = COALESCE($3, finding_value),
        severity = COALESCE($4, severity),
        score = COALESCE($5, score),
        description = COALESCE($6, description),
        source = COALESCE($7, source),
        evidence = COALESCE($8, evidence)
        WHERE id = $1 RETURNING *;
      `;
      const values = [
        id,
        data.finding_type ?? null,
        data.finding_value ?? null,
        data.severity ?? null,
        data.score ?? null,
        data.description ?? null,
        data.source ?? null,
        data.evidence ?? null,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      console.log("Error updating scan finding.", error);
      throw error;
    }
  }
  /** Delete a finding */
  static async delete(id) {
    try {
      const query = `
        DELETE FROM scan_findings WHERE id = $1 RETURNING *;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0];
    } catch (error) {
      console.log("Error deleting scan finding.", error);
      throw error;
    }
  }
  /**Delete all findings for a scan */
  static async deleteByScanId(scanId) {
    try {
      const query = `
        DELETE FROM scan_findings WHERE scan_id = $1 RETURNING *;
      `;
      const { rows } = await dbPool.query(query, [scanId]);
      return rows;
    } catch (error) {
      console.log("Error deleting scan findings.", error);
      throw error;
    }
  }
}
export default ScanFindingModel;
