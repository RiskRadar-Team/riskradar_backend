import { dbPool } from "../config/db.js";

class ScanModel {
  /**creating a new scan */
  static async create(data) {
    try {
      const query = `
      INSERT INTO scans(user_id,scan_type,status,engine_version)
      VALUES($1,$2,$3,$4) RETURNING *;
    `;
      const values = [
        data.user_id,
        data.scan_type,
        data.status,
        data.engine_version,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /** find scan by ID */
  static async findById(id) {
    try {
      const query = `
        SELECT * FROM scans WHERE id = $1 LIMIT 1;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /**update scan status */
  static async updateStatus(id, status) {
    try {
      const query = `
        UPDATE scans SET status = $1, updated_at = CURRENT_TIMESTAMP
        WHERE id = $2 RETURNING *;
      `;
      const values = [status, id];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /** marking scan status as processing */
  static async markProcessing(id) {
    try {
      const query = `
        UPDATE scans SET status = 'PROCESSING', started_at=CURRENT_TIMESTAMP,
         updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 RETURNING *;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /** marking scan status as failed */
  static async markFailed(id) {
    try {
      const query = `
        UPDATE scans SET status = 'FAILED', updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 RETURNING *;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /** scan status to complete and update other results */
  static async complete(id, data) {
    try {
      const query = `
        UPDATE scans SET status = 'COMPLETED',
        risk_score = $1,risk_level_id = $2,is_phishing = $3,
        scan_duration_ms = $4,
        completed_at = CURRENT_TIMESTAMP
        WHERE id=$5 RETURNING *;
      `;
      const values = [
        data.risk_score,
        data.risk_level_id,
        data.is_phishing,
        data.scan_duration_ms,
        id,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /**search scan and pagination */
  static async searchAndFindAll(
    userId,
    page = 1,
    limit = 10,
    search = "",
    scan_type,
    status,
    risk_level_id,
    sort_by = "created_at",
    sort_order = "DESC",
  ) {
    try {
      const offset = (page - 1) * limit;
      const conditions = ["user_id=$1"];
      const values = [userId];
      let index = 2;
      if (search) {
        conditions.push(`CAST(id AS TEXT) ILIKE $${index++}`);
        /** if here we use id only then it will search for exact match for UUID
         * so casting id as text for partial match and search
         */
        values.push(`%${search}%`);
      }
      if (scan_type) {
        conditions.push(`scan_type=$${index++}`);
        values.push(scan_type);
      }

      if (status) {
        conditions.push(`status=$${index++}`);
        values.push(status);
      }

      if (risk_level_id) {
        conditions.push(`risk_level_id=$${index++}`);
        values.push(risk_level_id);
      }
      const whereClause = conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";
      const countQuery = `
      SELECT COUNT(*) AS total
      FROM scans
      ${whereClause};
    `;
      const {
        rows: [{ total }],
      } = await dbPool.query(countQuery, values);

      values.push(limit);
      values.push(offset);
      const query = `
          SELECT *
          FROM scans
          ${whereClause}
          ORDER BY ${sort_by} ${sort_order}
          LIMIT $${index++}
          OFFSET $${index};
        `;

      const { rows } = await dbPool.query(query, values);
      return {
        scans: rows,
        pagination: {
          page,
          limit,
          totalItems: Number(total),
          totalPages: Math.ceil(Number(total) / limit),
        },
      };
    } catch (error) {
      throw error;
    }
  }
  static async delete(id) {
    try {
      const query = `
        DELETE FROM scans WHERE id = $1 RETURNING *;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
}
export default ScanModel;
