import { dbPool } from "../config/db.js";

class UrlModel {
  /**create url function */
  static async create({
    url,
    domain_id,
    list_type,
    threat_type_id,
    reason,
    source,
    confidence_score,
    created_by,
  }) {
    try {
      const query = `
        INSERT INTO urls (url,domain_id,list_type,threat_type_id,reason,source,
        confidence_score,created_by
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *;
      `;
      const values = [
        url,
        domain_id,
        list_type,
        threat_type_id,
        reason,
        source,
        confidence_score,
        created_by,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /**find url by it's Id */
  static async findById(id) {
    try {
      const query = `
        SELECT urls.*,domains.domain_name,
        threat_types.code AS threat_type, threat_types.display_name AS threat_name
        FROM urls
        LEFT JOIN domains 
        ON  urls.domain_id =  domains.id
        LEFT JOIN threat_types
        ON urls.threat_type_id = threat_types.id
        WHERE urls.id = $1 
        LIMIT 1;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /** find url by url value, here we are not going to join with
   * domains table as this function can be use while scaning later
   */
  static async findByUrl(url) {
    try {
      // const query = `
      //   SELECT * FROM urls WHERE LOWER(url) = LOWER($1) LIMIT 1;
      // `;
      const query = `
         SELECT * FROM urls
          WHERE url = $1
          AND is_active = TRUE
          LIMIT 1;
        `;
      const { rows } = await dbPool.query(query, [url]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /** update url details */
  static async update(
    id,
    {
      url,
      domain_id,
      list_type,
      threat_type_id,
      reason,
      source,
      confidence_score,
      updated_by,
    },
  ) {
    try {
      const query = `
        UPDATE urls SET url = $1, domain_id = $2, list_type = $3,
        threat_type_id = $4, reason = $5, source = $6, 
        confidence_score = $7, updated_by = $8,
        updated_at =  CURRENT_TIMESTAMP
        WHERE id = $9 RETURNING *;
      `;
      const values = [
        url,
        domain_id,
        list_type,
        threat_type_id,
        reason,
        source,
        confidence_score,
        updated_by,
        id,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /**update url status */
  static async updateUrlStatus(id, is_active, updated_by) {
    try {
      const query = `
        UPDATE urls SET 
          is_active = $1, updated_by = $2,
          updated_at = CURRENT_TIMESTAMP
          WHERE id = $3 RETURNING *;
      `;
      const values = [is_active, updated_by, id];
      const { rows } = await dbPool.query(query, values);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /** delete url */
  static async delete(id) {
    try {
      const query = `
        DELETE FROM urls
        WHERE id = $1 RETURNING  *;  
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || [];
    } catch (error) {
      throw error;
    }
  }
  /**get all urls */
  static async getAllUrls() {
    try {
      const query = `
        SELECT urls.*,domains.domain_name,
        threat_types.code AS threat_type, threat_types.display_name AS threat_name
        FROM urls
        LEFT JOIN domains 
        ON  urls.domain_id =  domains.id
        LEFT JOIN threat_types
        ON urls.threat_type_id = threat_types.id
        ORDER BY urls.created_at DESC;
      `;
      const { rows } = await dbPool.query(query);
      return rows || null;
    } catch (error) {
      throw error;
    }
  }
  /**search and get all urls */
  static async searchAndFindAll(
    page = 1,
    limit = 10,
    search = "",
    list_type,
    is_active,
    domain_id,
    sort_by = "created_at",
    sort_order = "DESC",
  ) {
    try {
      const offset = (page - 1) * limit;
      const conditions = [];
      const values = [];
      let index = 1;
      if (search) {
        conditions.push(`urls.url ILIKE $${index++}`);
        values.push(`%${search}%`);
      }
      if (list_type) {
        conditions.push(`urls.list_type ILIKE $${index++}`);
        values.push(list_type);
      }
      if (typeof is_active === "boolean") {
        conditions.push(`urls.is_active = $${index++}`);
        values.push(is_active);
      }
      if (domain_id) {
        conditions.push(`urls.domain_id = $${index++}`);
        values.push(domain_id);
      }
      const whereClause = conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

      const countQuery = `
      SELECT COUNT(*) AS total FROM urls ${whereClause};
    `;
      const {
        rows: [{ total }],
      } = await dbPool.query(countQuery, values);

      const allowedSortColumns = [
        "url",
        "list_type",
        "confidence_score",
        "created_at",
        "updated_at",
      ];
      const safeSortBy = allowedSortColumns.includes(sort_by)
        ? sort_by
        : "created_at";
      const safeSortOrder = sort_order.toUpperCase() === "ASC" ? "ASC" : "DESC";
      values.push(limit);
      values.push(offset);

      const query = `
      SELECT urls.*,domains.domain_name,
      threat_types.code AS threat_type, threat_types.display_name AS threat_name
      FROM urls 
      LEFT JOIN domains 
      ON urls.domain_id =  domains.id
      LEFT JOIN threat_types
      ON urls.threat_type_id = threat_types.id
      ${whereClause}
      ORDER BY urls.${safeSortBy} ${safeSortOrder}
      LIMIT $${index++}
      OFFSET $${index};
    `;
      const { rows } = await dbPool.query(query, values);
      return {
        urls: rows,
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
}
export default UrlModel;
