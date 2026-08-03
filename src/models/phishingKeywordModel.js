import { dbPool } from "../config/db.js";

class PhishingKeywordModel {
  /** create keyword */
  static async create({
    keyword,
    category_id,
    severity,
    match_type,
    score,
    description,
    example,
    is_case_sensitive,
    created_by,
  }) {
    try {
      const query = `
      INSERT INTO phishing_keywords (keyword,category_id,severity,
      match_type,score,description,example,is_case_sensitive,created_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING *;
    `;
      const values = [
        keyword,
        category_id,
        severity,
        match_type,
        score,
        description,
        example,
        is_case_sensitive,
        created_by,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /**find keyword by it's ID */
  static async findById(id) {
    try {
      const query = `
        SELECT phishing_keywords.*,keyword_categories.code AS category,
        keyword_categories.display_name AS category_name
        FROM phishing_keywords
        LEFT JOIN keyword_categories
        ON phishing_keywords.category_id = keyword_categories.id
        WHERE phishing_keywords.id  = $1 LIMIT 1;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /**Find keyword by keyword name */
  static async findByKeyword(keyword) {
    try {
      const query = `
      SELECT * FROM phishing_keywords
      WHERE LOWER(keyword) = LOWER($1) LIMIT 1; 
    `;

      const { rows } = await dbPool.query(query, [keyword]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /**get all the keywords */
  static async getAllKeywords() {
    try {
      const query = `
        SELECT phishing_keywords.*,keyword_categories.code AS category,
        keyword_categories.display_name AS category_name
        FROM phishing_keywords
        LEFT JOIN keyword_categories
        ON phishing_keywords.category_id = keyword_categories.id
        ORDER BY created_at DESC;
      `;
      const { rows } = await dbPool.query(query);
      return rows || [];
    } catch (error) {
      throw error;
    }
  }
  /** update keyword details */
  static async update(
    id,
    {
      keyword,
      category_id,
      serverity,
      match_type,
      score,
      description,
      example,
      is_case_sensitive,
      updated_by,
    },
  ) {
    try {
      const query = `
      UPDATE phishing_keywords SET
      keyword = $1, category_id = $2, severity = $3,
      match_type = $4, score = $5, description = $6,
      example = $7, is_case_sensitive = $8,
      updated_by = $9, updated_at = CURRENT_TIMESTAMP
      WHERE id = $10 RETURNING *;
    `;
      const values = [
        keyword,
        category_id,
        serverity,
        match_type,
        score,
        description,
        example,
        is_case_sensitive,
        updated_by,
        id,
      ];
      const { rows } = await dbPool.query(query, values);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /**update keyword status */
  static async updateStatus(id, is_active, updated_by) {
    try {
      const query = `
        UPDATE phishing_keywords 
        SET is_active = $1, updated_by = $2,
        updated_at = CURRENT_TIMESTAMP WHERE id = $3
        RETURNING *;
      `;
      const values = [is_active, updated_by, id];
      const { rows } = await dbPool.query(query, values);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /** delete keyword */
  static async delete(id) {
    try {
      const query = `
        DELETE FROM phishing_keywords
        WHERE id = $1 RETURNING *;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /** search and find all  */
  static async searchAndFindAll(
    page = 1,
    limit = 10,
    search = "",
    category,
    severity,
    match_type,
    is_active,
    sort_by = "created_at",
    sort_order = "DESC",
  ) {
    try {
      const offset = (page - 1) * limit;
      const conditions = [];
      const values = [];
      let index = 1;
      if (search) {
        conditions.push(`phishing_keywords.keyword ILIKE $${index++}`);
        values.push(`%${search}%`);
      }
      if (category) {
        conditions.push(`keyword_categories.code = $${index++}`);
        values.push(category);
      }
      if (severity) {
        conditions.push(`phishing_keywords.severity = $${index++}`);
        values.push(severity);
      }
      if (match_type) {
        conditions.push(`phishing_keywords.match_type = $${index++}`);
        values.push(match_type);
      }
      if (typeof is_active === "boolean") {
        conditions.push(`phishing_keywords.is_active = $${index++}`);
        values.push(is_active);
      }
      const whereClause = conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";
      //   const countQuery = `
      //   SELECT COUNT(*) AS total FROM phishing_keywords
      //   ${whereClause};
      // `;
      const countQuery = `
      SELECT COUNT(*) AS total
      FROM phishing_keywords
      LEFT JOIN keyword_categories
        ON phishing_keywords.category_id = keyword_categories.id
      ${whereClause};
    `;

      const {
        rows: [{ total }],
      } = await dbPool.query(countQuery, values);

      const allowedSortColumns = [
        "keyword",
        "category_id",
        "severity",
        "score",
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
        SELECT phishing_keywords.*,keyword_categories.code AS category,
        keyword_categories.display_name AS category_name
        FROM phishing_keywords
        LEFT JOIN keyword_categories
        ON phishing_keywords.category_id = keyword_categories.id
        ${whereClause}
        ORDER BY ${safeSortBy} ${safeSortOrder}
        LIMIT $${index++} OFFSET $${index};
      `;
      const { rows } = await dbPool.query(query, values);

      return {
        keywords: rows,
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
  /**get active phishing keywords */
  static async getActiveKeywords() {
    try {
      const query = `
        SELECT * FROM phishing_keywords
        WHERE is_active = TRUE
        ORDER BY severity DESC, score DESC;
      `;
      const { rows } = await dbPool.query(query);
      return rows;
    } catch (error) {
      throw error;
    }
  }
}
export default PhishingKeywordModel;
