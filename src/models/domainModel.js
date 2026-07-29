import { dbPool } from "../config/db.js";

class DomainModel {
  /** create domain */
  static async create({
    domain_name,
    list_type,
    threat_type_id,
    reason,
    source,
    confidence_score,
    created_by,
  }) {
    try {
      // console.log("from model", domain_name);
      // console.log("from model", list_type);
      const query = `
        INSERT INTO domains (domain_name,list_type,threat_type_id,reason,source,confidence_score,created_by)
        VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *;
      `;
      const values = [
        domain_name,
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
  /** find domain by id */
  static async findById(id) {
    try {
      const query = `
        SELECT domains.*,threat_types.code AS threat_type, threat_types.display_name AS threat_name
        FROM domains
        LEFT JOIN threat_types
        ON domains.threat_type_id = threat_types.id
        WHERE domains.id = $1 LIMIT 1;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /**find domain by domain name */
  static async findByDomainName(domain_name) {
    try {
      const query = `
        SELECT * FROM domains WHERE LOWER(domain_name) = LOWER($1)
        LIMIT 1;
      `;
      const { rows } = await dbPool.query(query, [domain_name]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /** get all the domain  */
  static async getAll() {
    try {
      // const query = `
      //   SELECT * FROM domains ORDER BY created_at DESC;
      // `;
      const query = `
        SELECT domains.*, threat_types.code AS threat_type, threat_types.display_name AS threat_name
        FROM domains
        LEFT JOIN threat_types
        ON domains.threat_type_id = threat_types.id
        ORDER BY created_at DESC;
      `;
      const { rows } = await dbPool.query(query);
      // console.log(rows);
      return rows;
    } catch (error) {
      throw error;
    }
  }
  /** update domain details */
  static async update(
    id,
    {
      domain_name,
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
        UPDATE domains SET domain_name = $1,list_type = $2, threat_type_id = $3,
        reason = $4, source = $5, confidence_score = $6, updated_by = $7,
        updated_at = CURRENT_TIMESTAMP WHERE id =  $8 RETURNING *;
      `;
      const values = [
        domain_name,
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
  static async updateStatus(id, is_active, updated_by) {
    try {
      const query = `
        UPDATE domains SET is_active =  $1, updated_by = $2,
        updated_at =  CURRENT_TIMESTAMP WHERE id = $3 
        RETURNING * ;
      `;
      const values = [is_active, updated_by, id];
      const { rows } = await dbPool.query(query, values);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /** delete domain */
  static async delete(id) {
    try {
      const query = `
        DELETE FROM domains WHERE id = $1
        RETURNING *;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /** search with domain name, list_type,is_active and pagenation */
  static async searchAndFindAll(
    page = 1,
    limit = 10,
    search = "",
    list_type,
    is_active,
    sort_by = "created_at",
    sort_order = "DESC",
  ) {
    const offset = (page - 1) * limit; // how many records to skip
    const conditions = [];
    const values = [];
    let index = 1;
    if (search) {
      conditions.push(`domains.domain_name ILIKE $${index++}`);
      values.push(`%${search}%`);
    }
    if (list_type) {
      conditions.push(`domains.list_type = $${index++}`);
      values.push(list_type);
    }
    if (typeof is_active === "boolean") {
      conditions.push(`domains.is_active =  $${index++}`);
      values.push(is_active);
    }
    const whereClause = conditions.length
      ? `WHERE ${conditions.join(" AND ")}`
      : "";

    const countQuery = `SELECT  COUNT(*) AS total FROM domains ${whereClause};`;
    const {
      rows: [{ total }],
    } = await dbPool.query(countQuery, values);
    values.push(limit);
    values.push(offset);
    const allowedSortColumns = [
      "domain_name",
      "list_type",
      "confidence_score",
      "created_at",
      "updated_at",
    ];

    const allowedSortOrders = ["ASC", "DESC"];

    const safeSortBy = allowedSortColumns.includes(sort_by)
      ? sort_by
      : "created_at";

    const safeSortOrder = allowedSortOrders.includes(sort_order.toUpperCase())
      ? sort_order.toUpperCase()
      : "DESC";
    // const query = `
    //   SELECT * FROM domains ${whereClause}
    //   ORDER BY ${safeSortBy} ${safeSortOrder}
    //   LIMIT $${index++} OFFSET $${index};
    // `;
    const query = `
    SELECT domains.*, threat_types.code AS threat_type, threat_types.display_name AS threat_name
    FROM domains
    LEFT JOIN threat_types
      ON domains.threat_type_id = threat_types.id
    ${whereClause}
    ORDER BY ${safeSortBy} ${safeSortOrder}
    LIMIT $${index++} OFFSET $${index};
  `;

    const { rows } = await dbPool.query(query, values);
    return {
      domains: rows,
      pagination: {
        page,
        limit,
        totalItems: Number(total),
        totalPages: Math.ceil(Number(total) / limit),
      },
    };
  }
}
export default DomainModel;
