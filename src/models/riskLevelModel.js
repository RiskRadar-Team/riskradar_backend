import { dbPool } from "../config/db.js";

class RiskLevelModel {
  /**get all the threat type function */
  static async getAll() {
    try {
      const query = `
        SELECT * FROM  risk_levels ORDER BY code;
      `;
      const { rows } = await dbPool.query(query);
      return rows || [];
    } catch (error) {
      throw error;
    }
  }
  /**get threat type by id */
  static async getById(id) {
    try {
      const query = `
        SELECT * FROM risk_levels WHERE id = $1 LIMIT 1;
      `;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
}
export default RiskLevelModel;
