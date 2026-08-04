import { dbPool } from "../config/db.js";

class RiskLevelModel {
  /**get all the risk levels function */
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
  /**get risk level by id */
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
  /** get risk level by score */
  static async getByScore(score) {
    try {
      const query = `
        SELECT * FROM risk_levels WHERE min_score <= $1 AND max_score >= $1 LIMIT 1;
      `;
      const { rows } = await dbPool.query(query, [score]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
}
export default RiskLevelModel;
