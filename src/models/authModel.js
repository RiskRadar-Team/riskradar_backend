import { dbPool } from "../config/db.js";

/** this model deals with multiple device login for user */
class AuthModel {
  /** save refresh token */
  static async createRefreshToken(user_id, token, expires_at) {
    try {
      const query = `INSERT INTO refresh_tokens (user_id,token,expires_at)
      VALUES($1,$2,$3) RETURNING *;`;
      const values = [user_id, token, expires_at];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }

  /** find refresh token */
  static async findRefreshToken(token) {
    try {
      const query = `SELECT * FROM refresh_tokens WHERE token = $1 LIMIT 1`;
      const { rows } = await dbPool.query(query, [token]);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /** DELETE one refresh token */
  static async deleteRefreshToken(token) {
    try {
      const query = `
        DELETE FROM refresh_tokens
        WHERE token = $1;`;
      await dbPool.query(query, [token]);
      return true;
    } catch (error) {
      throw error;
    }
  }

  /** Logout from all devices or Delete all refresh tokens for a user */
  static async deleteUserRefreshTokens(userId) {
    try {
      const query = `
        DELETE FROM refresh_tokens
        WHERE user_id = $1;`;

      await dbPool.query(query, [userId]);
      return true;
    } catch (error) {
      throw error;
    }
  }
  /** Delete expried tokens */
  static async deleteExpiredTokens() {
    try {
      const query = `
        DELETE FROM refresh_tokens
        WHERE expires_at < CURRENT_TIMESTAMP;`;

      await dbPool.query(query);
      return true;
    } catch (error) {
      throw error;
    }
  }
  /** Get active token session */
  static async getUserSessions(userId) {
    try {
      const query = `
      SELECT id,created_at,expires_at
      FROM refresh_tokens
      WHERE user_id = $1
      ORDER BY created_at DESC;`;

      const { rows } = await dbPool.query(query, [userId]);

      return rows;
    } catch (error) {
      throw error;
    }
  }
}

export default AuthModel;
