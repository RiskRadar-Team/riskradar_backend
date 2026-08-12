import { dbPool } from "../config/db.js";

class PasswordResetOtpModel {
  static async create({ userId, otpHash, expiresAt }) {
    try {
      const query = `
      INSERT INTO password_reset_otps (
        user_id,
        otp_hash,
        expires_at
      )
      VALUES ($1, $2, $3)
      RETURNING
        id,
        user_id,
        expires_at,
        created_at
    `;

      const { rows } = await dbPool.query(query, [userId, otpHash, expiresAt]);

      return rows[0];
    } catch (error) {
      console.log("Error creating reset otp:", error);
      throw error;
    }
  }

  static async findLatestValidByUserId(userId) {
    try {
      const query = `
      SELECT
        id,
        user_id,
        otp_hash,
        expires_at,
        attempts,
        verified_at,
        created_at
      FROM password_reset_otps
      WHERE user_id = $1
        AND verified_at IS NULL
        AND expires_at > CURRENT_TIMESTAMP
      ORDER BY created_at DESC
      LIMIT 1
    `;

      const { rows } = await dbPool.query(query, [userId]);

      return rows[0] || null;
    } catch (error) {
      console.log("Error getting the latest valid user by id:", error);
      throw error;
    }
  }

  static async incrementAttempts(id) {
    try {
      const query = `
      UPDATE password_reset_otps
      SET attempts = attempts + 1
      WHERE id = $1
      RETURNING attempts
    `;

      const { rows } = await dbPool.query(query, [id]);

      return rows[0] || null;
    } catch (error) {
      console.log("Error while incrementing otp attempts:", error);
      throw error;
    }
  }

  static async markAsVerified(id) {
    try {
      const query = `
      UPDATE password_reset_otps
      SET verified_at = CURRENT_TIMESTAMP
      WHERE id = $1
    `;

      await dbPool.query(query, [id]);
    } catch (error) {
      console.log("Error while marking otp as verified:", error);
      throw error;
    }
  }

  static async deleteUserOtps(userId) {
    try {
      const query = `
      DELETE FROM password_reset_otps
      WHERE user_id = $1
    `;

      await dbPool.query(query, [userId]);
    } catch (error) {
      console.log("Error while deleting otp:", error);
      throw error;
    }
  }

  static async deleteExpired() {
    try {
      const query = `
      DELETE FROM password_reset_otps
      WHERE expires_at <= CURRENT_TIMESTAMP
    `;

      await dbPool.query(query);
    } catch (error) {
      console.log("Error while deleting expired otps:", error);
      throw error;
    }
  }
}

export default PasswordResetOtpModel;
