import { dbPool } from "../config/db.js";

class AdminUserModel {
  /**
   * Get users with pagination, search,
   * role filter and active-status filter.
   */
  static async getAll({
    page = 1,
    limit = 10,
    search = null,
    role = null,
    isActive = null,
  } = {}) {
    try {
      const offset = (page - 1) * limit;

      const values = [search, role, isActive, limit, offset];

      const query = `
      SELECT
        id,
        full_name,
        email,
        role,
        email_verified,
        is_active,
        last_login,
        created_at,
        updated_at

      FROM users

      WHERE
        (
          $1::TEXT IS NULL
          OR full_name ILIKE '%' || $1 || '%'
          OR email ILIKE '%' || $1 || '%'
        )

        AND (
          $2::VARCHAR IS NULL
          OR role = $2
        )

        AND (
          $3::BOOLEAN IS NULL
          OR is_active = $3
        )

      ORDER BY created_at DESC

      LIMIT $4
      OFFSET $5;
    `;

      const { rows } = await dbPool.query(query, values);

      return rows || [];
    } catch (error) {
      console.log("Error occur while searching users:", error);
      throw error;
    }
  }

  /**
   * Get total number of users matching filters.
   */
  static async getCount({ search = null, role = null, isActive = null } = {}) {
    try {
      const query = `
      SELECT COUNT(*)::INTEGER AS total

      FROM users

      WHERE
        (
          $1::TEXT IS NULL
          OR full_name ILIKE '%' || $1 || '%'
          OR email ILIKE '%' || $1 || '%'
        )

        AND (
          $2::VARCHAR IS NULL
          OR role = $2
        )

        AND (
          $3::BOOLEAN IS NULL
          OR is_active = $3
        );
    `;

      const { rows } = await dbPool.query(query, [search, role, isActive]);

      return rows[0]?.total || 0;
    } catch (error) {
      console.log("Error while counting filtered users.", error);
      throw error;
    }
  }

  /**
   * Get a single user by ID.
   */
  static async getById(userId) {
    try {
      const query = `
      SELECT
        id,
        full_name,
        email,
        role,
        email_verified,
        is_active,
        last_login,
        created_at,
        updated_at

      FROM users

      WHERE id = $1

      LIMIT 1;
    `;

      const { rows } = await dbPool.query(query, [userId]);

      return rows[0] || null;
    } catch (error) {
      console.log("Error occur while getting user by ID:", error);
      throw error;
    }
  }

  /**
   * Update user's active status.
   */
  static async updateStatus(userId, isActive) {
    try {
      const query = `
      UPDATE users
      SET
        is_active = $2,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING
        id,
        full_name,
        email,
        role,
        email_verified,
        is_active,
        last_login,
        created_at,
        updated_at;
    `;

      const { rows } = await dbPool.query(query, [userId, isActive]);

      return rows[0] || null;
    } catch (error) {
      console.log("Error updating user status:", error);
      throw error;
    }
  }

  /**
   * Update user's role.
   */
  static async updateRole(userId, role) {
    try {
      const query = `
      UPDATE users
      SET
        role = $2,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING
        id,
        full_name,
        email,
        role,
        email_verified,
        is_active,
        last_login,
        created_at,
        updated_at;
    `;

      const { rows } = await dbPool.query(query, [userId, role]);

      return rows[0] || null;
    } catch (error) {
      console.log("Error updating user role:", error);
      throw error;
    }
  }

  /**
   * Delete a user.
   */
  static async delete(userId) {
    try {
      const query = `
      DELETE FROM users
      WHERE id = $1
      RETURNING
        id,
        full_name,
        email,
        role;
    `;

      const { rows } = await dbPool.query(query, [userId]);

      return rows[0] || null;
    } catch (error) {
      console.log("Error occur while deleting the user:", error);
      throw error;
    }
  }

  /**
   * Check whether a user exists.
   */
  static async exists(userId) {
    try {
      const query = `
      SELECT EXISTS (
        SELECT 1
        FROM users
        WHERE id = $1
      ) AS exists;
    `;

      const { rows } = await dbPool.query(query, [userId]);

      return Boolean(rows[0]?.exists);
    } catch (error) {
      console.log("Error while checking user exists or not:", error);
      throw error;
    }
  }

  /**
   * Get user statistics.
   *
   * Uses the existing scans table.
   */
  static async getUserStatistics(userId) {
    try {
      const query = `
      SELECT
        COUNT(scans.id)::INTEGER AS total_scans,

        COUNT(scans.id) FILTER (
          WHERE scans.is_phishing = TRUE
        )::INTEGER AS threats_detected,

        COUNT(scans.id) FILTER (
          WHERE scans.is_phishing = FALSE
        )::INTEGER AS safe_scans,

        COALESCE(
          ROUND(AVG(scans.risk_score), 2),
          0
        ) AS average_risk_score

      FROM scans

      WHERE scans.user_id = $1
        AND scans.status = 'COMPLETED';
    `;

      const { rows } = await dbPool.query(query, [userId]);

      return (
        rows[0] || {
          total_scans: 0,
          threats_detected: 0,
          safe_scans: 0,
          average_risk_score: 0,
        }
      );
    } catch (error) {
      console.log("Error while getting user statistics:", error);
      throw error;
    }
  }
  /**
   * Get admin count
   */
  static async getAdminCount() {
    try {
      const query = `
        SELECT COUNT(*)::INTEGER AS count
        FROM users
        WHERE role = 'ADMIN';
      `;

      const { rows } = await dbPool.query(query);

      return Number(rows[0]?.count || 0);
    } catch (error) {
      console.log("Error while counting admins:", error);
      throw error;
    }
  }
}

export default AdminUserModel;
