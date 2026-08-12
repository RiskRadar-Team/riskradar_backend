import { dbPool } from "../config/db.js";

class UserModel {
  /** create user function */
  static async create(full_name, email, password, role = "USER") {
    try {
      // db query
      const query = `INSERT INTO users(full_name, email, password, role)
      VALUES($1,$2,$3,$4) RETURNING *;`;
      // values for db columns
      const values = [full_name, email.toLowerCase(), password, role];
      //run query
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /** find user by ID */
  static async findById(id) {
    try {
      const query = `SELECT * FROM users WHERE id = $1 LIMIT 1`;
      const { rows } = await dbPool.query(query, [id]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /**  find user by email */
  static async findByEmail(email) {
    try {
      const query = `SELECT * FROM users WHERE email = $1 LIMIT 1`;
      const { rows } = await dbPool.query(query, [email.toLowerCase()]);
      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
  /**verify email -
   * this will only be used when we extend the project and add the verfication of mail ids */
  static async verfiyEmail(userId) {
    try {
      const query = `UPDATE users SET email_verified = TRUE WHERE id =  $1 RETURNING *;`;
      const { rows } = await dbPool.query(query, [userId]);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /**update last login */
  static async updateLastLogin(userId) {
    try {
      const query = `UPDATE users SET last_login = CURRENT_TIMESTAMP,
     updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *;`;

      const { rows } = await dbPool.query(query, [userId]);
      if (rows.length === 0) {
        return false;
      }
      return true;
    } catch (error) {
      throw error;
    }
  }

  /**update user detail/details */
  static async updateProfile(userId, full_name) {
    try {
      const query = `UPDATE users SET full_name = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *;`;
      const values = [full_name, userId];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /**change password */
  static async changePassword(userId, password) {
    try {
      // console.log("user id", userId);
      const query = `UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *;`;
      const values = [password, userId];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  /** Activate or Deactivate user */

  static async updateStatus(userId, is_active) {
    try {
      const query = `UPDATE users SET is_active = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *;`;
      const { rows } = await dbPool.query(query, [userId, is_active]);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }

  /**update user role  */
  static async updateRole(userId, role) {
    try {
      const query = `UPDATE users SET role =$1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *;`;
      const values = [role, userId];
      const { rows } = await dbPool.query(query, values);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }

  /**get all users */

  static async getAllUsers() {
    try {
      const query = `SELECT * FROM users ORDER BY created_at DESC;`;
      const { rows } = await dbPool.query(query);
      return rows;
    } catch (error) {
      throw error;
    }
  }
  /**delete user */
  static async deleteUser(userId) {
    try {
      const query = `DELETE FROM users WHERE id = $1 RETURNING *;`;
      const { rows } = await dbPool.query(query, [userId]);
      return rows[0];
    } catch (error) {
      throw error;
    }
  }
  static async updatePassword(userId, passwordHash) {
    try {
      const query = `
    UPDATE users
    SET
      password = $1,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = $2
    RETURNING id, email, updated_at
  `;

      const { rows } = await dbPool.query(query, [passwordHash, userId]);

      return rows[0] || null;
    } catch (error) {
      throw error;
    }
  }
}

export default UserModel;
