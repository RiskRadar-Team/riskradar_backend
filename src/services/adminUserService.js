import ApiError from "../utils/ApiError.js";
import AdminUserModel from "../models/adminUserModel.js";

class AdminUserService {
  /**
   * Get users for admin panel.
   */
  static async getUsers({
    page = 1,
    limit = 10,
    search = null,
    role = null,
    isActive = null,
  } = {}) {
    /*
     * Normalize pagination.
     */
    page = Number(page);
    limit = Number(limit);

    if (!Number.isInteger(page) || page < 1) {
      throw new ApiError(400, "Page must be a positive integer.");
    }

    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new ApiError(400, "Limit must be between 1 and 100.");
    }

    /*
     * Validate role filter.
     */
    if (role !== null && role !== undefined && role !== "") {
      role = String(role).toUpperCase();

      if (!["USER", "ADMIN"].includes(role)) {
        throw new ApiError(400, "Invalid role. Use USER or ADMIN.");
      }
    } else {
      role = null;
    }

    /*
     * Normalize active filter.
     */
    if (isActive !== null && isActive !== undefined && isActive !== "") {
      if (
        isActive !== true &&
        isActive !== false &&
        isActive !== "true" &&
        isActive !== "false"
      ) {
        throw new ApiError(400, "isActive must be true or false.");
      }

      isActive = isActive === true || isActive === "true";
    } else {
      isActive = null;
    }

    /*
     * Normalize search.
     */
    if (search !== null && search !== undefined) {
      search = String(search).trim();

      if (search === "") {
        search = null;
      }

      /*
       * Prevent unnecessarily large search strings.
       */
      if (search && search.length > 100) {
        throw new ApiError(400, "Search cannot exceed 100 characters.");
      }
    }

    /*
     * Fetch users and total count concurrently.
     */
    const [users, total] = await Promise.all([
      AdminUserModel.getAll({
        page,
        limit,
        search,
        role,
        isActive,
      }),

      AdminUserModel.getCount({
        search,
        role,
        isActive,
      }),
    ]);

    const totalPages = total === 0 ? 0 : Math.ceil(total / limit);

    return {
      users: users.map((user) => this.formatUser(user)),

      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1,
      },
    };
  }

  /**
   * Get a single user.
   */
  static async getUserById(userId) {
    if (!userId) {
      throw new ApiError(400, "User id is required.");
    }

    const user = await AdminUserModel.getById(userId);

    if (!user) {
      throw new ApiError(404, "User not found.");
    }

    const statistics = await AdminUserModel.getUserStatistics(userId);

    return {
      ...this.formatUser(user),

      statistics: {
        totalScans: Number(statistics.total_scans || 0),

        threatsDetected: Number(statistics.threats_detected || 0),

        safeScans: Number(statistics.safe_scans || 0),

        averageRiskScore: Number(statistics.average_risk_score || 0),
      },
    };
  }

  /**
   * Activate or deactivate a user.
   */
  static async updateUserStatus(targetUserId, isActive, adminUserId) {
    if (!targetUserId) {
      throw new ApiError(400, "User id is required.");
    }

    if (isActive !== true && isActive !== false) {
      throw new ApiError(400, "isActive must be a boolean.");
    }

    /*
     * Prevent admin from disabling
     * their own account.
     */
    if (adminUserId && targetUserId === adminUserId) {
      throw new ApiError(400, "You cannot change your own account status.");
    }

    const user = await AdminUserModel.getById(targetUserId);

    if (!user) {
      throw new ApiError(404, "User not found.");
    }

    /*
     * If the status is already correct,
     * simply return the existing user.
     */
    if (user.is_active === isActive) {
      return this.formatUser(user);
    }

    const updatedUser = await AdminUserModel.updateStatus(
      targetUserId,
      isActive,
    );

    if (!updatedUser) {
      throw new ApiError(500, "Failed to update user status.");
    }

    return this.formatUser(updatedUser);
  }

  /**
   * Change user role.
   */
  static async updateUserRole(targetUserId, role, adminUserId) {
    if (!targetUserId) {
      throw new ApiError(400, "User id is required.");
    }

    role = String(role || "")
      .trim()
      .toUpperCase();

    if (!["USER", "ADMIN"].includes(role)) {
      throw new ApiError(400, "Invalid role. Use USER or ADMIN.");
    }

    /*
     * Prevent an admin from changing
     * their own role.
     */
    if (adminUserId && targetUserId === adminUserId) {
      throw new ApiError(400, "You cannot change your own role.");
    }

    const user = await AdminUserModel.getById(targetUserId);

    if (!user) {
      throw new ApiError(404, "User not found.");
    }

    /*
     * Prevent unnecessary database update.
     */
    if (user.role === role) {
      return this.formatUser(user);
    }

    /*
     * Prevent removing the last admin.
     */
    if (user.role === "ADMIN" && role === "USER") {
      const adminCount = await AdminUserModel.getAdminCount();

      if (adminCount <= 1) {
        throw new ApiError(400, "Cannot remove the last administrator.");
      }
    }

    const updatedUser = await AdminUserModel.updateRole(targetUserId, role);

    if (!updatedUser) {
      throw new ApiError(500, "Failed to update user role.");
    }

    return this.formatUser(updatedUser);
  }

  /**
   * Delete user.
   */
  static async deleteUser(targetUserId, adminUserId) {
    if (!targetUserId) {
      throw new ApiError(400, "User id is required.");
    }

    /*
     * Prevent self deletion.
     */
    if (adminUserId && targetUserId === adminUserId) {
      throw new ApiError(400, "You cannot delete your own account.");
    }

    const user = await AdminUserModel.getById(targetUserId);

    if (!user) {
      throw new ApiError(404, "User not found.");
    }

    /*
     * Prevent deletion of the last admin.
     */
    if (user.role === "ADMIN") {
      const adminCount = await AdminUserModel.getAdminCount();

      if (adminCount <= 1) {
        throw new ApiError(400, "Cannot delete the last administrator.");
      }
    }

    const deletedUser = await AdminUserModel.delete(targetUserId);

    if (!deletedUser) {
      throw new ApiError(500, "Failed to delete user.");
    }

    return {
      id: deletedUser.id,
      fullName: deletedUser.full_name,
      email: deletedUser.email,
      role: deletedUser.role,
    };
  }

  /**
   * Format user response.
   *
   * Never expose password.
   */
  static formatUser(user) {
    return {
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      role: user.role,
      emailVerified: user.email_verified,
      isActive: user.is_active,
      lastLogin: user.last_login,
      createdAt: user.created_at,
      updatedAt: user.updated_at,
    };
  }
}

export default AdminUserService;
