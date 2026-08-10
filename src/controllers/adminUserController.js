import AdminUserService from "../services/adminUserService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class AdminUserController {
  /**
   * Get users.
   *
   * GET /riskradar/users/admin
   *
   * Query params:
   * ?page=1
   * ?limit=10
   * ?search=sandeep
   * ?role=USER
   * ?isActive=true
   */
  static getUsers = catchAsync(async (request, response) => {
    const { page, limit, search, role, isActive } = request.query;

    const result = await AdminUserService.getUsers({
      page,
      limit,
      search,
      role,
      isActive,
    });

    return response
      .status(200)
      .json(new ApiResponse(200, "Users retrieved successfully.", result));
  });

  /**
   * Get user by ID.
   *
   * GET /riskradar/users/:id/admin
   */
  static getUserById = catchAsync(async (request, response) => {
    const { id } = request.params;

    const user = await AdminUserService.getUserById(id);

    return response
      .status(200)
      .json(new ApiResponse(200, "User retrieved successfully.", user));
  });

  /**
   * Activate or deactivate a user.
   *
   * PATCH /riskradar/users/:id/admin/status
   *
   * Body:
   * {
   *   "isActive": false
   * }
   */
  static updateUserStatus = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { isActive } = request.body;

    const { id: adminUserId } = request.user;

    const user = await AdminUserService.updateUserStatus(
      id,
      isActive,
      adminUserId,
    );

    return response
      .status(200)
      .json(new ApiResponse(200, "User status updated successfully.", user));
  });

  /**
   * Change user role.
   *
   * PATCH /riskradar/users/:id/admin/role
   *
   * Body:
   * {
   *   "role": "ADMIN"
   * }
   */
  static updateUserRole = catchAsync(async (request, res) => {
    const { id } = request.params;
    const { role } = request.body;

    const { id: adminUserId } = request.user;

    const user = await AdminUserService.updateUserRole(id, role, adminUserId);

    return res
      .status(200)
      .json(new ApiResponse(200, "User role updated successfully.", user));
  });

  /**
   * Delete user.
   *
   * DELETE /riskradar/users/:id/admin
   */
  static deleteUser = catchAsync(async (request, response) => {
    const { id } = request.params;

    const { id: adminUserId } = request.user;

    const deletedUser = await AdminUserService.deleteUser(id, adminUserId);

    return response
      .status(200)
      .json(new ApiResponse(200, "User deleted successfully.", deletedUser));
  });
}

export default AdminUserController;
