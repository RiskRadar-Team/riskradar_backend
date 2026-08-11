import AdminDashboardService from "../services/adminDashboardService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class AdminDashboardController {
  /**
   * Get platform-wide admin dashboard.
   *
   * GET /riskradar/admin/dashboard
   *
   * Optional:
   * GET /riskradar/admin/dashboard?period=7d
   * GET /riskradar/admin/dashboard?period=30d
   * GET /riskradar/admin/dashboard?period=90d
   * GET /riskradar/admin/dashboard?period=all
   */
  static getDashboard = catchAsync(async (request, response) => {
    const period = request.query.period || "30d";

    const dashboard = await AdminDashboardService.getDashboard(period);

    return response
      .status(200)
      .json(
        new ApiResponse(
          200,
          "Admin dashboard data retrieved successfully.",
          dashboard,
        ),
      );
  });
}

export default AdminDashboardController;
