import DashboardService from "../services/dashboardService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class DashboardController {
  /**
   * Get authenticated user's dashboard.
   *
   * GET /riskradar/dashboard
   * GET /riskradar/dashboard?period=30d
   */
  static getDashboard = catchAsync(async (request, response) => {
    /*
     * User id comes from authentication middleware.
     */
    const { id: userId } = request.user;

    /*
     * Default dashboard period.
     */
    const period = request.query.period || "30d";

    const dashboard = await DashboardService.getDashboard(userId, period);

    return response
      .status(200)
      .json(
        new ApiResponse(
          200,
          "Dashboard data retrieved successfully.",
          dashboard,
        ),
      );
  });
}

export default DashboardController;
