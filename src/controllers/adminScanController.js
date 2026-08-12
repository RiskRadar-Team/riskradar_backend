import AdminScanService from "../services/adminScanService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class AdminScanController {
  /**
   * Get platform-wide scan history.
   *
   * GET /riskradar/admin/scans
   *
   * Query parameters:
   *
   * ?page=1
   * ?limit=20
   * ?userId=<UUID>
   * ?scanType=URL
   * ?riskLevel=HIGH
   * ?isPhishing=true
   * ?status=COMPLETED
   * ?from=2026-08-01
   * ?to=2026-08-12
   */
  static getScans = catchAsync(async (request, response) => {
    const {
      page,
      limit,
      userId,
      scanType,
      riskLevel,
      isPhishing,
      status,
      from,
      to,
    } = request.query;

    const result = await AdminScanService.getScans({
      page,
      limit,
      userId,
      scanType,
      riskLevel,
      isPhishing,
      status,
      from,
      to,
    });

    return response
      .status(200)
      .json(
        new ApiResponse(
          200,
          "Admin scan history retrieved successfully.",
          result,
        ),
      );
  });

  /**
   * Get complete details of one scan.
   *
   * GET /riskradar/admin/scans/:scanId
   */
  static getScanById = catchAsync(async (req, res) => {
    const { scanId } = req.params;

    const result = await AdminScanService.getScanById(scanId);

    return res
      .status(200)
      .json(
        new ApiResponse(200, "Scan details retrieved successfully.", result),
      );
  });
}

export default AdminScanController;
