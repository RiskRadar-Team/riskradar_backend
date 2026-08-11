import HistoryService from "../services/historyService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class HistoryController {
  /**
   * Get authenticated user's scan history.
   *
   * GET /riskradar/history
   *
   * Query parameters:
   *
   * ?page=1
   * ?limit=20
   * ?scanType=URL
   * ?riskLevel=HIGH
   * ?isPhishing=true
   * ?from=2026-08-01
   * ?to=2026-08-11
   */
  static getHistory = catchAsync(async (request, response) => {
    const { id: userId } = request.user;

    const { page, limit, scanType, riskLevel, isPhishing, from, to } =
      request.query;

    const result = await HistoryService.getHistory({
      userId,
      page,
      limit,
      scanType,
      riskLevel,
      isPhishing,
      from,
      to,
    });

    return response
      .status(200)
      .json(
        new ApiResponse(200, "Scan history retrieved successfully.", result),
      );
  });

  /**
   * Get complete details of one scan.
   *
   * GET /riskradar/history/:scanId
   */
  static getScanById = catchAsync(async (request, response) => {
    const { id: userId } = request.user;

    const { scanId } = request.params;

    const result = await HistoryService.getScanById(userId, scanId);

    return response
      .status(200)
      .json(
        new ApiResponse(200, "Scan details retrieved successfully.", result),
      );
  });
}

export default HistoryController;
