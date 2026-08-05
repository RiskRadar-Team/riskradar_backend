import ScanService from "../services/scanService.js";
import catchAsync from "../utils/catchAsync.js";
import ApiResponse from "../utils/ApiResponse.js";
class ScanController {
  /**create scan and run url scanner
   * this will make the request
   * POST http://localhost:5000/riskradar/scan/url
   */

  static createAndScanUrl = catchAsync(async (request, response) => {
    const userId = request.user.id;

    const { url } = request.body;

    const result = await ScanService.createAndScanUrl(userId, url);

    return response
      .status(200)
      .json(new ApiResponse(200, "URL scanned successfully.", result));
  });

  /**scan a url
   * POST /riskradar/scans/:id/url
   */
  static scanUrl = catchAsync(async (req, res) => {
    const { scanId } = req.params;
    const { url } = req.body;

    const result = await ScanService.scanUrl(scanId, url);

    return res
      .status(200)
      .json(new ApiResponse(200, "URL scanned successfully.", result));
  });
  /**create a new scan
   * POST /riskradar/scans
   */
  static createScan = catchAsync(async (request, response) => {
    const userId = request.user.id;
    const { scan_type } = request.body;

    const scan = await ScanService.createScan(userId, scan_type);

    return response
      .status(201)
      .json(new ApiResponse(201, "Scan created successfully.", scan));
  });
  /** start a scan
   * POST /riskradar/scans/:id/start
   */
  static startScan = catchAsync(async (request, response) => {
    const { id } = request.params;
    const scan = await ScanService.startScan(id);
    return response
      .status(200)
      .json(new ApiResponse(201, "Scan processing started.", scan));
  });
  /**Get scan by ID
   * GET /riskradar/scans/:id
   */
  static getScanById = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const scan = await ScanService.getScanById(id, userId);
    return response
      .status(200)
      .json(new ApiResponse(200, "Scan Details.", scan));
  });
  /**Get authenticated user's scan history
   * GET /riskradar/scans
   */
  static getUserScans = catchAsync(async (request, response) => {
    const userId = request.user.id;

    const {
      page = 1,
      limit = 10,
      search = "",
      scan_type,
      status,
      risk_level_id,
      sort_by = "created_at",
      sort_order = "DESC",
    } = request.query;

    const result = await ScanService.searchAndGetUserScans(
      userId,
      Number(page),
      Number(limit),
      search,
      scan_type,
      status,
      risk_level_id,
      sort_by,
      sort_order,
    );

    return response
      .status(200)
      .json(new ApiResponse(200, "Scan history fetched successfully.", result));
  });
  /**mark scan as completed
   * POST /riskradar/scans/:id/complete
   */
  static completeScan = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { risk_score, risk_level_id, is_phishing, scan_duration_ms } =
      request.body;
    const scan = await ScanService.completeScan(id, {
      risk_score,
      risk_level_id,
      is_phishing,
      scan_duration_ms,
    });
    return response
      .status(200)
      .json(new ApiResponse(200, "Scan completed successfully", scan));
  });
  /**mark scan as failed
   * POST /riskradar/scans/:id/fail
   */
  static failedScan = catchAsync(async (request, response) => {
    const { id } = request.params;
    const scan = await ScanService.failScan(id);
    return response
      .status(200)
      .json(new ApiResponse(200, "Scan marked as failed", scan));
  });
  /**delete scan
   * DELETE /riskradar/scans/:id
   */
  static deleteScan = catchAsync(async (request, response) => {
    const { id } = request.params;
    const { id: userId } = request.user;
    const scan = await ScanService.deleteScan(id, userId);
    return response
      .status(200)
      .json(new ApiResponse(200, "Scan deleted successfully.", scan));
  });
}

export default ScanController;
