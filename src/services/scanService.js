import ScanModel from "../models/scanModel.js";
import ApiError from "../utils/ApiError.js";

class ScanService {
  /**create a new scan */
  static async createScan(userId, scanType) {
    if (!userId) {
      throw new ApiError(401, "User Authencation is required.");
    }
    if (!scanType) {
      throw new ApiError(400, "Scan type is required.");
    }
    const allowedScanTypes = ["URL", "EMAIL", "MESSAGE"];
    if (!allowedScanTypes.includes(scanType)) {
      throw new ApiError(400, "Invalid scan type.");
    }
    const scan = await ScanModel.create({
      user_id: userId,
      scan_type: scanType,
      status: "PENDING",
      engine_version: "1.0.0",
    });

    return scan;
  }
  /**start processing a scan */
  static async startScan(scanId) {
    const scan = await ScanModel.findById(scanId);
    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }
    if (scan.status !== "PENDING") {
      throw new ApiError(
        400,
        `Scan cannot be started because its current status is ${scan.status}.`,
      );
    }
    const processingScan = await ScanModel.markProcessing(scanId);
    return processingScan;
  }
  /** scan completed funtion */
  static async completeScan(scanId, scanResult) {
    const scan = await ScanModel.findById(scanId);
    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }
    if (scan.status !== "PROCESSING") {
      throw new ApiError(
        400,
        `Scan cannot be completed because its current status is ${scan.status}.`,
      );
    }
    const { risk_score, risk_level_id, is_phishing, scan_duration_ms } =
      scanResult;
    if (risk_score === undefined || risk_score === null) {
      throw new ApiError(400, "Risk score is required.");
    }
    if (!risk_level_id) {
      throw new ApiError(400, "Risk level is required.");
    }
    if (is_phishing === undefined) {
      throw new ApiError(400, "Phishing result is required.");
    }
    const completeScan = await ScanModel.complete(scanId, {
      risk_score,
      risk_level_id,
      is_phishing,
      scan_duration_ms: scan_duration_ms || null,
    });
    return completeScan;
  }
  /** mark scan as failed */
  static async failScan(scanId) {
    const scan = await ScanModel.findById(scanId);
    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }
    if (scan.status === "COMPLETED") {
      throw new ApiError(400, "A completed scan cannot be marked as failed.");
    }
    if (scan.status === "FAILED") {
      return scan;
    }
    const failedScan = await ScanModel.markFailed(scanId);
    return failedScan;
  }
  /** get scan by it's ID */
  static async getScanById(scanId, userId) {
    // console.log("scanId:", scanId, "userId:", userId);
    const scan = await ScanModel.findById(scanId);
    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }
    /**users should only be able to access their own scans */
    if (userId && scan.user_id !== userId) {
      throw new ApiError(403, "You are not authorized to access this scan.");
    }
    return scan;
  }
  /** Search and get user's scan history */
  static async searchAndGetUserScans(
    userId,
    page = 1,
    limit = 10,
    search = "",
    scanType,
    status,
    riskLevelId,
    sortBy = "created_at",
    sortOrder = "DESC",
  ) {
    if (!userId) {
      throw new ApiError(401, "User authentication is required.");
    }
    const result = await ScanModel.searchAndFindAll(
      userId,
      page,
      limit,
      search,
      scanType,
      status,
      riskLevelId,
      sortBy,
      sortOrder,
    );
    // /**filter results to the authenticated user. */
    // result.scans = result.scans.filter((scan) => scan.user_id === userId);
    return result;
  }
  /** Delete a scan  */
  static async deleteScan(scanId, userId) {
    const scan = await ScanModel.findById(scanId);
    if (!scan) {
      throw new ApiError(404, "Scan not found.");
    }

    if (userId && scan.user_id !== userId) {
      throw new ApiError(403, "You are not authorized to access this scan.");
    }
    if (scan.status === "PROCESSING") {
      throw new ApiError(
        400,
        "A scan currently being processed cannot be deleted.",
      );
    }
    const deleted = await ScanModel.delete(scanId);
    if (!deleted) {
      throw new ApiError(404, "Scan already deleted or not found.");
    }
    return deleted;
  }
}
export default ScanService;
